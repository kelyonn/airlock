package image

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// This file implements verification for the signature format CURRENT cosign
// actually writes — the OCI 1.1 "referrers" layout carrying a Sigstore
// bundle with a DSSE envelope inside it. signature.go implements the older
// tag-based "simple signing" format. Both are supported because both exist
// in the wild: anything signed by cosign 2.x, or by 3.x with the legacy
// mode selected, uses the old layout; anything signed by a current cosign
// with default settings uses this one.
//
// The whole shape here was confirmed empirically against a real cosign
// 3.1.2 signing a real image into a real registry, not written from
// documentation — the previous round of this work established the hard way
// that cosign's on-registry format had moved on from what its own docs
// describe. What that inspection found:
//
//	tag "sha256-<hex>"                     (note: no ".sig" suffix)
//	  └─ an OCI image INDEX
//	       └─ a manifest entry whose artifactType is
//	          application/vnd.dev.sigstore.bundle.v0.3+json
//	            └─ that manifest's single layer blob = the bundle JSON
//	                 └─ .dsseEnvelope = { payload (base64 in-toto
//	                    statement), payloadType, signatures[].sig (base64
//	                    ASN.1 DER ECDSA) }
//
// The signature is NOT over the payload bytes directly (that's the older
// format's rule). DSSE signs a "pre-authentication encoding" that binds the
// payload to its declared type, so a payload can't be reinterpreted as a
// different content type by an attacker who only controls the envelope.

const (
	// sigstoreBundleArtifactType identifies the signature manifest inside
	// the index that the fallback tag resolves to.
	sigstoreBundleArtifactType = "application/vnd.dev.sigstore.bundle.v0.3+json"

	// dsseInTotoPayloadType is the payload type cosign uses for image
	// signatures. Checked rather than assumed: the PAE binds this string
	// into what gets signed, so accepting an unexpected type would mean
	// verifying a signature over something this code isn't parsing as such.
	dsseInTotoPayloadType = "application/vnd.in-toto+json"

	// ociImageIndexMediaType / ociImageManifestMediaType are the Accept
	// values needed to retrieve each level of the structure above.
	ociImageIndexMediaType    = "application/vnd.oci.image.index.v1+json"
	ociImageManifestMediaType = "application/vnd.oci.image.manifest.v1+json"
)

// sigstoreBundle is the subset of the bundle JSON verification needs. The
// real format carries considerably more (transparency-log entries,
// timestamp material, certificate chains for keyless signing) — none of
// which applies to static-key verification, and all of which is ignored
// here rather than half-checked.
type sigstoreBundle struct {
	MediaType    string `json:"mediaType"`
	DSSEEnvelope struct {
		Payload     string `json:"payload"`     // base64 in-toto statement
		PayloadType string `json:"payloadType"` // e.g. application/vnd.in-toto+json
		Signatures  []struct {
			Sig string `json:"sig"` // base64 ASN.1 DER ECDSA
		} `json:"signatures"`
	} `json:"dsseEnvelope"`
}

// inTotoStatement is the decoded DSSE payload. Its subject digests are what
// tie the signature to a specific image — the modern equivalent of the old
// format's critical.image.docker-manifest-digest.
type inTotoStatement struct {
	Type    string `json:"_type"`
	Subject []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
}

// ociIndex is a minimal OCI image index. The existing ManifestList type in
// registry.go can't be reused: it models platform-based multi-arch entries
// and has no artifactType field, which is the only thing distinguishing a
// signature manifest here.
type ociIndex struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Manifests     []struct {
		MediaType    string `json:"mediaType"`
		ArtifactType string `json:"artifactType"`
		Digest       string `json:"digest"`
		Size         int64  `json:"size"`
	} `json:"manifests"`
}

// bundleTagForDigest returns the tag cosign publishes the referrers
// fallback under: "sha256:abc…" → "sha256-abc…". Identical to the legacy
// convention except for the absent ".sig" suffix, which is the only thing
// keeping the two formats' tags from colliding.
func bundleTagForDigest(manifestDigest string) (string, error) {
	if !strings.HasPrefix(manifestDigest, "sha256:") {
		return "", fmt.Errorf("unsupported digest algorithm (only sha256 is supported): %s", manifestDigest)
	}
	return strings.Replace(manifestDigest, "sha256:", "sha256-", 1), nil
}

// dssePAE builds the DSSE Pre-Authentication Encoding:
//
//	"DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload
//
// where each LEN is the decimal byte count in ASCII. This exact byte string
// — not the payload alone — is what gets hashed and signed, which is what
// stops a signature over one payload type being replayed as another.
// Assembled with a byte buffer rather than fmt.Sprintf so payload bytes are
// copied verbatim with no risk of formatting-verb interpretation.
func dssePAE(payloadType string, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1 ")
	fmt.Fprintf(&b, "%d ", len(payloadType))
	b.WriteString(payloadType)
	b.WriteByte(' ')
	fmt.Fprintf(&b, "%d ", len(payload))
	b.Write(payload)
	return b.Bytes()
}

// verifyDSSEEnvelope checks the bundle's DSSE signature against pubKey and
// confirms the signed statement actually names wantDigest as its subject.
// Both halves matter: the signature proves the key signed something, the
// subject check proves that something was THIS image. Split from the
// network fetching below so it can be unit tested against a real keypair
// with no registry involved.
func verifyDSSEEnvelope(bundle *sigstoreBundle, wantDigest string, pubKey *ecdsa.PublicKey) error {
	env := bundle.DSSEEnvelope

	if env.PayloadType != dsseInTotoPayloadType {
		return fmt.Errorf("unexpected DSSE payload type %q (want %q)", env.PayloadType, dsseInTotoPayloadType)
	}
	if len(env.Signatures) == 0 {
		return fmt.Errorf("bundle contains no signatures")
	}

	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return fmt.Errorf("decode DSSE payload: %w", err)
	}

	pae := dssePAE(env.PayloadType, payload)
	hash := sha256.Sum256(pae)

	// Any one valid signature is enough: a bundle may legitimately carry
	// several (multiple signers), and requiring all of them to match this
	// single key would reject a correctly-signed image.
	verified := false
	for _, s := range env.Signatures {
		sig, decErr := base64.StdEncoding.DecodeString(s.Sig)
		if decErr != nil {
			continue
		}
		if ecdsa.VerifyASN1(pubKey, hash[:], sig) {
			verified = true
			break
		}
	}
	if !verified {
		return fmt.Errorf("signature verification failed")
	}

	return verifyStatementSubject(payload, wantDigest)
}

// verifyStatementSubject confirms the signed in-toto statement names
// wantDigest among its subjects. Without this a valid signature over some
// OTHER image, made by the same signer, would satisfy the cryptographic
// check while attesting to nothing about the image actually being pulled.
func verifyStatementSubject(payload []byte, wantDigest string) error {
	var stmt inTotoStatement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return fmt.Errorf("parse in-toto statement: %w", err)
	}
	if len(stmt.Subject) == 0 {
		return fmt.Errorf("signed statement lists no subjects")
	}

	wantHex := strings.TrimPrefix(wantDigest, "sha256:")
	var found []string
	for _, sub := range stmt.Subject {
		got := sub.Digest["sha256"]
		if got == "" {
			continue
		}
		if strings.EqualFold(got, wantHex) {
			return nil
		}
		found = append(found, got)
	}
	return fmt.Errorf("signature is for a different image: signed digest(s) %s, expected %s",
		strings.Join(found, ", "), wantHex)
}

// fetchRawManifest retrieves a manifest or index as raw bytes with a
// caller-chosen Accept header.
//
// Deliberately separate from registry.go's FetchManifest rather than
// extending it: that function is on the critical path of every image pull,
// decodes into a fixed Manifest shape, and enforces digest verification —
// none of which fits fetching an index whose entries are identified by
// artifactType. Keeping this here confines the change to signature
// verification instead of touching the pull path everything else depends on.
func fetchRawManifest(ref ImageRef, tagOrDigest, token, accept string) ([]byte, error) {
	url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", ref.Registry, ref.Repo, tagOrDigest)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create manifest request: %w", err)
	}
	req.Header.Set("Accept", accept)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("fetch manifest returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return io.ReadAll(resp.Body)
}

// verifyBundleSignature is the modern-format half of VerifyCosignSignature:
// resolve the referrers fallback tag to an index, find the bundle manifest
// inside it, fetch the bundle blob, and verify its DSSE envelope.
func verifyBundleSignature(ref ImageRef, manifestDigest, token string, pubKey *ecdsa.PublicKey) error {
	tag, err := bundleTagForDigest(manifestDigest)
	if err != nil {
		return err
	}

	indexBytes, err := fetchRawManifest(ref, tag, token,
		ociImageIndexMediaType+","+ociImageManifestMediaType)
	if err != nil {
		return fmt.Errorf("no signature bundle found: %w", err)
	}

	var index ociIndex
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		return fmt.Errorf("parse signature index: %w", err)
	}

	var bundleManifestDigest string
	for _, m := range index.Manifests {
		if m.ArtifactType == sigstoreBundleArtifactType {
			bundleManifestDigest = m.Digest
			break
		}
	}
	if bundleManifestDigest == "" {
		return fmt.Errorf("signature index contains no %s entry", sigstoreBundleArtifactType)
	}

	manifestBytes, err := fetchRawManifest(ref, bundleManifestDigest, token, ociImageManifestMediaType)
	if err != nil {
		return fmt.Errorf("fetch signature manifest: %w", err)
	}
	var sigManifest Manifest
	if err := json.Unmarshal(manifestBytes, &sigManifest); err != nil {
		return fmt.Errorf("parse signature manifest: %w", err)
	}
	if len(sigManifest.Layers) == 0 {
		return fmt.Errorf("signature manifest has no layers")
	}

	blobReader, err := FetchBlob(ref, sigManifest.Layers[0].Digest, token)
	if err != nil {
		return fmt.Errorf("fetch signature bundle: %w", err)
	}
	defer blobReader.Close()
	bundleBytes, err := io.ReadAll(blobReader)
	if err != nil {
		return fmt.Errorf("read signature bundle: %w", err)
	}

	var bundle sigstoreBundle
	if err := json.Unmarshal(bundleBytes, &bundle); err != nil {
		return fmt.Errorf("parse signature bundle: %w", err)
	}

	return verifyDSSEEnvelope(&bundle, manifestDigest, pubKey)
}
