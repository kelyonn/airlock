package image

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
)

// This file implements cosign STATIC-KEY signature verification — the same
// mode as `cosign sign --key cosign.key` / `cosign verify --key cosign.pub`
// — using nothing beyond Go's standard crypto/ecdsa and crypto/sha256. It
// deliberately does NOT implement Sigstore's keyless flow (Fulcio
// short-lived certs + Rekor transparency-log inclusion proofs): that would
// mean either pulling in the full sigstore-go SDK (undercutting this
// project's from-scratch ethos the same way depending on runc/libcontainer
// would) or reimplementing a nontrivial PKI + Merkle-log verification stack
// from nothing. Static-key is the honest, achievable slice: real
// cryptographic provenance verification, entirely opt-in (via --verify-key;
// see cmd/run.go), no new dependency.
//
// Format, for reference: a cosign-signed image has a sibling artifact in
// the SAME repository, tagged "sha256-<manifest-digest-hex>.sig". That
// artifact's own manifest has one layer whose blob is a small JSON "simple
// signing" payload (the containers/image project's format, which cosign
// reuses rather than inventing its own) — critically including the digest
// of the image it was signed for, so a signature can't just be replayed
// against a different image with the same signer key. The actual signature
// itself isn't in the payload; it lives in that layer descriptor's own
// dev.cosignproject.cosign/signature annotation, base64-encoded, ECDSA
// (P-256/SHA-256, ASN.1 DER) over the raw payload bytes.

// cosignSignatureAnnotation is the well-known annotation key cosign writes
// the base64 signature into, on the signature artifact's own layer
// descriptor (not the signed image's manifest — a separate fetch).
const cosignSignatureAnnotation = "dev.cosignproject.cosign/signature"

// simpleSigningPayload is the "simple signing" JSON format cosign's
// signature layer blob contains — the thing actually signed, not the
// signature itself. Only the one field verification needs is modeled here;
// the real format has more (identity, optional metadata) that this doesn't
// need to round-trip.
type simpleSigningPayload struct {
	Critical struct {
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
	} `json:"critical"`
}

// cosignSignatureTag returns the tag cosign publishes a signature artifact
// under for the given image manifest digest — e.g. "sha256:abc123..." →
// "sha256-abc123....sig". Cosign's own convention: colons aren't legal in
// tags, so it substitutes a hyphen.
func cosignSignatureTag(manifestDigest string) (string, error) {
	if !strings.HasPrefix(manifestDigest, "sha256:") {
		return "", fmt.Errorf("unsupported digest algorithm (only sha256 is supported): %s", manifestDigest)
	}
	return strings.Replace(manifestDigest, "sha256:", "sha256-", 1) + ".sig", nil
}

// parseECDSAPublicKeyPEM reads and parses a PEM-encoded PKIX public key —
// the format cosign's own `cosign generate-key-pair` writes (cosign.pub) —
// requiring it to be ECDSA specifically, since that's the only algorithm
// this verifier implements.
func parseECDSAPublicKeyPEM(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ECDSA (got %T) — only ECDSA (cosign's default) is supported", pub)
	}
	return ecPub, nil
}

// verifyPayloadSignature checks a base64-encoded ASN.1 DER ECDSA signature
// (cosign's default: P-256, SHA-256) over payload against pubKey. Split out
// from the network-fetching orchestration below purely so it — and the two
// functions after it — can be unit tested directly: real keypair, real
// signature, no registry or filesystem involved.
func verifyPayloadSignature(payload []byte, sigB64 string, pubKey *ecdsa.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	hash := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(pubKey, hash[:], sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// verifyPayloadDigest checks that a simple-signing payload was actually
// signed FOR the image being pulled, not some other image entirely reusing
// the same signer's key — a valid signature alone doesn't establish that;
// nothing about ECDSA verification ties a signature to a specific digest
// unless the signed payload itself is checked. Without this, a correctly
// signed-and-verifying artifact for image A could be pointed at as if it
// verified image B.
func verifyPayloadDigest(payload []byte, wantDigest string) error {
	var p simpleSigningPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("parse signed payload: %w", err)
	}
	if !strings.EqualFold(p.Critical.Image.DockerManifestDigest, wantDigest) {
		return fmt.Errorf("signature is for a different image: signed digest %s, expected %s",
			p.Critical.Image.DockerManifestDigest, wantDigest)
	}
	return nil
}

// VerifyCosignSignature verifies that ref's image, at manifestDigest, has a
// valid cosign static-key signature from the key at pubKeyPath. Returns a
// descriptive error on any failure — no signature artifact found (image
// isn't signed at all), a signature that doesn't verify (wrong key, or
// genuinely tampered), or one that verifies but is for a different image —
// and a nil error only when a real, correctly-targeted signature checks out.
// Callers should treat any non-nil error as "do not run this image."
func VerifyCosignSignature(ref ImageRef, manifestDigest string, token string, pubKeyPath string) error {
	pubKeyPEM, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return fmt.Errorf("read public key %s: %w", pubKeyPath, err)
	}
	pubKey, err := parseECDSAPublicKeyPEM(pubKeyPEM)
	if err != nil {
		return fmt.Errorf("parse public key %s: %w", pubKeyPath, err)
	}

	// Two on-registry formats exist and both are supported, because both
	// are genuinely in use: the OCI-referrers/DSSE-bundle layout current
	// cosign writes by default, and the older tag-based "simple signing"
	// layout from cosign 2.x. They live under different tags
	// ("sha256-<hex>" and "sha256-<hex>.sig" respectively), so trying one
	// then the other is unambiguous rather than a guess.
	//
	// Modern first, since that's what a current `cosign sign --key`
	// produces. A failure here isn't returned immediately — an image signed
	// with the older format has no bundle at all, which is a "not this
	// format" answer rather than a verification failure — so the legacy
	// path gets its turn before anything is reported.
	bundleErr := verifyBundleSignature(ref, manifestDigest, token, pubKey)
	if bundleErr == nil {
		return nil
	}

	legacyErr := verifyLegacySignature(ref, manifestDigest, token, pubKey)
	if legacyErr == nil {
		return nil
	}

	// Neither worked. Both errors are surfaced: which one matters depends
	// on which format the image was actually signed with, and collapsing
	// them into one message would routinely hide the relevant half — a
	// genuine bad-signature failure in one format reads very differently
	// from "no signature artifact of this kind exists."
	return fmt.Errorf("no valid signature for %s:\n  bundle format (current cosign): %v\n  legacy tag format (cosign 2.x): %v",
		ref, bundleErr, legacyErr)
}

// verifyLegacySignature verifies the older tag-based "simple signing"
// format — see this file's header comment for its layout.
func verifyLegacySignature(ref ImageRef, manifestDigest string, token string, pubKey *ecdsa.PublicKey) error {
	sigTag, err := cosignSignatureTag(manifestDigest)
	if err != nil {
		return err
	}
	sigRef := ImageRef{Registry: ref.Registry, Repo: ref.Repo, Tag: sigTag}

	sigManifest, _, err := FetchManifest(sigRef, token)
	if err != nil {
		return fmt.Errorf("image is not signed (no signature artifact found for %s): %w", ref, err)
	}

	var sigLayer *Descriptor
	for i := range sigManifest.Layers {
		if sigManifest.Layers[i].Annotations[cosignSignatureAnnotation] != "" {
			sigLayer = &sigManifest.Layers[i]
			break
		}
	}
	if sigLayer == nil {
		return fmt.Errorf("signature artifact for %s has no %s annotation on any layer", ref, cosignSignatureAnnotation)
	}

	blobReader, err := FetchBlob(sigRef, sigLayer.Digest, token)
	if err != nil {
		return fmt.Errorf("fetch signed payload: %w", err)
	}
	defer blobReader.Close()
	payload, err := io.ReadAll(blobReader)
	if err != nil {
		return fmt.Errorf("read signed payload: %w", err)
	}

	if err := verifyPayloadSignature(payload, sigLayer.Annotations[cosignSignatureAnnotation], pubKey); err != nil {
		return fmt.Errorf("signature verification failed for %s: %w", ref, err)
	}
	if err := verifyPayloadDigest(payload, manifestDigest); err != nil {
		return err
	}

	return nil
}
