package image

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The fixtures in testdata/ are REAL output from cosign 3.1.2 signing a real
// image into a real registry — captured rather than synthesized, so these
// tests fail if this code drifts away from what cosign actually writes. That
// distinction matters here specifically: the first version of this feature
// was written against cosign's documented format and turned out not to match
// what current cosign produces at all, which is the whole reason the bundle
// format is now supported.
const (
	fixtureBundlePath = "testdata/cosign_v3_bundle.json"
	fixtureKeyPath    = "testdata/cosign_v3_key.pub"
	fixtureDigest     = "sha256:45e09956dc667c5eff3583c9d94830261fb1ca0be10a0a7db36266edf5de9e1d"
)

func loadFixtureBundle(t *testing.T) *sigstoreBundle {
	t.Helper()
	raw, err := os.ReadFile(fixtureBundlePath)
	if err != nil {
		t.Fatalf("read bundle fixture: %v", err)
	}
	var b sigstoreBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("parse bundle fixture: %v", err)
	}
	return &b
}

func loadFixtureKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	pem, err := os.ReadFile(fixtureKeyPath)
	if err != nil {
		t.Fatalf("read key fixture: %v", err)
	}
	key, err := parseECDSAPublicKeyPEM(pem)
	if err != nil {
		t.Fatalf("parse key fixture: %v", err)
	}
	return key
}

// TestVerifyRealCosignBundle is the interop test: a genuine cosign 3.1.2
// signature must verify with the matching public key, for the exact image
// digest it was made for.
func TestVerifyRealCosignBundle(t *testing.T) {
	if err := verifyDSSEEnvelope(loadFixtureBundle(t), fixtureDigest, loadFixtureKey(t)); err != nil {
		t.Fatalf("genuine cosign 3.1.2 bundle failed to verify: %v", err)
	}
}

func TestVerifyRealCosignBundleRejections(t *testing.T) {
	key := loadFixtureKey(t)

	t.Run("wrong image digest", func(t *testing.T) {
		// The signature itself is valid — this is the check that stops a
		// genuine signature for image A being presented as covering image B.
		other := "sha256:" + strings.Repeat("ab", 32)
		err := verifyDSSEEnvelope(loadFixtureBundle(t), other, key)
		if err == nil {
			t.Fatal("expected rejection for a signature covering a different image")
		}
		if !strings.Contains(err.Error(), "different image") {
			t.Errorf("expected a digest-mismatch error, got: %v", err)
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		otherKey, genErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if genErr != nil {
			t.Fatalf("generate key: %v", genErr)
		}
		if err := verifyDSSEEnvelope(loadFixtureBundle(t), fixtureDigest, &otherKey.PublicKey); err == nil {
			t.Fatal("expected rejection when verifying with an unrelated key")
		}
	})

	t.Run("tampered payload", func(t *testing.T) {
		b := loadFixtureBundle(t)
		payload, decErr := base64.StdEncoding.DecodeString(b.DSSEEnvelope.Payload)
		if decErr != nil {
			t.Fatalf("decode payload: %v", decErr)
		}
		// Flip the image digest inside the signed statement, then re-encode.
		// The signature no longer matches the payload it covers.
		tampered := strings.Replace(string(payload),
			"45e09956dc667c5eff3583c9d94830261fb1ca0be10a0a7db36266edf5de9e1d",
			strings.Repeat("ab", 32), 1)
		b.DSSEEnvelope.Payload = base64.StdEncoding.EncodeToString([]byte(tampered))
		if err := verifyDSSEEnvelope(b, fixtureDigest, key); err == nil {
			t.Fatal("expected rejection for a tampered payload")
		}
	})

	t.Run("unexpected payload type", func(t *testing.T) {
		// The payload type is bound into the signed PAE, so accepting an
		// unexpected one would mean verifying a signature over bytes this
		// code then parses as something else entirely.
		b := loadFixtureBundle(t)
		b.DSSEEnvelope.PayloadType = "application/vnd.something-else+json"
		if err := verifyDSSEEnvelope(b, fixtureDigest, key); err == nil {
			t.Fatal("expected rejection for an unexpected payload type")
		}
	})

	t.Run("no signatures", func(t *testing.T) {
		b := loadFixtureBundle(t)
		b.DSSEEnvelope.Signatures = nil
		if err := verifyDSSEEnvelope(b, fixtureDigest, key); err == nil {
			t.Fatal("expected rejection for a bundle with no signatures")
		}
	})
}

// TestDSSEPAEMatchesSpec pins the pre-authentication encoding byte-for-byte.
// This is the single most breakage-prone part of DSSE: get the framing
// subtly wrong and every signature silently fails to verify, with no clue
// as to why.
func TestDSSEPAEMatchesSpec(t *testing.T) {
	got := string(dssePAE("application/vnd.in-toto+json", []byte(`{"a":1}`)))
	want := `DSSEv1 28 application/vnd.in-toto+json 7 {"a":1}`
	if got != want {
		t.Errorf("PAE mismatch:\n got: %q\nwant: %q", got, want)
	}

	// Empty payload: the length field must still be present and zero.
	if got, want := string(dssePAE("t", nil)), "DSSEv1 1 t 0 "; got != want {
		t.Errorf("empty-payload PAE mismatch:\n got: %q\nwant: %q", got, want)
	}
}

// TestDSSEPAEIsUsedForSigning confirms the signature is over the PAE and not
// the bare payload — verifying against the raw payload must NOT succeed,
// which is what distinguishes this format from the legacy one.
func TestDSSEPAEIsUsedForSigning(t *testing.T) {
	b := loadFixtureBundle(t)
	key := loadFixtureKey(t)

	payload, err := base64.StdEncoding.DecodeString(b.DSSEEnvelope.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(b.DSSEEnvelope.Signatures[0].Sig)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	bare := sha256.Sum256(payload)
	if ecdsa.VerifyASN1(key, bare[:], sig) {
		t.Error("signature verified against the bare payload — this format signs the PAE, so that should not hold")
	}

	pae := sha256.Sum256(dssePAE(b.DSSEEnvelope.PayloadType, payload))
	if !ecdsa.VerifyASN1(key, pae[:], sig) {
		t.Error("signature did not verify against the PAE, which is what DSSE actually signs")
	}
}

func TestBundleTagForDigest(t *testing.T) {
	// The modern tag has NO .sig suffix — that absence is the only thing
	// keeping it from colliding with the legacy format's tag for the same
	// image, which is what lets VerifyCosignSignature try both unambiguously.
	got, err := bundleTagForDigest(fixtureDigest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "sha256-45e09956dc667c5eff3583c9d94830261fb1ca0be10a0a7db36266edf5de9e1d"
	if got != want {
		t.Errorf("bundleTagForDigest = %q, want %q", got, want)
	}
	if strings.HasSuffix(got, ".sig") {
		t.Error("modern bundle tag must not carry the legacy .sig suffix")
	}

	legacy, err := cosignSignatureTag(fixtureDigest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if legacy == got {
		t.Error("legacy and bundle tags collide — the two formats must be distinguishable")
	}

	if _, err := bundleTagForDigest("sha512:abc"); err == nil {
		t.Error("expected an error for a non-sha256 digest algorithm")
	}
}

func TestVerifyStatementSubject(t *testing.T) {
	stmt := func(digests ...string) []byte {
		var s inTotoStatement
		s.Type = "https://in-toto.io/Statement/v1"
		for _, d := range digests {
			s.Subject = append(s.Subject, struct {
				Name   string            `json:"name"`
				Digest map[string]string `json:"digest"`
			}{Digest: map[string]string{"sha256": d}})
		}
		raw, _ := json.Marshal(s)
		return raw
	}

	hex := strings.TrimPrefix(fixtureDigest, "sha256:")

	if err := verifyStatementSubject(stmt(hex), fixtureDigest); err != nil {
		t.Errorf("matching subject rejected: %v", err)
	}
	// A statement may legitimately carry several subjects; matching any is enough.
	if err := verifyStatementSubject(stmt(strings.Repeat("cd", 32), hex), fixtureDigest); err != nil {
		t.Errorf("subject list containing the digest was rejected: %v", err)
	}
	if err := verifyStatementSubject(stmt(strings.Repeat("cd", 32)), fixtureDigest); err == nil {
		t.Error("expected rejection when no subject matches")
	}
	if err := verifyStatementSubject(stmt(), fixtureDigest); err == nil {
		t.Error("expected rejection for a statement with no subjects")
	}
	if err := verifyStatementSubject([]byte("not json"), fixtureDigest); err == nil {
		t.Error("expected rejection for an unparseable statement")
	}
}
