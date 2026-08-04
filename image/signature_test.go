package image

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

// genTestKeypair returns a real ECDSA P-256 keypair and its PEM-encoded
// public key (the same PKIX format cosign generate-key-pair writes to
// cosign.pub), so tests exercise the exact primitives production code does
// rather than stand-in fakes.
func genTestKeypair(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return priv, pubPEM
}

// signPayload produces the same base64(ASN.1 DER ECDSA-over-SHA256)
// signature format cosign writes into a signature layer's
// dev.cosignproject.cosign/signature annotation.
func signPayload(t *testing.T, priv *ecdsa.PrivateKey, payload []byte) string {
	t.Helper()
	hash := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("sign payload: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func TestCosignSignatureTag(t *testing.T) {
	cases := []struct {
		name    string
		digest  string
		want    string
		wantErr bool
	}{
		{name: "typical sha256 digest", digest: "sha256:abc123def456", want: "sha256-abc123def456.sig"},
		{name: "unsupported algorithm", digest: "sha512:deadbeef", wantErr: true},
		{name: "malformed, no algorithm prefix", digest: "abc123", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cosignSignatureTag(tc.digest)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("cosignSignatureTag(%q) = %q, want error", tc.digest, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("cosignSignatureTag(%q) unexpected error: %v", tc.digest, err)
			}
			if got != tc.want {
				t.Errorf("cosignSignatureTag(%q) = %q, want %q", tc.digest, got, tc.want)
			}
		})
	}
}

func TestParseECDSAPublicKeyPEM(t *testing.T) {
	_, pubPEM := genTestKeypair(t)

	t.Run("valid ECDSA key parses", func(t *testing.T) {
		key, err := parseECDSAPublicKeyPEM(pubPEM)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key == nil {
			t.Fatal("got nil key with no error")
		}
	})

	t.Run("garbage PEM rejected", func(t *testing.T) {
		if _, err := parseECDSAPublicKeyPEM([]byte("not a pem block at all")); err == nil {
			t.Fatal("expected error for non-PEM input, got nil")
		}
	})

	t.Run("non-ECDSA key rejected (RSA)", func(t *testing.T) {
		rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate RSA key: %v", err)
		}
		der, err := x509.MarshalPKIXPublicKey(&rsaPriv.PublicKey)
		if err != nil {
			t.Fatalf("marshal RSA public key: %v", err)
		}
		rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		if _, err := parseECDSAPublicKeyPEM(rsaPEM); err == nil {
			t.Fatal("expected error for RSA key (only ECDSA is supported), got nil")
		}
	})
}

func TestVerifyPayloadSignature(t *testing.T) {
	priv, pubPEM := genTestKeypair(t)
	pubKey, err := parseECDSAPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("parse test public key: %v", err)
	}

	payload := []byte(`{"critical":{"image":{"docker-manifest-digest":"sha256:abc123"}}}`)
	sigB64 := signPayload(t, priv, payload)

	t.Run("genuine signature verifies", func(t *testing.T) {
		if err := verifyPayloadSignature(payload, sigB64, pubKey); err != nil {
			t.Errorf("expected genuine signature to verify, got: %v", err)
		}
	})

	t.Run("tampered payload rejected", func(t *testing.T) {
		tampered := []byte(`{"critical":{"image":{"docker-manifest-digest":"sha256:evil000"}}}`)
		if err := verifyPayloadSignature(tampered, sigB64, pubKey); err == nil {
			t.Error("expected tampered payload to fail verification, got nil error")
		}
	})

	t.Run("wrong key rejected", func(t *testing.T) {
		_, otherPubPEM := genTestKeypair(t)
		otherKey, err := parseECDSAPublicKeyPEM(otherPubPEM)
		if err != nil {
			t.Fatalf("parse other public key: %v", err)
		}
		if err := verifyPayloadSignature(payload, sigB64, otherKey); err == nil {
			t.Error("expected wrong-key verification to fail, got nil error")
		}
	})

	t.Run("malformed base64 signature rejected", func(t *testing.T) {
		if err := verifyPayloadSignature(payload, "not-valid-base64!!!", pubKey); err == nil {
			t.Error("expected malformed base64 to fail, got nil error")
		}
	})
}

func TestVerifyPayloadDigest(t *testing.T) {
	cases := []struct {
		name       string
		payload    string
		wantDigest string
		wantErr    bool
	}{
		{
			name:       "matching digest",
			payload:    `{"critical":{"image":{"docker-manifest-digest":"sha256:abc123"}}}`,
			wantDigest: "sha256:abc123",
		},
		{
			name:       "matching digest, different case",
			payload:    `{"critical":{"image":{"docker-manifest-digest":"SHA256:ABC123"}}}`,
			wantDigest: "sha256:abc123",
		},
		{
			name:       "mismatched digest — signature for a different image",
			payload:    `{"critical":{"image":{"docker-manifest-digest":"sha256:someone-elses-image"}}}`,
			wantDigest: "sha256:abc123",
			wantErr:    true,
		},
		{
			name:       "malformed JSON",
			payload:    `not json at all`,
			wantDigest: "sha256:abc123",
			wantErr:    true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyPayloadDigest([]byte(tc.payload), tc.wantDigest)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestVerifyCosignSignatureFullRoundTrip exercises the same sign-then-verify
// path as the four unit tests above, but as a single combined round trip
// through the same two checks VerifyCosignSignature itself runs in
// sequence (signature, then digest) — catching anything only visible when
// they're chained, not just individually.
func TestVerifyCosignSignatureFullRoundTrip(t *testing.T) {
	priv, pubPEM := genTestKeypair(t)
	pubKey, err := parseECDSAPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}

	const manifestDigest = "sha256:abc123"
	payload := []byte(`{"critical":{"image":{"docker-manifest-digest":"` + manifestDigest + `"}}}`)
	sigB64 := signPayload(t, priv, payload)

	if err := verifyPayloadSignature(payload, sigB64, pubKey); err != nil {
		t.Fatalf("signature check failed: %v", err)
	}
	if err := verifyPayloadDigest(payload, manifestDigest); err != nil {
		t.Fatalf("digest check failed: %v", err)
	}
}
