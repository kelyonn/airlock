package image

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
)

// Manifest represents an OCI or Docker image manifest.
type Manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        Descriptor   `json:"config"`
	Layers        []Descriptor `json:"layers"`
}

// Descriptor points to a blob (layer or config) by digest.
type Descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// authTokenResponse is the JSON payload returned by the Docker Hub token endpoint.
type authTokenResponse struct {
	Token string `json:"token"`
}

// ManifestList represents an OCI image index or Docker manifest list (multi-arch fat manifest).
type ManifestList struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	Manifests     []ManifestPointer `json:"manifests"`
}

// ManifestPointer is one entry in a ManifestList pointing to a platform-specific manifest.
type ManifestPointer struct {
	MediaType string       `json:"mediaType"`
	Digest    string       `json:"digest"`
	Size      int64        `json:"size"`
	Platform  PlatformSpec `json:"platform"`
}

// PlatformSpec describes the OS/architecture for a ManifestPointer entry.
type PlatformSpec struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

// GetAuthToken obtains a pull token for the given image reference.
// For Docker Hub registries it fetches a Bearer token from auth.docker.io.
// For all other registries it returns an empty string (no auth required).
func GetAuthToken(ref ImageRef) (string, error) {
	authURL := ref.AuthURL()
	if authURL == "" {
		// Non-Docker Hub registry — skip auth.
		return "", nil
	}

	// Build token request URL:
	// GET https://auth.docker.io/token?service=registry.docker.io&scope=repository:<repo>:pull
	url := fmt.Sprintf("%s?service=registry.docker.io&scope=repository:%s:pull", authURL, ref.Repo)

	resp, err := http.Get(url) //nolint:noctx
	if err != nil {
		return "", fmt.Errorf("auth token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth token request returned HTTP %d", resp.StatusCode)
	}

	var payload authTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("auth token decode failed: %w", err)
	}

	return payload.Token, nil
}

// FetchManifest retrieves the image manifest for ref from its registry.
// token is the Bearer token obtained from GetAuthToken; pass "" if not needed.
// Both OCI and Docker V2 manifest media types are accepted.
func FetchManifest(ref ImageRef, token string) (Manifest, error) {
	// Determine the tag or digest portion of the URL.
	tagOrDigest := ref.Tag
	if ref.Digest != "" {
		tagOrDigest = ref.Digest
	}

	url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", ref.Registry, ref.Repo, tagOrDigest)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return Manifest{}, fmt.Errorf("create manifest request: %w", err)
	}

	// Accept both OCI and Docker Distribution manifest schemas.
	req.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json")
	req.Header.Add("Accept", "application/vnd.docker.distribution.manifest.v2+json")

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Manifest{}, fmt.Errorf("fetch manifest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return Manifest{}, fmt.Errorf("fetch manifest returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	// Read the full body so we can verify it against ref.Digest (when the
	// caller requested a specific digest) before trusting any of its content.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest body: %w", err)
	}

	if ref.Digest != "" {
		wantHex := strings.TrimPrefix(ref.Digest, "sha256:")
		sum := sha256.Sum256(body)
		gotHex := hex.EncodeToString(sum[:])
		if !strings.EqualFold(gotHex, wantHex) {
			return Manifest{}, fmt.Errorf("manifest digest mismatch: expected sha256:%s, got sha256:%s", wantHex, gotHex)
		}
	}

	// Check whether the registry returned a manifest list / OCI index instead of
	// a single-arch manifest.  This happens for multi-arch images on Docker Hub.
	contentType := resp.Header.Get("Content-Type")
	isManifestList := strings.Contains(contentType, "manifest.list") ||
		strings.Contains(contentType, "image.index")

	if isManifestList {
		var ml ManifestList
		if err := json.Unmarshal(body, &ml); err != nil {
			return Manifest{}, fmt.Errorf("decode manifest list: %w", err)
		}

		// Go's GOARCH strings already match OCI architecture names for the
		// architectures airlock supports (amd64, arm64).
		ociArch := runtime.GOARCH

		// Pick the manifest matching our OS+arch, falling back to first linux entry.
		var fallback string
		for _, mp := range ml.Manifests {
			if mp.Platform.OS != "linux" {
				continue
			}
			if fallback == "" {
				fallback = mp.Digest
			}
			if mp.Platform.Architecture == ociArch {
				// Re-fetch the concrete single-arch manifest by digest.
				platformRef := ImageRef{
					Registry: ref.Registry,
					Repo:     ref.Repo,
					Digest:   mp.Digest,
				}
				return FetchManifest(platformRef, token)
			}
		}
		if fallback != "" {
			platformRef := ImageRef{Registry: ref.Registry, Repo: ref.Repo, Digest: fallback}
			return FetchManifest(platformRef, token)
		}
		return Manifest{}, fmt.Errorf("no linux platform found in manifest list for %s", ref)
	}

	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}

	return m, nil
}

// FetchBlob retrieves a blob (layer or config) from the registry by digest.
// token is the Bearer token; pass "" if not needed.
// The caller is responsible for closing the returned ReadCloser.
func FetchBlob(ref ImageRef, digest string, token string) (io.ReadCloser, error) {
	url := fmt.Sprintf("https://%s/v2/%s/blobs/%s", ref.Registry, ref.Repo, digest)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create blob request: %w", err)
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch blob: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("fetch blob returned HTTP %d for %s", resp.StatusCode, digest)
	}

	return resp.Body, nil
}
