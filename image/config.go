package image

import (
	"encoding/json"
	"fmt"
	"io"
)

// ImageConfig holds the parts of an OCI/Docker image config blob that
// airlock actually uses to run a container without requiring the caller to
// spell out the image's own startup command by hand.
type ImageConfig struct {
	Entrypoint []string
	Cmd        []string
	Env        []string
	WorkingDir string
	User       string
}

// rawImageConfig mirrors the subset of the OCI image config spec
// (https://github.com/opencontainers/image-spec/blob/main/config.md) that
// ImageConfig needs. The manifest's "config" descriptor points at a blob
// with exactly this shape (Docker's own legacy v1 config format is
// field-for-field identical here).
type rawImageConfig struct {
	Config struct {
		Env        []string `json:"Env"`
		Entrypoint []string `json:"Entrypoint"`
		Cmd        []string `json:"Cmd"`
		WorkingDir string   `json:"WorkingDir"`
		User       string   `json:"User"`
	} `json:"config"`
}

// FetchImageConfig downloads the image's config blob (referenced by
// manifest.Config.Digest), verifies it against that digest the same way
// layer blobs are verified, and parses out the fields airlock cares about.
func FetchImageConfig(ref ImageRef, manifest Manifest, token string) (ImageConfig, error) {
	if manifest.Config.Digest == "" {
		return ImageConfig{}, nil
	}

	rc, err := FetchBlob(ref, manifest.Config.Digest, token)
	if err != nil {
		return ImageConfig{}, fmt.Errorf("fetch image config blob: %w", err)
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return ImageConfig{}, fmt.Errorf("read image config blob: %w", err)
	}

	if err := verifyDigestBytes(data, manifest.Config.Digest); err != nil {
		return ImageConfig{}, fmt.Errorf("image config blob: %w", err)
	}

	var raw rawImageConfig
	if err := json.Unmarshal(data, &raw); err != nil {
		return ImageConfig{}, fmt.Errorf("parse image config blob: %w", err)
	}

	return ImageConfig{
		Entrypoint: raw.Config.Entrypoint,
		Cmd:        raw.Config.Cmd,
		Env:        raw.Config.Env,
		WorkingDir: raw.Config.WorkingDir,
		User:       raw.Config.User,
	}, nil
}

// Command returns the effective argv for this image per OCI semantics: an
// ENTRYPOINT, if set, is the program to run, with CMD supplying its default
// arguments; with no ENTRYPOINT, CMD is the program itself. Returns
// (nil, nil) if the image specifies neither — an oddity, but not this
// function's job to reject.
func (c ImageConfig) Command() (command string, args []string) {
	full := append(append([]string(nil), c.Entrypoint...), c.Cmd...)
	if len(full) == 0 {
		return "", nil
	}
	return full[0], full[1:]
}
