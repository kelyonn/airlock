// Package image provides OCI image registry operations: parsing image references,
// fetching manifests and blobs, local caching, and extracting rootfs layers.
package image

import (
	"strings"
)

// ImageRef holds a parsed image reference.
type ImageRef struct {
	Registry string // e.g. "registry-1.docker.io"
	Repo     string // e.g. "library/alpine" or "myuser/myapp"
	Tag      string // e.g. "3.20" or "latest"
	Digest   string // e.g. "sha256:abc..." (optional, mutually exclusive with Tag)
}

// ParseReference parses an image reference string into an ImageRef.
// Supports formats:
//
//	alpine                         → docker.io/library/alpine:latest
//	alpine:3.20                    → docker.io/library/alpine:3.20
//	ubuntu:24.04                   → docker.io/library/ubuntu:24.04
//	nginx:alpine                   → docker.io/library/nginx:alpine
//	myuser/myapp:v1                → docker.io/myuser/myapp:v1
//	ghcr.io/owner/repo:tag         → ghcr.io/owner/repo:tag
//	myregistry.example.com/repo:t  → myregistry.example.com/repo:t
func ParseReference(ref string) ImageRef {
	var r ImageRef

	// Split off digest if present (image@sha256:...)
	name := ref
	if idx := strings.Index(ref, "@"); idx != -1 {
		name = ref[:idx]
		r.Digest = ref[idx+1:]
	}

	// Split tag from name (only if no digest was found)
	if r.Digest == "" {
		if idx := strings.LastIndex(name, ":"); idx != -1 {
			// Make sure the colon isn't part of the registry host (e.g. localhost:5000)
			// — only treat it as a tag separator if it appears after any slash.
			slashIdx := strings.LastIndex(name, "/")
			if idx > slashIdx {
				r.Tag = name[idx+1:]
				name = name[:idx]
			}
		}
	}
	if r.Tag == "" && r.Digest == "" {
		r.Tag = "latest"
	}

	// Determine whether the first path segment is a registry host.
	// A segment is treated as a registry host when it contains a dot or a colon,
	// OR when it equals "localhost".
	parts := strings.SplitN(name, "/", 2)
	isRegistry := false
	if len(parts) >= 2 {
		first := parts[0]
		if strings.ContainsAny(first, ".:") || first == "localhost" {
			isRegistry = true
		}
	}

	if isRegistry {
		// Custom registry: e.g. ghcr.io/owner/repo or myregistry:5000/repo
		r.Registry = parts[0]
		r.Repo = parts[1]
	} else {
		// Docker Hub
		r.Registry = "registry-1.docker.io"
		if len(parts) == 1 {
			// Official library image: alpine → library/alpine
			r.Repo = "library/" + parts[0]
		} else {
			// User-namespaced image: myuser/myapp
			r.Repo = name
		}
	}

	return r
}

// String returns the canonical string form of the reference.
func (r ImageRef) String() string {
	s := r.Registry + "/" + r.Repo
	if r.Digest != "" {
		s += "@" + r.Digest
	} else {
		s += ":" + r.Tag
	}
	return s
}

// CacheKey returns a filesystem-safe cache key for this image.
// e.g. "registry-1.docker.io/library/alpine/3.20"
func (r ImageRef) CacheKey() string {
	if r.Digest != "" {
		// Use the hex portion of the digest as the tag-equivalent
		hexPart := strings.TrimPrefix(r.Digest, "sha256:")
		return r.Registry + "/" + r.Repo + "/" + hexPart
	}
	return r.Registry + "/" + r.Repo + "/" + r.Tag
}

// AuthURL returns the token auth endpoint for this registry.
// Returns the Docker Hub token URL for Docker Hub images, and an empty string
// for other registries (assumed to not require token auth by default).
func (r ImageRef) AuthURL() string {
	if r.Registry == "registry-1.docker.io" {
		return "https://auth.docker.io/token"
	}
	return ""
}
