package image

import "testing"

func TestParseReference(t *testing.T) {
	cases := []struct {
		name     string
		ref      string
		wantReg  string
		wantRepo string
		wantTag  string
		wantDig  string
	}{
		{
			name:     "bare official image, no tag",
			ref:      "alpine",
			wantReg:  "registry-1.docker.io",
			wantRepo: "library/alpine",
			wantTag:  "latest",
		},
		{
			name:     "bare official image with tag",
			ref:      "alpine:3.20",
			wantReg:  "registry-1.docker.io",
			wantRepo: "library/alpine",
			wantTag:  "3.20",
		},
		{
			name:     "official image, alpha tag",
			ref:      "nginx:alpine",
			wantReg:  "registry-1.docker.io",
			wantRepo: "library/nginx",
			wantTag:  "alpine",
		},
		{
			name:     "user-namespaced image with tag",
			ref:      "myuser/myapp:v1",
			wantReg:  "registry-1.docker.io",
			wantRepo: "myuser/myapp",
			wantTag:  "v1",
		},
		{
			name:     "user-namespaced image, no tag",
			ref:      "myuser/myapp",
			wantReg:  "registry-1.docker.io",
			wantRepo: "myuser/myapp",
			wantTag:  "latest",
		},
		{
			name:     "custom registry with dot",
			ref:      "ghcr.io/owner/repo:tag",
			wantReg:  "ghcr.io",
			wantRepo: "owner/repo",
			wantTag:  "tag",
		},
		{
			name:     "custom registry with port, disambiguated from tag",
			ref:      "localhost:5000/repo:tag",
			wantReg:  "localhost:5000",
			wantRepo: "repo",
			wantTag:  "tag",
		},
		{
			name:     "custom registry with port, no image tag",
			ref:      "localhost:5000/repo",
			wantReg:  "localhost:5000",
			wantRepo: "repo",
			wantTag:  "latest",
		},
		{
			name:     "bare localhost registry without port",
			ref:      "localhost/repo:tag",
			wantReg:  "localhost",
			wantRepo: "repo",
			wantTag:  "tag",
		},
		{
			name:     "custom registry with subdomain and explicit port",
			ref:      "myregistry.example.com:5000/team/app:1.2.3",
			wantReg:  "myregistry.example.com:5000",
			wantRepo: "team/app",
			wantTag:  "1.2.3",
		},
		{
			name:     "digest reference",
			ref:      "alpine@sha256:abc123",
			wantReg:  "registry-1.docker.io",
			wantRepo: "library/alpine",
			wantDig:  "sha256:abc123",
		},
		{
			name:     "digest reference on custom registry",
			ref:      "ghcr.io/owner/repo@sha256:deadbeef",
			wantReg:  "ghcr.io",
			wantRepo: "owner/repo",
			wantDig:  "sha256:deadbeef",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseReference(tc.ref)
			if got.Registry != tc.wantReg {
				t.Errorf("Registry = %q, want %q", got.Registry, tc.wantReg)
			}
			if got.Repo != tc.wantRepo {
				t.Errorf("Repo = %q, want %q", got.Repo, tc.wantRepo)
			}
			if got.Tag != tc.wantTag {
				t.Errorf("Tag = %q, want %q", got.Tag, tc.wantTag)
			}
			if got.Digest != tc.wantDig {
				t.Errorf("Digest = %q, want %q", got.Digest, tc.wantDig)
			}
		})
	}
}

func TestImageRefString(t *testing.T) {
	r := ParseReference("alpine:3.20")
	want := "registry-1.docker.io/library/alpine:3.20"
	if got := r.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}

	d := ParseReference("alpine@sha256:abc123")
	wantDig := "registry-1.docker.io/library/alpine@sha256:abc123"
	if got := d.String(); got != wantDig {
		t.Errorf("String() = %q, want %q", got, wantDig)
	}
}

func TestImageRefCacheKey(t *testing.T) {
	r := ParseReference("alpine:3.20")
	want := "registry-1.docker.io/library/alpine/3.20"
	if got := r.CacheKey(); got != want {
		t.Errorf("CacheKey() = %q, want %q", got, want)
	}

	d := ParseReference("alpine@sha256:abcdef")
	wantDig := "registry-1.docker.io/library/alpine/abcdef"
	if got := d.CacheKey(); got != wantDig {
		t.Errorf("CacheKey() = %q, want %q", got, wantDig)
	}
}

func TestAuthURL(t *testing.T) {
	dockerHub := ParseReference("alpine")
	if dockerHub.AuthURL() != "https://auth.docker.io/token" {
		t.Errorf("expected Docker Hub auth URL, got %q", dockerHub.AuthURL())
	}

	ghcr := ParseReference("ghcr.io/owner/repo")
	if ghcr.AuthURL() != "" {
		t.Errorf("expected empty auth URL for ghcr.io, got %q", ghcr.AuthURL())
	}
}
