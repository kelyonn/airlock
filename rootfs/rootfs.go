package rootfs

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	alpineVersion = "3.20.0"
	alpineBranch  = "v3.20"
)

// alpineArch maps GOARCH to the architecture name Alpine's own release
// paths use. Deliberately a lookup with no default: an unrecognized
// architecture returns a clear error from alpineRootfsURL rather than
// silently falling back to x86_64 and downloading a rootfs whose binaries
// cannot execute on this machine — which is exactly the bug this replaced.
var alpineArch = map[string]string{
	"amd64": "x86_64",
	"arm64": "aarch64",
}

// alpineRootfsURL returns the Alpine mini-rootfs download URL for the
// architecture this binary is running on.
//
// The URL used to hardcode x86_64 in both the path and the filename. On an
// arm64 host that silently downloaded an x86_64 rootfs, so every legacy-mode
// container (`airlock run /bin/sh`, the built-in mini-rootfs path — OCI
// images were unaffected, since image.Pull resolves a multi-arch manifest
// list for the running platform correctly) failed the instant it tried to
// exec a binary of the wrong architecture. It compiled and passed the whole
// test suite on amd64 the entire time; only actually running the suite on
// an arm64 machine surfaced it. Same shape as this project's earlier
// hardcoded-AUDIT_ARCH seccomp bug, and found the same way.
func alpineRootfsURL() (string, error) {
	arch, ok := alpineArch[runtime.GOARCH]
	if !ok {
		return "", fmt.Errorf("no Alpine mini-rootfs known for architecture %q "+
			"(supported: amd64, arm64) — use an OCI image reference instead, "+
			"e.g. `airlock run alpine:3.20 /bin/sh`", runtime.GOARCH)
	}
	return fmt.Sprintf(
		"https://dl-cdn.alpinelinux.org/alpine/%s/releases/%s/alpine-minirootfs-%s-%s.tar.gz",
		alpineBranch, arch, alpineVersion, arch,
	), nil
}

// CacheDir returns the path to the cached rootfs directory.
//
// Keyed by architecture ("alpine-amd64", "alpine-arm64") rather than a
// single shared "alpine". Two reasons, one of them a genuine upgrade-path
// bug: a machine that ran the previous version of this code on arm64 has a
// fully-extracted *x86_64* rootfs sitting at the old shared path complete
// with a valid .airlock-extracted marker, so Ensure would take the cache-hit
// branch and keep handing back the same unusable rootfs even after the URL
// itself was fixed. A distinct path per architecture sidesteps that with no
// migration or invalidation logic — the corrected architecture simply has no
// cache entry yet — and, incidentally, also makes a $HOME shared across
// architectures (NFS and the like) behave correctly. `airlock clean` removes
// the whole ~/.airlock/rootfs tree, so stale entries under the old path
// still get cleaned up by it.
func CacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".airlock", "rootfs", "alpine-"+runtime.GOARCH), nil
}

// Ensure downloads and extracts the Alpine rootfs if not already cached.
// Returns the path to the rootfs directory.
func Ensure(verbose bool) (string, error) {
	cacheDir, err := CacheDir()
	if err != nil {
		return "", err
	}

	// Check if rootfs already exists
	marker := filepath.Join(cacheDir, ".airlock-extracted")
	if _, err := os.Stat(marker); err == nil {
		if verbose {
			fmt.Println("[rootfs] Using cached Alpine rootfs")
		}
		return cacheDir, nil
	}

	// Resolved before anything is created or downloaded, so an unsupported
	// architecture fails immediately with an actionable message instead of
	// part-way through setup.
	url, err := alpineRootfsURL()
	if err != nil {
		return "", err
	}

	fmt.Printf("⬇  Downloading Alpine Linux rootfs (%s)...\n", runtime.GOARCH)

	// Create cache directory
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return "", fmt.Errorf("cannot create cache directory: %w", err)
	}

	// Download the tarball
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	// Wrap response body with a progress counter
	totalSize := resp.ContentLength
	reader := &progressReader{
		reader:    resp.Body,
		totalSize: totalSize,
	}

	// Extract directly from the HTTP stream
	if err := extractTarGz(reader, cacheDir); err != nil {
		// Clean up on failure
		os.RemoveAll(cacheDir)
		return "", fmt.Errorf("extraction failed: %w", err)
	}
	fmt.Println() // newline after progress

	// Write marker file to indicate successful extraction
	if err := os.WriteFile(marker, []byte(alpineVersion), 0644); err != nil {
		return "", fmt.Errorf("cannot write marker file: %w", err)
	}

	fmt.Println("✓ Alpine Linux rootfs ready")
	return cacheDir, nil
}

// extractTarGz extracts a .tar.gz stream into the destination directory.
func extractTarGz(r io.Reader, dest string) error {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gzip error: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar error: %w", err)
		}

		// Sanitize the path to prevent directory traversal attacks
		target := filepath.Join(dest, header.Name)
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(dest)) {
			return fmt.Errorf("invalid tar path: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			// Ensure parent directory exists
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			// Remove existing entry (symlink or file) before creating the new one.
			os.Remove(target)
			if err := os.Symlink(header.Linkname, target); err != nil {
				return err
			}
		case tar.TypeLink:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			// Remove existing entry before hard-linking.
			os.Remove(target)
			linkTarget := filepath.Join(dest, header.Linkname)
			if err := os.Link(linkTarget, target); err != nil {
				return err
			}
		}
	}

	return nil
}

// progressReader wraps an io.Reader to print download progress.
type progressReader struct {
	reader      io.Reader
	totalSize   int64
	bytesRead   int64
	lastPercent int
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	pr.bytesRead += int64(n)

	if pr.totalSize > 0 {
		percent := int(float64(pr.bytesRead) / float64(pr.totalSize) * 100)
		if percent != pr.lastPercent {
			pr.lastPercent = percent
			fmt.Printf("\r   Progress: %d%% (%d / %d bytes)", percent, pr.bytesRead, pr.totalSize)
		}
	}

	return n, err
}
