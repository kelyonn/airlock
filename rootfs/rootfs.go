package rootfs

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	alpineVersion = "3.20.0"
	alpineURL     = "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-" + alpineVersion + "-x86_64.tar.gz"
)

// CacheDir returns the path to the cached rootfs directory.
func CacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".airlock", "rootfs", "alpine"), nil
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

	fmt.Println("⬇  Downloading Alpine Linux rootfs...")

	// Create cache directory
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return "", fmt.Errorf("cannot create cache directory: %w", err)
	}

	// Download the tarball
	resp, err := http.Get(alpineURL)
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
