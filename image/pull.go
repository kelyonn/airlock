package image

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Pull ensures the named image is locally cached and returns the path to its
// extracted rootfs directory. If the image is already cached the function
// returns immediately without hitting the network. Otherwise it:
//  1. Obtains an auth token (Docker Hub only).
//  2. Fetches the image manifest.
//  3. Downloads any missing layer blobs.
//  4. Extracts each layer in order (bottom-most first) with whiteout support.
//  5. Writes a .airlock-pulled marker so future calls skip the download.
func Pull(ref string, verbose bool) (string, error) {
	imgRef := ParseReference(ref)

	// --- Fast-path: already cached ---
	cached, err := IsCached(imgRef)
	if err != nil {
		return "", fmt.Errorf("cache check failed: %w", err)
	}
	if cached {
		fmt.Printf("✓  Using cached %s\n", imgRef.String())
		cacheDir, err := ImageCacheDir(imgRef)
		if err != nil {
			return "", err
		}
		return filepath.Join(cacheDir, "rootfs"), nil
	}

	fmt.Printf("⬇  Pulling %s...\n", imgRef.String())

	// --- Auth ---
	token, err := GetAuthToken(imgRef)
	if err != nil {
		return "", fmt.Errorf("auth failed: %w", err)
	}

	// --- Manifest ---
	manifest, err := FetchManifest(imgRef, token)
	if err != nil {
		return "", fmt.Errorf("fetch manifest: %w", err)
	}

	fmt.Printf("🔍 Image has %d layer(s)\n", len(manifest.Layers))

	// --- Ensure blob cache directory exists ---
	blobDir, err := BlobDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(blobDir, 0755); err != nil {
		return "", fmt.Errorf("create blob cache dir: %w", err)
	}

	// --- Download missing layers ---
	for i, layer := range manifest.Layers {
		shortDigest := layer.Digest
		if len(shortDigest) > 19 {
			shortDigest = shortDigest[:19] + "..."
		}
		fmt.Printf("   Layer %d/%d: %s\n", i+1, len(manifest.Layers), shortDigest)

		isCached, err := IsBlobCached(layer.Digest)
		if err != nil {
			return "", fmt.Errorf("blob cache check: %w", err)
		}
		if isCached {
			if verbose {
				fmt.Printf("      (cached)\n")
			}
			continue
		}

		// Download blob from registry.
		rc, err := FetchBlob(imgRef, layer.Digest, token)
		if err != nil {
			return "", fmt.Errorf("fetch layer %s: %w", layer.Digest, err)
		}

		blobPath, err := BlobCachePath(layer.Digest)
		if err != nil {
			rc.Close()
			return "", err
		}

		if err := saveBlob(rc, blobPath); err != nil {
			rc.Close()
			return "", fmt.Errorf("save layer %s: %w", layer.Digest, err)
		}
		rc.Close()
	}

	// --- Prepare rootfs directory ---
	cacheDir, err := ImageCacheDir(imgRef)
	if err != nil {
		return "", err
	}
	rootfsDir := filepath.Join(cacheDir, "rootfs")
	if err := os.MkdirAll(rootfsDir, 0755); err != nil {
		return "", fmt.Errorf("create rootfs dir: %w", err)
	}

	// --- Extract layers in order (bottom layer first) ---
	for i, layer := range manifest.Layers {
		shortDigest := layer.Digest
		if len(shortDigest) > 19 {
			shortDigest = shortDigest[:19] + "..."
		}
		if verbose {
			fmt.Printf("   Extracting layer %d/%d: %s\n", i+1, len(manifest.Layers), shortDigest)
		}

		blobPath, err := BlobCachePath(layer.Digest)
		if err != nil {
			return "", err
		}

		f, err := os.Open(blobPath)
		if err != nil {
			return "", fmt.Errorf("open layer blob: %w", err)
		}
		err = extractLayerTarGz(f, rootfsDir)
		f.Close()
		if err != nil {
			return "", fmt.Errorf("extract layer %s: %w", layer.Digest, err)
		}
	}

	// --- Write pulled marker ---
	marker := filepath.Join(cacheDir, ".airlock-pulled")
	if err := os.WriteFile(marker, []byte(imgRef.String()), 0644); err != nil {
		return "", fmt.Errorf("write pulled marker: %w", err)
	}

	fmt.Printf("✓  Image ready: %s\n", imgRef.String())
	return rootfsDir, nil
}

// saveBlob reads from rc and writes the contents to path atomically (via a temp file).
func saveBlob(rc io.Reader, path string) error {
	// Write to a temp file first, then rename to avoid partial writes.
	tmpPath := path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create temp blob file: %w", err)
	}

	if _, err := io.Copy(f, rc); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write blob: %w", err)
	}
	f.Close()

	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename blob file: %w", err)
	}
	return nil
}

// extractLayerTarGz extracts a gzip-compressed tar layer into dest, applying
// OCI/Docker whiteout semantics:
//   - A file named ".wh.<name>" causes <name> to be deleted from dest.
//   - A file named ".wh..wh..opq" marks an opaque whiteout: the entire parent
//     directory is cleared and re-created so upper layers shadow it completely.
func extractLayerTarGz(r io.Reader, dest string) error {
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

		// Sanitize path to prevent directory traversal.
		target := filepath.Join(dest, header.Name)
		if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), filepath.Clean(dest)+string(os.PathSeparator)) {
			// Allow exact match for the dest itself.
			if filepath.Clean(target) != filepath.Clean(dest) {
				return fmt.Errorf("invalid tar path: %s", header.Name)
			}
		}

		// --- Whiteout handling ---
		base := filepath.Base(header.Name)
		parentDir := filepath.Dir(target)

		// Opaque whiteout: clear and recreate the parent directory.
		if base == ".wh..wh..opq" {
			if err := os.RemoveAll(parentDir); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("opaque whiteout remove %s: %w", parentDir, err)
			}
			if err := os.MkdirAll(parentDir, 0755); err != nil {
				return fmt.Errorf("opaque whiteout recreate %s: %w", parentDir, err)
			}
			continue
		}

		// Standard whiteout: delete the named file/directory.
		if strings.HasPrefix(base, ".wh.") {
			realName := strings.TrimPrefix(base, ".wh.")
			realTarget := filepath.Join(parentDir, realName)
			if err := os.RemoveAll(realTarget); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("whiteout remove %s: %w", realTarget, err)
			}
			continue
		}

		// --- Normal entries ---
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("mkdir %s: %w", target, err)
			}

		case tar.TypeReg, tar.TypeRegA:
			// Ensure parent directory exists.
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("mkdir parent %s: %w", filepath.Dir(target), err)
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("create file %s: %w", target, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("write file %s: %w", target, err)
			}
			f.Close()

		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("mkdir parent %s: %w", filepath.Dir(target), err)
			}
			// Remove existing symlink/file before creating new one.
			os.Remove(target)
			if err := os.Symlink(header.Linkname, target); err != nil {
				return fmt.Errorf("symlink %s -> %s: %w", target, header.Linkname, err)
			}

		case tar.TypeLink:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("mkdir parent %s: %w", filepath.Dir(target), err)
			}
			linkTarget := filepath.Join(dest, header.Linkname)
			// Remove existing before linking.
			os.Remove(target)
			if err := os.Link(linkTarget, target); err != nil {
				return fmt.Errorf("hard link %s -> %s: %w", target, linkTarget, err)
			}
		}
	}

	return nil
}
