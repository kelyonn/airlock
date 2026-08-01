package image

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Pull ensures the named image is locally cached and returns the path to its
// extracted rootfs directory, along with the image's parsed config
// (ENTRYPOINT/CMD/ENV/WORKDIR/USER) so callers can run the image the way it
// was built to run without the caller having to already know its startup
// command. If the image is already cached the function returns immediately
// without hitting the network. Otherwise it:
//  1. Obtains an auth token (Docker Hub only).
//  2. Fetches the image manifest.
//  3. Downloads and verifies the image config blob.
//  4. Downloads any missing layer blobs.
//  5. Extracts each layer in order (bottom-most first) with whiteout support.
//  6. Writes a .airlock-pulled marker so future calls skip the download.
func Pull(ref string, verbose bool) (string, ImageConfig, error) {
	imgRef := ParseReference(ref)

	// --- Fast-path: already cached ---
	cached, err := IsCached(imgRef)
	if err != nil {
		return "", ImageConfig{}, fmt.Errorf("cache check failed: %w", err)
	}
	if cached {
		if verbose {
			fmt.Printf("✓  Using cached %s\n", imgRef.String())
		}
		cacheDir, err := ImageCacheDir(imgRef)
		if err != nil {
			return "", ImageConfig{}, err
		}
		// Images cached before image config parsing was added won't have
		// this file — that's fine, loadCachedImageConfig degrades to a zero
		// value and callers just fall back to requiring an explicit command,
		// exactly like before this feature existed.
		cfg := loadCachedImageConfig(cacheDir)
		return filepath.Join(cacheDir, "rootfs"), cfg, nil
	}

	fmt.Printf("⬇  Pulling %s...\n", imgRef.String())

	// --- Auth ---
	token, err := GetAuthToken(imgRef)
	if err != nil {
		return "", ImageConfig{}, fmt.Errorf("auth failed: %w", err)
	}

	// --- Manifest ---
	manifest, err := FetchManifest(imgRef, token)
	if err != nil {
		return "", ImageConfig{}, fmt.Errorf("fetch manifest: %w", err)
	}

	// --- Image config (ENTRYPOINT/CMD/ENV/WORKDIR/USER) ---
	// Not fatal on its own: a config-fetch failure still leaves the rootfs
	// pullable, just without defaults — the caller falls back to requiring
	// an explicit command, same as before this existed.
	imgConfig, cfgErr := FetchImageConfig(imgRef, manifest, token)
	if cfgErr != nil {
		fmt.Fprintf(os.Stderr, "warning: fetch image config failed: %v\n", cfgErr)
	}

	if verbose {
		fmt.Printf("🔍 Image has %d layer(s)\n", len(manifest.Layers))
	}

	// --- Ensure blob cache directory exists ---
	blobDir, err := BlobDir()
	if err != nil {
		return "", ImageConfig{}, err
	}
	if err := os.MkdirAll(blobDir, 0755); err != nil {
		return "", ImageConfig{}, fmt.Errorf("create blob cache dir: %w", err)
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
			return "", ImageConfig{}, fmt.Errorf("blob cache check: %w", err)
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
			return "", ImageConfig{}, fmt.Errorf("fetch layer %s: %w", layer.Digest, err)
		}

		blobPath, err := BlobCachePath(layer.Digest)
		if err != nil {
			rc.Close()
			return "", ImageConfig{}, err
		}

		if err := saveBlob(rc, blobPath, layer.Digest); err != nil {
			rc.Close()
			return "", ImageConfig{}, fmt.Errorf("save layer %s: %w", layer.Digest, err)
		}
		rc.Close()
	}

	// --- Prepare rootfs directory ---
	cacheDir, err := ImageCacheDir(imgRef)
	if err != nil {
		return "", ImageConfig{}, err
	}
	rootfsDir := filepath.Join(cacheDir, "rootfs")
	if err := os.MkdirAll(rootfsDir, 0755); err != nil {
		return "", ImageConfig{}, fmt.Errorf("create rootfs dir: %w", err)
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
			return "", ImageConfig{}, err
		}

		f, err := os.Open(blobPath)
		if err != nil {
			return "", ImageConfig{}, fmt.Errorf("open layer blob: %w", err)
		}
		err = extractLayerTarGz(f, rootfsDir)
		f.Close()
		if err != nil {
			return "", ImageConfig{}, fmt.Errorf("extract layer %s: %w", layer.Digest, err)
		}
	}

	// --- Write pulled marker ---
	marker := filepath.Join(cacheDir, ".airlock-pulled")
	if err := os.WriteFile(marker, []byte(imgRef.String()), 0644); err != nil {
		return "", ImageConfig{}, fmt.Errorf("write pulled marker: %w", err)
	}

	// Persist the parsed config alongside the rootfs so a future cache hit
	// (which skips the network entirely, including the manifest fetch this
	// config came from) can still return it.
	saveCachedImageConfig(cacheDir, imgConfig)

	fmt.Printf("✓  Image ready: %s\n", imgRef.String())
	return rootfsDir, imgConfig, nil
}

// imageConfigCacheFile is the filename an image's parsed ImageConfig is
// persisted under, alongside its rootfs and .airlock-pulled marker.
const imageConfigCacheFile = "image-config.json"

// saveCachedImageConfig writes cfg to cacheDir for later cache-hit reads.
// Best-effort: a failure here doesn't fail the pull, it just means the next
// cache hit falls back to a zero-value ImageConfig (same as an image pulled
// before this feature existed).
func saveCachedImageConfig(cacheDir string, cfg ImageConfig) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(cacheDir, imageConfigCacheFile), data, 0644)
}

// loadCachedImageConfig reads back what saveCachedImageConfig wrote. Returns
// a zero-value ImageConfig on any error (missing file, corrupt JSON) rather
// than failing the pull — the caller degrades to requiring an explicit
// command, exactly as if this feature didn't exist.
func loadCachedImageConfig(cacheDir string) ImageConfig {
	data, err := os.ReadFile(filepath.Join(cacheDir, imageConfigCacheFile))
	if err != nil {
		return ImageConfig{}
	}
	var cfg ImageConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return ImageConfig{}
	}
	return cfg
}

// saveBlob reads from rc, writes the contents to path atomically (via a temp
// file), and verifies the SHA-256 digest matches expectedDigest before the
// rename. A digest mismatch (corrupted download, MITM'd response, etc.)
// deletes the temp file and returns an error — the bad blob never reaches
// the cache, and is never extracted into a rootfs.
func saveBlob(rc io.Reader, path string, expectedDigest string) error {
	wantHex := strings.TrimPrefix(expectedDigest, "sha256:")

	// Write to a temp file first, then rename to avoid partial writes.
	tmpPath := path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create temp blob file: %w", err)
	}

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), rc); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write blob: %w", err)
	}
	f.Close()

	gotHex := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(gotHex, wantHex) {
		os.Remove(tmpPath)
		return fmt.Errorf("digest mismatch: expected sha256:%s, got sha256:%s", wantHex, gotHex)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename blob file: %w", err)
	}
	return nil
}

// verifyDigestBytes checks data's SHA-256 against expectedDigest. Used for
// blobs (like the image config) that are small enough to hold in memory
// entirely, rather than streamed through saveBlob's temp-file dance.
func verifyDigestBytes(data []byte, expectedDigest string) error {
	wantHex := strings.TrimPrefix(expectedDigest, "sha256:")
	sum := sha256.Sum256(data)
	gotHex := hex.EncodeToString(sum[:])
	if !strings.EqualFold(gotHex, wantHex) {
		return fmt.Errorf("digest mismatch: expected sha256:%s, got sha256:%s", wantHex, gotHex)
	}
	return nil
}

// VerifyBlob re-hashes an already-cached blob and checks it against its
// digest (the digest is also the blob's filename, per BlobCachePath). Used
// by `airlock clean --verify` to catch blobs cached before digest
// verification was added, or corrupted by disk issues after the fact.
func VerifyBlob(digest string) error {
	path, err := BlobCachePath(digest)
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open blob: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("read blob: %w", err)
	}

	wantHex := strings.TrimPrefix(digest, "sha256:")
	gotHex := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(gotHex, wantHex) {
		return fmt.Errorf("digest mismatch: expected sha256:%s, got sha256:%s", wantHex, gotHex)
	}
	return nil
}

// VerifyAllCachedBlobs walks the blob cache directory and verifies every
// blob's SHA-256 digest matches its filename. Returns the digests of any
// blobs that fail verification (corrupted or tampered).
func VerifyAllCachedBlobs() (bad []string, err error) {
	dir, err := BlobDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read blob cache dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".tmp") {
			continue
		}
		digest := "sha256:" + e.Name()
		if verr := VerifyBlob(digest); verr != nil {
			bad = append(bad, digest)
		}
	}
	return bad, nil
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
