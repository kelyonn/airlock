package image

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CacheDir returns the root cache directory for images: ~/.airlock/images
func CacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".airlock", "images"), nil
}

// BlobDir returns the blob cache directory: ~/.airlock/blobs/sha256
func BlobDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".airlock", "blobs", "sha256"), nil
}

// ImageCacheDir returns the top-level cache directory for a specific image ref.
// Path: ~/.airlock/images/<cacheKey>
func ImageCacheDir(ref ImageRef) (string, error) {
	base, err := CacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, filepath.FromSlash(ref.CacheKey())), nil
}

// IsCached returns true if the image has already been pulled and extracted.
// It checks for a .airlock-pulled marker file inside the image cache directory.
func IsCached(ref ImageRef) (bool, error) {
	dir, err := ImageCacheDir(ref)
	if err != nil {
		return false, err
	}
	marker := filepath.Join(dir, ".airlock-pulled")
	if _, err := os.Stat(marker); err == nil {
		return true, nil
	}
	return false, nil
}

// BlobCachePath returns the local filesystem path where a blob is (or should be) cached.
// Path: ~/.airlock/blobs/sha256/<hex-digest>  (strips the "sha256:" prefix).
func BlobCachePath(digest string) (string, error) {
	dir, err := BlobDir()
	if err != nil {
		return "", err
	}
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	return filepath.Join(dir, hexDigest), nil
}

// IsBlobCached returns true if the blob with the given digest already exists on disk.
func IsBlobCached(digest string) (bool, error) {
	path, err := BlobCachePath(digest)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(path); err == nil {
		return true, nil
	}
	return false, nil
}

// CleanImageCache removes all cached images and blobs from ~/.airlock/images and
// ~/.airlock/blobs. Returns the number of bytes freed and any error encountered.
func CleanImageCache() (int64, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return 0, fmt.Errorf("cannot determine home directory: %w", err)
	}

	imagesDir := filepath.Join(home, ".airlock", "images")
	blobsDir := filepath.Join(home, ".airlock", "blobs")

	var freed int64

	// Measure and remove images directory.
	if _, err := os.Stat(imagesDir); err == nil {
		sz, err := dirSize(imagesDir)
		if err == nil {
			freed += sz
		}
		if err := os.RemoveAll(imagesDir); err != nil {
			return freed, fmt.Errorf("remove images cache: %w", err)
		}
	}

	// Measure and remove blobs directory.
	if _, err := os.Stat(blobsDir); err == nil {
		sz, err := dirSize(blobsDir)
		if err == nil {
			freed += sz
		}
		if err := os.RemoveAll(blobsDir); err != nil {
			return freed, fmt.Errorf("remove blobs cache: %w", err)
		}
	}

	return freed, nil
}

// dirSize computes the total byte size of all files in a directory tree.
func dirSize(path string) (int64, error) {
	var total int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total, err
}
