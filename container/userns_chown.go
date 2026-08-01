//go:build linux

package container

import (
	"fmt"
	"os"
	"path/filepath"
)

// chownForUserNS recursively changes ownership of every entry under root to
// userNSHostIDOffset:userNSHostIDOffset — the host UID/GID that a --userns
// container's mapped root resolves to. See the call site in container.go's
// Run for why this is necessary at all: an extracted rootfs is owned by
// real root by default, which a mapped-uid child process has no write
// access to.
//
// Lchown (not Chown) is used deliberately so symlinks are re-owned without
// following them — chasing a symlink here could walk outside root entirely
// (e.g. a layer containing an absolute symlink), which os.Walk's own
// symlink handling already avoids by not auto-following, but Chown() as an
// operation would still resolve the link if used instead of Lchown().
func chownForUserNS(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Best-effort: skip entries we can't stat rather than aborting
			// the whole walk over one bad entry (broken symlink target,
			// permission oddity from a prior partial run, etc).
			return nil
		}
		if cerr := os.Lchown(path, userNSHostIDOffset, userNSHostIDOffset); cerr != nil {
			// Also best-effort per-entry: a single stubborn file (e.g. one
			// with an unusual extended attribute) shouldn't block every
			// other file in the tree from being chowned correctly.
			fmt.Fprintf(os.Stderr, "warning: chown %s: %v\n", path, cerr)
		}
		return nil
	})
}
