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

// ensureTraversableForUserNS grants execute ("search") permission to
// "other" on every directory between $HOME and path — NOT path itself,
// chownForUserNS already makes that tree owned outright by the mapped UID.
//
// Owning a directory tree outright isn't enough to reach it: every
// component along the way is checked separately for search permission,
// and ~/.airlock (like most of a fresh $HOME) defaults to mode 0700 owned
// by real root. A mapped UID that owns the rootfs completely still gets
// EPERM the moment it tries to reach it, because it can't even traverse
// through ~/.airlock's own default permissions to get there — confirmed
// by hand: pivot_root's own os.MkdirAll failed with "permission denied"
// on ~/.airlock itself, several levels above the (correctly owned) rootfs.
//
// This only ever adds the execute bit, never read or write, so it doesn't
// let another local user list or read what's inside ~/.airlock's
// directories — only pass through a path they'd have to already know, to
// reach something they (here, the mapped UID) have separate permission on
// further down. Stops at $HOME rather than continuing up to "/", since
// everything above a user's home directory is outside airlock's own data
// and ordinarily already traversable by default on any standard install.
func ensureTraversableForUserNS(path string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("determine home directory: %w", err)
	}
	home = filepath.Clean(home)

	var ancestors []string
	dir := filepath.Dir(filepath.Clean(path))
	for {
		ancestors = append(ancestors, dir)
		if dir == home {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached the filesystem root without finding $HOME along the
			// way (path wasn't under $HOME at all) — stop rather than
			// looping forever or touching directories airlock has no
			// business modifying.
			break
		}
		dir = parent
	}

	for _, d := range ancestors {
		info, statErr := os.Stat(d)
		if statErr != nil {
			continue
		}
		mode := info.Mode().Perm()
		if mode&0o001 != 0 {
			continue // already traversable by "other"
		}
		if chmodErr := os.Chmod(d, mode|0o001); chmodErr != nil {
			return fmt.Errorf("chmod %s: %w", d, chmodErr)
		}
	}
	return nil
}
