//go:build linux

package container

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// SetupOverlay gives a single container its own private, writable view of
// an image's cached rootfs, without copying it.
//
// Before this existed, every container run from the same image shared
// image.Pull's single cached rootfs directory directly — Run() would
// pivot_root straight into `~/.airlock/images/<ref>/rootfs`, the exact
// same path every other container (or repeat run) from that image also
// used. Two containers from the same image running concurrently (e.g. two
// replicas in a compose stack, or just two overlapping `airlock run`
// invocations) would see and corrupt each other's writes to that shared
// directory, and cleanup from one could delete files the other was still
// using.
//
// This mounts a Linux overlayfs: lowerDir (the shared, read-only cached
// image layers) stays untouched and shared across every container that
// uses it; a fresh, empty upperdir+workdir unique to THIS container
// instance captures every write; the merged view at the returned path is
// what the container actually pivot_roots into. Nothing written by one
// container is visible to another, and tearing a container down just
// means unmounting and removing its own small upper/work directories —
// the shared lowerdir (and the cost of extracting it) is untouched.
//
// Returns the merged directory to use as the container's rootfs, a
// cleanup function that unmounts and removes this instance's directories,
// and an error. If overlayfs isn't available in this environment (e.g. an
// unusual kernel build, or the lowerdir's filesystem doesn't support
// being stacked), the caller should fall back to using lowerDir directly
// — see Run()'s handling of this.
func SetupOverlay(lowerDir, instanceID string) (mergedDir string, cleanup func(), err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", nil, fmt.Errorf("determine home directory: %w", err)
	}

	instanceDir := filepath.Join(home, ".airlock", "containers", instanceID)
	upperDir := filepath.Join(instanceDir, "upper")
	workDir := filepath.Join(instanceDir, "work")
	mergedDir = filepath.Join(instanceDir, "merged")

	for _, d := range []string{upperDir, workDir, mergedDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			os.RemoveAll(instanceDir)
			return "", nil, fmt.Errorf("create %s: %w", d, err)
		}
	}

	// overlayfs requires upperdir and workdir on the same filesystem —
	// both live under instanceDir here, so that's satisfied by construction.
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lowerDir, upperDir, workDir)
	if err := syscall.Mount("overlay", mergedDir, "overlay", 0, opts); err != nil {
		os.RemoveAll(instanceDir)
		return "", nil, fmt.Errorf("mount overlay: %w", err)
	}

	cleanup = func() {
		// MNT_DETACH: lazy-unmount: if the merged dir is still momentarily
		// busy (e.g. a straggler process), this still detaches it from the
		// namespace immediately and finishes unmounting once it's no
		// longer referenced, rather than making cleanup fail outright.
		if err := syscall.Unmount(mergedDir, syscall.MNT_DETACH); err != nil {
			fmt.Fprintf(os.Stderr, "warning: unmount overlay %s: %v\n", mergedDir, err)
		}
		if err := os.RemoveAll(instanceDir); err != nil {
			fmt.Fprintf(os.Stderr, "warning: remove overlay instance dir %s: %v\n", instanceDir, err)
		}
	}

	return mergedDir, cleanup, nil
}
