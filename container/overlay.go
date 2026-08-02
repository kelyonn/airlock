//go:build linux

package container

import (
	"errors"
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
		unmountStack(mergedDir)
		if err := os.RemoveAll(instanceDir); err != nil {
			fmt.Fprintf(os.Stderr, "warning: remove overlay instance dir %s: %v\n", instanceDir, err)
		}
	}

	return mergedDir, cleanup, nil
}

// unmountStack unmounts every mount currently stacked at path, not just the
// topmost one.
//
// One unmount is not enough, because more than one mount can sit at the same
// path. Under --userns in particular, Run mounts the overlay here and then
// bind-mounts the result onto itself (bindRootfsToSelf, a pivot_root
// prerequisite that has to happen parent-side — see Run's Step 1.6), leaving
// two stacked mounts at this exact path. Unmounting once left the other one
// behind permanently: it kept the instance directory busy, so the RemoveAll
// that follows failed with ENOTEMPTY, and the mount itself stayed in the
// HOST mount namespace — airlock's parent process does this mounting as real
// root in the initial namespace, so nothing tears it down when the container
// exits. Confirmed by hand before the fix: three --userns runs left three
// overlay entries in /proc/mounts, and they never went away.
//
// A plain unmount is tried first so the directory is genuinely gone before
// RemoveAll runs; MNT_DETACH is the fallback for the case where something
// still holds the mount (a straggler process), which detaches it from the
// namespace immediately and completes once the last reference goes away.
// The loop stops as soon as the path isn't a mount point (EINVAL), so it
// only ever removes mounts that were actually stacked here, and is bounded
// regardless so a surprising mount table can't spin it forever.
func unmountStack(path string) {
	const maxStacked = 16
	for range maxStacked {
		err := syscall.Unmount(path, 0)
		if err == nil {
			continue // another mount may be stacked underneath this one
		}
		if errors.Is(err, syscall.EINVAL) {
			return // not a mount point any more: the stack is fully cleared
		}

		// Busy. In practice this is the normal case for the topmost mount
		// here, not an exceptional one — the bind and the overlay beneath
		// it reference each other, so a plain unmount of the top reports
		// EBUSY even with the container long gone.
		//
		// MNT_DETACH removes it from the mount tree immediately (only the
		// final teardown is deferred until the last reference drops), which
		// exposes whatever was stacked underneath — so keep looping rather
		// than returning here. Returning was the original bug: it detached
		// exactly one mount, left the one below it mounted and therefore
		// still full of the image's files, and the RemoveAll that follows
		// then failed with ENOTEMPTY while the mount stayed behind for good.
		derr := syscall.Unmount(path, syscall.MNT_DETACH)
		if derr == nil {
			continue
		}
		if errors.Is(derr, syscall.EINVAL) {
			return
		}
		fmt.Fprintf(os.Stderr, "warning: unmount overlay %s: %v\n", path, derr)
		return
	}
}
