//go:build linux

package container

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// PrepareVolumeMounts bind-mounts host paths into the container rootfs.
// This MUST be called BEFORE setupChroot/pivot_root, because after pivot_root
// the host paths are no longer accessible from the new mount namespace.
// Each mount appears at vol.ContainerPath once pivot_root makes rootfsDir the new /.
func PrepareVolumeMounts(rootfsDir string, volumes []VolumeMount) error {
	for _, vol := range volumes {
		// Target inside the rootfs (on the host side, before pivot_root)
		target := filepath.Join(rootfsDir, vol.ContainerPath)

		// Create the target directory if it doesn't exist
		if err := os.MkdirAll(target, 0755); err != nil {
			return fmt.Errorf("cannot create mount target %s: %w", target, err)
		}

		// Bind-mount: MS_BIND|MS_REC recursively maps host_path → rootfs/container_path.
		// MS_NOSUID|MS_NODEV mean a setuid binary or device node planted on a
		// host volume can't be used to escalate privileges or touch hardware
		// from inside the container.
		bindFlags := uintptr(syscall.MS_BIND | syscall.MS_REC | syscall.MS_NOSUID | syscall.MS_NODEV)
		if err := syscall.Mount(vol.HostPath, target, "", bindFlags, ""); err != nil {
			return fmt.Errorf("bind mount %s → %s failed: %w", vol.HostPath, vol.ContainerPath, err)
		}

		// Enforce read-only. A single MS_REMOUNT|MS_RDONLY only affects the
		// top-level mount, not any submounts the MS_REC bind above pulled in
		// (e.g. the host path is itself a mountpoint, or contains one) — so we
		// walk /proc/self/mountinfo for every mount under target and remount
		// each one individually read-only, deepest first.
		if vol.ReadOnly {
			if err := remountReadOnlyRecursive(target); err != nil {
				return fmt.Errorf("remount read-only %s failed: %w", vol.ContainerPath, err)
			}
		}

		if Verbose {
			if vol.ReadOnly {
				fmt.Printf("   📁 Volume: %s → %s (ro)\n", vol.HostPath, vol.ContainerPath)
			} else {
				fmt.Printf("   📁 Volume: %s → %s\n", vol.HostPath, vol.ContainerPath)
			}
		}
	}
	return nil
}

// remountReadOnlyRecursive remounts root and every submount beneath it
// (as found in /proc/self/mountinfo) read-only, in leaf-to-root order so a
// parent's remount never fails because a child mount point is still nested
// under it.
func remountReadOnlyRecursive(root string) error {
	mounts, err := mountpointsUnder(root)
	if err != nil {
		return err
	}

	// mountpointsUnder returns shallow-to-deep; remount deepest-first so we
	// never try to remount a parent while a child mount is still attached
	// somewhere the kernel considers "in the way".
	for i := len(mounts) - 1; i >= 0; i-- {
		roFlags := uintptr(syscall.MS_BIND | syscall.MS_REMOUNT | syscall.MS_RDONLY |
			syscall.MS_NOSUID | syscall.MS_NODEV)
		if err := syscall.Mount("", mounts[i], "", roFlags, ""); err != nil {
			return fmt.Errorf("remount %s: %w", mounts[i], err)
		}
	}
	return nil
}

// mountpointsUnder parses /proc/self/mountinfo and returns every mount
// point at or under root, shallow-to-deep (mountinfo is already emitted in
// mount order, which is always parent-before-child).
func mountpointsUnder(root string) ([]string, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, fmt.Errorf("open mountinfo: %w", err)
	}
	defer f.Close()

	cleanRoot := filepath.Clean(root)
	var points []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		mountPoint := fields[4]
		if mountPoint == cleanRoot || strings.HasPrefix(mountPoint, cleanRoot+"/") {
			points = append(points, mountPoint)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan mountinfo: %w", err)
	}
	if len(points) == 0 {
		// root itself should always be a mount point once bind-mounted; if
		// mountinfo parsing found nothing, fall back to just root so callers
		// still get *a* remount attempt instead of silently doing nothing.
		points = append(points, cleanRoot)
	}
	return points, nil
}
