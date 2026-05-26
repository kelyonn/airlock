//go:build linux

package container

import (
	"fmt"
	"os"
	"path/filepath"
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

		// Bind-mount: MS_BIND|MS_REC recursively maps host_path → rootfs/container_path
		if err := syscall.Mount(vol.HostPath, target, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
			return fmt.Errorf("bind mount %s → %s failed: %w", vol.HostPath, vol.ContainerPath, err)
		}

		// Enforce read-only by remounting with MS_RDONLY
		if vol.ReadOnly {
			roFlags := uintptr(syscall.MS_BIND | syscall.MS_REMOUNT | syscall.MS_RDONLY)
			if err := syscall.Mount("", target, "", roFlags, ""); err != nil {
				return fmt.Errorf("remount read-only %s failed: %w", vol.ContainerPath, err)
			}
		}

		if vol.ReadOnly {
			fmt.Printf("   📁 Volume: %s → %s (ro)\n", vol.HostPath, vol.ContainerPath)
		} else {
			fmt.Printf("   📁 Volume: %s → %s\n", vol.HostPath, vol.ContainerPath)
		}
	}
	return nil
}
