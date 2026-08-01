//go:build linux

package container

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// devNode describes a character device to create under /dev.
type devNode struct {
	name        string
	major       uint32
	minor       uint32
	permissions os.FileMode
}

// standardDevNodes is the minimal set of device nodes most userspace
// programs assume exist. Major/minor numbers are the well-known Linux
// values for these devices (see Documentation/admin-guide/devices.txt).
var standardDevNodes = []devNode{
	{"null", 1, 3, 0666},
	{"zero", 1, 5, 0666},
	{"full", 1, 7, 0666},
	{"random", 1, 8, 0666},
	{"urandom", 1, 9, 0666},
	{"tty", 5, 0, 0666},
}

// bindHostDeviceFilesForUserNS bind-mounts the host's real device files
// individually into rootfsDir/dev — NOT the whole host /dev tree, just
// these six names — for the --userns case, where mknod(2) for a real
// char-device-backed node (major/minor matching an actual device) is
// refused by the kernel outside the initial user namespace even though the
// namespaced process otherwise holds full capabilities within its own
// namespace. Bind-mounting an existing node doesn't need that privilege,
// only mknod'ing a NEW one does.
//
// This is safe in a way the old whole-/dev bind-mount wasn't: with
// --userns active, "root" inside the container is mapped to an
// unprivileged host UID (see container.go's userNSHostIDOffset), so even a
// bind-mounted host device node doesn't hand out real host root access —
// DAC permissions on the host device files themselves (owned by the real
// root, typically mode 0666 for exactly these six) still apply.
//
// Must run BEFORE pivot_root, while the host's /dev is still reachable.
func bindHostDeviceFilesForUserNS(rootfsDir string) error {
	destDir := filepath.Join(rootfsDir, "dev")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", destDir, err)
	}

	for _, d := range standardDevNodes {
		hostPath := "/dev/" + d.name
		destPath := filepath.Join(destDir, d.name)

		if _, err := os.Stat(hostPath); err != nil {
			continue // this host doesn't have it — nothing to bind
		}
		f, err := os.OpenFile(destPath, os.O_CREATE, 0666)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: create placeholder %s: %v\n", destPath, err)
			continue
		}
		f.Close()

		if err := syscall.Mount(hostPath, destPath, "", syscall.MS_BIND, ""); err != nil {
			fmt.Fprintf(os.Stderr, "warning: bind %s: %v\n", hostPath, err)
		}
	}

	return nil
}

// setupContainerDev finishes /dev setup inside the container, run AFTER
// pivot_root. Its job differs depending on whether a user namespace is
// active:
//
//   - Without --userns (the default): mount a fresh tmpfs on /dev and
//     mknod the standard character devices directly onto it. Earlier
//     versions of airlock bind-mounted the HOST's entire /dev into the
//     container instead (MS_BIND|MS_REC) — a serious flaw, since without a
//     user namespace the container's root IS the host's root, and a
//     bind-mounted host /dev hands that root direct read/write access to
//     host block devices (/dev/sda included) with no boundary in between.
//     Blocking mount(2) via seccomp doesn't help; raw disk access needs
//     nothing but open()+write().
//   - With --userns: mknod for a real char-device-backed node is refused
//     by the kernel outside the initial user namespace, so there's nothing
//     to mknod here — bindHostDeviceFilesForUserNS already placed the six
//     device files via bind mount before pivot_root, and they're sitting
//     at /dev/* right now as a side effect of pivot_root swapping roots.
//     Skip the tmpfs+mknod step entirely (mounting tmpfs over /dev at this
//     point would just shadow those bind mounts).
//
// Either way, this also sets up /dev/pts, /dev/shm, and the standard
// /proc/self symlinks, none of which require mknod.
func setupContainerDev(userNS bool) error {
	if !userNS {
		if err := os.MkdirAll("/dev", 0755); err != nil {
			return fmt.Errorf("mkdir /dev: %w", err)
		}
		if err := syscall.Mount("tmpfs", "/dev", "tmpfs", syscall.MS_NOSUID, "mode=755,size=65536k"); err != nil {
			return fmt.Errorf("mount tmpfs on /dev: %w", err)
		}

		for _, d := range standardDevNodes {
			path := "/dev/" + d.name
			dev := int(unix.Mkdev(d.major, d.minor))
			if err := syscall.Mknod(path, syscall.S_IFCHR|uint32(d.permissions), dev); err != nil {
				fmt.Fprintf(os.Stderr, "warning: mknod %s failed: %v\n", path, err)
				continue
			}
			_ = os.Chmod(path, d.permissions)
		}
	}

	// /dev/pts + /dev/ptmx: pseudo-terminal support for interactive shells.
	if err := os.MkdirAll("/dev/pts", 0755); err == nil {
		if err := syscall.Mount("devpts", "/dev/pts", "devpts", 0,
			"newinstance,ptmxmode=0666,mode=0620"); err != nil {
			fmt.Fprintf(os.Stderr, "warning: mount devpts failed: %v\n", err)
		} else if err := os.Symlink("pts/ptmx", "/dev/ptmx"); err != nil {
			fmt.Fprintf(os.Stderr, "warning: symlink /dev/ptmx failed: %v\n", err)
		}
	}

	// Standard symlinks into /proc/self that shells and CLI tools expect.
	_ = os.Symlink("/proc/self/fd", "/dev/fd")
	_ = os.Symlink("/proc/self/fd/0", "/dev/stdin")
	_ = os.Symlink("/proc/self/fd/1", "/dev/stdout")
	_ = os.Symlink("/proc/self/fd/2", "/dev/stderr")

	// /dev/shm for POSIX shared memory (glibc, many runtimes assume it exists).
	if err := os.MkdirAll("/dev/shm", 01777); err == nil {
		if err := syscall.Mount("tmpfs", "/dev/shm", "tmpfs",
			syscall.MS_NOSUID|syscall.MS_NODEV, "mode=1777"); err != nil {
			fmt.Fprintf(os.Stderr, "warning: mount /dev/shm failed: %v\n", err)
		}
	}

	return nil
}
