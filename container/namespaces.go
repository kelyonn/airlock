//go:build linux

package container

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
)

// Child is called inside the new namespaces. It sets up chroot, mounts,
// cgroups, hostname, and then execs the user's command.
// Args: rootfsDir, hostname, memoryLimit, cpuLimit, volumesJSON, noSeccomp, command, [command args...]
func Child(args []string) error {
	if len(args) < 7 {
		return fmt.Errorf("insufficient arguments for child process")
	}

	rootfsDir := args[0]
	hostname := args[1]
	memoryLimit := args[2]
	cpuLimit, _ := strconv.Atoi(args[3])

	var volumes []VolumeMount
	if err := json.Unmarshal([]byte(args[4]), &volumes); err != nil {
		return fmt.Errorf("failed to parse volume specs: %w", err)
	}
	noSeccomp := args[5] == "true"

	command := args[6]
	cmdArgs := args[7:]

	// Step 1: Set hostname
	if err := syscall.Sethostname([]byte(hostname)); err != nil {
		return fmt.Errorf("failed to set hostname: %w", err)
	}

	// Step 2: Set up cgroups (before chroot, as cgroup fs is on the host)
	cgroupCleanup, err := SetupCgroups(memoryLimit, cpuLimit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: cgroup setup failed: %v\n", err)
		// Continue without cgroups — don't fail hard
	}
	defer func() {
		if cgroupCleanup != nil {
			cgroupCleanup()
		}
	}()

	// Step 3: Bind-mount the rootfs to itself FIRST (makes it a mount point for pivot_root).
	// We do NOT use MS_REC — that causes kernel lock contention when source == destination
	// and submounts already exist.
	if err := bindRootfsToSelf(rootfsDir); err != nil {
		return fmt.Errorf("rootfs bind mount failed: %w", err)
	}

	// Step 4: Bind-mount volumes into the rootfs AFTER the bind mount but BEFORE pivot_root.
	// At this point rootfsDir is its own mount point; volumes stack on top cleanly.
	if len(volumes) > 0 {
		if err := PrepareVolumeMounts(rootfsDir, volumes); err != nil {
			return fmt.Errorf("volume mount failed: %w", err)
		}
	}

	// Step 5: Complete the chroot by performing pivot_root
	if err := completePivotRoot(rootfsDir); err != nil {
		return fmt.Errorf("chroot setup failed: %w", err)
	}

	// Step 6: Mount /proc inside the container
	if err := mountProc(); err != nil {
		return fmt.Errorf("failed to mount /proc: %w", err)
	}

	// Step 7: Install seccomp filter LAST — after all our own mounts are done.
	// SYS_MOUNT is in the deny list, so applying seccomp before our mounts would
	// break pivot_root and the proc/volume bind mounts.
	if !noSeccomp {
		if err := ApplySeccomp(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: seccomp filter failed: %v\n", err)
			// Continue — seccomp failure is logged but not fatal
		}
	} else {
		fmt.Println("   ⚠️  Seccomp disabled (--no-seccomp)")
	}

	// Step 7: Execute the user's command
	fmt.Printf("🔒 Entering container (hostname: %s)\n", hostname)
	fmt.Println("   Type 'exit' to leave the container.\n")

	binary, err := exec.LookPath(command)
	if err != nil {
		return fmt.Errorf("command not found: %s", command)
	}

	env := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/root",
		"TERM=xterm-256color",
		fmt.Sprintf("HOSTNAME=%s", hostname),
	}

	return syscall.Exec(binary, append([]string{command}, cmdArgs...), env)
}

// bindRootfsToSelf bind-mounts rootfsDir onto itself, making it its own mount point.
// This is required by pivot_root. We deliberately do NOT use MS_REC to avoid
// kernel lock contention when source == destination and submounts already exist.
func bindRootfsToSelf(rootfsDir string) error {
	if err := syscall.Mount(rootfsDir, rootfsDir, "", syscall.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind mount failed: %w", err)
	}
	return nil
}

// completePivotRoot performs the pivot_root (or falls back to chroot) to make
// rootfsDir the new root filesystem. Called after volumes are mounted.
func completePivotRoot(rootfsDir string) error {
	// Create the old_root directory for pivot_root
	oldRoot := filepath.Join(rootfsDir, ".pivot_root")
	if err := os.MkdirAll(oldRoot, 0700); err != nil {
		return fmt.Errorf("failed to create pivot_root dir: %w", err)
	}

	// pivot_root swaps the root filesystem
	if err := syscall.PivotRoot(rootfsDir, oldRoot); err != nil {
		// Fall back to chroot if pivot_root fails (e.g., some Docker environments)
		fmt.Fprintf(os.Stderr, "warning: pivot_root failed (%v), falling back to chroot\n", err)
		if err := syscall.Chroot(rootfsDir); err != nil {
			return fmt.Errorf("chroot failed: %w", err)
		}
		return os.Chdir("/")
	}

	// Change to new root
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("chdir failed: %w", err)
	}

	// Unmount old root
	if err := syscall.Unmount("/.pivot_root", syscall.MNT_DETACH); err != nil {
		fmt.Fprintf(os.Stderr, "warning: unmount old root failed: %v\n", err)
	}

	// Remove the old root mount point
	os.RemoveAll("/.pivot_root")

	return nil
}


// mountProc mounts the proc filesystem inside the container.
func mountProc() error {
	if err := os.MkdirAll("/proc", 0755); err != nil {
		return err
	}
	return syscall.Mount("proc", "/proc", "proc", 0, "")
}
