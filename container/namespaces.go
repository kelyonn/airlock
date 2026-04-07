//go:build linux

package container

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
)

// Child is called inside the new namespaces. It sets up chroot, mounts,
// cgroups, hostname, and then execs the user's command.
// Args: rootfsDir, hostname, memoryLimit, cpuLimit, command, [command args...]
func Child(args []string) error {
	if len(args) < 5 {
		return fmt.Errorf("insufficient arguments for child process")
	}

	rootfsDir := args[0]
	hostname := args[1]
	memoryLimit := args[2]
	cpuLimit, _ := strconv.Atoi(args[3])
	command := args[4]
	cmdArgs := args[5:]

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

	// Step 3: Set up chroot with pivot_root
	if err := setupChroot(rootfsDir); err != nil {
		return fmt.Errorf("chroot setup failed: %w", err)
	}

	// Step 4: Mount /proc inside the container
	if err := mountProc(); err != nil {
		return fmt.Errorf("failed to mount /proc: %w", err)
	}

	// Step 5: Execute the user's command
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

// setupChroot sets up the root filesystem using chroot.
func setupChroot(rootfsDir string) error {
	// Mount the rootfs as a bind mount to itself (required for pivot_root)
	if err := syscall.Mount(rootfsDir, rootfsDir, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("bind mount failed: %w", err)
	}

	// Create the old_root directory for pivot_root
	oldRoot := filepath.Join(rootfsDir, ".pivot_root")
	if err := os.MkdirAll(oldRoot, 0700); err != nil {
		return fmt.Errorf("failed to create pivot_root dir: %w", err)
	}

	// pivot_root swaps the root filesystem
	if err := syscall.PivotRoot(rootfsDir, oldRoot); err != nil {
		// Fall back to chroot if pivot_root fails
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
