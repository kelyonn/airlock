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
	"time"
)

// Child is called inside the new namespaces. It sets up chroot, mounts,
// cgroups, hostname, and then execs the user's command.
// Args: rootfsDir, hostname, memoryLimit, cpuLimit, volumesJSON,
//
//	noSeccomp, containerIP, noNetwork, command, [command args...]
func Child(args []string) error {
	if len(args) < 9 {
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
	containerIP := args[6]
	noNetwork := args[7] == "true"

	command := args[8]
	cmdArgs := args[9:]

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

	// Step 3.5: Bind-mount the host /dev into the new root so that device nodes
	// (/dev/null, /dev/zero, /dev/random, etc.) are available inside the container.
	// This must happen BEFORE pivot_root while the host path is still reachable.
	devDest := filepath.Join(rootfsDir, "dev")
	if err := os.MkdirAll(devDest, 0755); err == nil {
		if mErr := syscall.Mount("/dev", devDest, "", syscall.MS_BIND|syscall.MS_REC, ""); mErr != nil {
			fmt.Fprintf(os.Stderr, "warning: /dev bind mount failed: %v\n", mErr)
		}
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

	// Step 7: Configure container networking (lo + eth0 + default route + resolv.conf).
	// This runs after mountProc() so /proc is available, and before seccomp so
	// the ip commands can make their syscalls freely.
	if !noNetwork && containerIP != "" {
		if err := configureContainerNetwork(containerIP); err != nil {
			fmt.Fprintf(os.Stderr, "warning: network config failed: %v\n", err)
		}
	}

	// Step 8: Install seccomp filter LAST — after all our own mounts are done.
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

	// Step 9: Execute the user's command
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

// configureContainerNetwork configures the network interfaces inside the container.
// It brings up the loopback and eth0 interfaces, adds a default route via the
// bridge gateway, and writes /etc/resolv.conf with public DNS servers.
// Falls back to ifconfig/route (busybox equivalents) if the iproute2 'ip' binary
// is not present in the container image.
func configureContainerNetwork(containerIP string) error {
	// --- loopback ---
	// Try iproute2 first; fall back to busybox ifconfig.
	if err := runCmd("ip", "link", "set", "lo", "up"); err != nil {
		if err2 := runCmd("ifconfig", "lo", "up"); err2 != nil {
			return fmt.Errorf("bring up lo: ip failed (%v), ifconfig also failed (%v)", err, err2)
		}
	}

	// --- eth0 ---
	// The parent assigns the IP via nsenter, but the child might race ahead of the parent.
	// We retry bringing up the link up to 10 times (100ms max) to wait for the parent to finish injecting it.
	var eth0Err error
	for i := 0; i < 10; i++ {
		if eth0Err = runCmd("ip", "link", "set", "eth0", "up"); eth0Err == nil {
			break
		} else if err2 := runCmd("ifconfig", "eth0", "up"); err2 == nil {
			eth0Err = nil
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if eth0Err != nil {
		fmt.Fprintf(os.Stderr, "warning: bring up eth0 failed after retries: %v\n", eth0Err)
	}

	// --- default route ---
	if err := runCmd("ip", "route", "add", "default", "via", gateway); err != nil {
		// Ignore if a default route already exists; try busybox route as fallback.
		_ = runCmd("route", "add", "default", "gw", gateway)
	}

	// --- DNS ---
	// Write /etc/resolv.conf with Google and Cloudflare resolvers.
	if err := os.WriteFile("/etc/resolv.conf",
		[]byte("nameserver 8.8.8.8\nnameserver 1.1.1.1\n"), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "warning: write resolv.conf: %v\n", err)
	}

	return nil
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
