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
// Args: rootfsDir, hostname, memoryLimit, cpuLimit, volumesJSON,
//
//	noSeccomp, containerIP, noNetwork, envJSON, verbose, workingDir, user,
//	userNS, readyPipe, command, [command args...]
func Child(args []string) error {
	if len(args) < 15 {
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

	var extraEnv []string
	if args[8] != "" {
		if err := json.Unmarshal([]byte(args[8]), &extraEnv); err != nil {
			return fmt.Errorf("failed to parse env vars: %w", err)
		}
	}

	// Set the package-level Verbose flag before any setup step that checks
	// it (PrepareVolumeMounts, ApplySeccomp, and this function's own prints
	// below) — this process is a fresh re-exec, so Config.Verbose from Run
	// doesn't carry over automatically; it has to arrive as an arg like
	// everything else here.
	Verbose = args[9] == "true"

	workingDir := args[10]
	userSpec := args[11]
	userNS := args[12] == "true"
	hasReadyPipe := args[13] == "true"

	command := args[14]
	cmdArgs := args[15:]

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
	//
	// --userns skips this: mount() (including MS_BIND) requires
	// CAP_SYS_ADMIN in the user namespace that owns the TARGET
	// filesystem's superblock, not just DAC/ownership permission on the
	// path — and rootfsDir's superblock belongs to the initial namespace,
	// not this container's. By the time this function runs, Run's parent
	// process has already done this exact bind-mount itself while still
	// real root (see container.go's Step 1.6) — clone(CLONE_NEWUSER)
	// snapshots the mount table at Start() time, so it's already present
	// here, and attempting it again from the mapped, unprivileged UID
	// would just fail with EPERM for no benefit.
	if !userNS {
		if err := bindRootfsToSelf(rootfsDir); err != nil {
			return fmt.Errorf("rootfs bind mount failed: %w", err)
		}
	}

	// Step 4: Bind-mount volumes into the rootfs AFTER the bind mount but BEFORE pivot_root.
	// At this point rootfsDir is its own mount point; volumes stack on top cleanly.
	//
	// --userns skips this too, for the same reason as the rootfs self-bind
	// above: Run's parent process already set these up before Start(),
	// while still real root.
	if len(volumes) > 0 && !userNS {
		if err := PrepareVolumeMounts(rootfsDir, volumes); err != nil {
			return fmt.Errorf("volume mount failed: %w", err)
		}
	}

	// (Step 4.5 used to bind-mount the standard device files here for
	// --userns — mknod for a real device node is refused outside the
	// initial user namespace, see devices.go — but that's the same
	// "requires CAP_SYS_ADMIN over the target's superblock" problem as the
	// rootfs self-bind above. Run's parent process handles it before
	// Start() now, for the same reason.)

	// Step 5: Complete the chroot by performing pivot_root
	if err := completePivotRoot(rootfsDir); err != nil {
		return fmt.Errorf("chroot setup failed: %w", err)
	}

	// Step 6: Finish /dev setup (tmpfs+mknod, or — with --userns — just
	// devpts/shm/symlinks, since the device files themselves were already
	// bind-mounted in step 4.5). Must run after pivot_root since it
	// operates on the container's own /dev, not the host's.
	if err := setupContainerDev(userNS); err != nil {
		fmt.Fprintf(os.Stderr, "warning: /dev setup failed: %v\n", err)
	}

	// Step 7: Mount /proc inside the container (hardened + masked — see proc.go).
	// Runs after setupContainerDev because masking bind-mounts /dev/null,
	// which setupContainerDev just created, over sensitive /proc files.
	if err := mountProc(); err != nil {
		return fmt.Errorf("failed to mount /proc: %w", err)
	}

	// Step 8: Write /etc/resolv.conf. eth0 itself (rename, address, up,
	// default route) is configured by the parent's CreateVethPair
	// (container/network.go) over netlink rather than by this process —
	// which removes the OLD race this comment used to describe here (a
	// 10-iteration retry loop bringing up eth0 with `ip`/`ifconfig`,
	// needed because the parent used to inject eth0 well after this child
	// had already started trying to configure it itself). It does NOT
	// remove every race, though: this process and the parent still run
	// concurrently, and the parent's CreateVethPair call — several netlink
	// round trips — isn't guaranteed to finish before this process reaches
	// its own exec. Confirmed by hand: the user's command occasionally ran
	// fast enough to see the interface still under its pre-rename peer
	// name. See the wait on the readyPipe fd right before this function's
	// final exec for how that's actually closed, not just narrowed.
	if !noNetwork && containerIP != "" {
		if err := os.WriteFile("/etc/resolv.conf",
			[]byte("nameserver 8.8.8.8\nnameserver 1.1.1.1\n"), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "warning: write resolv.conf: %v\n", err)
		}
	}

	// Step 9: Drop Linux capabilities down to a minimal allowlist before
	// installing seccomp and exec'ing the user's command. Runs after
	// networking (bringing up eth0 needs CAP_NET_ADMIN) but before seccomp,
	// since dropping capabilities uses prctl/capset calls that are simplest
	// to reason about with the full syscall surface still available.
	if err := DropCapabilities(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: capability drop failed: %v\n", err)
	}

	// Step 9.5: Change to the requested working directory and switch to the
	// requested user, in that order — while still root, we can always chdir
	// anywhere; once ApplyUser drops the UID, a directory the target user
	// can't enter would otherwise fail this step instead of just failing to
	// chdir as root (which basically never fails for a path that exists).
	if workingDir != "" && workingDir != "/" {
		if err := os.Chdir(workingDir); err != nil {
			return fmt.Errorf("chdir to working dir %s: %w", workingDir, err)
		}
	}
	userHome, err := ApplyUser(userSpec)
	if err != nil {
		return fmt.Errorf("switch to user %q: %w", userSpec, err)
	}

	// Step 10: Install seccomp filter LAST — after all our own mounts are done.
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

	// Step 10.5: Block until the parent signals that networking (if any)
	// is actually configured — see the long comment above reexecCommand's
	// pipe creation in container.go's Run for the full reasoning. fd 3 is
	// the read end of that pipe, passed via cmd.ExtraFiles; a Read here
	// returning (for any reason — real data, EOF once the parent closes
	// its write end, or even an error) means "stop waiting," since there's
	// nothing left worth blocking on beyond that signal.
	if hasReadyPipe {
		readyFile := os.NewFile(3, "ready")
		var buf [1]byte
		_, _ = readyFile.Read(buf[:])
		readyFile.Close()
	}

	// Step 11: Execute the user's command
	if Verbose {
		fmt.Printf("🔒 Entering container (hostname: %s)\n", hostname)
		fmt.Println("   Type 'exit' to leave the container.")
	}

	binary, err := exec.LookPath(command)
	if err != nil {
		return fmt.Errorf("command not found: %s", command)
	}

	home := "/root"
	if userHome != "" {
		home = userHome
	}

	env := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		fmt.Sprintf("HOME=%s", home),
		"TERM=xterm-256color",
		fmt.Sprintf("HOSTNAME=%s", hostname),
	}
	env = append(env, extraEnv...)

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
