//go:build linux

package container

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"

	"github.com/kelyonn/airlock/image"
	"github.com/kelyonn/airlock/rootfs"
	"github.com/kelyonn/airlock/state"
)

// userNSHostIDOffset / userNSIDRangeSize define the host UID/GID range a
// --userns container's own 0-65535 range is mapped onto. 100000 is the
// same convention most distros' subuid/subgid defaults and other container
// tools use, chosen simply to stay clear of real system accounts (which
// end well before 100000 on virtually every distro).
const (
	userNSHostIDOffset = 100000
	userNSIDRangeSize  = 65536
)

// Run creates and runs a new container with the given configuration.
// It re-executes the current binary with a special "child" argument
// so that the child process runs inside the new namespaces.
func Run(config Config) error {
	Verbose = config.Verbose
	if Verbose {
		fmt.Println("🔒 Airlock: Starting container...")
	}

	// Step 1: Ensure rootfs is available.
	// If an OCI image reference is specified, pull/cache it; otherwise fall back
	// to the default Alpine mini-rootfs.
	var rootfsDir string
	var err error
	if config.Image != "" {
		var imgConfig image.ImageConfig
		rootfsDir, imgConfig, err = image.Pull(config.Image, config.Verbose)
		if err != nil {
			return fmt.Errorf("image pull failed: %w", err)
		}

		// If the caller didn't give an explicit command, fall back to the
		// image's own ENTRYPOINT/CMD — this is what makes `airlock run
		// nginx:alpine` work with no trailing command at all, instead of
		// requiring the user to already know (and spell out by hand) what
		// the image's own startup command is.
		if config.Command == "" {
			cmd, args := imgConfig.Command()
			if cmd == "" {
				return fmt.Errorf("no command given, and image %s specifies neither ENTRYPOINT nor CMD", config.Image)
			}
			config.Command = cmd
			config.Args = args
		}

		config.Env = mergeEnv(imgConfig.Env, config.Env)

		if config.WorkingDir == "" {
			config.WorkingDir = imgConfig.WorkingDir
		}
		if config.User == "" {
			config.User = imgConfig.User
		}
	} else {
		if config.Command == "" {
			return fmt.Errorf("no command given (the default Alpine rootfs has no image config to fall back to)")
		}
		rootfsDir, err = rootfs.Ensure(config.Verbose)
		if err != nil {
			return fmt.Errorf("rootfs setup failed: %w", err)
		}
	}

	if config.WorkingDir == "" {
		config.WorkingDir = "/"
	}

	if config.Verbose {
		fmt.Printf("[container] rootfs: %s\n", rootfsDir)
	}

	// Give this container its own private, writable view of rootfsDir via
	// overlayfs instead of pivot_rooting directly into the shared image
	// cache — see overlay.go for the full reasoning: concurrent containers
	// from the same image would otherwise pivot_root into, and corrupt,
	// the exact same writable directory. Everything from here on operates
	// on containerRootfs, not rootfsDir, so this is a drop-in swap for the
	// rest of Run. Falls back to the shared directory directly if overlay
	// setup fails for any reason (e.g. overlayfs unavailable on this
	// kernel) — degraded (containers sharing the image will conflict
	// again), but not fatal.
	containerRootfs := rootfsDir
	overlayCleanup := func() {}
	if mergedDir, cleanup, overlayErr := SetupOverlay(rootfsDir, state.GenerateID()); overlayErr != nil {
		fmt.Fprintf(os.Stderr, "warning: overlay setup failed, falling back to the shared image rootfs directly (concurrent containers from this image may conflict): %v\n", overlayErr)
	} else {
		containerRootfs = mergedDir
		overlayCleanup = cleanup
	}
	// Runs on every return path from here on, success or error, so a
	// failure partway through setup (a bad volume spec, cmd.Start()
	// failing, etc.) never leaks the overlay mount and its upper/work
	// directories.
	defer overlayCleanup()

	// --userns: the rootfs directory was extracted (or, now, overlaid)
	// by this process while it was still real root, so it's owned by
	// uid/gid 0 with normal 0755/0644 permissions — no write access for
	// anyone else. Once CLONE_NEWUSER/the ID mapping takes effect, the
	// child is host uid userNSHostIDOffset, not real root, and would fail
	// on the very first mkdir/mount it tries against that tree
	// (bindRootfsToSelf, then pivot_root's own working directory).
	// Chowning the tree to the mapped range fixes that; it has to happen
	// here, from this still-real-root parent, before Start() — the child
	// itself no longer has the privilege to chown anything once it's
	// running as the mapped uid.
	//
	// Every --userns container currently maps to the same fixed range (see
	// userNSHostIDOffset), so this is safe to reapply on every run: it's
	// idempotent, and a later NON-userns run of the same image is
	// unaffected (real root bypasses DAC checks regardless of file
	// ownership).
	if config.UserNS {
		if err := chownForUserNS(containerRootfs); err != nil {
			return fmt.Errorf("prepare rootfs ownership for --userns: %w", err)
		}
		// Owning the rootfs tree outright still isn't sufficient to reach
		// it — every directory between $HOME and it is checked separately
		// for search permission, and ~/.airlock defaults to mode 0700
		// owned by real root like the rest of a fresh $HOME. See
		// ensureTraversableForUserNS's doc comment for the full story.
		if err := ensureTraversableForUserNS(containerRootfs); err != nil {
			return fmt.Errorf("prepare rootfs path for --userns: %w", err)
		}
	}

	// Step 1.5: Validate that all host volume paths exist before starting the child.
	// Fail fast with a clear error rather than a cryptic mount failure.
	for _, vol := range config.Volumes {
		if _, err := os.Stat(vol.HostPath); err != nil {
			return fmt.Errorf("volume host path does not exist: %s", vol.HostPath)
		}
	}

	// Step 1.6: --userns only. Every bind-mount Child() would normally set
	// up itself (rootfs-to-self, volumes, the standard device files) has to
	// happen HERE instead, in this still-real-root parent, before Start().
	//
	// The reason is a kernel rule that isn't about DAC permissions at all:
	// mount() — including MS_BIND — requires CAP_SYS_ADMIN in the user
	// namespace that owns the TARGET filesystem's superblock, not just
	// ownership of or access to the path. containerRootfs sits on the
	// host's real filesystem, whose superblock belongs to the *initial*
	// user namespace. Once CLONE_NEWUSER takes effect, the child only has
	// CAP_SYS_ADMIN within its own new namespace — chownForUserNS already
	// grants it DAC write access to the tree, but that's a separate check,
	// and mount() still refuses it. Confirmed by hand: bindRootfsToSelf
	// failed with EPERM here even after the chown, on a plain --userns run
	// with no volumes at all.
	//
	// Doing the mounting here instead sidesteps the problem rather than
	// solving it: this parent process is still real root in the initial
	// namespace, so none of these calls are restricted. clone(CLONE_NEWNS)
	// takes a snapshot of the calling process's mount table at the moment
	// of Start() — so every mount set up here, right before Start(), is
	// already present in the child's own freshly-cloned mount namespace
	// the instant it exists, with no further mount() calls required once
	// the child is actually running as the mapped, unprivileged UID.
	//
	// completePivotRoot's own pivot_root attempt will still fail under
	// --userns for the same superblock-ownership reason — pivot_root is
	// itself a mount-namespace operation — but its existing chroot(2)
	// fallback works: CAP_SYS_CHROOT is checked against the CALLING
	// process's own (new) namespace, not the target filesystem's
	// superblock, so it isn't subject to this restriction at all.
	if config.UserNS {
		if err := bindRootfsToSelf(containerRootfs); err != nil {
			return fmt.Errorf("prepare rootfs mount point for --userns: %w", err)
		}
		if len(config.Volumes) > 0 {
			if err := PrepareVolumeMounts(containerRootfs, config.Volumes); err != nil {
				return fmt.Errorf("prepare volume mounts for --userns: %w", err)
			}
		}
		if err := bindHostDeviceFilesForUserNS(containerRootfs); err != nil {
			fmt.Fprintf(os.Stderr, "warning: prepare device files for --userns: %v\n", err)
		}
	}

	// Step 2: Set up the network bridge on the host before forking, so it is
	// ready as soon as the child's network namespace is visible.
	containerIP := config.ContainerIP
	if !config.NoNetwork {
		if err := SetupBridge(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: bridge setup failed: %v\n", err)
			// Non-fatal — container can still run without outbound NAT
		}

		// Only allocate a fresh IP if the caller didn't already pin one.
		// Compose pins ContainerIP to the address it pre-allocated for
		// /etc/hosts generation across the whole stack — allocating again
		// here would hand the container a different address than the one
		// every other service was told to resolve it at.
		if containerIP == "" {
			ip, err := AllocateIP()
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: IP allocation failed: %v\n", err)
			} else {
				containerIP = ip
			}
		}
	}

	// Step 3: Re-execute ourselves with "child" as the first argument.
	// This new process will be created inside the new namespaces.
	//
	// Networking is configured entirely from THIS side (CreateVethPair,
	// below) after Start() — necessarily, since it needs the child's PID
	// to target its network namespace. That leaves a real race: the child
	// runs concurrently and, once it reaches its own exec, whatever
	// command the caller gave it might immediately try to use eth0 —
	// which, timing depending, may not have been renamed/configured yet.
	// Confirmed by hand: the child's own `ip addr` occasionally still saw
	// the interface under its pre-rename peer name.
	//
	// readyR/readyW is a synchronization pipe (not a race-reducing
	// optimization — an actual deterministic barrier): its read end is
	// handed to the child via ExtraFiles (arriving as fd 3), which the
	// child blocks on immediately before its own final exec. Once
	// CreateVethPair (and any port forwards) below are done, the parent
	// closes its write end, which unblocks the child's read with EOF —
	// exactly like the pattern Go's own os/exec uses internally to
	// sequence a child past its parent's post-fork setup.
	readyR, readyW, pipeErr := os.Pipe()
	if pipeErr != nil {
		fmt.Fprintf(os.Stderr, "warning: could not create network-ready pipe, proceeding without it: %v\n", pipeErr)
		readyR, readyW = nil, nil
	}

	cmd := reexecCommand(config, containerRootfs, containerIP, readyR != nil)
	if readyR != nil {
		cmd.ExtraFiles = []*os.File{readyR}
	}

	cmd.Stdin = os.Stdin

	// Tee stdout/stderr to a per-container log file as well as the
	// terminal, so `airlock logs` has something to show even for a
	// container that's already exited (previously only compose services,
	// which redirect to their own log file instead of a terminal at all,
	// had any output persisted anywhere). The container's ID — which
	// becomes the log file's name — isn't known until after Start()
	// returns a PID, so this opens a temp file now and renames it into
	// place once that ID exists; renaming an already-open file is safe on
	// Linux and doesn't disturb the fd cmd.Stdout/Stderr already hold.
	logFile, logFileErr := os.CreateTemp("", "airlock-pending-log-*")
	if logFileErr != nil {
		fmt.Fprintf(os.Stderr, "warning: could not create log file: %v\n", logFileErr)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	} else {
		cmd.Stdout = io.MultiWriter(os.Stdout, logFile)
		cmd.Stderr = io.MultiWriter(os.Stderr, logFile)
		defer logFile.Close()
	}

	// Build namespace flags. Always clone UTS, PID, and mount namespaces.
	// Add CLONE_NEWNET when networking is enabled, CLONE_NEWUSER when
	// --userns is requested.
	cloneFlags := uintptr(syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS)
	if !config.NoNetwork {
		cloneFlags |= syscall.CLONE_NEWNET
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:   cloneFlags,
		Unshareflags: syscall.CLONE_NEWNS,
	}

	if config.UserNS {
		cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWUSER
		// Map the container's entire UID/GID range (0-65535) to an
		// unprivileged block starting at userNSHostIDOffset on the host.
		// Container UID 0 becomes host UID userNSHostIDOffset — a process
		// that's root *inside* the namespace is just an arbitrary
		// unprivileged UID from the host's point of view, with none of
		// real root's access to host files, other processes, or devices
		// outside what that UID already owns.
		//
		// This requires airlock's own process (the one calling Start) to
		// hold CAP_SETUID/CAP_SETGID over the mapped range — true when
		// airlock runs as real root, which every other feature here
		// (namespace creation, cgroups, mounts) already assumes. Without
		// that, the kernel would require the /etc/subuid delegation dance
		// rootless tools like rootlesskit use instead; airlock doesn't
		// support that path.
		idMap := []syscall.SysProcIDMap{{ContainerID: 0, HostID: userNSHostIDOffset, Size: userNSIDRangeSize}}
		cmd.SysProcAttr.UidMappings = idMap
		cmd.SysProcAttr.GidMappings = idMap
		// Without this, setgroups(2) is denied inside the new user
		// namespace by default (a kernel hardening measure), which would
		// break ApplyUser's Setgroups call whenever --user is combined
		// with --userns.
		cmd.SysProcAttr.GidMappingsEnableSetgroups = true

		// Establishing uid_map/gid_map does NOT, by itself, change this
		// process's own credentials — clone(CLONE_NEWUSER) doesn't alter
		// who you are, only how uids/gids get translated across the
		// namespace boundary from here on. The airlock parent process
		// calling Start() is real host root (kuid 0 in the initial
		// namespace), and kuid 0 isn't covered by the map above (which
		// only covers the range starting at userNSHostIDOffset) — left
		// alone, the child would keep that same real-root kuid, which is
		// unmapped from inside its own new namespace and therefore reports
		// as the kernel's overflow uid (65534, "nobody") with NO
		// capabilities at all — every operation Child() does after this,
		// starting with Sethostname, would fail with EPERM.
		//
		// Setting Credential here makes Go call setuid(0)/setgid(0) as
		// part of the fork/exec sequence, AFTER uid_map/gid_map are
		// written — namespace-relative, so this targets container-uid 0,
		// which the map resolves to host uid userNSHostIDOffset. That's
		// what actually makes the process "become" mapped-root: its real
		// kuid changes to the mapped value, which the kernel then
		// recognizes as namespace-uid 0 for every future capability check,
		// all the way through the "/proc/self/exe child ..." exec that
		// follows and everything Child() does afterward.
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: 0, Gid: 0}
	}

	// Step 4: Start the child process
	if err := cmd.Start(); err != nil {
		if readyR != nil {
			readyR.Close()
			readyW.Close()
		}
		return fmt.Errorf("failed to start container: %w", err)
	}
	if readyR != nil {
		// The child has its own independent duplicate of this fd (passed
		// via ExtraFiles); the parent's copy of the read end serves no
		// purpose from here on.
		readyR.Close()
	}

	// Step 5: Register container in state (before Wait so it appears in `ps`).
	// We use the child's OS PID as the container ID — it is kernel-guaranteed unique
	// among all running processes, preventing veth name collisions when many
	// containers start in rapid succession (e.g. compose stacks).
	containerID := fmt.Sprintf("%d", cmd.Process.Pid)
	state.Register(containerID, cmd.Process.Pid, config.Command, containerRootfs, "", containerIP, config.Image, config.ServiceName, config.ComposeFile)

	if logFile != nil {
		if finalPath, err := ContainerLogPath(containerID); err == nil {
			if err := os.Rename(logFile.Name(), finalPath); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not finalize log file: %v\n", err)
			}
		}
	}

	// Step 6: Wire up veth pair between host netns and container netns.
	// This MUST happen after cmd.Start() so the container's PID (and thus its
	// /proc/<pid>/ns/net) is already visible in the /proc filesystem.
	if !config.NoNetwork && containerIP != "" {
		if err := CreateVethPair(cmd.Process.Pid, containerIP, containerID); err != nil {
			fmt.Fprintf(os.Stderr, "warning: veth setup failed: %v\n", err)
		}

		// Install any port-forward rules the caller requested
		for _, pf := range config.PortForwards {
			if err := SetupPortForward(pf.HostPort, containerIP, pf.ContainerPort); err != nil {
				fmt.Fprintf(os.Stderr, "warning: port forward %s→%s failed: %v\n",
					pf.HostPort, pf.ContainerPort, err)
			}
		}
	}

	// Release the child from the pipe barrier described above Step 3, now
	// that networking (if any) is actually configured — regardless of
	// whether it succeeded, since the warnings above already cover
	// failure and there's nothing left worth making the child wait for.
	if readyW != nil {
		readyW.Close()
	}

	// Step 7: Wait for the child to exit
	err = cmd.Wait()

	// Step 8: Tear down networking and unregister container
	if !config.NoNetwork {
		CleanupNetwork(containerID)
	}
	state.Unregister(containerID)

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// The container's OWN command exited non-zero (or died from a
			// signal, which runAsInit already encodes as 128+signal) —
			// this is the container's business, not an airlock failure.
			// Returning it as a distinct type lets callers mirror the
			// exact exit code (the way `docker run` does) instead of
			// collapsing every non-zero outcome into a generic exit 1.
			return &ExitError{Code: exitErr.ExitCode()}
		}
		return fmt.Errorf("container exited with error: %w", err)
	}

	if Verbose {
		fmt.Println("🔓 Airlock: Container stopped.")
	}
	return nil
}

// reexecCommand builds an exec.Cmd that re-invokes the current binary
// in "child" mode. We pass the config as command-line arguments.
// Arg order: rootfsDir, hostname, memoryLimit, cpuLimit, volumesJSON,
//
//	noSeccomp, containerIP, noNetwork, envJSON, verbose, workingDir, user,
//	userNS, command, [cmdArgs...]
func reexecCommand(config Config, rootfsDir, containerIP string, hasReadyPipe bool) *exec.Cmd {
	volumesJSON, _ := json.Marshal(config.Volumes)
	envJSON, _ := json.Marshal(config.Env)
	noSeccomp := "false"
	if config.NoSeccomp {
		noSeccomp = "true"
	}
	noNetwork := "false"
	if config.NoNetwork {
		noNetwork = "true"
	}
	verbose := "false"
	if config.Verbose {
		verbose = "true"
	}
	userNS := "false"
	if config.UserNS {
		userNS = "true"
	}
	readyPipe := "false"
	if hasReadyPipe {
		readyPipe = "true"
	}
	initFlag := "false"
	if config.Init {
		initFlag = "true"
	}

	args := []string{
		"child",
		rootfsDir,
		config.Hostname,
		config.MemoryLimit,
		fmt.Sprintf("%d", config.CPULimit),
		string(volumesJSON),
		noSeccomp,
		containerIP, // may be empty string when NoNetwork=true
		noNetwork,
		string(envJSON),
		verbose,
		config.WorkingDir,
		config.User, // may be empty string — means "stay root"
		userNS,
		readyPipe,
		initFlag,
		config.Command,
	}
	args = append(args, config.Args...)

	cmd := exec.Command("/proc/self/exe", args...)
	return cmd
}
