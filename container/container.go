//go:build linux

package container

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/kelyonnnn17/airlock/image"
	"github.com/kelyonnnn17/airlock/rootfs"
	"github.com/kelyonnnn17/airlock/state"
)

// Run creates and runs a new container with the given configuration.
// It re-executes the current binary with a special "child" argument
// so that the child process runs inside the new namespaces.
func Run(config Config) error {
	fmt.Println("🔒 Airlock: Starting container...")

	// Step 1: Ensure rootfs is available.
	// If an OCI image reference is specified, pull/cache it; otherwise fall back
	// to the default Alpine mini-rootfs.
	var rootfsDir string
	var err error
	if config.Image != "" {
		rootfsDir, err = image.Pull(config.Image, config.Verbose)
		if err != nil {
			return fmt.Errorf("image pull failed: %w", err)
		}
	} else {
		rootfsDir, err = rootfs.Ensure(config.Verbose)
		if err != nil {
			return fmt.Errorf("rootfs setup failed: %w", err)
		}
	}

	if config.Verbose {
		fmt.Printf("[container] rootfs: %s\n", rootfsDir)
	}

	// Step 1.5: Validate that all host volume paths exist before starting the child.
	// Fail fast with a clear error rather than a cryptic mount failure.
	for _, vol := range config.Volumes {
		if _, err := os.Stat(vol.HostPath); err != nil {
			return fmt.Errorf("volume host path does not exist: %s", vol.HostPath)
		}
	}

	// Step 2: Set up the network bridge on the host before forking, so it is
	// ready as soon as the child's network namespace is visible.
	var containerIP string
	if !config.NoNetwork {
		if err := SetupBridge(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: bridge setup failed: %v\n", err)
			// Non-fatal — container can still run without outbound NAT
		}

		ip, err := AllocateIP()
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: IP allocation failed: %v\n", err)
		} else {
			containerIP = ip
		}
	}

	// Step 3: Re-execute ourselves with "child" as the first argument.
	// This new process will be created inside the new namespaces.
	cmd := reexecCommand(config, rootfsDir, containerIP)

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Build namespace flags. Always clone UTS, PID, and mount namespaces.
	// Add CLONE_NEWNET when networking is enabled.
	cloneFlags := uintptr(syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS)
	if !config.NoNetwork {
		cloneFlags |= syscall.CLONE_NEWNET
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  cloneFlags,
		Unshareflags: syscall.CLONE_NEWNS,
	}

	// Step 4: Start the child process
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	// Step 5: Register container in state (before Wait so it appears in `ps`).
	// We use the child's OS PID as the container ID — it is kernel-guaranteed unique
	// among all running processes, preventing veth name collisions when many
	// containers start in rapid succession (e.g. compose stacks).
	containerID := fmt.Sprintf("%d", cmd.Process.Pid)
	state.Register(containerID, cmd.Process.Pid, config.Command, rootfsDir, "", containerIP, config.Image, "", "")

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

	// Step 7: Wait for the child to exit
	err = cmd.Wait()

	// Step 8: Tear down networking and unregister container
	if !config.NoNetwork {
		CleanupNetwork(containerID)
	}
	state.Unregister(containerID)

	if err != nil {
		return fmt.Errorf("container exited with error: %w", err)
	}

	fmt.Println("🔓 Airlock: Container stopped.")
	return nil
}

// reexecCommand builds an exec.Cmd that re-invokes the current binary
// in "child" mode. We pass the config as command-line arguments.
// Arg order: rootfsDir, hostname, memoryLimit, cpuLimit, volumesJSON,
//
//	noSeccomp, containerIP, noNetwork, command, [cmdArgs...]
func reexecCommand(config Config, rootfsDir, containerIP string) *exec.Cmd {
	volumesJSON, _ := json.Marshal(config.Volumes)
	noSeccomp := "false"
	if config.NoSeccomp {
		noSeccomp = "true"
	}
	noNetwork := "false"
	if config.NoNetwork {
		noNetwork = "true"
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
		config.Command,
	}
	args = append(args, config.Args...)

	cmd := exec.Command("/proc/self/exe", args...)
	return cmd
}
