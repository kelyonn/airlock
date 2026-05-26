//go:build linux

package container

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/kelyonnnn17/airlock/rootfs"
	"github.com/kelyonnnn17/airlock/state"
)

// Run creates and runs a new container with the given configuration.
// It re-executes the current binary with a special "child" argument
// so that the child process runs inside the new namespaces.
func Run(config Config) error {
	fmt.Println("🔒 Airlock: Starting container...")

	// Step 1: Ensure rootfs is available
	rootfsDir, err := rootfs.Ensure(config.Verbose)
	if err != nil {
		return fmt.Errorf("rootfs setup failed: %w", err)
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

	// Step 2: Re-execute ourselves with "child" as the first argument.
	// This new process will be created inside the new namespaces.
	cmd := reexecCommand(config, rootfsDir)

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Set namespace flags on the new process
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUTS |
			syscall.CLONE_NEWPID |
			syscall.CLONE_NEWNS,
		Unshareflags: syscall.CLONE_NEWNS,
	}

	// Step 3: Start the child process
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	// Step 4: Register container in state
	containerID := state.GenerateID()
	state.Register(containerID, cmd.Process.Pid, config.Command, rootfsDir, "")

	// Step 5: Wait for the child to exit
	err = cmd.Wait()

	// Step 6: Unregister container
	state.Unregister(containerID)

	if err != nil {
		return fmt.Errorf("container exited with error: %w", err)
	}

	fmt.Println("🔓 Airlock: Container stopped.")
	return nil
}

// reexecCommand builds an exec.Cmd that re-invokes the current binary
// in "child" mode. We pass the config as command-line arguments.
// Arg order: rootfsDir, hostname, memoryLimit, cpuLimit, volumesJSON, command, [cmdArgs...]
func reexecCommand(config Config, rootfsDir string) *exec.Cmd {
	volumesJSON, _ := json.Marshal(config.Volumes)

	args := []string{"child", rootfsDir, config.Hostname, config.MemoryLimit, fmt.Sprintf("%d", config.CPULimit), string(volumesJSON), config.Command}
	args = append(args, config.Args...)

	cmd := exec.Command("/proc/self/exe", args...)
	return cmd
}
