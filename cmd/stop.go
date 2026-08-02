package cmd

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/kelyonn/airlock/container"
	"github.com/kelyonn/airlock/state"
	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop CONTAINER [CONTAINER...]",
	Short: "Stop one or more running containers",
	Long: `Stop sends SIGTERM to each container's process, waits up to 5 seconds
for it to exit, and escalates to SIGKILL if it hasn't. CONTAINER may be the
full ID or any unique prefix, as shown by "airlock ps".`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		exitCode := 0
		for _, idArg := range args {
			c, err := state.Resolve(idArg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				exitCode = 1
				continue
			}
			if err := stopContainer(c); err != nil {
				fmt.Fprintf(os.Stderr, "error stopping %s: %v\n", c.ID, err)
				exitCode = 1
				continue
			}
			fmt.Println(c.ID)
		}
		os.Exit(exitCode)
	},
}

// stopContainer sends SIGTERM, waits, escalates to SIGKILL if needed, and
// tears down network/state either way — mirroring compose.Orchestrator's
// Down() so `airlock stop` and `airlock compose down` behave consistently.
func stopContainer(c state.Container) error {
	process, err := os.FindProcess(c.PID)
	if err != nil {
		// Already gone; still worth cleaning up state/network in case a
		// prior run crashed before it could.
		return cleanupStoppedContainer(c)
	}

	if err := process.Signal(syscall.SIGTERM); err == nil {
		if waitForContainerExit(c.PID, 5*time.Second) {
			return cleanupStoppedContainer(c)
		}
	}

	_ = process.Signal(syscall.SIGKILL)
	waitForContainerExit(c.PID, 2*time.Second)

	return cleanupStoppedContainer(c)
}

func cleanupStoppedContainer(c state.Container) error {
	_ = container.CleanupNetwork(c.ID)
	return state.Unregister(c.ID)
}

func waitForContainerExit(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !containerProcessAlive(pid) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return !containerProcessAlive(pid)
}

func containerProcessAlive(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return process.Signal(syscall.Signal(0)) == nil
}

func init() {
	rootCmd.AddCommand(stopCmd)
}
