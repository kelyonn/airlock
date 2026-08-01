package cmd

import (
	"fmt"
	"os"

	"github.com/kelyonn/airlock/container"
	"github.com/kelyonn/airlock/state"
	"github.com/spf13/cobra"
)

var execCmd = &cobra.Command{
	Use:   "exec CONTAINER COMMAND [ARGS...]",
	Short: "Run a command inside a running container",
	Long: `Exec joins a running container's mount, UTS, network, IPC, and PID
namespaces and runs COMMAND there — airlock's equivalent of "docker exec".

CONTAINER may be the full ID or any unique prefix of it, as shown by
"airlock ps".`,
	Args: cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		c, err := state.Resolve(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		if err := container.Exec(c.PID, args[1], args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	// Stop flag parsing after the container ID, same reasoning as `run`:
	// `airlock exec mybox ls -la` shouldn't try to parse -la as an airlock flag.
	execCmd.Flags().SetInterspersed(false)
	rootCmd.AddCommand(execCmd)
}
