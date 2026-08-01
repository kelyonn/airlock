package cmd

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kelyonn/airlock/container"
	"github.com/kelyonn/airlock/state"
	"github.com/spf13/cobra"
)

var followLogs bool

var logsCmd = &cobra.Command{
	Use:   "logs CONTAINER",
	Short: "View a container's output",
	Long: `Logs prints the stdout/stderr a container has produced since it started
(captured to ~/.airlock/logs/containers/<id>.log for the lifetime of the
container, and kept afterward until "airlock clean --all" removes it).
CONTAINER may be the full ID or any unique prefix, as shown by "airlock ps".`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		c, err := state.Resolve(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		logPath, err := container.ContainerLogPath(c.ID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		f, err := os.Open(logPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: no logs found for %s: %v\n", c.ID, err)
			os.Exit(1)
		}
		defer f.Close()

		if _, err := io.Copy(os.Stdout, f); err != nil {
			fmt.Fprintf(os.Stderr, "error reading logs: %v\n", err)
			os.Exit(1)
		}

		if !followLogs {
			return
		}

		// Simple poll-based follow: the log file is append-only for the
		// life of the container, so re-reading from the current offset
		// after a short sleep picks up whatever's been written since —
		// no inotify machinery needed for something this size.
		for {
			time.Sleep(300 * time.Millisecond)
			if _, err := io.Copy(os.Stdout, f); err != nil {
				return
			}
		}
	},
}

func init() {
	logsCmd.Flags().BoolVarP(&followLogs, "follow", "f", false, "keep printing new output as it's written (like tail -f)")
	rootCmd.AddCommand(logsCmd)
}
