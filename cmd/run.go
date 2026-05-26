package cmd

import (
	"fmt"
	"os"

	"github.com/kelyonnnn17/airlock/container"
	"github.com/spf13/cobra"
)

var (
	memoryLimit string
	cpuLimit    int
	hostname    string
)

var runCmd = &cobra.Command{
	Use:   "run [command] [args...]",
	Short: "Run a command inside a new container",
	Long: `Run launches a new isolated container and executes the given command inside it.
The container uses Linux namespaces, chroot, and cgroups for isolation.

Example:
  airlock run /bin/sh
  airlock run --memory 256m --cpu 80 /bin/sh`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		config := container.Config{
			Command:     args[0],
			Args:        args[1:],
			Hostname:    hostname,
			MemoryLimit: memoryLimit,
			CPULimit:    cpuLimit,
			Verbose:     verbose,
		}

		if err := container.Run(config); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	runCmd.Flags().StringVarP(&memoryLimit, "memory", "m", "100m", "memory limit (e.g., 100m, 1g)")
	runCmd.Flags().IntVar(&cpuLimit, "cpu", 50, "CPU limit as percentage (1-100)")
	runCmd.Flags().StringVar(&hostname, "hostname", "airlock-container", "container hostname")
	// Stop flag parsing after the first positional arg (the container command).
	// Without this, `airlock run /bin/sh -c "cmd"` would try to parse -c as an airlock flag.
	runCmd.Flags().SetInterspersed(false)
	rootCmd.AddCommand(runCmd)
}
