package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var verbose bool

var rootCmd = &cobra.Command{
	Use:   "airlock",
	Short: "A mini container runtime",
	Long: `Airlock is a mini-Docker that isolates processes using Linux kernel features.
It uses namespaces, chroot, and cgroups to create lightweight containers.`,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "enable verbose output")
}
