package cmd

import (
	"fmt"
	"os"

	"github.com/kelyonnnn17/airlock/compose"
	"github.com/spf13/cobra"
)

var (
	composeFile string
)

var composeCmd = &cobra.Command{
	Use:   "compose",
	Short: "Multi-container orchestration",
	Long: `Compose manages multi-container applications defined in an airlock-compose.yml file.
It parses dependencies, pre-allocates IPs, generates internal /etc/hosts for DNS,
and starts the containers in the correct topological order.`,
}

var composeUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Create and start containers",
	Run: func(cmd *cobra.Command, args []string) {
		orch, err := compose.NewOrchestrator(composeFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading compose file: %v\n", err)
			os.Exit(1)
		}

		if err := orch.Up(verbose); err != nil {
			fmt.Fprintf(os.Stderr, "error starting compose stack: %v\n", err)
			os.Exit(1)
		}
	},
}

var composeDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Stop and remove containers",
	Run: func(cmd *cobra.Command, args []string) {
		orch, err := compose.NewOrchestrator(composeFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading compose file: %v\n", err)
			os.Exit(1)
		}

		if err := orch.Down(); err != nil {
			fmt.Fprintf(os.Stderr, "error stopping compose stack: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	composeCmd.PersistentFlags().StringVarP(&composeFile, "file", "f", "airlock-compose.yml", "Specify an alternate compose file")
	
	composeCmd.AddCommand(composeUpCmd)
	composeCmd.AddCommand(composeDownCmd)
	
	rootCmd.AddCommand(composeCmd)
}
