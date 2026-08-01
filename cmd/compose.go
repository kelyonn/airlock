package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kelyonn/airlock/compose"
	"github.com/spf13/cobra"
)

var (
	composeFile string
	detach      bool
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

		if detach {
			fmt.Println("Stack started in the background (-d). Use 'airlock compose down' to stop it.")
			return
		}

		// Foreground mode (the default, matching docker-compose): block until
		// interrupted, then tear the stack down. Every service is already a
		// real detached OS process at this point (see compose/orchestrator.go),
		// so it would keep running with or without this — the block-and-clean-up
		// behavior here is purely so Ctrl+C does what a user expects instead of
		// silently leaving everything running.
		fmt.Println("Attached to stack — press Ctrl+C to stop.")
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		fmt.Println("\nStopping stack...")
		if err := orch.Down(); err != nil {
			fmt.Fprintf(os.Stderr, "error stopping compose stack: %v\n", err)
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
	composeUpCmd.Flags().BoolVarP(&detach, "detach", "d", false, "run the stack in the background instead of blocking in the foreground")

	composeCmd.AddCommand(composeUpCmd)
	composeCmd.AddCommand(composeDownCmd)

	rootCmd.AddCommand(composeCmd)
}
