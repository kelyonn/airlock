package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/kelyonnnn17/airlock/state"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List running containers",
	Aliases: []string{"ls", "ps"},
	Run: func(cmd *cobra.Command, args []string) {
		containers, err := state.List()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		if len(containers) == 0 {
			fmt.Println("No running containers.")
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tPID\tCOMMAND\tSTARTED")
		for _, c := range containers {
			fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", c.ID[:12], c.PID, c.Command, c.StartedAt)
		}
		w.Flush()
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
