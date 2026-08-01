package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/kelyonn/airlock/state"
	"github.com/spf13/cobra"
)

// truncate returns s truncated to maxLen characters, appending "…" if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}

var listCmd = &cobra.Command{
	Use:     "list",
	Short:   "List running containers",
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
		fmt.Fprintln(w, "ID\tPID\tSERVICE\tIMAGE\tCOMMAND\tSTARTED")
		for _, c := range containers {
			img := c.Image
			if img == "" {
				img = "alpine (default)"
			}
			svc := c.ServiceName
			if svc == "" {
				svc = "-"
			}
			fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\n",
				truncate(c.ID, 12), c.PID, svc, truncate(img, 20), c.Command, c.StartedAt)
		}
		w.Flush()
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
