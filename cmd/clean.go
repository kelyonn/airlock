package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Remove cached rootfs and container data",
	Long:  `Clean removes the cached Alpine rootfs and all container data from ~/.airlock/`,
	Run: func(cmd *cobra.Command, args []string) {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		airlockDir := filepath.Join(home, ".airlock")

		if _, err := os.Stat(airlockDir); os.IsNotExist(err) {
			fmt.Println("Nothing to clean.")
			return
		}

		if err := os.RemoveAll(airlockDir); err != nil {
			fmt.Fprintf(os.Stderr, "error removing %s: %v\n", airlockDir, err)
			os.Exit(1)
		}

		fmt.Println("✓ Cleaned up ~/.airlock/")
	},
}

func init() {
	rootCmd.AddCommand(cleanCmd)
}
