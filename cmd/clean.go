package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/kelyonn/airlock/image"
	"github.com/spf13/cobra"
)

var (
	cleanImages bool
	cleanAll    bool
	cleanVerify bool
)

var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Remove cached rootfs, images, and container data",
	Long: `Clean removes cached data from ~/.airlock/.

By default, only the Alpine rootfs cache and container state are removed.
Use --images to also remove pulled OCI image layers, or --all to remove everything.`,
	Run: func(cmd *cobra.Command, args []string) {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		airlockDir := filepath.Join(home, ".airlock")

		// --verify: re-hash every cached blob against its digest and remove
		// any that fail. Useful for catching blobs cached before digest
		// verification was added on download, or corrupted on disk since.
		if cleanVerify {
			bad, err := image.VerifyAllCachedBlobs()
			if err != nil {
				fmt.Fprintf(os.Stderr, "error verifying blob cache: %v\n", err)
				os.Exit(1)
			}
			if len(bad) == 0 {
				fmt.Println("✓ All cached blobs verified OK")
				return
			}
			fmt.Printf("⚠ %d blob(s) failed verification, removing:\n", len(bad))
			for _, digest := range bad {
				path, err := image.BlobCachePath(digest)
				if err == nil {
					os.Remove(path)
				}
				fmt.Printf("   - %s\n", digest)
			}
			return
		}

		// --all: wipe the entire ~/.airlock directory.
		if cleanAll {
			if _, err := os.Stat(airlockDir); os.IsNotExist(err) {
				fmt.Println("Nothing to clean.")
				return
			}
			if err := os.RemoveAll(airlockDir); err != nil {
				fmt.Fprintf(os.Stderr, "error removing %s: %v\n", airlockDir, err)
				os.Exit(1)
			}
			fmt.Println("✓ Cleaned up ~/.airlock/ (everything)")
			return
		}

		// --images (or default): selectively clean.
		cleaned := false

		// Clean OCI image and blob cache when --images is set.
		if cleanImages {
			freed, err := image.CleanImageCache()
			if err != nil {
				fmt.Fprintf(os.Stderr, "error cleaning image cache: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("✓ Cleaned image cache (freed %s)\n", formatBytes(freed))
			cleaned = true
		}

		// Always clean the Alpine rootfs cache and containers state.
		rootfsDir := filepath.Join(airlockDir, "rootfs")
		if _, err := os.Stat(rootfsDir); err == nil {
			if err := os.RemoveAll(rootfsDir); err != nil {
				fmt.Fprintf(os.Stderr, "error removing rootfs cache: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("✓ Cleaned Alpine rootfs cache")
			cleaned = true
		}

		stateFile := filepath.Join(airlockDir, "containers.json")
		if _, err := os.Stat(stateFile); err == nil {
			if err := os.Remove(stateFile); err != nil {
				fmt.Fprintf(os.Stderr, "error removing state file: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("✓ Cleaned container state")
			cleaned = true
		}

		if !cleaned {
			fmt.Println("Nothing to clean.")
		}
	},
}

// formatBytes converts a byte count into a human-readable string (KB, MB, GB).
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func init() {
	cleanCmd.Flags().BoolVar(&cleanImages, "images", false, "also remove pulled OCI image layer cache")
	cleanCmd.Flags().BoolVar(&cleanAll, "all", false, "remove all cached data (rootfs, images, blobs, state)")
	cleanCmd.Flags().BoolVar(&cleanVerify, "verify", false, "verify cached blob digests and remove any that fail")
	rootCmd.AddCommand(cleanCmd)
}
