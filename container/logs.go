// No build tag — ContainerLogPath is a pure path computation, needed both
// by Run (linux-only, writes the log file) and by cmd/logs.go (cross-
// platform CLI code, reads it back for `airlock logs`).

package container

import (
	"os"
	"path/filepath"
)

// ContainerLogPath returns the path a container's stdout/stderr are
// captured to, keyed by container ID (the same ID `airlock ps` shows).
func ContainerLogPath(containerID string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".airlock", "logs", "containers")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	return filepath.Join(dir, containerID+".log"), nil
}
