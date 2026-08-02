package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kelyonn/airlock/internal/filelock"
)

// Container represents a running container's state.
type Container struct {
	ID          string `json:"id"`
	PID         int    `json:"pid"`
	Command     string `json:"command"`
	StartedAt   string `json:"started_at"`
	RootfsDir   string `json:"rootfs_dir"`
	CgroupDir   string `json:"cgroup_dir"`
	IPAddress   string `json:"ip_address"`             // allocated container IP (empty if --no-network)
	Image       string `json:"image"`                  // OCI image reference (empty if using default Alpine rootfs)
	ServiceName string `json:"service_name,omitempty"` // for compose
	ComposeFile string `json:"compose_file,omitempty"` // for compose
	// UserNSBase is the first host UID/GID of the range this container's
	// user namespace maps onto, or 0 for a container running without
	// --userns. It's recorded here because that's what makes the range
	// reclaimable: allocation cross-checks live containers rather than
	// trusting a standalone counter, so unregistering a container is what
	// frees its range (see container.allocateUserNSRange).
	UserNSBase int `json:"userns_base,omitempty"`
}

// stateFilePath returns the path to the containers state file.
func stateFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".airlock", "containers.json"), nil
}

// withLock acquires an exclusive lock on the state file (via internal/filelock)
// and runs fn.  This makes Register/Unregister/List safe across multiple
// concurrent airlock processes (e.g. compose stacks starting several
// containers at once).
func withLock(fn func(statePath string) error) error {
	path, err := stateFilePath()
	if err != nil {
		return err
	}
	return filelock.WithLock(path, func() error {
		return fn(path)
	})
}

// loadUnlocked reads and returns all containers from the state file.
// Caller MUST hold the state lock.
func loadUnlocked(statePath string) []Container {
	data, err := os.ReadFile(statePath)
	if err != nil {
		return []Container{}
	}
	var containers []Container
	if err := json.Unmarshal(data, &containers); err != nil {
		return []Container{}
	}
	return containers
}

// saveUnlocked writes the containers list to the state file.
// Caller MUST hold the state lock.
func saveUnlocked(statePath string, containers []Container) error {
	if containers == nil {
		containers = []Container{}
	}
	data, err := json.MarshalIndent(containers, "", "  ")
	if err != nil {
		return err
	}
	// Write atomically: write to a temp file then rename.
	tmp := statePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, statePath)
}

// List returns all tracked containers whose processes are still alive.
// Stale entries are pruned from the state file as a side-effect.
func List() ([]Container, error) {
	var alive []Container
	err := withLock(func(path string) error {
		containers := loadUnlocked(path)

		var pruned bool
		for _, c := range containers {
			if processExists(c.PID) {
				alive = append(alive, c)
			} else {
				pruned = true
			}
		}

		// Persist the cleaned-up list only when something was removed.
		if pruned {
			return saveUnlocked(path, alive)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return alive, nil
}

// Register adds a new container to the state file.
// ipAddress is the allocated container IP (e.g. "10.0.42.2") or empty string if
// networking is disabled. image is the OCI image reference or empty string if using
// the default Alpine rootfs. serviceName and composeFile are used for compose stacks.
func Register(id string, pid int, command string, rootfsDir string, cgroupDir string, ipAddress string, image string, serviceName string, composeFile string, userNSBase int) error {
	return withLock(func(path string) error {
		containers := loadUnlocked(path)

		c := Container{
			ID:          id,
			PID:         pid,
			Command:     command,
			StartedAt:   time.Now().Format("2006-01-02 15:04:05"),
			RootfsDir:   rootfsDir,
			CgroupDir:   cgroupDir,
			IPAddress:   ipAddress,
			Image:       image,
			ServiceName: serviceName,
			ComposeFile: composeFile,
			UserNSBase:  userNSBase,
		}

		containers = append(containers, c)
		return saveUnlocked(path, containers)
	})
}

// Unregister removes a container from the state file.
func Unregister(id string) error {
	return withLock(func(path string) error {
		containers := loadUnlocked(path)

		var updated []Container
		for _, c := range containers {
			if c.ID != id {
				updated = append(updated, c)
			}
		}

		return saveUnlocked(path, updated)
	})
}

// processExists checks if a process with the given PID is still running.
// It sends signal 0 (kill(pid, 0)), which performs an existence/permission
// check without delivering any signal.
func processExists(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// syscall.Signal(0) is "signal 0" — probes existence without signalling.
	// NOTE: process.Signal(nil) must NOT be used; nil fails the os.Signal
	// interface type assertion inside Go's runtime and always returns an error.
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

// GenerateID creates a simple unique container ID.
func GenerateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// ListByCompose returns all tracked containers belonging to the given compose file.
func ListByCompose(composeFile string) ([]Container, error) {
	all, err := List()
	if err != nil {
		return nil, err
	}
	var match []Container
	for _, c := range all {
		if c.ComposeFile == composeFile {
			match = append(match, c)
		}
	}
	return match, nil
}

// Resolve finds the single running container whose ID starts with prefix —
// the same kind of short-ID lookup `docker exec`/`docker stop` accept, so
// users can pass the truncated 12-character ID `airlock ps` prints instead
// of the full PID-derived one. Returns an error if no container matches,
// or if more than one does (asks the caller to be more specific rather
// than guessing).
func Resolve(prefix string) (Container, error) {
	if prefix == "" {
		return Container{}, fmt.Errorf("container ID cannot be empty")
	}

	containers, err := List()
	if err != nil {
		return Container{}, err
	}

	var matches []Container
	for _, c := range containers {
		if c.ID == prefix || strings.HasPrefix(c.ID, prefix) {
			matches = append(matches, c)
		}
	}

	switch len(matches) {
	case 0:
		return Container{}, fmt.Errorf("no running container matches ID %q", prefix)
	case 1:
		return matches[0], nil
	default:
		return Container{}, fmt.Errorf("ID %q is ambiguous — matches %d running containers, use more characters", prefix, len(matches))
	}
}
