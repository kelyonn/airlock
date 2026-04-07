package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Container represents a running container's state.
type Container struct {
	ID        string    `json:"id"`
	PID       int       `json:"pid"`
	Command   string    `json:"command"`
	StartedAt string    `json:"started_at"`
	RootfsDir string    `json:"rootfs_dir"`
	CgroupDir string    `json:"cgroup_dir"`
}

// stateFilePath returns the path to the containers state file.
func stateFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".airlock", "containers.json"), nil
}

// List returns all tracked containers.
func List() ([]Container, error) {
	path, err := stateFilePath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []Container{}, nil
		}
		return nil, err
	}

	var containers []Container
	if err := json.Unmarshal(data, &containers); err != nil {
		return nil, err
	}

	// Filter out stale containers (process no longer exists)
	var alive []Container
	for _, c := range containers {
		if processExists(c.PID) {
			alive = append(alive, c)
		}
	}

	// Update state file with only alive containers
	if len(alive) != len(containers) {
		save(alive)
	}

	return alive, nil
}

// Register adds a new container to the state file.
func Register(id string, pid int, command string, rootfsDir string, cgroupDir string) error {
	containers, err := List()
	if err != nil {
		containers = []Container{}
	}

	c := Container{
		ID:        id,
		PID:       pid,
		Command:   command,
		StartedAt: time.Now().Format("2006-01-02 15:04:05"),
		RootfsDir: rootfsDir,
		CgroupDir: cgroupDir,
	}

	containers = append(containers, c)
	return save(containers)
}

// Unregister removes a container from the state file.
func Unregister(id string) error {
	containers, err := List()
	if err != nil {
		return err
	}

	var updated []Container
	for _, c := range containers {
		if c.ID != id {
			updated = append(updated, c)
		}
	}

	return save(updated)
}

// save writes the containers list to the state file.
func save(containers []Container) error {
	path, err := stateFilePath()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(containers, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// processExists checks if a process with the given PID is still running.
func processExists(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds. Send signal 0 to test if process exists.
	err = process.Signal(nil)
	if err != nil {
		return false
	}
	return true
}

// GenerateID creates a simple unique container ID.
func GenerateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
