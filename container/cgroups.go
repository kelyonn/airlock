//go:build linux

package container

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const cgroupRoot = "/sys/fs/cgroup"

// SetupCgroups applies resource limits using cgroups v2.
// It first tries to create a child cgroup. If that fails (e.g., inside Docker
// where we're already in a leaf cgroup), it writes limits directly to the
// current cgroup.
// Returns a cleanup function to remove the cgroup when the container exits.
func SetupCgroups(memoryLimit string, cpuPercent int) (func(), error) {
	pid := os.Getpid()

	memBytes, err := parseMemoryLimit(memoryLimit)
	if err != nil {
		return nil, fmt.Errorf("invalid memory limit: %w", err)
	}

	// Try to create a child cgroup first (the "proper" way)
	cgroupPath, useChild := tryCreateChildCgroup(pid)

	cleanup := func() {
		if useChild {
			// Move process back to parent and remove child cgroup
			os.WriteFile(filepath.Join(cgroupRoot, "cgroup.procs"), []byte(fmt.Sprintf("%d", pid)), 0644)
			os.Remove(cgroupPath)
		}
	}

	// Apply memory limit
	memFile := filepath.Join(cgroupPath, "memory.max")
	if err := os.WriteFile(memFile, []byte(fmt.Sprintf("%d", memBytes)), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "info: memory limit not applied: %v\n", err)
	} else {
		fmt.Printf("   Memory limit: %s\n", memoryLimit)
	}

	// Apply CPU limit (quota/period in microseconds)
	if cpuPercent > 0 && cpuPercent <= 100 {
		quota := cpuPercent * 1000 // out of 100000 period
		cpuMax := fmt.Sprintf("%d 100000", quota)
		cpuFile := filepath.Join(cgroupPath, "cpu.max")
		if err := os.WriteFile(cpuFile, []byte(cpuMax), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "info: CPU limit not applied: %v\n", err)
		} else {
			fmt.Printf("   CPU limit: %d%%\n", cpuPercent)
		}
	}

	// If using a child cgroup, move this process into it
	if useChild {
		procsFile := filepath.Join(cgroupPath, "cgroup.procs")
		if err := os.WriteFile(procsFile, []byte(fmt.Sprintf("%d", pid)), 0644); err != nil {
			cleanup()
			return nil, fmt.Errorf("cannot add process to cgroup: %w", err)
		}
	}

	return cleanup, nil
}

// tryCreateChildCgroup attempts to create a child cgroup under the root.
// Returns (cgroupPath, true) if successful, or (cgroupRoot, false) if we
// should write directly to the current cgroup (e.g., inside Docker).
func tryCreateChildCgroup(pid int) (string, bool) {
	// Enable controller delegation
	subtreeControl := filepath.Join(cgroupRoot, "cgroup.subtree_control")
	os.WriteFile(subtreeControl, []byte("+memory +cpu"), 0644)

	cgroupName := fmt.Sprintf("airlock-%d", pid)
	cgroupPath := filepath.Join(cgroupRoot, cgroupName)

	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		// Can't create child cgroup — write limits to current cgroup directly
		return cgroupRoot, false
	}

	// Check if memory.max exists in the child (controllers delegated properly)
	if _, err := os.Stat(filepath.Join(cgroupPath, "memory.max")); err != nil {
		// Controllers not delegated — clean up and fall back
		os.Remove(cgroupPath)
		return cgroupRoot, false
	}

	return cgroupPath, true
}

// parseMemoryLimit converts a human-readable memory limit to bytes.
// Supports: "100m", "256m", "1g", "512k", or raw bytes as a number.
func parseMemoryLimit(limit string) (int64, error) {
	limit = strings.TrimSpace(strings.ToLower(limit))
	if limit == "" {
		return 100 * 1024 * 1024, nil // default 100MB
	}

	var multiplier int64 = 1
	numStr := limit

	if strings.HasSuffix(limit, "g") {
		multiplier = 1024 * 1024 * 1024
		numStr = strings.TrimSuffix(limit, "g")
	} else if strings.HasSuffix(limit, "m") {
		multiplier = 1024 * 1024
		numStr = strings.TrimSuffix(limit, "m")
	} else if strings.HasSuffix(limit, "k") {
		multiplier = 1024
		numStr = strings.TrimSuffix(limit, "k")
	}

	num, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("cannot parse '%s': %w", limit, err)
	}

	return num * multiplier, nil
}
