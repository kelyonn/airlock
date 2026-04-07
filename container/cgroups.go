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

// SetupCgroups creates a cgroup for the container and applies resource limits.
// Returns a cleanup function to remove the cgroup when the container exits.
func SetupCgroups(memoryLimit string, cpuPercent int) (func(), error) {
	pid := os.Getpid()
	cgroupName := fmt.Sprintf("airlock-%d", pid)
	cgroupPath := filepath.Join(cgroupRoot, cgroupName)

	// Create cgroup directory
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		return nil, fmt.Errorf("cannot create cgroup: %w", err)
	}

	cleanup := func() {
		// Remove the container PID from the cgroup first
		os.WriteFile(filepath.Join(cgroupRoot, "cgroup.procs"), []byte(fmt.Sprintf("%d", pid)), 0644)
		// Remove the cgroup directory
		os.Remove(cgroupPath)
	}

	// Set memory limit
	memBytes, err := parseMemoryLimit(memoryLimit)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("invalid memory limit: %w", err)
	}
	if err := os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte(fmt.Sprintf("%d", memBytes)), 0644); err != nil {
		cleanup()
		return nil, fmt.Errorf("cannot set memory limit: %w", err)
	}

	// Set CPU limit (using cpu.max with period of 100000 microseconds)
	if cpuPercent > 0 && cpuPercent <= 100 {
		quota := cpuPercent * 1000 // microseconds out of 100000
		cpuMax := fmt.Sprintf("%d 100000", quota)
		if err := os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte(cpuMax), 0644); err != nil {
			cleanup()
			return nil, fmt.Errorf("cannot set CPU limit: %w", err)
		}
	}

	// Add current process to the cgroup
	if err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), []byte(fmt.Sprintf("%d", pid)), 0644); err != nil {
		cleanup()
		return nil, fmt.Errorf("cannot add process to cgroup: %w", err)
	}

	return cleanup, nil
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
