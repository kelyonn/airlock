//go:build linux

package container

import (
	"fmt"
	"os"
	"path/filepath"
)

const cgroupRoot = "/sys/fs/cgroup"

// SetupCgroups applies resource limits using cgroups v2, by creating a
// dedicated child cgroup for this container and moving the process into it.
//
// If a child cgroup can't be created (e.g. this process's own cgroup
// doesn't have the memory/cpu controllers delegated to it — common when
// airlock itself is being run inside another container for development),
// limits are skipped entirely rather than applied. An earlier version
// fell back to writing memory.max/cpu.max directly onto THIS process's own
// current cgroup — which, since the "child" process hasn't been moved
// anywhere at that point, is the cgroup it still shares with the parent
// airlock process (and, inside a container, potentially the whole
// container's other processes too). Capping that shared cgroup to the
// container's configured memory limit (100m by default) doesn't sandbox
// just the container — it can OOM-kill the parent airlock process and
// anything else sharing that cgroup the moment combined usage crosses the
// limit, which for image pulling/extraction of anything beyond a tiny
// single-layer image is trivial to hit. Skipping the limit is strictly
// safer than mis-scoping it.
// Returns a cleanup function to remove the cgroup when the container exits.
func SetupCgroups(memoryLimit string, cpuPercent int) (func(), error) {
	pid := os.Getpid()

	memBytes, err := parseMemoryLimit(memoryLimit)
	if err != nil {
		return nil, fmt.Errorf("invalid memory limit: %w", err)
	}

	cgroupPath, useChild := tryCreateChildCgroup(pid)
	if !useChild {
		fmt.Fprintln(os.Stderr, "info: could not create a delegated child cgroup — skipping resource limits (not applying them to a shared cgroup)")
		return func() {}, nil
	}

	cleanup := func() {
		// Move process back to parent and remove child cgroup
		os.WriteFile(filepath.Join(cgroupRoot, "cgroup.procs"), []byte(fmt.Sprintf("%d", pid)), 0644)
		os.Remove(cgroupPath)
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

	// Move this process into the child cgroup.
	procsFile := filepath.Join(cgroupPath, "cgroup.procs")
	if err := os.WriteFile(procsFile, []byte(fmt.Sprintf("%d", pid)), 0644); err != nil {
		cleanup()
		return nil, fmt.Errorf("cannot add process to cgroup: %w", err)
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
