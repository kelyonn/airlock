//go:build !linux

package container

import (
	"fmt"
	"runtime"
)

// Run is a stub for non-Linux platforms.
// Container isolation requires Linux kernel features (namespaces, cgroups, chroot).
func Run(config Config) error {
	return fmt.Errorf(
		"containers are only supported on Linux (current OS: %s)\n"+
			"  Tip: Use Docker Desktop to run Airlock inside a Linux container:\n"+
			"    docker build -t airlock-dev .\n"+
			"    docker run --rm -it --privileged airlock-dev airlock run /bin/sh",
		runtime.GOOS,
	)
}

// Child is a stub for non-Linux platforms.
func Child(args []string) error {
	return fmt.Errorf("container child process can only run on Linux (current OS: %s)", runtime.GOOS)
}

// Exec is a stub for non-Linux platforms.
func Exec(targetPID int, command string, args []string) error {
	return fmt.Errorf("airlock exec is only supported on Linux (current OS: %s)", runtime.GOOS)
}
