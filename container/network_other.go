//go:build !linux

package container

import "fmt"

// SetupBridge is a stub for non-Linux platforms.
// Networking requires Linux kernel features (network namespaces, veth, iptables).
func SetupBridge() error {
	return fmt.Errorf("networking only supported on Linux")
}

// AllocateIP is a stub for non-Linux platforms. Returns an empty string and nil
// so callers can still compile and detect the missing network case gracefully.
func AllocateIP() (string, error) {
	return "", nil
}

// CreateVethPair is a stub for non-Linux platforms.
func CreateVethPair(containerPID int, containerIP, containerID string) error {
	return fmt.Errorf("networking only supported on Linux")
}

// SetupPortForward is a stub for non-Linux platforms.
func SetupPortForward(hostPort, containerIP, containerPort string) error {
	return fmt.Errorf("networking only supported on Linux")
}

// CleanupNetwork is a stub for non-Linux platforms.
func CleanupNetwork(containerID string) error {
	return fmt.Errorf("networking only supported on Linux")
}
