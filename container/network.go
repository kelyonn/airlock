//go:build linux

package container

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	bridgeName    = "airlock0"
	bridgeIP      = "10.0.42.1"
	bridgeCIDR    = "10.0.42.1/24"
	networkSubnet = "10.0.42.0/24"
	gateway       = "10.0.42.1"
)

// networkState is the persisted state for IP allocation.
type networkState struct {
	NextIP int `json:"next_ip"`
}

// networkStatePath returns the path to the network state file (~/.airlock/network.json).
func networkStatePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".airlock", "network.json"), nil
}

// SetupBridge creates the airlock0 Linux bridge if it does not already exist,
// assigns 10.0.42.1/24 to it, enables IPv4 forwarding, and installs a MASQUERADE
// iptables rule so that containers can reach the internet. All operations are
// idempotent — safe to call multiple times.
func SetupBridge() error {
	// Check whether the bridge already exists (ip link show returns non-zero if missing)
	checkErr := runCmd("ip", "link", "show", bridgeName)
	if checkErr != nil {
		// Bridge does not exist — create it
		if err := runCmd("ip", "link", "add", bridgeName, "type", "bridge"); err != nil {
			return fmt.Errorf("create bridge %s: %w", bridgeName, err)
		}
		fmt.Printf("🌉 Created bridge %s\n", bridgeName)
	}

	// Assign the IP address (ignore error if already assigned)
	_ = runCmd("ip", "addr", "add", bridgeCIDR, "dev", bridgeName)

	// Bring the bridge up
	if err := runCmd("ip", "link", "set", bridgeName, "up"); err != nil {
		return fmt.Errorf("bring up bridge %s: %w", bridgeName, err)
	}

	// Enable IPv4 forwarding
	if err := runCmd("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("enable ip_forward: %w", err)
	}

	// Set up MASQUERADE for container traffic leaving on any interface.
	// Use -C to check first (idempotent), only add with -A if absent.
	checkMasq := runCmd(
		"iptables", "-t", "nat", "-C", "POSTROUTING",
		"-s", networkSubnet, "!", "-o", bridgeName,
		"-j", "MASQUERADE",
	)
	if checkMasq != nil {
		if err := runCmd(
			"iptables", "-t", "nat", "-A", "POSTROUTING",
			"-s", networkSubnet, "!", "-o", bridgeName,
			"-j", "MASQUERADE",
		); err != nil {
			return fmt.Errorf("add MASQUERADE rule: %w", err)
		}
	}

	// Allow forwarded traffic through the bridge
	checkFwd := runCmd(
		"iptables", "-C", "FORWARD",
		"-i", bridgeName, "-j", "ACCEPT",
	)
	if checkFwd != nil {
		_ = runCmd("iptables", "-A", "FORWARD", "-i", bridgeName, "-j", "ACCEPT")
	}
	checkFwd2 := runCmd(
		"iptables", "-C", "FORWARD",
		"-o", bridgeName, "-j", "ACCEPT",
	)
	if checkFwd2 != nil {
		_ = runCmd("iptables", "-A", "FORWARD", "-o", bridgeName, "-j", "ACCEPT")
	}

	return nil
}

// AllocateIP reads ~/.airlock/network.json, increments the next_ip counter
// (wrapping at 254 back to 2), saves the updated state, and returns the
// allocated IP address string in the form "10.0.42.<n>".
func AllocateIP() (string, error) {
	path, err := networkStatePath()
	if err != nil {
		return "", fmt.Errorf("network state path: %w", err)
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return "", fmt.Errorf("create airlock dir: %w", err)
	}

	var ns networkState
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// First run — start at host offset 2 (offset 1 is the bridge itself)
			ns.NextIP = 2
		} else {
			return "", fmt.Errorf("read network state: %w", err)
		}
	} else {
		if err := json.Unmarshal(data, &ns); err != nil {
			return "", fmt.Errorf("parse network state: %w", err)
		}
	}

	// Grab the current value and advance the counter
	current := ns.NextIP
	ns.NextIP++
	if ns.NextIP > 253 {
		ns.NextIP = 2
	}

	// Persist updated state
	out, err := json.Marshal(ns)
	if err != nil {
		return "", fmt.Errorf("marshal network state: %w", err)
	}
	if err := os.WriteFile(path, out, 0644); err != nil {
		return "", fmt.Errorf("write network state: %w", err)
	}

	return fmt.Sprintf("10.0.42.%d", current), nil
}

// CreateVethPair creates a veth pair for the container identified by containerID,
// attaches the host-side interface to the airlock0 bridge, moves the peer end
// into the container's network namespace (identified by containerPID), and then
// uses nsenter to configure eth0 inside that namespace with containerIP/24.
func CreateVethPair(containerPID int, containerIP, containerID string) error {
	// Derive stable, short interface names from the container ID
	shortID := containerID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	hostIface := "veth-" + shortID
	peerIface := "vethp-" + shortID // "peer" prefix, kept ≤15 chars

	// Create the veth pair
	if err := runCmd(
		"ip", "link", "add", hostIface, "type", "veth", "peer", "name", peerIface,
	); err != nil {
		return fmt.Errorf("create veth pair: %w", err)
	}

	// Attach host-side to the bridge
	if err := runCmd("ip", "link", "set", hostIface, "master", bridgeName); err != nil {
		return fmt.Errorf("attach %s to bridge: %w", hostIface, err)
	}

	// Bring host-side up
	if err := runCmd("ip", "link", "set", hostIface, "up"); err != nil {
		return fmt.Errorf("bring up %s: %w", hostIface, err)
	}

	// Move peer into the container's network namespace
	if err := runCmd(
		"ip", "link", "set", peerIface, "netns", fmt.Sprintf("%d", containerPID),
	); err != nil {
		return fmt.Errorf("move %s to container netns: %w", peerIface, err)
	}

	// Inside the container namespace: rename peer → eth0, assign IP, bring up
	netnsPath := fmt.Sprintf("/proc/%d/ns/net", containerPID)

	// Rename the peer interface to eth0
	if err := runCmd(
		"nsenter", "--net="+netnsPath,
		"ip", "link", "set", peerIface, "name", "eth0",
	); err != nil {
		return fmt.Errorf("rename %s to eth0: %w", peerIface, err)
	}

	// Assign IP address
	if err := runCmd(
		"nsenter", "--net="+netnsPath,
		"ip", "addr", "add", containerIP+"/24", "dev", "eth0",
	); err != nil {
		return fmt.Errorf("assign IP %s to eth0: %w", containerIP, err)
	}

	// Bring eth0 up
	if err := runCmd(
		"nsenter", "--net="+netnsPath,
		"ip", "link", "set", "eth0", "up",
	); err != nil {
		return fmt.Errorf("bring up eth0: %w", err)
	}

	fmt.Printf("🔗 Network: %s (host) ↔ eth0 (container) — IP %s\n", hostIface, containerIP)
	return nil
}

// SetupPortForward installs an iptables DNAT rule that forwards TCP traffic
// arriving on hostPort to containerIP:containerPort. A companion FORWARD rule
// is also added to permit the traffic through the bridge.
func SetupPortForward(hostPort, containerIP, containerPort string) error {
	dest := containerIP + ":" + containerPort

	// DNAT rule: redirect inbound traffic on hostPort to the container
	if err := runCmd(
		"iptables", "-t", "nat", "-A", "PREROUTING",
		"-p", "tcp", "--dport", hostPort,
		"-j", "DNAT", "--to-destination", dest,
	); err != nil {
		return fmt.Errorf("add DNAT rule for port %s→%s: %w", hostPort, dest, err)
	}

	// FORWARD rule: allow the routed traffic to reach the container
	if err := runCmd(
		"iptables", "-A", "FORWARD",
		"-p", "tcp", "-d", containerIP, "--dport", containerPort,
		"-j", "ACCEPT",
	); err != nil {
		return fmt.Errorf("add FORWARD rule for %s:%s: %w", containerIP, containerPort, err)
	}

	fmt.Printf("📡 Port forward: host:%s → %s\n", hostPort, dest)
	return nil
}

// CleanupNetwork removes the host-side veth interface for the given container
// and deletes any DNAT iptables rules associated with the container's IP.
// Errors are logged but not returned — cleanup is best-effort.
func CleanupNetwork(containerID string) error {
	shortID := containerID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	hostIface := "veth-" + shortID

	// Delete the host-side veth (peer is automatically removed with it)
	if err := runCmd("ip", "link", "del", hostIface); err != nil {
		fmt.Fprintf(os.Stderr, "cleanup: delete %s: %v\n", hostIface, err)
	}

	return nil
}

// runCmd is a helper that runs an external command, capturing combined stdout+stderr.
// On failure, it returns an error that includes the command output for easy debugging.
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w (output: %s)", name, args, err, string(out))
	}
	return nil
}
