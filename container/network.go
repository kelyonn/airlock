//go:build linux

package container

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/kelyonn/airlock/internal/filelock"
	"github.com/kelyonn/airlock/state"
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
//
// This package used to shell out to the `ip`, `iptables`, `sysctl`, and
// `nsenter` binaries for every one of these operations — a silent
// dependency on all four existing in $PATH (true in the dev Docker image,
// not guaranteed on every host), nothing but a process exit code to tell
// success from failure, and a fork+exec per call. The `ip`- and
// `nsenter`-shaped calls (link/bridge/veth/address/route setup, all of
// SetupBridge below except the iptables rules, plus all of CreateVethPair)
// are now netlink: a direct AF_NETLINK socket to the kernel, no
// subprocess, no PATH dependency, typed Go errors instead of stderr text.
// The iptables-shaped calls (MASQUERADE/FORWARD/DNAT below and in
// SetupPortForward) go through github.com/coreos/go-iptables instead —
// worth being precise about what that buys: go-iptables is a thin,
// well-tested wrapper that still shells out to the `iptables` binary
// itself (there's no mature, widely-adopted pure-Go netfilter/iptables
// implementation as of this writing; google/nftables exists but targets
// the newer nftables framework, a bigger swap than this warranted). So
// this still depends on `iptables` being present — but it's down from
// four external binaries to one, with idempotency (AppendUnique) and
// error handling actually built into the library instead of hand-rolled
// `-C` check-then-`-A` add dances.
func SetupBridge() error {
	link, err := netlink.LinkByName(bridgeName)
	if err != nil {
		// Bridge doesn't exist yet — create it. (netlink.LinkByName returns
		// an error for "not found" the same way exec would return a
		// non-zero exit code for `ip link show` on a missing interface.)
		br := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: bridgeName}}
		if err := netlink.LinkAdd(br); err != nil {
			return fmt.Errorf("create bridge %s: %w", bridgeName, err)
		}
		if Verbose {
			fmt.Printf("🌉 Created bridge %s\n", bridgeName)
		}
		link, err = netlink.LinkByName(bridgeName)
		if err != nil {
			return fmt.Errorf("look up newly created bridge %s: %w", bridgeName, err)
		}
	}

	// Assign the bridge's own address. Ignore errors here (same as the old
	// code's ignored `ip addr add` exit code) — the common failure is
	// "already assigned", which is fine.
	if addr, err := netlink.ParseAddr(bridgeCIDR); err == nil {
		_ = netlink.AddrAdd(link, addr)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring up bridge %s: %w", bridgeName, err)
	}

	// Enable IPv4 forwarding by writing the sysctl's /proc file directly —
	// this *is* what the external `sysctl` binary does under the hood, so
	// there's no behavior difference, just no subprocess.
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644); err != nil {
		return fmt.Errorf("enable ip_forward: %w", err)
	}

	// route_localnet: without it, SetupPortForward's OUTPUT-chain DNAT rule
	// rewrites a locally-generated packet's destination from
	// 127.0.0.1:hostPort to the container's real bridge address, but the
	// kernel still drops it afterward — routing a loopback-SOURCED packet
	// out any real interface is normally refused outright as a martian
	// packet, regardless of what DNAT already rewrote the destination to.
	// This is the same sysctl Docker's own bridge driver sets, for the same
	// reason: it's what makes `curl localhost:PORT` reach a published
	// container port work at all, rather than only working for connections
	// that actually arrive from a real network interface.
	//
	// Writing "all" alone isn't enough, confirmed by hand: it only seeds
	// the DEFAULT applied to interfaces created AFTER the write, not a live
	// OR/AND against ones that already exist — "lo" (this packet's
	// originating interface) stayed 0 even with "all" at 1, and the
	// connection kept failing. The interfaces that are actually consulted
	// are "lo" (loopback-sourced packets are evaluated against it) and this
	// bridge (the post-DNAT route lookup for the container's address
	// resolves to going out here) — both are set explicitly rather than
	// relying on "all" to cover them.
	for _, iface := range []string{"all", "lo", bridgeName} {
		path := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/route_localnet", iface)
		if err := os.WriteFile(path, []byte("1\n"), 0644); err != nil {
			return fmt.Errorf("enable route_localnet on %s: %w", iface, err)
		}
	}

	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("init iptables: %w", err)
	}

	// AppendUnique checks for an existing identical rule before adding —
	// the netlink/go-iptables equivalent of the old code's manual
	// "iptables -C ... || iptables -A ..." idempotency dance.
	if err := ipt.AppendUnique("nat", "POSTROUTING",
		"-s", networkSubnet, "!", "-o", bridgeName, "-j", "MASQUERADE"); err != nil {
		return fmt.Errorf("add MASQUERADE rule: %w", err)
	}
	if err := ipt.AppendUnique("filter", "FORWARD", "-i", bridgeName, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("add FORWARD (in) rule: %w", err)
	}
	if err := ipt.AppendUnique("filter", "FORWARD", "-o", bridgeName, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("add FORWARD (out) rule: %w", err)
	}

	return nil
}

// minHostOctet / maxHostOctet bound the allocatable range within the
// 10.0.42.0/24 subnet: .0 is the network address, .1 is the bridge
// (gateway), and .254/.255 are left free (broadcast + headroom).
const (
	minHostOctet = 2
	maxHostOctet = 253
)

// AllocateIP hands out an unused IP in the 10.0.42.0/24 subnet.
//
// The whole read-check-write sequence runs under an exclusive flock (via
// internal/filelock, the same mechanism state.go uses) so two airlock
// processes starting containers at the same moment — e.g. a compose stack
// launching several services back to back — can't both read the same
// next_ip counter and hand out the same address.
//
// Beyond just locking, allocation is cross-checked against state.List(),
// the set of currently-live containers and the IPs they actually hold.
// The previous version trusted a bare incrementing counter that wrapped at
// 253 back to 2 with no awareness of what was still in use — long-running
// stacks would eventually wrap the counter onto an IP a live container
// still held. Skipping any octet currently assigned to a live container
// closes that hole; the persisted counter is now only a hint for where to
// start looking, not a source of truth.
func AllocateIP() (string, error) {
	path, err := networkStatePath()
	if err != nil {
		return "", fmt.Errorf("network state path: %w", err)
	}

	var allocated string
	err = filelock.WithLock(path, func() error {
		inUse, err := inUseHostOctets()
		if err != nil {
			return fmt.Errorf("determine in-use IPs: %w", err)
		}

		var ns networkState
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("read network state: %w", err)
			}
			ns.NextIP = minHostOctet
		} else if err := json.Unmarshal(data, &ns); err != nil {
			return fmt.Errorf("parse network state: %w", err)
		}
		if ns.NextIP < minHostOctet || ns.NextIP > maxHostOctet {
			ns.NextIP = minHostOctet
		}

		// Walk forward from the hinted starting point looking for the first
		// octet nothing is currently using, wrapping once around the range.
		candidate := ns.NextIP
		start := candidate
		for inUse[candidate] {
			candidate++
			if candidate > maxHostOctet {
				candidate = minHostOctet
			}
			if candidate == start {
				return fmt.Errorf("no free IPs left in 10.0.42.0/24 (subnet exhausted)")
			}
		}

		// Persist the next hint one past what we just handed out.
		ns.NextIP = candidate + 1
		if ns.NextIP > maxHostOctet {
			ns.NextIP = minHostOctet
		}

		out, err := json.Marshal(ns)
		if err != nil {
			return fmt.Errorf("marshal network state: %w", err)
		}
		if err := os.WriteFile(path, out, 0644); err != nil {
			return fmt.Errorf("write network state: %w", err)
		}

		allocated = fmt.Sprintf("10.0.42.%d", candidate)
		return nil
	})
	if err != nil {
		return "", err
	}
	return allocated, nil
}

// inUseHostOctets returns the set of host octets (the "N" in 10.0.42.N)
// currently held by live containers, per state.List().
func inUseHostOctets() (map[int]bool, error) {
	containers, err := state.List()
	if err != nil {
		return nil, err
	}
	inUse := make(map[int]bool, len(containers))
	for _, c := range containers {
		if c.IPAddress == "" {
			continue
		}
		idx := strings.LastIndex(c.IPAddress, ".")
		if idx == -1 {
			continue
		}
		octet, err := strconv.Atoi(c.IPAddress[idx+1:])
		if err != nil {
			continue
		}
		inUse[octet] = true
	}
	return inUse, nil
}

// vethInterfaceNames derives the stable, ≤15-char host/peer interface names
// used for a container's veth pair from its container ID.
func vethInterfaceNames(containerID string) (hostIface, peerIface string) {
	shortID := containerID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	return "veth-" + shortID, "vethp-" + shortID
}

// CreateVethPair creates a veth pair for the container identified by
// containerID, attaches the host-side interface to the airlock0 bridge,
// moves the peer end into the container's network namespace (identified by
// containerPID), and configures it there — renamed to eth0, given
// containerIP/24, brought up, with loopback up and a default route via the
// bridge — entirely over netlink, without ever leaving this process.
//
// The previous version used `nsenter --net=/proc/<pid>/ns/net -- ip ...`
// for every one of those in-container steps: three subprocess spawns, each
// depending on the container's OWN image having a working `nsenter`-callable
// `ip` (or falling back to busybox `ifconfig`) binary on the HOST side of
// that nsenter call — nsenter itself runs from the host's PATH, but see
// below for the flip side. netlink.NewHandleAt opens a netlink socket
// bound to the target namespace directly (via its /proc/<pid>/ns/net file
// descriptor) and every call after that operates inside it, with no
// subprocess and no dependency on any binary existing anywhere.
//
// This also removes the eth0 setup race that used to live in
// namespaces.go's configureContainerNetwork: previously, the parent
// injected eth0 via nsenter *after* cmd.Start(), while the child
// concurrently tried to bring up an eth0 that might not have arrived yet —
// hence a 10-iteration retry loop there. Configuring eth0 fully here,
// synchronously as part of CreateVethPair, means the interface is already
// up with its address and route by the time this function returns, so the
// child no longer needs to poll for it at all.
func CreateVethPair(containerPID int, containerIP, containerID string) error {
	hostIface, peerIface := vethInterfaceNames(containerID)

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: hostIface},
		PeerName:  peerIface,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("create veth pair: %w", err)
	}

	hostLink, err := netlink.LinkByName(hostIface)
	if err != nil {
		return fmt.Errorf("look up host veth %s: %w", hostIface, err)
	}
	bridgeLink, err := netlink.LinkByName(bridgeName)
	if err != nil {
		return fmt.Errorf("look up bridge %s: %w", bridgeName, err)
	}
	if err := netlink.LinkSetMaster(hostLink, bridgeLink); err != nil {
		return fmt.Errorf("attach %s to bridge: %w", hostIface, err)
	}
	if err := netlink.LinkSetUp(hostLink); err != nil {
		return fmt.Errorf("bring up %s: %w", hostIface, err)
	}

	peerLink, err := netlink.LinkByName(peerIface)
	if err != nil {
		return fmt.Errorf("look up peer veth %s: %w", peerIface, err)
	}
	if err := netlink.LinkSetNsPid(peerLink, containerPID); err != nil {
		return fmt.Errorf("move %s to container netns: %w", peerIface, err)
	}

	nsHandle, err := netns.GetFromPath(fmt.Sprintf("/proc/%d/ns/net", containerPID))
	if err != nil {
		return fmt.Errorf("open container netns: %w", err)
	}
	defer nsHandle.Close()

	nsLink, err := netlink.NewHandleAt(nsHandle)
	if err != nil {
		return fmt.Errorf("open netlink handle in container netns: %w", err)
	}
	defer nsLink.Close()

	// peerLink was looked up in OUR namespace before the move; look it up
	// again through the namespace-scoped handle to get a Link value valid
	// for operations inside the container's netns.
	containerPeer, err := nsLink.LinkByName(peerIface)
	if err != nil {
		return fmt.Errorf("look up %s inside container netns: %w", peerIface, err)
	}
	if err := nsLink.LinkSetName(containerPeer, "eth0"); err != nil {
		return fmt.Errorf("rename %s to eth0: %w", peerIface, err)
	}
	// LinkSetName doesn't mutate containerPeer in place; re-fetch by the
	// new name for the calls that follow.
	eth0, err := nsLink.LinkByName("eth0")
	if err != nil {
		return fmt.Errorf("look up eth0 in container netns: %w", err)
	}

	addr, err := netlink.ParseAddr(containerIP + "/24")
	if err != nil {
		return fmt.Errorf("parse container IP %s: %w", containerIP, err)
	}
	if err := nsLink.AddrAdd(eth0, addr); err != nil {
		return fmt.Errorf("assign IP %s to eth0: %w", containerIP, err)
	}
	if err := nsLink.LinkSetUp(eth0); err != nil {
		return fmt.Errorf("bring up eth0: %w", err)
	}

	// Loopback, brought up the same way — previously the very first `ip`/
	// `ifconfig` call the container's own init made for itself.
	if lo, err := nsLink.LinkByName("lo"); err == nil {
		_ = nsLink.LinkSetUp(lo)
	}

	// Default route via the bridge.
	route := &netlink.Route{LinkIndex: eth0.Attrs().Index, Gw: net.ParseIP(gateway)}
	if err := nsLink.RouteAdd(route); err != nil {
		fmt.Fprintf(os.Stderr, "warning: add default route failed: %v\n", err)
	}

	if Verbose {
		fmt.Printf("🔗 Network: %s (host) ↔ eth0 (container) — IP %s\n", hostIface, containerIP)
	}
	return nil
}

// SetupPortForward installs an iptables DNAT rule that forwards TCP traffic
// arriving on hostPort to containerIP:containerPort. A companion FORWARD rule
// is also added to permit the traffic through the bridge.
func SetupPortForward(hostPort, containerIP, containerPort string) error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("init iptables: %w", err)
	}

	dest := containerIP + ":" + containerPort
	if err := ipt.AppendUnique("nat", "PREROUTING",
		"-p", "tcp", "--dport", hostPort, "-j", "DNAT", "--to-destination", dest); err != nil {
		return fmt.Errorf("add DNAT rule for port %s→%s: %w", hostPort, dest, err)
	}
	// PREROUTING alone only catches packets ARRIVING on a real interface —
	// it's the wrong chain for `curl localhost:hostPort` run on the same
	// host airlock itself is running on, since a locally-generated packet
	// never passes through PREROUTING at all; it originates already past
	// that point, in OUTPUT. Without this, the single most obvious way
	// anyone would try a freshly published port — from the very machine
	// that published it — silently fails to connect, while the exact same
	// port forward works fine from any other machine. Needs
	// route_localnet enabled (see SetupBridge) for the loopback-sourced
	// case specifically, or the kernel drops the packet after DNAT
	// rewrites it anyway.
	if err := ipt.AppendUnique("nat", "OUTPUT",
		"-p", "tcp", "--dport", hostPort, "-j", "DNAT", "--to-destination", dest); err != nil {
		return fmt.Errorf("add OUTPUT DNAT rule for port %s→%s: %w", hostPort, dest, err)
	}
	if err := ipt.AppendUnique("filter", "FORWARD",
		"-p", "tcp", "-d", containerIP, "--dport", containerPort, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("add FORWARD rule for %s:%s: %w", containerIP, containerPort, err)
	}

	if Verbose {
		fmt.Printf("📡 Port forward: host:%s → %s\n", hostPort, dest)
	}
	return nil
}

// CleanupNetwork removes the host-side veth interface for the given
// container. Errors are logged but not returned — cleanup is best-effort,
// and a link that's already gone (the kernel auto-removes a veth pair's
// host side once its peer's namespace is torn down) isn't an error at all.
func CleanupNetwork(containerID string) error {
	hostIface, _ := vethInterfaceNames(containerID)

	link, err := netlink.LinkByName(hostIface)
	if err != nil {
		return nil // already gone — nothing to clean up
	}
	if err := netlink.LinkDel(link); err != nil {
		fmt.Fprintf(os.Stderr, "cleanup: delete %s: %v\n", hostIface, err)
	}
	return nil
}
