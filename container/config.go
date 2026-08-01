package container

// Verbose controls whether low-level container setup narration (namespace
// setup, bridge/veth/port-forward wiring, seccomp filter installation) gets
// printed. It's a package-level flag rather than a parameter threaded
// through every setup function because several of those (SetupBridge,
// CreateVethPair) are called both from Run (which has a Config in scope)
// and directly by the compose orchestrator ahead of any single container's
// Config existing. Run and Child each set it from their own source of
// truth (Config.Verbose, and the re-exec'd "child" process's verbose arg,
// respectively) before doing any setup work.
var Verbose bool

// VolumeMount represents a bind-mount from a host path into the container.
// Both paths must be absolute. ReadOnly enforces MS_RDONLY on the mount.
// This is in a file without build tags so it's available on all platforms
// (needed for CLI flag parsing on the host side).
type VolumeMount struct {
	HostPath      string // absolute path on the host
	ContainerPath string // absolute path inside the container
	ReadOnly      bool   // mount as read-only
}

// PortForward maps a host TCP port to a container port via iptables DNAT.
// It is used to expose container services on the host network.
type PortForward struct {
	HostPort      string // host-side TCP port, e.g. "8080"
	ContainerPort string // container-side TCP port, e.g. "80"
}

// Config holds the configuration for a new container.
// This is in a separate file without build tags so it's available on all platforms.
type Config struct {
	Command      string
	Args         []string
	Hostname     string
	MemoryLimit  string
	CPULimit     int
	Verbose      bool
	Volumes      []VolumeMount // bind-mounts to set up inside the container
	NoSeccomp    bool          // if true, skip seccomp filter (for debugging)
	// Image is the OCI image reference (e.g. "alpine:3.20"). If empty, uses the default Alpine rootfs.
	Image        string
	NoNetwork    bool          // if true, skip network namespace and networking setup
	PortForwards []PortForward // host-to-container port forwards via iptables DNAT
}
