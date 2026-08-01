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
	Env          []string      // extra "KEY=VALUE" environment variables for the container process
	// ContainerIP, when set, pins the container to this address instead of
	// letting Run allocate a fresh one from AllocateIP(). Compose relies on
	// this: the orchestrator allocates every service's IP up front so it can
	// write a consistent /etc/hosts before any container starts, and without
	// a way to hand that exact IP to Run, Run would allocate a second,
	// different IP internally — leaving every service's /etc/hosts pointing
	// at addresses no container actually holds, silently breaking
	// service-name DNS resolution between containers in the same stack.
	ContainerIP string
	// ServiceName and ComposeFile identify this container as belonging to a
	// compose stack (see the compose package). Both are empty for a plain
	// `airlock run`. Passing them through Config — rather than registering
	// under blank values and patching the state entry afterward — is what
	// lets state.Register tag the container correctly the first time.
	ServiceName string
	ComposeFile string
	// WorkingDir sets the container process's working directory. If empty,
	// Run fills it in from the image's own WorkingDir (when an image is
	// used), falling back to "/" if the image doesn't specify one either.
	WorkingDir string
	// User selects which user (and optionally group) the container process
	// runs as, in "uid", "uid:gid", "name", or "name:group" form — the same
	// forms Docker's own USER accepts. If empty, Run fills it in from the
	// image's own USER (when an image is used); if that's also empty, the
	// container runs as root, unchanged from airlock's original behavior.
	User string
	// UserNS enables a Linux user namespace (CLONE_NEWUSER): container UID 0
	// is mapped to an unprivileged host UID (see container/container.go's
	// userNSHostIDOffset), so a process that's root *inside* the container
	// is not real root on the host — it cannot touch host files it doesn't
	// already have permission for, signal host processes, etc. Off by
	// default: see the README's "Security model & limitations" section for
	// why (interacts with device-node creation and cgroup delegation).
	UserNS bool
}
