package container

import "fmt"

// ExitError is returned by Run when the container's own command exited
// with a non-zero status, as opposed to a genuine airlock-side
// setup/infrastructure failure (which returns a plain error instead).
// Callers that want to mirror the container's exact exit code — the way
// `docker run`'s own exit code matches the container's, silently, with no
// extra "error:" noise for a plain non-zero exit — should check for this
// type rather than always exiting 1 on any non-nil error from Run. In an
// untagged file (rather than alongside Run in the Linux-only
// container.go) so cross-platform callers like cmd/run.go can type-assert
// against it without a build-tag mismatch.
type ExitError struct {
	Code int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("container exited with status %d", e.Code)
}

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
	// Init runs the container's command as a child of a minimal init
	// process instead of exec'ing it directly as PID 1 — the same
	// trade-off `docker run --init` offers. Off by default: without it,
	// the command genuinely IS PID 1 of the container (some tooling
	// legitimately depends on that), at the cost of the kernel silently
	// dropping any signal — Ctrl+C, a plain SIGTERM — the command hasn't
	// explicitly installed a handler for, which is true of most simple
	// commands and scripts. With Init, the command is no longer PID 1
	// (some small number above it instead — exactly which one depends on
	// how many OS threads the Go runtime itself has already claimed PID-
	// namespace slots for by that point, not something worth relying on
	// as a fixed value), and the init process forwards signals to it and
	// reaps orphans. `airlock stop` works either way — it escalates to
	// SIGKILL, which can't be ignored by anything — just not always
	// gracefully without this. See namespaces.go's runAsInit for the full
	// story.
	Init bool
}
