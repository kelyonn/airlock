package container

// VolumeMount represents a bind-mount from a host path into the container.
// Both paths must be absolute. ReadOnly enforces MS_RDONLY on the mount.
// This is in a file without build tags so it's available on all platforms
// (needed for CLI flag parsing on the host side).
type VolumeMount struct {
	HostPath      string // absolute path on the host
	ContainerPath string // absolute path inside the container
	ReadOnly      bool   // mount as read-only
}

// Config holds the configuration for a new container.
// This is in a separate file without build tags so it's available on all platforms.
type Config struct {
	Command     string
	Args        []string
	Hostname    string
	MemoryLimit string
	CPULimit    int
	Verbose     bool
	Volumes     []VolumeMount // bind-mounts to set up inside the container
	NoSeccomp   bool          // if true, skip seccomp filter (for debugging)
}
