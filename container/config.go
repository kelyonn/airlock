package container

// Config holds the configuration for a new container.
// This is in a separate file without build tags so it's available on all platforms.
type Config struct {
	Command     string
	Args        []string
	Hostname    string
	MemoryLimit string
	CPULimit    int
	Verbose     bool
}
