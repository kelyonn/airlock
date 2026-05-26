// No build tag — ParseVolumeSpec is pure string parsing used by the CLI on all platforms.

package container

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ParseVolumeSpec parses a volume specification string in the format:
//
//	host_path:container_path[:ro]
//
// Both paths must be absolute. The optional ":ro" suffix makes the mount read-only.
// Example: "/tmp/data:/data:ro"
func ParseVolumeSpec(spec string) (VolumeMount, error) {
	parts := strings.Split(spec, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return VolumeMount{}, fmt.Errorf("invalid volume spec %q: expected host:container[:ro]", spec)
	}

	vol := VolumeMount{
		HostPath:      parts[0],
		ContainerPath: parts[1],
	}

	if len(parts) == 3 {
		if parts[2] == "ro" {
			vol.ReadOnly = true
		} else {
			return VolumeMount{}, fmt.Errorf("invalid volume option %q: only 'ro' is supported", parts[2])
		}
	}

	if vol.HostPath == "" || vol.ContainerPath == "" {
		return VolumeMount{}, fmt.Errorf("invalid volume spec %q: paths cannot be empty", spec)
	}

	if !filepath.IsAbs(vol.HostPath) {
		return VolumeMount{}, fmt.Errorf("host path must be absolute, got: %s", vol.HostPath)
	}

	if !filepath.IsAbs(vol.ContainerPath) {
		return VolumeMount{}, fmt.Errorf("container path must be absolute, got: %s", vol.ContainerPath)
	}

	return vol, nil
}
