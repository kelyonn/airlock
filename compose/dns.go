package compose

import (
	"fmt"
	"os"
	"path/filepath"
)

// InjectHostsFile writes an /etc/hosts file into the container's rootfs.
// It maps the container's own IP to localhost and maps all other service names
// to their allocated IPs, allowing containers to resolve each other by name.
func InjectHostsFile(rootfsDir string, serviceIPs map[string]string, myServiceName, myIP string) error {
	hostsPath := filepath.Join(rootfsDir, "etc", "hosts")

	// Ensure /etc exists
	if err := os.MkdirAll(filepath.Dir(hostsPath), 0755); err != nil {
		return fmt.Errorf("create /etc: %w", err)
	}

	content := "127.0.0.1 localhost\n"
	if myIP != "" && myServiceName != "" {
		content += fmt.Sprintf("%s %s\n", myIP, myServiceName)
	}

	for name, ip := range serviceIPs {
		if name != myServiceName {
			content += fmt.Sprintf("%s %s\n", ip, name)
		}
	}

	if err := os.WriteFile(hostsPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write hosts file: %w", err)
	}

	return nil
}
