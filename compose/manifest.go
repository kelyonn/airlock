package compose

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Manifest represents the parsed airlock-compose.yml file.
type Manifest struct {
	Version  string                `yaml:"version"`
	Services map[string]ServiceDef `yaml:"services"`
}

// ServiceDef defines a single container in the compose manifest.
type ServiceDef struct {
	Image       string   `yaml:"image"`
	Command     string   `yaml:"command"`
	Ports       []string `yaml:"ports"`
	Volumes     []string `yaml:"volumes"`
	Memory      string   `yaml:"memory"`
	CPU         int      `yaml:"cpu"`
	DependsOn   []string `yaml:"depends_on"`
	Environment []string `yaml:"environment"`
}

// ParseManifest reads and parses the compose YAML file.
// It validates that the dependency graph is a DAG (no cycles).
func ParseManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest: %w", err)
	}

	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("parse manifest: %w", err)
	}

	// Validate dependencies
	for name, svc := range m.Services {
		for _, dep := range svc.DependsOn {
			if _, ok := m.Services[dep]; !ok {
				return Manifest{}, fmt.Errorf("service %q depends on unknown service %q", name, dep)
			}
		}
	}

	if err := validateDAG(m.Services); err != nil {
		return Manifest{}, fmt.Errorf("invalid dependency graph: %w", err)
	}

	return m, nil
}

// validateDAG checks for cyclic dependencies using depth-first search.
func validateDAG(services map[string]ServiceDef) error {
	visited := make(map[string]bool)
	visiting := make(map[string]bool)

	var visit func(node string) error
	visit = func(node string) error {
		if visiting[node] {
			return fmt.Errorf("cycle detected involving %q", node)
		}
		if visited[node] {
			return nil
		}
		visiting[node] = true
		for _, dep := range services[node].DependsOn {
			if err := visit(dep); err != nil {
				return err
			}
		}
		visiting[node] = false
		visited[node] = true
		return nil
	}

	for name := range services {
		if !visited[name] {
			if err := visit(name); err != nil {
				return err
			}
		}
	}

	return nil
}

// TopoSort returns the service names in topological order (dependencies first).
func TopoSort(services map[string]ServiceDef) []string {
	var order []string
	visited := make(map[string]bool)

	var visit func(node string)
	visit = func(node string) {
		if visited[node] {
			return
		}
		visited[node] = true
		for _, dep := range services[node].DependsOn {
			visit(dep)
		}
		order = append(order, node)
	}

	// Sort keys alphabetically for deterministic output
	// (Go maps iteration is randomized)
	// We do a simple insertion sort for keys here to avoid bringing in "sort"
	// just for this, but since we can't import it easily without changing standard libs, let's just use it.
	// Actually, let's just iterate normally; map randomization might mean different startup orders
	// for independent services, which is fine and typical for docker-compose.
	for name := range services {
		visit(name)
	}
	return order
}
