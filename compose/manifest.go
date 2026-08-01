package compose

import (
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/kelyonn/airlock/internal/shellwords"
)

// Manifest represents the parsed airlock-compose.yml file.
type Manifest struct {
	Version  string                `yaml:"version"`
	Services map[string]ServiceDef `yaml:"services"`
}

// ServiceDef defines a single container in the compose manifest.
type ServiceDef struct {
	Image       string        `yaml:"image"`
	Command     StringOrSlice `yaml:"command"`
	Ports       []string      `yaml:"ports"`
	Volumes     []string      `yaml:"volumes"`
	Memory      string        `yaml:"memory"`
	CPU         int           `yaml:"cpu"`
	DependsOn   []string      `yaml:"depends_on"`
	Environment []string      `yaml:"environment"`
	WorkingDir  string        `yaml:"working_dir"`
	User        string        `yaml:"user"`
}

// StringOrSlice supports a compose "command" field written either as a
// single shell-like string:
//
//	command: nginx -g "daemon off;"
//
// or as an explicit argv array:
//
//	command: ["nginx", "-g", "daemon off;"]
//
// The string form used to be split with strings.Fields, which has no
// concept of quoting — `nginx -g "daemon off;"` (the exact example in this
// project's own README) came out as ["nginx", "-g", `"daemon`, `off;"`],
// four broken arguments instead of three correct ones. The array form is
// the only way to express an argument containing a space without this kind
// of ambiguity; the string form now goes through internal/shellwords so
// quoted arguments survive intact either way.
type StringOrSlice []string

// UnmarshalYAML implements yaml.Unmarshaler for StringOrSlice.
func (s *StringOrSlice) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		var str string
		if err := value.Decode(&str); err != nil {
			return err
		}
		parts, err := shellwords.Split(str)
		if err != nil {
			return fmt.Errorf("command: %w", err)
		}
		*s = parts
		return nil
	case yaml.SequenceNode:
		var parts []string
		if err := value.Decode(&parts); err != nil {
			return err
		}
		*s = parts
		return nil
	default:
		return fmt.Errorf("command: expected a string or a list of strings")
	}
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

// TopoSort returns the service names in topological order (dependencies
// first). Services with no dependency relationship to each other are
// ordered alphabetically, so the same manifest always produces the same
// startup order — Go's map iteration is randomized per-run, and without
// sorting the visit order here, two runs of the same stack could start
// independent services in a different sequence each time.
func TopoSort(services map[string]ServiceDef) []string {
	var order []string
	visited := make(map[string]bool)

	names := make([]string, 0, len(services))
	for name := range services {
		names = append(names, name)
	}
	sort.Strings(names)

	var visit func(node string)
	visit = func(node string) {
		if visited[node] {
			return
		}
		visited[node] = true
		deps := append([]string(nil), services[node].DependsOn...)
		sort.Strings(deps)
		for _, dep := range deps {
			visit(dep)
		}
		order = append(order, node)
	}

	for _, name := range names {
		visit(name)
	}
	return order
}
