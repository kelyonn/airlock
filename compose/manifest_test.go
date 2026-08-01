package compose

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func svc(dependsOn ...string) ServiceDef {
	return ServiceDef{DependsOn: dependsOn}
}

func TestTopoSort_RespectsDependencies(t *testing.T) {
	services := map[string]ServiceDef{
		"web":      svc("api"),
		"api":      svc("database", "cache"),
		"database": svc(),
		"cache":    svc(),
	}

	order := TopoSort(services)

	pos := make(map[string]int, len(order))
	for i, name := range order {
		pos[name] = i
	}

	if pos["database"] > pos["api"] {
		t.Errorf("database (pos %d) must come before api (pos %d)", pos["database"], pos["api"])
	}
	if pos["cache"] > pos["api"] {
		t.Errorf("cache (pos %d) must come before api (pos %d)", pos["cache"], pos["api"])
	}
	if pos["api"] > pos["web"] {
		t.Errorf("api (pos %d) must come before web (pos %d)", pos["api"], pos["web"])
	}
	if len(order) != 4 {
		t.Fatalf("expected 4 services in order, got %d: %v", len(order), order)
	}
}

func TestTopoSort_Deterministic(t *testing.T) {
	services := map[string]ServiceDef{
		"zeta":  svc(),
		"alpha": svc(),
		"mid":   svc(),
		"beta":  svc(),
	}

	first := TopoSort(services)
	for i := 0; i < 20; i++ {
		got := TopoSort(services)
		if !reflect.DeepEqual(first, got) {
			t.Fatalf("TopoSort not deterministic across runs: %v vs %v", first, got)
		}
	}

	// With no dependency edges at all, independent services should come out
	// alphabetically — this is what makes the result deterministic instead
	// of following Go's randomized map iteration order.
	want := []string{"alpha", "beta", "mid", "zeta"}
	if !reflect.DeepEqual(first, want) {
		t.Errorf("TopoSort() = %v, want %v", first, want)
	}
}

func TestValidateDAG_DetectsCycle(t *testing.T) {
	services := map[string]ServiceDef{
		"a": svc("b"),
		"b": svc("c"),
		"c": svc("a"),
	}

	err := validateDAG(services)
	if err == nil {
		t.Fatal("expected a cycle to be detected, got nil error")
	}
}

func TestValidateDAG_AcceptsDAG(t *testing.T) {
	services := map[string]ServiceDef{
		"a": svc("b"),
		"b": svc("c"),
		"c": svc(),
	}

	if err := validateDAG(services); err != nil {
		t.Fatalf("expected no error for a valid DAG, got %v", err)
	}
}

func TestParseManifest_RejectsUnknownDependency(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/compose.yml"
	content := `
version: "1.0"
services:
  web:
    image: nginx:alpine
    command: nginx
    depends_on:
      - ghost
`
	writeFile(t, path, content)

	_, err := ParseManifest(path)
	if err == nil {
		t.Fatal("expected an error for a dependency on an undefined service, got nil")
	}
	if !strings.Contains(err.Error(), "ghost") {
		t.Errorf("expected error to mention the unknown service %q, got: %v", "ghost", err)
	}
}

func TestStringOrSlice_ScalarUsesShellwords(t *testing.T) {
	var s StringOrSlice
	err := yaml.Unmarshal([]byte(`nginx -g "daemon off;"`), &s)
	if err != nil {
		t.Fatalf("unmarshal scalar command: %v", err)
	}
	want := StringOrSlice{"nginx", "-g", "daemon off;"}
	if !reflect.DeepEqual(s, want) {
		t.Errorf("StringOrSlice = %v, want %v", s, want)
	}
}

func TestStringOrSlice_SequenceIsUsedVerbatim(t *testing.T) {
	var s StringOrSlice
	err := yaml.Unmarshal([]byte(`["nginx", "-g", "daemon off;"]`), &s)
	if err != nil {
		t.Fatalf("unmarshal sequence command: %v", err)
	}
	want := StringOrSlice{"nginx", "-g", "daemon off;"}
	if !reflect.DeepEqual(s, want) {
		t.Errorf("StringOrSlice = %v, want %v", s, want)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write test fixture %s: %v", path, err)
	}
}
