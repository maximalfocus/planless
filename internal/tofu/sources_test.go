package tofu

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The checked-in configuration must keep every security-relevant value out of
// its resource blocks. If this test fails, the demonstration's sharpest lesson
// has quietly stopped being true.
func TestCheckedInConfigurationKeepsValuesOutOfResourceBlocks(t *testing.T) {
	findings, err := CheckSources("../../infra")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("configuration source layout is wrong: %+v", findings)
	}
}

// The values must exist somewhere, or the configuration would not describe the
// intended posture at all: they live in the variable file and in module
// defaults.
func TestSecurityRelevantValuesLiveOutsideResourceBlocks(t *testing.T) {
	var found int
	err := filepath.WalkDir("../../infra", func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, v := range SecurityRelevantValues {
			if strings.Contains(string(body), v) {
				found++
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found < len(SecurityRelevantValues) {
		t.Fatalf("expected every security-relevant value to appear in the configuration somewhere, saw %d", found)
	}
}

func TestResourceBlockBodies(t *testing.T) {
	src := `
resource "democloud_grant" "a" {
  id            = "grant-a"
  principals    = var.readers
  nested {
    value = "x"
  }
}

variable "readers" {
  default = ["finance-reporting"]
}
`
	bodies := ResourceBlockBodies(src)
	if len(bodies) != 1 {
		t.Fatalf("expected one resource block, got %d", len(bodies))
	}
	if !strings.Contains(bodies[0], "grant-a") || !strings.Contains(bodies[0], `value = "x"`) {
		t.Fatalf("resource body did not span its nested block: %q", bodies[0])
	}
	if strings.Contains(bodies[0], "finance-reporting") {
		t.Fatal("the variable default leaked into the resource block body")
	}
}

func TestCheckSourcesCatchesLeaksAndExecution(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("leak.tf", "resource \"democloud_grant\" \"a\" {\n  principals = [\"*\"]\n}\n")
	write("exec.tf", "resource \"democloud_bucket\" \"b\" {\n  provisioner \"local-exec\" {\n    command = \"id\"\n  }\n}\n")
	findings, err := CheckSources(dir)
	if err != nil {
		t.Fatal(err)
	}
	rules := map[string]bool{}
	for _, f := range findings {
		rules[f.Rule] = true
	}
	if !rules["security_relevant_value_in_resource_block"] {
		t.Fatalf("expected the leaked value to be caught, got %+v", findings)
	}
	if !rules["no_execution_path"] {
		t.Fatalf("expected the execution path to be caught, got %+v", findings)
	}
}

func TestCheckSourcesFailsClosedOnAnEmptyTree(t *testing.T) {
	if _, err := CheckSources(t.TempDir()); err == nil {
		t.Fatal("expected an empty configuration tree to be an error")
	}
}

func TestCanonicalPlanDropsTheProductionTimestamp(t *testing.T) {
	raw := []byte(`{"format_version":"1.2","timestamp":"2026-08-18T00:00:00Z","resource_changes":[]}`)
	other := []byte(`{"format_version":"1.2","timestamp":"2027-01-01T00:00:00Z","resource_changes":[]}`)
	a, err := CanonicalPlan(raw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CanonicalPlan(other)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("the same desired state produced two artifacts:\n%s\n%s", a, b)
	}
	var tree map[string]any
	if err := json.Unmarshal(a, &tree); err != nil {
		t.Fatal(err)
	}
	if _, ok := tree["timestamp"]; ok {
		t.Fatal("the production timestamp survived canonicalization")
	}
	if _, err := CanonicalPlan([]byte("{not json")); err == nil {
		t.Fatal("expected an unparsable plan artifact to be an error")
	}
}

func TestValuesMissingFromPlan(t *testing.T) {
	if missing := ValuesMissingFromPlan([]byte(`{}`)); len(missing) != len(SecurityRelevantValues) {
		t.Fatalf("expected every value to be reported missing, got %v", missing)
	}
	full := strings.Join(SecurityRelevantValues, " ")
	if missing := ValuesMissingFromPlan([]byte(full)); len(missing) != 0 {
		t.Fatalf("expected no value to be reported missing, got %v", missing)
	}
}

// The provider must contain no execution, no environment lookup, and no
// redirectable endpoint.
func TestProviderHasNoExecutionOrEnvironmentPath(t *testing.T) {
	forbidden := []string{`"os/exec"`, "os.Getenv", "exec.Command", `"net"`, "Setenv"}
	var checked int
	err := filepath.WalkDir("../../provider", func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".go" {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		checked++
		for _, f := range forbidden {
			if strings.Contains(string(body), f) {
				t.Fatalf("%s contains %s", path, f)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no provider sources were checked")
	}
}
