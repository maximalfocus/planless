package controls

import (
	"os"
	"path/filepath"
	"testing"
)

// This is why A06:2021 and CWE-1104 are not claimed: no component version,
// patch level or advisory identifier is a variable anywhere.
func TestNoComponentVersionIsAVariable(t *testing.T) {
	findings, err := NoComponentVersionIsAVariable("../../infra", "../../manifests")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("a component version is a variable: %+v", findings)
	}
}

// The check has to be able to find one, or its silence means nothing.
func TestTheVersionControlWouldNoticeOne(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "vars.tf", "variable \"image_tag\" {\n  default = \"1.2.3\"\n}\n")
	findings, err := NoComponentVersionIsAVariable(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("a version variable was not noticed")
	}

	dir = t.TempDir()
	write(t, dir, "vars.tf", "variable \"patched_for\" {\n  default = \"CVE-2026-1234\"\n}\n")
	findings, err = NoComponentVersionIsAVariable(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("an advisory identifier was not noticed")
	}
}

// Nothing in the declared sources executes. The attacker's entire contribution
// is an ordinary unauthenticated request the platform is configured to accept.
func TestNothingInTheDeclaredSourcesExecutes(t *testing.T) {
	findings, err := NothingInTheDeclaredSourcesExecutes("../../infra", "../../manifests")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("something in the declared sources executes: %+v", findings)
	}
}

func TestTheExecutionControlWouldNoticeOne(t *testing.T) {
	for name, body := range map[string]string{
		"provisioner.tf":  "resource \"x\" \"y\" {\n  provisioner \"local-exec\" {\n    command = \"id\"\n  }\n}\n",
		"container.yaml":  "spec:\n  containers:\n    - name: x\n      command: [\"/bin/sh\"]\n",
		"privileged.yaml": "spec:\n  securityContext:\n    privileged: true\n",
	} {
		dir := t.TempDir()
		write(t, dir, name, body)
		findings, err := NothingInTheDeclaredSourcesExecutes(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) == 0 {
			t.Fatalf("%s was not noticed", name)
		}
	}
}

func TestControlsFailClosedOnAnEmptyTree(t *testing.T) {
	if _, err := NoComponentVersionIsAVariable(t.TempDir()); err == nil {
		t.Fatal("expected an empty tree to be an error")
	}
	if _, err := NothingInTheDeclaredSourcesExecutes(t.TempDir()); err == nil {
		t.Fatal("expected an empty tree to be an error")
	}
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
