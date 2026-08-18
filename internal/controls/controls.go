// Package controls automates the six things this flaw is not.
//
// Each control is present, correct, and irrelevant to the outcome. A reader who
// suspects one of them is the real explanation should be able to see it checked
// rather than asserted — and each check is written so that it fails if the
// property stops holding, not merely if somebody deletes it.
package controls

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Finding is one violated control.
type Finding struct {
	Control string `json:"control"`
	Where   string `json:"where"`
	Detail  string `json:"detail"`
}

// versionish matches the shapes a component version, patch level or advisory
// identifier takes. If any of them is a variable in this project's
// configuration, the demonstration would be about something else.
var versionish = regexp.MustCompile(`(?i)\b(version|patch_level|patchlevel|image_tag|imagetag|chart_version|app_version|semver)\b`)

// advisory matches a security advisory identifier, which has no business
// appearing anywhere in this project at all.
var advisory = regexp.MustCompile(`(?i)\bcve-\d{4}-\d+\b`)

// variableish marks a line that declares or reads a variable. The control is
// about a component version being a *variable*: a pinned provider or toolchain
// version is a constant nothing in this project can change per run, and pinning
// is the opposite of the problem.
var variableish = regexp.MustCompile(`(variable\s+"|\bvar\.)`)

// NoComponentVersionIsAVariable asserts that no component version, patch level
// or advisory identifier is a variable anywhere in the declared infrastructure.
//
// This is why A06:2021 and CWE-1104 are not claimed: there is nothing here for
// them to be about.
func NoComponentVersionIsAVariable(dirs ...string) ([]Finding, error) {
	return scan(dirs, "no_component_version_is_a_variable", func(line string) bool {
		if advisory.MatchString(line) {
			return true
		}
		// An apiVersion names a manifest schema rather than a component.
		if strings.Contains(line, "apiVersion") {
			return false
		}
		return versionish.MatchString(line) && variableish.MatchString(line)
	})
}

// executionKeywords are the constructs that would run something. None may
// appear in any declarative source in this project.
var executionKeywords = []string{
	"provisioner", "local-exec", "remote-exec", "connection",
	"command:", "args:", "exec:", "lifecycle:", "postStart", "preStop",
	"privileged: true", "hostPID", "hostIPC",
}

// NothingInTheDeclaredSourcesExecutes asserts that no configuration or manifest
// content runs anything at all.
//
// The attacker's entire contribution to this demonstration is an ordinary
// unauthenticated request that the platform is configured to accept. Nothing is
// compiled, spawned, deserialized, rendered or evaluated from content.
func NothingInTheDeclaredSourcesExecutes(dirs ...string) ([]Finding, error) {
	return scan(dirs, "nothing_in_the_declared_sources_executes", func(line string) bool {
		for _, keyword := range executionKeywords {
			if strings.Contains(line, keyword) {
				return true
			}
		}
		return false
	})
}

// scan walks the declarative sources and reports every line the predicate
// matches. An empty tree is an error: a control that read nothing has not
// checked anything.
func scan(dirs []string, control string, match func(line string) bool) ([]Finding, error) {
	findings := []Finding{}
	seen := 0
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !declarative(path) {
				return nil
			}
			seen++
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, line := range strings.Split(string(body), "\n") {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" || strings.HasPrefix(trimmed, "#") {
					continue
				}
				if match(trimmed) {
					findings = append(findings, Finding{Control: control, Where: path, Detail: trimmed})
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if seen == 0 {
		return nil, fmt.Errorf("no declarative sources were found under %v", dirs)
	}
	return findings, nil
}

func declarative(path string) bool {
	switch filepath.Ext(path) {
	case ".tf", ".tfvars", ".yaml", ".yml":
		return true
	}
	return false
}
