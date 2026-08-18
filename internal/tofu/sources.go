package tofu

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SecurityRelevantValues are the resolved values that decide who can reach
// what. The whole demonstration turns on where these live: they must not appear
// in a resource block, because a reviewer reading the resource blocks would then
// see them — and the point is that they do not.
var SecurityRelevantValues = []string{
	`"finance-reporting"`,
	`"10.20.0.0/16"`,
	`"0.0.0.0/0"`,
	`"10.20.7.0/24"`,
	`"10.20.1.20"`,
	`"*"`,
}

// ExecutionKeywords are the configuration-language constructs that would run
// something. None of them may appear anywhere in this project's configuration.
var ExecutionKeywords = []string{
	"provisioner",
	"local-exec",
	"remote-exec",
	"connection",
	"external",
	"http",
}

// ResourceBlockBodies returns the body text of every `resource` block in one
// configuration file.
func ResourceBlockBodies(src string) []string {
	var bodies []string
	for i := 0; i < len(src); i++ {
		idx := strings.Index(src[i:], "resource \"")
		if idx < 0 {
			break
		}
		start := i + idx
		if start > 0 && !isBoundary(src[start-1]) {
			i = start + 1
			continue
		}
		open := strings.Index(src[start:], "{")
		if open < 0 {
			break
		}
		open += start
		depth, end := 1, -1
		for j := open + 1; j < len(src); j++ {
			switch src[j] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					end = j
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			break
		}
		bodies = append(bodies, src[open+1:end])
		i = end
	}
	return bodies
}

func isBoundary(c byte) bool {
	return c == '\n' || c == '\r' || c == ' ' || c == '\t'
}

// Finding is one violated source-layout rule.
type Finding struct {
	File   string `json:"file"`
	Rule   string `json:"rule"`
	Detail string `json:"detail"`
}

// CheckSources asserts two properties of the checked-in configuration: no
// security-relevant value appears in a resource block, and nothing anywhere
// executes.
func CheckSources(dir string) ([]Finding, error) {
	var findings []Finding
	seen := 0
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || (filepath.Ext(path) != ".tf" && filepath.Ext(path) != ".tfvars") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		seen++
		rel, _ := filepath.Rel(dir, path)
		src := string(body)
		for _, keyword := range ExecutionKeywords {
			for _, line := range strings.Split(src, "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "#") {
					continue
				}
				if strings.HasPrefix(trimmed, keyword+" ") || strings.HasPrefix(trimmed, keyword+"{") ||
					strings.Contains(trimmed, `"`+keyword+`"`) {
					findings = append(findings, Finding{File: rel, Rule: "no_execution_path", Detail: line})
				}
			}
		}
		if filepath.Ext(path) != ".tf" {
			return nil
		}
		for _, block := range ResourceBlockBodies(src) {
			for _, value := range SecurityRelevantValues {
				if strings.Contains(block, value) {
					findings = append(findings, Finding{
						File:   rel,
						Rule:   "security_relevant_value_in_resource_block",
						Detail: value,
					})
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if seen == 0 {
		return nil, fmt.Errorf("no configuration files found under %s", dir)
	}
	return findings, nil
}

// ValuesMissingFromPlan reports which security-relevant values are absent from
// the resolved artifact. Every one of them should be present: that is what
// "resolved" means, and it is the difference the source text cannot show.
func ValuesMissingFromPlan(planJSON []byte) []string {
	var missing []string
	plan := string(planJSON)
	for _, value := range SecurityRelevantValues {
		if !strings.Contains(plan, value) {
			missing = append(missing, value)
		}
	}
	return missing
}

// SourceFile is one configuration file as a scan sees it: its path and its
// resource definitions, with whitespace normalized so a scan matches shapes
// rather than one spelling of them.
type SourceFile struct {
	Path           string   `json:"path"`
	ResourceBlocks []string `json:"resource_blocks"`
}

// SourceBundle is the input a source-configuration scan reads.
//
// It carries the configuration files, and nothing else. Not the variable file
// the run was given, and not the resolved desired state — because a scanner of
// configuration files reads configuration files, and the point of this
// demonstration is what that leaves out.
type SourceBundle struct {
	Files []SourceFile `json:"files"`
}

// BuildSourceBundle reads the `.tf` files under dir into a scan input.
func BuildSourceBundle(dir string) (*SourceBundle, error) {
	bundle := &SourceBundle{Files: []SourceFile{}}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".tf" {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		blocks := []string{}
		for _, block := range ResourceBlockBodies(string(body)) {
			blocks = append(blocks, normalizeWhitespace(block))
		}
		bundle.Files = append(bundle.Files, SourceFile{Path: rel, ResourceBlocks: blocks})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(bundle.Files) == 0 {
		return nil, fmt.Errorf("no configuration files found under %s", dir)
	}
	sort.Slice(bundle.Files, func(i, j int) bool { return bundle.Files[i].Path < bundle.Files[j].Path })
	return bundle, nil
}

// normalizeWhitespace collapses runs of spaces and tabs so alignment cannot
// hide a match. A scan that missed a value because somebody lined up an equals
// sign would be a broken scan, not a defeated one.
func normalizeWhitespace(block string) string {
	lines := strings.Split(strings.Trim(block, "\n"), "\n")
	for i, line := range lines {
		lines[i] = strings.Join(strings.Fields(line), " ")
	}
	return strings.Join(lines, "\n") + "\n"
}
