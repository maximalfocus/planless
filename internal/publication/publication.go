// Package publication holds the checks that make this repository safe to be
// read by strangers.
//
// Publication is one way. A pull-request ref outlives any history rewrite, so
// anything that reaches a provider surface is permanent — which is why these
// checks exist before the transition rather than after it.
package publication

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Forbidden are the patterns that must not appear in any tracked file.
//
// The kubeconfig patterns look for the artifact rather than the word: this
// project's documentation says out loud that no kubeconfig exists anywhere, and
// a promise of absence is not an exposure.
var Forbidden = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`ASIA[0-9A-Z]{16}`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`xox[baprs]-`),
	regexp.MustCompile(`ghp_[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`KUBECONFIG=`),
	regexp.MustCompile(`(?m)^\s*current-context:`),
	regexp.MustCompile(`\.amazonaws\.com`),
	regexp.MustCompile(`\.blob\.core\.windows\.net`),
	regexp.MustCompile(`\.googleapis\.com`),
	regexp.MustCompile(`AWS_SECRET_ACCESS_KEY`),
	regexp.MustCompile(`AZURE_CLIENT_SECRET`),
	regexp.MustCompile(`GOOGLE_APPLICATION_CREDENTIALS`),
}

// PrivateCompanion is the name of a private repository that must never appear
// in anything published. A commit message, a branch name or a pull-request body
// naming it could not be taken back.
var PrivateCompanion = regexp.MustCompile(`planless-prd`)

// Finding is one thing that must not be published.
type Finding struct {
	File    string
	Pattern string
	Line    int
}

// ReviewTree scans every readable file under root, excluding the git directory
// and anything the caller names.
//
// It covers the working tree only. The history, the refs and the provider's own
// surfaces are reviewed separately, because a file that no longer exists is
// still published.
func ReviewTree(root string, skip ...string) ([]Finding, error) {
	findings := []Finding{}
	patterns := append([]*regexp.Regexp{PrivateCompanion}, Forbidden...)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		for _, s := range skip {
			if rel == s {
				return nil
			}
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if isBinary(body) {
			return nil
		}
		for i, line := range strings.Split(string(body), "\n") {
			for _, p := range patterns {
				if p.MatchString(line) {
					findings = append(findings, Finding{File: rel, Pattern: p.String(), Line: i + 1})
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return findings, nil
}

func isBinary(body []byte) bool {
	limit := len(body)
	if limit > 8000 {
		limit = 8000
	}
	for _, b := range body[:limit] {
		if b == 0 {
			return true
		}
	}
	return false
}
