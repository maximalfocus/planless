package publication

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const repoRoot = "../.."

// Nothing in the working tree names a credential, a real cloud target, or the
// private companion repository. The history, the refs and the provider's own
// surfaces are reviewed by scripts/exposure-review.sh, which needs git.
func TestNothingInTheTreeIsUnpublishable(t *testing.T) {
	findings, err := ReviewTree(repoRoot,
		// This file and the review script both carry the pattern list itself.
		filepath.Join("internal", "publication", "publication.go"),
		filepath.Join("internal", "publication", "publication_test.go"),
		filepath.Join("scripts", "exposure-review.sh"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("the working tree carries something unpublishable: %+v", findings)
	}
}

// The review has to be able to find one, or its silence means nothing.
func TestTheReviewWouldNoticeOne(t *testing.T) {
	for name, body := range map[string]string{
		"key.pem":     "-----BEGIN RSA PRIVATE KEY-----\nabc\n",
		"env.sh":      "export AWS_SECRET_ACCESS_KEY=abc\n",
		"notes.md":    "see the planless-prd repository for the rationale\n",
		"kube.yaml":   "current-context: production\n",
		"endpoint.tf": "bucket = \"exports.s3.amazonaws.com\"\n",
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		findings, err := ReviewTree(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) == 0 {
			t.Fatalf("%s was not noticed", name)
		}
	}
}

func read(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(repoRoot, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// The canonical MIT text, with the right year and holder.
func TestLicenceIsCanonicalMIT(t *testing.T) {
	licence := read(t, "LICENSE")
	if !strings.HasPrefix(licence, "MIT License\n\nCopyright (c) 2026 maximalfocus\n") {
		t.Fatalf("unexpected licence header:\n%s", strings.SplitN(licence, "\n\n", 3)[:2])
	}
	for _, clause := range []string{
		"Permission is hereby granted, free of charge, to any person obtaining a copy",
		"The above copyright notice and this permission notice shall be included in all",
		`THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND`,
		"IN NO EVENT SHALL THE",
	} {
		if !strings.Contains(licence, clause) {
			t.Fatalf("the licence is not the canonical MIT text: missing %q", clause)
		}
	}
}

// The notices name every third-party tool at the version actually pinned, so a
// version bump that forgets the notice fails rather than shipping.
func TestNoticesMatchThePinnedVersions(t *testing.T) {
	dockerfile := read(t, "deploy/Dockerfile")
	notice := read(t, "NOTICE.md")

	pins := map[string]*regexp.Regexp{
		"OpenTofu":  regexp.MustCompile(`TOFU_VERSION=([0-9.]+)`),
		"OPA":       regexp.MustCompile(`OPA_VERSION=(v[0-9.]+)`),
		"Kustomize": regexp.MustCompile(`KUSTOMIZE_VERSION=(v[0-9.]+)`),
	}
	for name, pattern := range pins {
		m := pattern.FindStringSubmatch(dockerfile)
		if m == nil {
			t.Fatalf("%s is no longer pinned in the Dockerfile", name)
		}
		if !strings.Contains(notice, m[1]) {
			t.Fatalf("the notices do not record %s %s", name, m[1])
		}
	}

	for _, required := range []string{"MIT", "MPL-2.0", "Apache-2.0", "terraform-plugin-framework"} {
		if !strings.Contains(notice, required) {
			t.Fatalf("the notices no longer record %q", required)
		}
	}
	if strings.Contains(notice, "vendors ") && !strings.Contains(notice, "vendors nothing") {
		t.Fatal("the notices claim something is vendored")
	}
}

// The security policy has to say which one to report, because this repository
// deliberately contains the other.
func TestSecurityPolicyDistinguishesTheIntentionalMisconfiguration(t *testing.T) {
	// Line wrapping is not meaning.
	policy := strings.ToLower(strings.Join(strings.Fields(read(t, "SECURITY.md")), " "))
	for _, phrase := range []string{
		"that is the product, not a bug",
		"an **unintended** security bug",
		"two separate opt-in actions",
		"report privately",
		"publishes no package, container image, provider artifact or policy bundle",
	} {
		if !strings.Contains(policy, strings.ToLower(phrase)) {
			t.Fatalf("the security policy no longer says: %q", phrase)
		}
	}
}

// Contribution guidance says how a change is verified and what it must keep
// true.
func TestContributingExplainsVerificationAndInvariants(t *testing.T) {
	doc := strings.ToLower(strings.Join(strings.Fields(read(t, "CONTRIBUTING.md")), " "))
	for _, phrase := range []string{
		"./scripts/demo.sh verify",
		"only docker and a posix shell",
		"every unfinished path denies",
		"nothing accepts an arbitrary target",
		"reachability is observed, never asserted",
		"ships no discovery capability",
		"security.md",
	} {
		if !strings.Contains(doc, phrase) {
			t.Fatalf("the contribution guidance no longer says: %q", phrase)
		}
	}
}

// Nothing in the public distribution implies that anything private is part of
// it.
func TestNothingClaimsAPrivateCompanion(t *testing.T) {
	for _, name := range []string{"README.md", "NOTICE.md", "SECURITY.md", "CONTRIBUTING.md", "docs/WALKTHROUGH.md"} {
		if PrivateCompanion.MatchString(read(t, name)) {
			t.Fatalf("%s names a private repository", name)
		}
	}
}
