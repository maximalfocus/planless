package graph

import (
	"os"
	"strings"
	"testing"
)

// The boundary statement is a deliverable, not a caveat.
//
// This project renders Kubernetes-shaped manifests and applies them to its own
// fictional platform. Somebody reading it must not come away thinking anything
// here describes a real cluster, so the documentation has to say so, and this
// test fails if it stops saying so.
func TestDocumentationStatesTheKubernetesBoundary(t *testing.T) {
	body, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	// Line wrapping is not meaning: the statement is checked as prose.
	readme := collapse(string(body))
	for _, required := range []string{
		"no kubernetes distribution, api server, admission controller or kubelet is implemented or emulated",
		"there is no cluster of any kind",
		"nothing here describes how real kubernetes behaves",
		"manifest-shaped inputs to this demonstration's own applier",
	} {
		if !strings.Contains(readme, required) {
			t.Fatalf("the documentation no longer states: %q", required)
		}
	}
}

// The same for the platform itself: democloud is fictional, and the
// documentation says so.
func TestDocumentationStatesThePlatformBoundary(t *testing.T) {
	body, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := collapse(string(body))
	for _, required := range []string{
		"not an emulator of",
		"contacts no cloud provider",
	} {
		if !strings.Contains(readme, required) {
			t.Fatalf("the documentation no longer states: %q", required)
		}
	}
}

// collapse turns the document into one lower-case line so a wrapped sentence is
// still the sentence it is.
func collapse(body string) string {
	return strings.Join(strings.Fields(strings.ToLower(body)), " ")
}
