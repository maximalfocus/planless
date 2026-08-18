package fixtures

import (
	"os"
	"strings"
	"testing"
)

func walkthrough(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile("../../docs/WALKTHROUGH.md")
	if err != nil {
		t.Fatal(err)
	}
	// Line wrapping is not meaning: statements are checked as prose.
	return strings.Join(strings.Fields(strings.ToLower(string(body))), " ")
}

// A learner has to be able to explain the flaw without reading source, which
// means the walkthrough has to actually teach each piece. If one goes missing,
// the documentation has quietly stopped doing its job.
func TestWalkthroughTeachesEveryRequiredPiece(t *testing.T) {
	doc := walkthrough(t)
	required := map[string][]string{
		"the four artifacts": {
			"source configuration", "resolved desired state",
			"the artifact the policy evaluated", "the state that was applied",
		},
		"the five gate-failure shapes": {
			"no gate at all", "scan the source text", "report, do not enforce",
			"guard the review path only", "denylist the known-bad literals",
		},
		"both denylist bypasses": {
			"separate permission resource", "0.0.0.0/1", "128.0.0.0/1",
			"fixed, enumerated teaching pair",
		},
		"the six negative controls": {
			"no vulnerable, outdated or unmaintained component",
			"no code execution and no hostile input",
			"the application is identical and correct",
			"correctness tooling is green",
			"encryption at rest is enabled and irrelevant",
			"the deployer is least-privileged",
		},
		"the four-part fix": {
			"evaluate the resolved desired state", "compute effective exposure",
			"deny by default", "bind the approved artifact to the applied artifact",
			"drift detection",
		},
		"the second surface":  {"the same invariant, a second format"},
		"the two-step opt-in": {"two separate opt-in actions", "allow_vulnerable_demo=true"},
	}
	for topic, phrases := range required {
		for _, phrase := range phrases {
			if !strings.Contains(doc, strings.ToLower(phrase)) {
				t.Fatalf("the walkthrough no longer teaches %s: missing %q", topic, phrase)
			}
		}
	}
}

// The taxonomy section states the whole posture, including the part that is
// least comfortable to state.
func TestWalkthroughStatesTheTaxonomyPosture(t *testing.T) {
	doc := walkthrough(t)
	for _, phrase := range []string{
		"no cwe in a05:2021's published mapping is the precise weakness here",
		"must not be used to map to real-world vulnerabilities",
		"a gap in the mapping, reported honestly",
	} {
		if !strings.Contains(doc, phrase) {
			t.Fatalf("the walkthrough no longer states: %q", phrase)
		}
	}
	// Every identifier, and its authoritative link.
	for _, c := range Taxonomy {
		if !strings.Contains(doc, strings.ToLower(c.ID)) {
			t.Fatalf("the walkthrough does not mention %s", c.ID)
		}
		if !strings.Contains(doc, strings.ToLower(c.URL)) {
			t.Fatalf("the walkthrough does not link the authoritative page for %s", c.ID)
		}
	}
	if !strings.Contains(doc, strings.ToLower(RecheckedOn)) {
		t.Fatalf("the walkthrough does not say when the taxonomy was last rechecked")
	}
}

// The boundaries are prominent, and they stay prominent.
func TestWalkthroughStatesEveryBoundary(t *testing.T) {
	doc := walkthrough(t)
	for _, phrase := range []string{
		"is not an emulator of, and makes no claim about, any real cloud provider",
		"nothing supplied as content is executed",
		"no real provider, cluster or account is contacted",
		"no finding is made about any real cloud service, iac tool, kubernetes distribution, policy engine or scanner",
		"no kubernetes distribution, api server, admission controller or kubelet is implemented or emulated",
		"there is no cluster of any kind",
		"nothing accepts an arbitrary target",
	} {
		if !strings.Contains(doc, phrase) {
			t.Fatalf("the walkthrough no longer states the boundary: %q", phrase)
		}
	}
}
