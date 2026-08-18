package tofu

import (
	"encoding/json"
	"strings"
	"testing"
)

func config(t *testing.T) Config {
	t.Helper()
	return Config{AllowlistDir: "../../policy/allowlists"}
}

// What the allowlist names as publicly reachable is computed from the entry's
// own address ranges, not from a label somebody wrote beside it.
func TestPublicEntriesAreComputedFromTheirRanges(t *testing.T) {
	entries, err := PublicEntries("../../policy/allowlists/default.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0] != "bucket/status-page" {
		t.Fatalf("expected only the deliberately public status page, got %v", entries)
	}
}

func TestUnreadableAllowlistIsAnError(t *testing.T) {
	if _, err := PublicEntries("../../policy/allowlists/does-not-exist.json"); err == nil {
		t.Fatal("expected a missing allowlist to be an error")
	}
}

func stream(t *testing.T, transcript *Transcript, sets ...ObservationSet) string {
	t.Helper()
	var b strings.Builder
	body, err := json.Marshal(transcript)
	if err != nil {
		t.Fatal(err)
	}
	b.Write(body)
	b.WriteString("\n")
	for _, set := range sets {
		body, err := json.Marshal(set)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(body)
		b.WriteString("\n")
	}
	return b.String()
}

func transcriptFor(scenario string) *Transcript {
	return &Transcript{
		Document: TranscriptDocument, Scenario: scenario,
		CorrelationID: correlationID(scenario), Expected: ExpectApplied, Passed: true,
	}
}

func observations(segment string, reachable map[string]bool) ObservationSet {
	set := ObservationSet{Document: ObservationDocument, Segment: segment}
	for resource, ok := range reachable {
		status := 403
		if ok {
			status = 200
		}
		set.Observations = append(set.Observations, Observation{
			Segment: segment, Resource: resource, Reachable: ok, Status: status,
		})
	}
	return set
}

func TestReconciliationPassesWhenOnlyReviewedExposureIsReachable(t *testing.T) {
	in := stream(t, transcriptFor("secure-apply"),
		observations("internet", map[string]bool{
			"bucket/status-page":           true,
			"bucket/fare-exports":          false,
			"workload/fare-engine:admin":   false,
			"workload/fare-engine:service": false,
		}),
		observations("corp", map[string]bool{"bucket/fare-exports": true}),
	)
	out, err := Reconcile(config(t), strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if out.Reconcile.Verdict != VerdictPass {
		t.Fatalf("got %s — %s", out.Reconcile.Verdict, out.Reconcile.Reason)
	}
	if !out.Passed {
		t.Fatal("a passing reconciliation should leave the transcript passing")
	}
}

// The reconciliation never reads the gate's verdict. Something reachable from
// the public segment that nobody reviewed is a failure however the gate voted.
func TestReconciliationFailsOnUnreviewedPublicReachability(t *testing.T) {
	transcript := transcriptFor("secure-apply")
	in := stream(t, transcript,
		observations("internet", map[string]bool{
			"bucket/status-page":         true,
			"bucket/fare-exports":        true,
			"workload/fare-engine:admin": true,
		}),
		observations("corp", map[string]bool{"bucket/fare-exports": true}),
	)
	out, err := Reconcile(config(t), strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if out.Reconcile.Verdict != VerdictFail {
		t.Fatalf("expected a failure, got %s", out.Reconcile.Verdict)
	}
	for _, want := range []string{"bucket/fare-exports", "workload/fare-engine:admin"} {
		if !strings.Contains(out.Reconcile.Reason, want) {
			t.Fatalf("the failure does not name %s: %s", want, out.Reconcile.Reason)
		}
	}
	if out.Passed {
		t.Fatal("a failing reconciliation must not leave the transcript passing")
	}
}

// Corporate reachability is not public reachability, and must not be mistaken
// for it.
func TestCorporateReachabilityIsNotAFailure(t *testing.T) {
	in := stream(t, transcriptFor("secure-apply"),
		observations("internet", map[string]bool{"bucket/status-page": true}),
		observations("corp", map[string]bool{
			"bucket/fare-exports":          true,
			"workload/fare-engine:service": true,
		}),
	)
	out, err := Reconcile(config(t), strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if out.Reconcile.Verdict != VerdictPass {
		t.Fatalf("got %s — %s", out.Reconcile.Verdict, out.Reconcile.Reason)
	}
}

func TestReconciliationFailsClosedOnBadInput(t *testing.T) {
	good := observations("internet", map[string]bool{"bucket/status-page": true})
	cases := map[string]string{
		"no transcript":    stream(t, nil, good)[len("null\n"):],
		"no observations":  stream(t, transcriptFor("secure-apply")),
		"two transcripts":  stream(t, transcriptFor("secure-apply")) + stream(t, transcriptFor("secure-apply"), good),
		"unknown document": `{"document":"something-else"}`,
		"unknown scenario": stream(t, transcriptFor("not-a-scenario"), good),
		"truncated stream": `{"document":"planless.transcript"`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Reconcile(config(t), strings.NewReader(in)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
