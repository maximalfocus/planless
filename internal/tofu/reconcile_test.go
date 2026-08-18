package tofu

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/maximalfocus/planless/internal/gate"
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

// The reviewed allowlist is the only thing that can widen exposure, and it does
// so by naming the resource. Nothing else in the system can.
func TestReviewedAllowlistNamesTheNewExposure(t *testing.T) {
	entries, err := PublicEntries("../../policy/allowlists/reviewed-exposure.json")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"bucket/status-page": true, "bucket/status-assets": true}
	if len(entries) != len(want) {
		t.Fatalf("got %v", entries)
	}
	for _, e := range entries {
		if !want[e] {
			t.Fatalf("the reviewed allowlist publishes %s, which nobody reviewed", e)
		}
	}
	// Everything else about the two allowlists is identical: reviewing an
	// exposure change must not quietly widen anything else.
	base, err := PublicEntries("../../policy/allowlists/default.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range base {
		if !want[e] {
			t.Fatalf("the default allowlist publishes %s, which the reviewed one does not", e)
		}
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

// Two observations of the same reachability are identical; one that changed is
// not. This is how an ordinary change is shown to have changed nothing.
func TestObservationComparison(t *testing.T) {
	same := observations("internet", map[string]bool{"bucket/status-page": true, "bucket/fare-exports": false})
	body, err := json.Marshal(same)
	if err != nil {
		t.Fatal(err)
	}
	twice := string(body) + "\n" + string(body) + "\n"
	if err := CompareObservations(strings.NewReader(twice)); err != nil {
		t.Fatalf("identical observations were reported as different: %v", err)
	}

	changed := observations("internet", map[string]bool{"bucket/status-page": true, "bucket/fare-exports": true})
	other, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if err := CompareObservations(strings.NewReader(string(body) + "\n" + string(other) + "\n")); err == nil {
		t.Fatal("a change in reachability was not reported")
	}

	if err := CompareObservations(strings.NewReader(string(body))); err == nil {
		t.Fatal("a single observation set is not a comparison")
	}
	if err := CompareObservations(strings.NewReader(`{"document":"planless.transcript"}`)); err == nil {
		t.Fatal("an unrecognized document should be refused")
	}
	empty, err := json.Marshal(ObservationSet{Document: ObservationDocument, Segment: "internet"})
	if err != nil {
		t.Fatal(err)
	}
	if err := CompareObservations(strings.NewReader(string(empty) + "\n" + string(empty))); err == nil {
		t.Fatal("an empty observation set should be refused")
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

// The application is identical in every variant. This is how that is compared
// rather than asserted.
func TestBuildComparison(t *testing.T) {
	transcript := func(scenario, build string) string {
		body, err := json.Marshal(&Transcript{
			Document: TranscriptDocument, Scenario: scenario, ApplicationBuild: build,
		})
		if err != nil {
			t.Fatal(err)
		}
		return string(body) + "\n"
	}
	same := transcript("secure-apply", "sha256:aaa") + transcript("vulnerable-ungated", "sha256:aaa")
	if err := CompareBuilds(strings.NewReader(same)); err != nil {
		t.Fatalf("identical builds were reported as different: %v", err)
	}

	changed := transcript("secure-apply", "sha256:aaa") + transcript("vulnerable-ungated", "sha256:bbb")
	if err := CompareBuilds(strings.NewReader(changed)); err == nil {
		t.Fatal("a changed application build was not reported")
	}
	if err := CompareBuilds(strings.NewReader(transcript("secure-apply", "sha256:aaa"))); err == nil {
		t.Fatal("a single transcript is not a comparison")
	}
	missing := transcript("secure-apply", "") + transcript("vulnerable-ungated", "sha256:aaa")
	if err := CompareBuilds(strings.NewReader(missing)); err == nil {
		t.Fatal("a transcript with no reported build should be refused")
	}
	if err := CompareBuilds(strings.NewReader(`{"document":"planless.observations"}`)); err == nil {
		t.Fatal("an unrecognized document should be refused")
	}
}

// The reconciliation asserts the verdict the scenario declared, so a run that
// stops failing is a regression rather than an improvement.
func TestReconciliationAssertsTheDeclaredVerdict(t *testing.T) {
	transcript := transcriptFor("vulnerable-ungated")
	in := stream(t, transcript,
		observations("internet", map[string]bool{
			"bucket/status-page":  true,
			"bucket/fare-exports": true,
		}),
		observations("corp", map[string]bool{"bucket/fare-exports": true}),
	)
	out, err := Reconcile(config(t), strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if out.Reconcile.Verdict != VerdictFail || out.Reconcile.Expected != VerdictFail {
		t.Fatalf("got %+v", out.Reconcile)
	}
	if !out.Passed {
		t.Fatal("a vulnerable run whose reconciliation failed as declared should pass its scenario")
	}

	// The same scenario with nothing exposed is a regression: the demonstration
	// stopped demonstrating.
	clean := stream(t, transcriptFor("vulnerable-ungated"),
		observations("internet", map[string]bool{"bucket/status-page": true}),
		observations("corp", map[string]bool{"bucket/fare-exports": true}),
	)
	out, err = Reconcile(config(t), strings.NewReader(clean))
	if err != nil {
		t.Fatal(err)
	}
	if out.Passed {
		t.Fatal("a vulnerable run that exposed nothing must not pass")
	}
}

// The drift check reports and does not remediate. That is a property of the
// report itself, and the demonstration depends on it: a check that repaired
// what it found would hide the gap between the repository and the world.
func TestDriftReportNeverClaimsToHaveRemediated(t *testing.T) {
	report := &DriftReport{
		Document: DriftDocument, ReadFrom: "the control plane's read-only state API",
		StateDigest: "sha256:aaa", Allowlist: "default.json",
		DriftDetected: true,
		Findings: []gate.Violation{{
			Class: "exposure_not_allowlisted", Resource: "bucket/fare-exports",
			Exposure: `principals=["*"] sources=["0.0.0.0/0"]`,
		}},
	}
	if report.Remediated {
		t.Fatal("a drift report must never claim to have remediated anything")
	}
	out := report.Render()
	for _, want := range []string{
		"drift detected", "bucket/fare-exports", "remediated anything", "false",
		"the repository may be entirely correct",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the rendered drift report omits %q:\n%s", want, out)
		}
	}

	clean := &DriftReport{Document: DriftDocument, StateDigest: "sha256:aaa"}
	if !strings.Contains(clean.Render(), "no drift") {
		t.Fatalf("a clean report should say so:\n%s", clean.Render())
	}
}

// Two spellings of one desired state must compute to one reachability. That
// equality is the claim the denylist shape rests on, so it is compared rather
// than argued.
func TestExposureComparison(t *testing.T) {
	transcript := func(scenario string, exposures ...gate.Exposure) string {
		body, err := json.Marshal(&Transcript{
			Document: TranscriptDocument, Scenario: scenario,
			WouldHaveDecided: &gate.Decision{Result: gate.ResultDeny, Exposures: exposures},
		})
		if err != nil {
			t.Fatal(err)
		}
		return string(body) + "\n"
	}
	literal := gate.Exposure{
		Resource:     "bucket/fare-exports",
		Computed:     `principals=["*"] sources=["0.0.0.0/0"] rules=["grant-a"]`,
		Reachability: `principals=["*"] sources=["0.0.0.0/0"]`,
	}
	// A different rule produced it, and the same people can reach it.
	bypassed := gate.Exposure{
		Resource:     "bucket/fare-exports",
		Computed:     `principals=["*"] sources=["0.0.0.0/0"] rules=["grant-a","grant-b"]`,
		Reachability: `principals=["*"] sources=["0.0.0.0/0"]`,
	}
	if err := CompareExposures(strings.NewReader(transcript("a", literal) + transcript("b", bypassed))); err != nil {
		t.Fatalf("two spellings of one desired state were reported as different: %v", err)
	}

	narrower := gate.Exposure{
		Resource:     "bucket/fare-exports",
		Reachability: `principals=["finance-reporting"] sources=["10.20.0.0/16"]`,
	}
	if err := CompareExposures(strings.NewReader(transcript("a", literal) + transcript("b", narrower))); err == nil {
		t.Fatal("a genuinely different reachability was not reported")
	}
	if err := CompareExposures(strings.NewReader(transcript("a", literal))); err == nil {
		t.Fatal("a single transcript is not a comparison")
	}
	if err := CompareExposures(strings.NewReader(transcript("a"))); err == nil {
		t.Fatal("a transcript that computed nothing should be refused")
	}
	unrelated := gate.Exposure{Resource: "bucket/other", Reachability: `principals=["*"] sources=["0.0.0.0/0"]`}
	if err := CompareExposures(strings.NewReader(transcript("a", literal) + transcript("b", unrelated))); err == nil {
		t.Fatal("transcripts with no resource in common should be refused")
	}
}
