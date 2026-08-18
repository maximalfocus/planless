package tofu

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/maximalfocus/planless/internal/gate"
)

func reconciled(t *testing.T, transcripts ...*Transcript) string {
	t.Helper()
	var b strings.Builder
	for _, tr := range transcripts {
		tr.Document = TranscriptDocument
		if tr.Reconcile == nil {
			tr.Reconcile = &Reconciliation{Verdict: VerdictPass, Expected: VerdictPass}
		}
		body, err := json.Marshal(tr)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(body)
		b.WriteString("\n")
	}
	return b.String()
}

// Reachability is what a client on the public segment observed. A policy
// decision is not evidence of exposure state, and the table must never quietly
// substitute one for the other.
func TestTableTakesReachabilityFromObservationsNotFromTheVerdict(t *testing.T) {
	tr := &Transcript{
		Scenario:    "vulnerable-ungated",
		Enforcement: Enforcement{Applied: true, OperatorResult: ResultDeployed},
		// The gate said nothing at all, and the export is reachable anyway.
		Observations: []Observation{
			{Segment: "internet", Resource: "bucket/fare-exports", Reachable: true},
			{Segment: "internet", Resource: "bucket/status-page", Reachable: true},
			{Segment: "internet", Resource: "workload/fare-engine:admin", Reachable: false},
			{Segment: "corp", Resource: "bucket/fare-exports", Reachable: true},
		},
		Reconcile: &Reconciliation{Verdict: VerdictFail, Expected: VerdictFail},
	}
	table, err := BuildTable(strings.NewReader(reconciled(t, tr)))
	if err != nil {
		t.Fatal(err)
	}
	row := table.Rows[0]
	if row.Decision != "none" {
		t.Fatalf("expected no decision, got %q", row.Decision)
	}
	if !strings.Contains(row.Reachable, "fare-exports") || !strings.Contains(row.Reachable, "status-page") {
		t.Fatalf("reachability column lost an observation: %q", row.Reachable)
	}
	if strings.Contains(row.Reachable, "admin") {
		t.Fatalf("reachability column claims something unreachable: %q", row.Reachable)
	}
	if row.Reconciled != VerdictFail {
		t.Fatalf("expected the reconciliation verdict to be carried, got %q", row.Reconciled)
	}
}

// Each control produces a distinguishable row, or the table teaches nothing.
func TestTableDistinguishesEveryShape(t *testing.T) {
	deny := &gate.Decision{Result: gate.ResultDeny, Violations: []gate.Violation{
		{Class: "exposure_not_allowlisted", Resource: "bucket/fare-exports"},
	}}
	observed := []Observation{{Segment: "internet", Resource: "bucket/status-page", Reachable: true}}

	cases := map[string]*Transcript{
		"refused": {
			Scenario: "refuse", Decision: deny, Observations: observed,
			Enforcement: Enforcement{OperatorResult: ResultRefused},
		},
		"advisory, applied": {
			Scenario: "advisory", Decision: deny, Observations: observed,
			Enforcement: Enforcement{Applied: true, Advisory: true, OperatorResult: ResultDeployed},
		},
		"refused, applied anyway": {
			Scenario: "out-of-band", Decision: deny, Observations: observed,
			Enforcement: Enforcement{Applied: true, OutOfBand: true, OperatorResult: ResultRefused},
		},
		"applied": {
			Scenario: "applied", Decision: &gate.Decision{Result: gate.ResultAdmit}, Observations: observed,
			Enforcement: Enforcement{Applied: true, OperatorResult: ResultDeployed},
		},
	}
	for want, tr := range cases {
		table, err := BuildTable(strings.NewReader(reconciled(t, tr)))
		if err != nil {
			t.Fatal(err)
		}
		if got := table.Rows[0].Enforcement; got != want {
			t.Fatalf("got %q want %q", got, want)
		}
	}
}

func TestTableNamesWhatEachPipelineEvaluated(t *testing.T) {
	observed := []Observation{{Segment: "internet", Resource: "bucket/status-page", Reachable: true}}
	cases := map[string]*Transcript{
		"nothing":                   {Scenario: "a", Observations: observed},
		"resolved state":            {Scenario: "b", Decision: &gate.Decision{Result: gate.ResultAdmit}, Observations: observed},
		"source text":               {Scenario: "c", Scan: &gate.ScanReport{Artifact: "the source configuration files"}, Observations: observed},
		"base manifests":            {Scenario: "d", Scan: &gate.ScanReport{Artifact: "the base manifest set"}, Observations: observed},
		"resolved state (literals)": {Scenario: "e", Denylist: &gate.DenylistReport{Rules: []string{"x"}}, Observations: observed},
	}
	for want, tr := range cases {
		table, err := BuildTable(strings.NewReader(reconciled(t, tr)))
		if err != nil {
			t.Fatal(err)
		}
		if got := table.Rows[0].Evaluated; got != want {
			t.Fatalf("got %q want %q", got, want)
		}
	}
}

func TestTableRendersEveryColumnDeterministically(t *testing.T) {
	tr := &Transcript{
		Scenario: "secure-apply", Decision: &gate.Decision{Result: gate.ResultAdmit},
		Enforcement: Enforcement{Applied: true, OperatorResult: ResultDeployed},
		StateBefore: "sha256:a", StateAfter: "sha256:b",
		Observations: []Observation{{Segment: "internet", Resource: "bucket/status-page", Reachable: true}},
	}
	table, err := BuildTable(strings.NewReader(reconciled(t, tr)))
	if err != nil {
		t.Fatal(err)
	}
	if table.Render() != table.Render() {
		t.Fatal("the table rendered differently twice")
	}
	out := table.Render()
	for _, column := range Columns {
		if !strings.Contains(out, column) {
			t.Fatalf("the table lost the %q column:\n%s", column, out)
		}
	}
	if !strings.Contains(out, "never a policy verdict") {
		t.Fatal("the table no longer says where reachability comes from")
	}
	if !strings.Contains(out, "changed") {
		t.Fatal("the table lost the platform state change")
	}
}

func TestTableFailsClosedOnBadInput(t *testing.T) {
	if _, err := BuildTable(strings.NewReader("")); err == nil {
		t.Fatal("expected an empty stream to be an error")
	}
	if _, err := BuildTable(strings.NewReader(`{"document":"planless.observations"}`)); err == nil {
		t.Fatal("expected an unrecognized document to be an error")
	}
	body, err := json.Marshal(&Transcript{Document: TranscriptDocument, Scenario: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildTable(strings.NewReader(string(body))); err == nil {
		t.Fatal("expected an unreconciled transcript to be an error")
	}
}
