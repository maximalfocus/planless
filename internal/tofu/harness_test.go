package tofu

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maximalfocus/planless/internal/canon"
	"github.com/maximalfocus/planless/internal/gate"
)

func writeApproval(t *testing.T, dir string, a Approval) string {
	t.Helper()
	path := filepath.Join(dir, "approval.json")
	if err := a.Write(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func writePlan(t *testing.T, dir string, body []byte) string {
	t.Helper()
	path := filepath.Join(dir, "plan.tfplan")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The binding is the gate's whole authority: only the artifact it approved, in
// this run, may be applied.
func TestBindingAdmitsOnlyTheApprovedArtifact(t *testing.T) {
	dir := t.TempDir()
	body := []byte("a plan artifact")
	planPath := writePlan(t, dir, body)
	digest := canon.Digest(body)
	approvalPath := writeApproval(t, dir, Approval{
		RunID:              RunID("secure-apply", digest),
		Scenario:           "secure-apply",
		PlanArtifactDigest: digest,
	})
	if class, err := VerifyApproval(approvalPath, planPath, "secure-apply"); err != nil {
		t.Fatalf("the approved artifact was refused: %s %v", class, err)
	}
}

func TestBindingRefusesEveryOtherArtifact(t *testing.T) {
	body := []byte("a plan artifact")
	digest := canon.Digest(body)

	t.Run("no approval at all", func(t *testing.T) {
		dir := t.TempDir()
		planPath := writePlan(t, dir, body)
		class, err := VerifyApproval(filepath.Join(dir, "approval.json"), planPath, "secure-apply")
		if err == nil || class != ClassNoApproval {
			t.Fatalf("got %s %v", class, err)
		}
	})

	t.Run("artifact changed after approval", func(t *testing.T) {
		dir := t.TempDir()
		planPath := writePlan(t, dir, body)
		approvalPath := writeApproval(t, dir, Approval{
			RunID:              RunID("secure-apply", digest),
			PlanArtifactDigest: digest,
		})
		if err := os.WriteFile(planPath, append(body, 0), 0o600); err != nil {
			t.Fatal(err)
		}
		class, err := VerifyApproval(approvalPath, planPath, "secure-apply")
		if err == nil || class != ClassDigestMismatch {
			t.Fatalf("got %s %v", class, err)
		}
	})

	t.Run("approval from another run", func(t *testing.T) {
		dir := t.TempDir()
		planPath := writePlan(t, dir, body)
		approvalPath := writeApproval(t, dir, Approval{
			RunID:              RunID("some-other-run", digest),
			PlanArtifactDigest: digest,
		})
		class, err := VerifyApproval(approvalPath, planPath, "secure-apply")
		if err == nil || class != ClassApprovalOtherRun {
			t.Fatalf("got %s %v", class, err)
		}
	})

	t.Run("unreadable approval", func(t *testing.T) {
		dir := t.TempDir()
		planPath := writePlan(t, dir, body)
		approvalPath := filepath.Join(dir, "approval.json")
		if err := os.WriteFile(approvalPath, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		class, err := VerifyApproval(approvalPath, planPath, "secure-apply")
		if err == nil || class != ClassApprovalUnusable {
			t.Fatalf("got %s %v", class, err)
		}
	})
}

func TestRunIDIsDeterministicAndArtifactBound(t *testing.T) {
	a := RunID("secure-apply", "sha256:aaa")
	if a != RunID("secure-apply", "sha256:aaa") {
		t.Fatal("the same scenario and artifact produced two run identities")
	}
	if a == RunID("secure-apply", "sha256:bbb") || a == RunID("other", "sha256:aaa") {
		t.Fatal("a different artifact or scenario produced the same run identity")
	}
}

func TestCorrelationIDIsDeterministicPerScenario(t *testing.T) {
	if correlationID("secure-apply") != correlationID("secure-apply") {
		t.Fatal("correlation ids are not deterministic")
	}
	if correlationID("secure-apply") == correlationID("refuse-anonymous-export") {
		t.Fatal("two scenarios share a correlation id")
	}
	if !strings.HasPrefix(correlationID("secure-apply"), "secure-apply-") {
		t.Fatal("a correlation id should name its scenario")
	}
}

// Every refusal returns the identical operator-facing result, whatever the
// reason. An operator learns that the deployment was refused and nothing else.
func TestOperatorResultIsGenericAcrossEveryRefusalClass(t *testing.T) {
	classes := []string{
		"exposure_not_allowlisted", "unknown_resource_type", "unrecognized_field",
		gate.ClassEngineError, gate.ClassNoDecision, gate.ClassUnparsablePlan,
		ClassNoApproval, ClassDigestMismatch, ClassApprovalOtherRun,
	}
	results := map[string]bool{}
	for _, class := range classes {
		tr := &Transcript{Scenario: "s", CorrelationID: "s-0001"}
		tr.refuse(StagePolicy, class, "deny-by-default")
		results[tr.Enforcement.OperatorResult] = true
		if tr.Enforcement.Applied {
			t.Fatalf("%s: a refusal reported an apply", class)
		}
		if len(tr.Audit) != 1 {
			t.Fatalf("%s: expected exactly one audit event, got %d", class, len(tr.Audit))
		}
	}
	if len(results) != 1 || !results[ResultRefused] {
		t.Fatalf("refusals returned more than one operator result: %v", results)
	}
}

// An audit event carries a fixed field set. Nothing else may leak into it.
func TestAuditEventCarriesOnlyItsFixedFields(t *testing.T) {
	tr := &Transcript{Scenario: "secure-apply", CorrelationID: "secure-apply-0001"}
	tr.refuse(StageBinding, ClassDigestMismatch, "gate-to-apply-binding")
	body, err := json.Marshal(tr.Audit[0])
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	want := []string{"event", "correlation_id", "scenario", "class", "rule", "stage"}
	if len(fields) != len(want) {
		t.Fatalf("audit event carries %v", fields)
	}
	for _, k := range want {
		if _, ok := fields[k]; !ok {
			t.Fatalf("audit event is missing %s", k)
		}
	}
	for _, forbidden := range []string{"principal", "address", "url", "host", "content", "token", "credential", "resource"} {
		if _, ok := fields[forbidden]; ok {
			t.Fatalf("audit event carries %s", forbidden)
		}
	}
}

// A refused scenario must additionally have changed nothing.
func TestRefusedScenarioMustLeaveStateUnchanged(t *testing.T) {
	scenario := Scenarios["refuse-anonymous-export"]
	tr := &Transcript{Scenario: scenario.ID, Expected: ExpectRefused, StateBefore: "sha256:a", StateAfter: "sha256:a"}
	tr.refuse(StagePolicy, "exposure_not_allowlisted", "deny-by-default")
	if !tr.assert(scenario) {
		t.Fatal("a refusal that changed nothing should pass")
	}
	tr.StateAfter = "sha256:b"
	if tr.assert(scenario) {
		t.Fatal("a refusal that changed platform state must fail")
	}
	tr.StateAfter = "sha256:a"
	tr.Audit = append(tr.Audit, tr.Audit[0])
	if tr.assert(scenario) {
		t.Fatal("a refusal that emitted two audit events must fail")
	}
}

func TestAppliedScenarioMustActuallyApply(t *testing.T) {
	scenario := Scenarios["secure-apply"]
	tr := &Transcript{Scenario: scenario.ID, Expected: ExpectApplied}
	if tr.assert(scenario) {
		t.Fatal("a scenario that applied nothing must not pass as applied")
	}
	tr.Enforcement.OperatorResult = ResultDeployed
	if !tr.assert(scenario) {
		t.Fatal("a scenario that applied should pass")
	}
}

// The scenario table is the whole input surface. Nothing outside it can be run.
func TestScenarioTableIsWellFormed(t *testing.T) {
	if len(Scenarios) == 0 {
		t.Fatal("no scenarios are declared")
	}
	for name, s := range Scenarios {
		if s.ID != name {
			t.Fatalf("scenario %q declares id %q", name, s.ID)
		}
		if s.Expect != ExpectApplied && s.Expect != ExpectRefused {
			t.Fatalf("scenario %s declares no expected outcome", name)
		}
		if s.VarFile == "" {
			t.Fatalf("scenario %s names no variable file", name)
		}
		if s.Description == "" {
			t.Fatalf("scenario %s carries no description", name)
		}
		if strings.Contains(s.AllowlistOf(), "/") || strings.Contains(s.AllowlistOf(), "..") {
			t.Fatalf("scenario %s names an allowlist outside the reviewed set", name)
		}
		if strings.Contains(s.Artifact, "/") || strings.Contains(s.Artifact, "..") {
			t.Fatalf("scenario %s names an artifact outside the checked-in set", name)
		}
	}
}

func TestTranscriptRendersDeterministically(t *testing.T) {
	tr := &Transcript{
		Document: TranscriptDocument, Scenario: "secure-apply", CorrelationID: "secure-apply-0001",
		Expected: ExpectApplied, Passed: true,
		Artifacts: Artifacts{
			SourceConfiguration:  "sha256:a",
			ResolvedDesiredState: "sha256:b",
			PlanArtifact:         "sha256:c",
			EvaluatedByPolicy:    "sha256:b",
			AppliedState:         "sha256:d",
			EvaluatedBy:          "the deny-by-default policy",
		},
		Decision: &gate.Decision{Result: "admit", Exposures: []gate.Exposure{
			{Resource: "bucket/status-page", Computed: "principals=[\"*\"]", AdmittedBy: "allow-status-page-public"},
		}},
		Enforcement:  Enforcement{Applied: true, OperatorResult: ResultDeployed},
		Observations: []Observation{{Segment: "internet", Resource: "bucket/status-page", Reachable: true, Status: 200}},
		Reconcile:    &Reconciliation{Verdict: VerdictPass, Reason: "nothing unreviewed"},
	}
	if tr.Render() != tr.Render() {
		t.Fatal("the transcript rendered differently twice")
	}
	out := tr.Render()
	for _, want := range []string{
		"artifact the policy evaluated", "plan artifact (apply input)", "applied state",
		"reconciliation PASS", "allow-status-page-public",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the rendered transcript omits %q:\n%s", want, out)
		}
	}
}

// The artifact the policy read and the artifact that was applied are always
// separate fields. The entire vulnerability class lives in the gap between them.
func TestArtifactFieldsAreNeverCollapsed(t *testing.T) {
	body, err := json.Marshal(Artifacts{})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{
		"source_configuration_digest", "resolved_desired_state_digest",
		"plan_artifact_digest", "artifact_evaluated_by_policy_digest", "applied_state_digest",
	} {
		if _, ok := fields[k]; !ok {
			t.Fatalf("the transcript has no %s field", k)
		}
	}
}

// The vulnerable path needs two separate opt-in actions, and neither alone is
// enough. Neither can be supplied by the scenario itself.
func TestVulnerableScenariosNeedBothOptIns(t *testing.T) {
	vulnerable := Scenarios["vulnerable-ungated"]
	secure := Scenarios["secure-apply"]

	cases := []struct {
		surface string
		ack     string
		allowed bool
	}{
		{SurfaceSecure, "", false},
		{SurfaceSecure, Acknowledgement, false},
		{SurfaceVulnerable, "", false},
		{SurfaceVulnerable, "yes", false},
		{SurfaceVulnerable, Acknowledgement, true},
	}
	for _, tc := range cases {
		if got := vulnerable.Available(tc.surface, tc.ack); got != tc.allowed {
			t.Fatalf("surface=%q acknowledgement=%q: available=%t, want %t", tc.surface, tc.ack, got, tc.allowed)
		}
		if !secure.Available(tc.surface, tc.ack) {
			t.Fatalf("a secure scenario became unavailable at surface=%q", tc.surface)
		}
	}
}

// The default surface offers no misconfigured scenario at all, whatever anyone
// acknowledges.
func TestDefaultSurfaceOffersNoVulnerableScenario(t *testing.T) {
	offered := AvailableScenarios(SurfaceSecure, Acknowledgement)
	for _, name := range offered {
		if Scenarios[name].Vulnerable {
			t.Fatalf("the secure surface offers %s", name)
		}
	}
	full := AvailableScenarios(SurfaceVulnerable, Acknowledgement)
	if len(full) <= len(offered) {
		t.Fatal("the vulnerable surface offers nothing extra")
	}
	vulnerable := 0
	for _, name := range full {
		if Scenarios[name].Vulnerable {
			vulnerable++
		}
	}
	if vulnerable == 0 {
		t.Fatal("no scenario is marked vulnerable")
	}
}

// Everything a vulnerable run produces says what it is.
func TestVulnerableRunsAreLabelled(t *testing.T) {
	if VulnerableWarning == "" {
		t.Fatal("there is no label")
	}
	for name, s := range Scenarios {
		if !s.Vulnerable {
			continue
		}
		if s.VarFile != "vulnerable.tfvars" {
			t.Fatalf("scenario %s is marked vulnerable but reads %s", name, s.VarFile)
		}
	}
	// A run that lands an exposure must declare that its reconciliation fails.
	if got := Scenarios["vulnerable-ungated"].ExpectReconciliationOf(); got != VerdictFail {
		t.Fatalf("the ungated vulnerable run expects reconciliation %s", got)
	}
	if got := Scenarios["vulnerable-gated"].ExpectReconciliationOf(); got != VerdictPass {
		t.Fatalf("the gated vulnerable run expects reconciliation %s", got)
	}
	if got := Scenarios["secure-apply"].ExpectReconciliationOf(); got != VerdictPass {
		t.Fatalf("the secure run expects reconciliation %s", got)
	}
}
