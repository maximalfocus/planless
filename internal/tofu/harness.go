package tofu

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/maximalfocus/planless/internal/canon"
	"github.com/maximalfocus/planless/internal/fixtures"
	"github.com/maximalfocus/planless/internal/gate"
	"github.com/maximalfocus/planless/internal/graph"
)

// Config is resolved from the container image layout, not from user input.
type Config struct {
	Tofu      string
	InfraDir  string
	WorkDir   string
	DataDir   string
	TempDir   string
	CLIConfig string
	StateAPI  string

	OPA          string
	PolicyDir    string
	AllowlistDir string
	ArtifactDir  string
}

// Run executes one enumerated scenario end to end and returns its transcript.
//
// The transcript is returned whatever happens: a refusal is an outcome, not an
// error, and the record of a refusal is the most interesting thing this
// pipeline produces.
func Run(cfg Config, scenario Scenario) (*Transcript, error) {
	t := &Transcript{
		Document:      TranscriptDocument,
		Scenario:      scenario.ID,
		CorrelationID: correlationID(scenario.ID),
		Expected:      scenario.Expect,
		Stages:        []Stage{},
		SourceLayout:  []Finding{},
		Audit:         []AuditEvent{},
		Observations:  []Observation{},
		Enforcement:   Enforcement{OperatorResult: ResultRefused},
	}
	t.Artifacts.EvaluatedBy = "nothing"

	if !scenario.SkipRemote {
		before, err := stateDigest(cfg.StateAPI)
		if err != nil {
			return t, err
		}
		t.StateBefore = before
		t.StateAfter = before
	}

	if err := prepare(cfg); err != nil {
		return t, err
	}
	sourceDigest, err := digestTree(cfg.WorkDir)
	if err != nil {
		return t, err
	}
	t.Artifacts.SourceConfiguration = sourceDigest

	findings, err := CheckSources(cfg.WorkDir)
	if err != nil {
		return t, err
	}
	t.SourceLayout = findings
	if len(findings) > 0 {
		return t, fmt.Errorf("configuration source layout is wrong: %+v", findings)
	}

	planPath := filepath.Join(cfg.WorkDir, "plan.tfplan")
	var evaluated []byte

	if scenario.Artifact == "" {
		if err := t.run(cfg, "init", "-input=false", "-no-color"); err != nil {
			return t, err
		}
		if err := t.run(cfg, "plan", "-input=false", "-no-color", "-lock=false",
			"-var-file="+scenario.VarFile, "-out=plan.tfplan"); err != nil {
			return t, err
		}
		planBytes, err := os.ReadFile(planPath)
		if err != nil {
			return t, err
		}
		t.Artifacts.PlanArtifact = canon.Digest(planBytes)

		planJSON, err := t.capture(cfg, "show", "-json", "plan.tfplan")
		if err != nil {
			return t, err
		}
		resolved, err := CanonicalPlan(planJSON)
		if err != nil {
			return t, err
		}
		t.Artifacts.ResolvedDesiredState = canon.Digest(resolved)
		if missing := ValuesMissingFromPlan(resolved); len(missing) > 0 {
			return t, fmt.Errorf("resolved artifact is missing security-relevant values %v", missing)
		}
		evaluated = resolved
	} else {
		// A refusal rehearsal. The policy is given a checked-in artifact
		// carrying one exposure shape, because no vulnerable configuration
		// exists in this repository. Nothing is planned, so nothing could be
		// applied even if the gate let it through.
		body, err := os.ReadFile(filepath.Join(cfg.ArtifactDir, scenario.Artifact))
		if err != nil {
			return t, err
		}
		evaluated = body
		t.Artifacts.ResolvedDesiredState = canon.Digest(body)
	}

	if !scenario.Gated {
		return t.finish(cfg, scenario, planPath)
	}
	t.Artifacts.EvaluatedByPolicy = canon.Digest(evaluated)
	t.Artifacts.EvaluatedBy = "the deny-by-default policy, over the resolved desired state"

	decision := t.evaluate(cfg, scenario, evaluated)
	t.Decision = &decision
	if decision.Denied() {
		t.refuse(StagePolicy, classOf(decision), "deny-by-default")
		return t.finish(cfg, scenario, planPath)
	}

	approval := Approval{
		RunID:              RunID(scenario.ID, t.Artifacts.PlanArtifact),
		Scenario:           scenario.ID,
		PlanArtifactDigest: t.Artifacts.PlanArtifact,
		ResolvedDigest:     t.Artifacts.ResolvedDesiredState,
		Allowlist:          scenario.AllowlistOf(),
	}
	approvalPath := filepath.Join(cfg.WorkDir, "approval.json")
	if err := t.rehearseBinding(scenario, approval, approvalPath, planPath); err != nil {
		return t, err
	}

	// The binding check happens here, before anything is applied and before the
	// control plane is contacted at all.
	if class, err := VerifyApproval(approvalPath, planPath, scenario.ID); err != nil {
		t.refuse(StageBinding, class, "gate-to-apply-binding")
		return t.finish(cfg, scenario, planPath)
	}

	return t.finish(cfg, scenario, planPath)
}

// rehearseBinding sets up one enumerated way the binding can be broken. Each is
// a checked-in rehearsal of a real failure, not a configurable option.
func (t *Transcript) rehearseBinding(scenario Scenario, approval Approval, approvalPath, planPath string) error {
	switch scenario.Binding {
	case BindingUnapproved:
		// No approval is written at all.
		return nil
	case BindingStale:
		approval.RunID = RunID("some-other-run", approval.PlanArtifactDigest)
		return approval.Write(approvalPath)
	case BindingModified:
		if err := approval.Write(approvalPath); err != nil {
			return err
		}
		// The artifact changes after approval. One byte is enough.
		f, err := os.OpenFile(planPath, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.Write([]byte{0})
		return err
	default:
		return approval.Write(approvalPath)
	}
}

func (t *Transcript) evaluate(cfg Config, scenario Scenario, artifact []byte) gate.Decision {
	normalized, err := graph.FromPlan(artifact, segments())
	if err != nil {
		return gate.Decision{
			Result: gate.ResultDeny,
			Class:  gate.ClassUnparsablePlan,
			Violations: []gate.Violation{{
				Class: gate.ClassUnparsablePlan, Resource: "<artifact>", Reason: err.Error(),
			}},
			Exposures: []gate.Exposure{},
		}
	}
	body, err := json.Marshal(normalized)
	if err != nil {
		return gate.Decision{
			Result: gate.ResultDeny, Class: gate.ClassEngineError,
			Violations: []gate.Violation{{Class: gate.ClassEngineError, Resource: "<artifact>", Reason: err.Error()}},
			Exposures:  []gate.Exposure{},
		}
	}
	opa := cfg.OPA
	if scenario.BreakEngine {
		opa = filepath.Join(cfg.WorkDir, "policy-engine-that-is-not-there")
	}
	return gate.Evaluate(gate.Config{
		OPA:           opa,
		PolicyDir:     cfg.PolicyDir,
		AllowlistPath: filepath.Join(cfg.AllowlistDir, scenario.AllowlistOf()),
	}, body)
}

// finish applies when nothing refused, then records the outcome and asserts the
// scenario's declared expectation.
func (t *Transcript) finish(cfg Config, scenario Scenario, planPath string) (*Transcript, error) {
	refused := len(t.Audit) > 0
	if !refused && scenario.Artifact != "" {
		return t, fmt.Errorf("scenario %s evaluated a checked-in artifact and was not refused", scenario.ID)
	}
	if !refused && !scenario.SkipApply {
		if err := t.run(cfg, "apply", "-input=false", "-no-color", "-lock=false", "plan.tfplan"); err != nil {
			return t, err
		}
		t.Enforcement.Applied = true
		t.Enforcement.OperatorResult = ResultDeployed
	}
	if !refused && scenario.SkipApply {
		t.Enforcement.OperatorResult = ResultDeployed
	}
	if !scenario.SkipRemote {
		after, err := stateDigest(cfg.StateAPI)
		if err != nil {
			return t, err
		}
		t.StateAfter = after
		if t.Enforcement.Applied {
			t.Artifacts.AppliedState = after
		}
	}

	t.Passed = t.assert(scenario)
	if !t.Passed {
		return t, fmt.Errorf("scenario %s did not meet its declared outcome", scenario.ID)
	}
	return t, nil
}

// assert checks the scenario's declared outcome. A refusal must additionally
// have changed nothing at all.
func (t *Transcript) assert(scenario Scenario) bool {
	switch scenario.Expect {
	case ExpectApplied:
		return t.Enforcement.OperatorResult == ResultDeployed
	case ExpectRefused:
		if t.Enforcement.OperatorResult != ResultRefused || t.Enforcement.Applied {
			return false
		}
		if len(t.Audit) != 1 {
			return false
		}
		if !scenario.SkipRemote && t.StateBefore != t.StateAfter {
			return false
		}
		return true
	}
	return false
}

// refuse records the one audit event a refusal produces and sets the generic
// operator-facing result.
func (t *Transcript) refuse(stage, class, rule string) {
	t.Enforcement.Applied = false
	t.Enforcement.OperatorResult = ResultRefused
	t.Enforcement.RefusedAtStage = stage
	t.Audit = append(t.Audit, AuditEvent{
		Event:         ResultRefused,
		CorrelationID: t.CorrelationID,
		Scenario:      t.Scenario,
		Class:         class,
		Rule:          rule,
		Stage:         stage,
	})
}

// classOf names the stable failure class an audit record carries. It is the
// class of the first violation, or the gate's own class when the policy never
// reached a decision at all.
func classOf(d gate.Decision) string {
	if len(d.Violations) == 0 {
		return d.Class
	}
	return d.Violations[0].Class
}

// correlationID is deterministic per scenario. It correlates the records of one
// run and is not a user identifier.
func correlationID(scenario string) string {
	return scenario + "-" + canon.Digest([]byte(scenario))[7:15]
}

func segments() []graph.Segment {
	out := make([]graph.Segment, 0, 2)
	for _, s := range fixtures.Segments() {
		out = append(out, graph.Segment{Name: s.Name, CIDR: s.CIDR})
	}
	return out
}

func stateDigest(api string) (string, error) {
	client := &httpClient{timeout: 10 * time.Second}
	return client.stateDigest(api)
}
