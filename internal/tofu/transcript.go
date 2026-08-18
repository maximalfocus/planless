package tofu

import (
	"fmt"
	"sort"
	"strings"

	"github.com/maximalfocus/planless/internal/gate"
)

// Stable operator-facing results. A refusal returns the same string whatever
// the reason: an operator learns that the deployment was refused, and nothing
// about whether a resource, field, allowlist entry or principal exists.
const (
	ResultDeployed = "DEPLOYED"
	ResultRefused  = "DEPLOY_REFUSED"
)

// Stages a refusal can happen at.
const (
	StageNormalization = "normalization"
	StagePolicy        = "policy"
	StageBinding       = "binding"
)

// Artifacts are the four things a pipeline produces, kept apart on purpose.
// The whole vulnerability class lives in the gap between the artifact a policy
// read and the artifact that was applied, so they are never one field.
type Artifacts struct {
	SourceConfiguration  string `json:"source_configuration_digest"`
	ResolvedDesiredState string `json:"resolved_desired_state_digest"`
	PlanArtifact         string `json:"plan_artifact_digest"`
	EvaluatedByPolicy    string `json:"artifact_evaluated_by_policy_digest"`
	AppliedState         string `json:"applied_state_digest"`

	// EvaluatedBy names what actually read the resolved desired state.
	EvaluatedBy string `json:"artifact_evaluated_by"`
}

// Enforcement is what the pipeline did about the decision.
type Enforcement struct {
	Applied        bool   `json:"applied"`
	OperatorResult string `json:"operator_result"`
	RefusedAtStage string `json:"refused_at_stage,omitempty"`
}

// AuditEvent is the structured record of one refusal. It carries a stable
// failure class and rule id, and no credential, hostname, address, URL or
// exported record content.
type AuditEvent struct {
	Event         string `json:"event"`
	CorrelationID string `json:"correlation_id"`
	Scenario      string `json:"scenario"`
	Class         string `json:"class"`
	Rule          string `json:"rule"`
	Stage         string `json:"stage"`
}

// Stage records one toolchain invocation.
type Stage struct {
	Name     string `json:"name"`
	Command  string `json:"command"`
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output,omitempty"`
}

// Observation is one thing a client on one segment could or could not reach.
type Observation struct {
	Segment   string `json:"segment"`
	Resource  string `json:"resource"`
	Reachable bool   `json:"reachable"`
	Status    int    `json:"status"`
	Digest    string `json:"digest,omitempty"`
}

// ObservationSet is what one client reports.
type ObservationSet struct {
	Document     string        `json:"document"`
	Segment      string        `json:"segment"`
	Observations []Observation `json:"observations"`
}

// ValueOrigin says where one resolved security-relevant value came from. It is
// the difference between "this is exposed" and "this is exposed, and here is the
// file nobody opened".
type ValueOrigin struct {
	Resource     string `json:"resource"`
	Field        string `json:"field"`
	Origin       string `json:"origin"`
	Reference    string `json:"reference"`
	Contributors string `json:"contributors,omitempty"`
}

// Reconciliation compares what the gate decided against what the public
// segment can actually reach. A policy decision is not evidence of exposure
// state, so this is computed from observations and never from a verdict.
type Reconciliation struct {
	Verdict           string   `json:"verdict"`
	Expected          string   `json:"expected_verdict"`
	Reason            string   `json:"reason"`
	PubliclyReachable []string `json:"publicly_reachable"`
	AllowedPublic     []string `json:"allowed_public"`
}

// Transcript is the deterministic record of one pipeline run.
type Transcript struct {
	Document      string `json:"document"`
	Scenario      string `json:"scenario"`
	CorrelationID string `json:"correlation_id"`

	// Warning labels everything a vulnerable run produces.
	Warning string `json:"warning,omitempty"`

	// ApplicationBuild is the digest the fare engine reports of its own
	// executable. It is here so "the application is identical across variants"
	// can be compared rather than asserted.
	ApplicationBuild string `json:"application_build_digest,omitempty"`

	Stages    []Stage   `json:"stages"`
	Artifacts Artifacts `json:"artifacts"`

	SourceLayout []Finding       `json:"source_layout_findings"`
	Decision     *gate.Decision  `json:"policy_decision,omitempty"`
	Enforcement  Enforcement     `json:"enforcement"`
	Audit        []AuditEvent    `json:"audit"`
	StateBefore  string          `json:"platform_state_before"`
	StateAfter   string          `json:"platform_state_after"`
	Observations []Observation   `json:"observations"`
	Provenance   []ValueOrigin   `json:"value_origins"`
	Reconcile    *Reconciliation `json:"reconciliation,omitempty"`

	Expected string `json:"expected_outcome"`
	Passed   bool   `json:"passed"`
	Error    string `json:"error,omitempty"`
}

// TranscriptDocument identifies a transcript on a mixed input stream.
const TranscriptDocument = "planless.transcript"

// ObservationDocument identifies an observation set on a mixed input stream.
const ObservationDocument = "planless.observations"

// Render produces the deterministic human-readable form of a transcript. It is
// the teaching artifact, and it deliberately shows more than the operator-facing
// result does: what the policy read, and what was applied, as separate fields.
func (t *Transcript) Render() string {
	var b strings.Builder
	line := func(k, v string) {
		fmt.Fprintf(&b, "  %-34s %s\n", k, v)
	}
	if t.Warning != "" {
		fmt.Fprintf(&b, "*** %s ***\n\n", t.Warning)
	}
	fmt.Fprintf(&b, "scenario %s (%s)\n", t.Scenario, t.CorrelationID)

	fmt.Fprintln(&b, "\nartifacts")
	line("source configuration", or(t.Artifacts.SourceConfiguration))
	line("resolved desired state", or(t.Artifacts.ResolvedDesiredState))
	line("plan artifact (apply input)", or(t.Artifacts.PlanArtifact))
	line("artifact the policy evaluated", or(t.Artifacts.EvaluatedByPolicy))
	line("evaluated by", or(t.Artifacts.EvaluatedBy))
	line("applied state", or(t.Artifacts.AppliedState))

	if t.Decision != nil {
		fmt.Fprintln(&b, "\ncomputed effective exposure")
		for _, e := range t.Decision.Exposures {
			admitted := e.AdmittedBy
			if admitted == "" {
				admitted = "not admitted"
			}
			line(e.Resource, e.Computed+"  ["+admitted+"]")
		}
		fmt.Fprintf(&b, "\ndecision %s\n", t.Decision.Result)
		for _, v := range t.Decision.Violations {
			line(v.Class, v.Resource+": "+v.Reason)
		}
	}

	fmt.Fprintln(&b, "\nenforcement")
	line("applied", fmt.Sprintf("%t", t.Enforcement.Applied))
	line("operator result", t.Enforcement.OperatorResult)
	if t.Enforcement.RefusedAtStage != "" {
		line("refused at stage", t.Enforcement.RefusedAtStage)
	}
	line("platform state before", or(t.StateBefore))
	line("platform state after", or(t.StateAfter))
	line("application build", or(t.ApplicationBuild))

	for _, e := range t.Audit {
		fmt.Fprintf(&b, "\naudit %s class=%s rule=%s stage=%s correlation=%s\n",
			e.Event, e.Class, or(e.Rule), e.Stage, e.CorrelationID)
	}

	if len(t.Observations) > 0 {
		fmt.Fprintln(&b, "\nobservations")
		for _, o := range t.Observations {
			line(o.Segment+" -> "+o.Resource, reach(o))
		}
	}
	if t.Reconcile != nil {
		note := ""
		if t.Reconcile.Expected != "" && t.Reconcile.Expected != VerdictPass {
			note = fmt.Sprintf(" (a %s here is the demonstration)", t.Reconcile.Expected)
		}
		fmt.Fprintf(&b, "\nreconciliation %s%s — %s\n", t.Reconcile.Verdict, note, t.Reconcile.Reason)
	}
	if t.Decision == nil {
		fmt.Fprintln(&b, "\nno artifact was evaluated: this pipeline has no policy step")
	}
	if len(t.Provenance) > 0 {
		fmt.Fprintln(&b, "\nwhere the exposure values came from")
		for _, p := range t.Provenance {
			line(p.Resource+"."+p.Field, p.Origin+" ("+p.Reference+")")
		}
	}
	fmt.Fprintf(&b, "\nexpected %s, %s\n", t.Expected, passed(t.Passed))
	if t.Error != "" {
		fmt.Fprintf(&b, "error: %s\n", t.Error)
	}
	return b.String()
}

func reach(o Observation) string {
	state := "refused"
	if o.Reachable {
		state = "reachable"
	}
	out := fmt.Sprintf("%s (status %d)", state, o.Status)
	if o.Digest != "" {
		out += " " + o.Digest
	}
	return out
}

func or(v string) string {
	if v == "" {
		return "—"
	}
	return v
}

func passed(v bool) string {
	if v {
		return "passed"
	}
	return "FAILED"
}

// sortObservations keeps the transcript deterministic whatever order the
// segments reported in.
func sortObservations(in []Observation) []Observation {
	out := append([]Observation(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Segment != out[j].Segment {
			return out[i].Segment < out[j].Segment
		}
		return out[i].Resource < out[j].Resource
	})
	return out
}
