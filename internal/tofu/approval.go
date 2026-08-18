package tofu

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/maximalfocus/planless/internal/canon"
)

// Refusal classes the binding produces. They are stable strings: an operator
// sees none of them, and an audit record carries exactly one.
const (
	ClassNoApproval       = "plan_artifact_not_approved"
	ClassDigestMismatch   = "plan_artifact_changed_after_approval"
	ClassApprovalOtherRun = "approval_issued_for_another_run"
	ClassApprovalUnusable = "approval_unreadable"
)

// Approval is what an admitted policy decision produces: a statement that one
// exact artifact, identified by digest, may be applied in this run.
//
// This is the whole of the gate's authority. A plan that was not approved
// cannot be applied, so a second path to apply cannot exist.
type Approval struct {
	RunID              string `json:"run_id"`
	Scenario           string `json:"scenario"`
	PlanArtifactDigest string `json:"plan_artifact_digest"`
	ResolvedDigest     string `json:"resolved_desired_state_digest"`
	Allowlist          string `json:"allowlist"`
}

// RunID identifies one run deterministically: the same scenario and the same
// plan artifact always produce the same run, and a different artifact never
// does.
func RunID(scenario, planDigest string) string {
	return canon.Digest([]byte(scenario + "\n" + planDigest))
}

// Write records an approval where the apply step will look for it.
func (a Approval) Write(path string) error {
	body, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o600)
}

// ReadApproval loads an approval, treating anything unreadable as absent.
func ReadApproval(path string) (Approval, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Approval{}, fmt.Errorf("%w: %v", errNoApproval, err)
	}
	var a Approval
	if err := json.Unmarshal(body, &a); err != nil {
		return Approval{}, fmt.Errorf("%w: %v", errUnusableApproval, err)
	}
	if a.RunID == "" || a.PlanArtifactDigest == "" {
		return Approval{}, errUnusableApproval
	}
	return a, nil
}

var (
	errNoApproval       = errors.New("no approval")
	errUnusableApproval = errors.New("unusable approval")
)

// VerifyApproval decides whether the artifact about to be applied is the one
// the gate approved in this run.
//
// It runs before any platform operation. Nothing is contacted, nothing is
// created, and nothing is changed by a refusal here.
func VerifyApproval(approvalPath, planPath, scenario string) (string, error) {
	plan, err := os.ReadFile(planPath)
	if err != nil {
		return ClassNoApproval, fmt.Errorf("the plan artifact could not be read: %w", err)
	}
	digest := canon.Digest(plan)

	approval, err := ReadApproval(approvalPath)
	switch {
	case errors.Is(err, errNoApproval):
		return ClassNoApproval, errors.New("no approval exists for this artifact")
	case errors.Is(err, errUnusableApproval):
		return ClassApprovalUnusable, errors.New("the approval could not be read")
	case err != nil:
		return ClassApprovalUnusable, err
	}
	if approval.PlanArtifactDigest != digest {
		return ClassDigestMismatch, errors.New("the artifact is not the one that was approved")
	}
	if approval.RunID != RunID(scenario, digest) {
		return ClassApprovalOtherRun, errors.New("the approval was issued for another run")
	}
	return "", nil
}
