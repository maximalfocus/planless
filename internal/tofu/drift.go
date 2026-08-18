package tofu

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/maximalfocus/planless/internal/gate"
	"github.com/maximalfocus/planless/internal/graph"
)

// DriftDocument identifies a drift report on a mixed input stream.
const DriftDocument = "planless.drift"

// DriftReport is what the drift check found, and what it read to find it.
//
// A gate answers "may this be applied?". This answers a different question at a
// different moment: "is what is actually there something anybody allowlisted?"
// The repository can be entirely correct and the answer can still be no.
type DriftReport struct {
	Document string `json:"document"`
	Warning  string `json:"warning,omitempty"`

	ReadFrom      string `json:"read_from"`
	StateDigest   string `json:"platform_state_digest"`
	Allowlist     string `json:"allowlist"`
	Remediated    bool   `json:"remediated"`
	DriftDetected bool   `json:"drift_detected"`

	Findings  []gate.Violation `json:"findings"`
	Exposures []gate.Exposure  `json:"exposures"`
}

// Drift reads live platform state, normalizes it into the policy contract and
// evaluates it with the same policy the gate uses.
//
// It changes nothing. A drift check that repaired what it found would be a
// reconciliation loop, and the demonstration needs the gap between the world
// and the repository to stay visible.
func Drift(cfg Config, allowlist string) (*DriftReport, error) {
	if allowlist == "" {
		allowlist = "default.json"
	}
	state, err := readState(cfg.StateAPI)
	if err != nil {
		return nil, err
	}
	digest, err := stateDigest(cfg.StateAPI)
	if err != nil {
		return nil, err
	}
	normalized, err := graph.FromPlatformState(*state, segments())
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	decision := gate.Evaluate(gate.Config{
		OPA:           cfg.OPA,
		PolicyDir:     cfg.PolicyDir,
		AllowlistPath: cfg.AllowlistDir + "/" + allowlist,
	}, body)

	report := &DriftReport{
		Document:      DriftDocument,
		ReadFrom:      "the control plane's read-only state API",
		StateDigest:   digest,
		Allowlist:     allowlist,
		Remediated:    false,
		DriftDetected: decision.Denied(),
		Findings:      decision.Violations,
		Exposures:     decision.Exposures,
	}
	if report.Findings == nil {
		report.Findings = []gate.Violation{}
	}
	sort.Slice(report.Findings, func(i, j int) bool {
		return report.Findings[i].Resource < report.Findings[j].Resource
	})
	return report, nil
}

// Render produces the human-readable form of a drift report.
func (r *DriftReport) Render() string {
	var b strings.Builder
	if r.Warning != "" {
		fmt.Fprintf(&b, "*** %s ***\n\n", r.Warning)
	}
	fmt.Fprintf(&b, "drift check\n")
	fmt.Fprintf(&b, "  %-30s %s\n", "read from", r.ReadFrom)
	fmt.Fprintf(&b, "  %-30s %s\n", "platform state", r.StateDigest)
	fmt.Fprintf(&b, "  %-30s %s\n", "reviewed allowlist", r.Allowlist)
	fmt.Fprintf(&b, "  %-30s %t\n", "remediated anything", r.Remediated)
	if !r.DriftDetected {
		fmt.Fprintln(&b, "\nno drift: everything reachable is something the allowlist names")
		return b.String()
	}
	fmt.Fprintln(&b, "\ndrift detected")
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "  %-30s %s\n", f.Resource, f.Exposure)
	}
	fmt.Fprintln(&b, "\nthe repository may be entirely correct. this is what is actually there.")
	return b.String()
}

func readState(api string) (*graph.State, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(api + "/v1/state")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the control plane returned %d reading state", resp.StatusCode)
	}
	var state graph.State
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

// DriftGrantID names the one change the drift scenario makes directly at the
// control plane. It is enumerated, documented, and the only such change the
// demonstration can make.
const DriftGrantID = "grant-fare-exports-console-read"

// applyDriftMutation makes that change: an anonymous read grant on the refund
// export, added straight at the platform, the way somebody would in a console.
// No configuration describes it, and no plan contains it.
func applyDriftMutation(api string) error {
	body, err := json.Marshal(map[string]any{
		"grant": map[string]any{
			"id":            DriftGrantID,
			"resource_kind": "bucket",
			"resource_name": "fare-exports",
			"principals":    []string{"*"},
			"actions":       []string{"read"},
			"source_ranges": []string{"0.0.0.0/0"},
		},
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, api+"/v1/resources/grant", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Democloud-Principal", "platform-deployer")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the control plane returned %d for the direct change", resp.StatusCode)
	}
	return nil
}

// RemoveDriftedGrant deletes the grant the drift scenario added directly at the
// control plane.
//
// This is deliberately not part of the drift check. The check reports; somebody
// then decides what to do about it. A check that quietly repaired what it found
// would hide the very gap the demonstration exists to show, and would make
// "the repository is correct and the world is not" impossible to observe.
func RemoveDriftedGrant(api string) error {
	req, err := http.NewRequest(http.MethodDelete, api+"/v1/resources/grant/"+DriftGrantID, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Democloud-Principal", "platform-deployer")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the control plane returned %d removing the drifted grant", resp.StatusCode)
	}
	return nil
}
