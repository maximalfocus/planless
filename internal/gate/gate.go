// Package gate evaluates a normalized resource graph against the deny-by-default
// policy and returns one decision.
//
// Every failure mode here is a denial. A policy engine that errors, a bundle
// that is empty, a decision that is missing or malformed, an artifact that does
// not parse: each of them ends in `deny`, because the alternative — treating an
// unanswered question as a yes — is the whole category of failure this project
// is about.
package gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// Stable decision results.
const (
	ResultAdmit = "admit"
	ResultDeny  = "deny"
)

// Stable failure classes the gate itself produces.
const (
	ClassEngineError    = "policy_engine_error"
	ClassNoDecision     = "no_decision"
	ClassUnparsablePlan = "unparsable_artifact"
	ClassMalformed      = "malformed_decision"
)

// Queries the policy bundle answers.
const (
	// Query is the decision the deployment gate is asked for.
	Query = "data.planless.gate.decision"

	// ScanQuery is the report a scan of the source configuration produces. It
	// is a separate policy over a separate artifact, which is the whole reason
	// this demonstration exists.
	ScanQuery = "data.planless.source_scan.report"

	// DenylistQuery is the report a denylist of known-bad literals produces
	// over the resolved desired state: the right artifact, the wrong question.
	DenylistQuery = "data.planless.denylist.report"
)

// Config locates the engine, the policy body, and the reviewed allowlist.
type Config struct {
	OPA           string
	PolicyDir     string
	AllowlistPath string
	Timeout       time.Duration
}

// ScanFinding is one thing a source scan matched.
type ScanFinding struct {
	Rule   string `json:"rule"`
	File   string `json:"file"`
	Reason string `json:"reason"`
}

// ScanReport is a source scan's account of itself: what it read, what it found,
// and what it did not read.
type ScanReport struct {
	ScannedFiles []string      `json:"scanned_files"`
	Findings     []ScanFinding `json:"findings"`
	FindingCount int           `json:"finding_count"`
	Artifact     string        `json:"artifact"`
	CorrectAbout string        `json:"correct_about"`
	DidNotRead   string        `json:"did_not_read"`
}

// Violation is one reason the gate refused.
type Violation struct {
	Class    string `json:"class"`
	Resource string `json:"resource"`
	Exposure string `json:"exposure"`
	Reason   string `json:"reason"`
}

// Exposure is the reachability the policy computed for one resource.
type Exposure struct {
	Resource string `json:"resource"`
	Computed string `json:"computed"`

	// Reachability is the exposure without the rules that produced it: who can
	// reach this, from where. Two spellings of one desired state differ in
	// their rules and agree here.
	Reachability string `json:"reachability"`

	AdmittedBy string `json:"admitted_by"`
}

// Decision is the gate's answer.
type Decision struct {
	Result     string      `json:"result"`
	Class      string      `json:"class"`
	Violations []Violation `json:"violations"`
	Exposures  []Exposure  `json:"exposures"`
}

// Denied reports whether the decision refuses the deployment.
func (d Decision) Denied() bool { return d.Result != ResultAdmit }

func denial(class, reason string) Decision {
	return Decision{
		Result:     ResultDeny,
		Class:      class,
		Violations: []Violation{{Class: class, Resource: "<artifact>", Reason: reason}},
		Exposures:  []Exposure{},
	}
}

// Scan runs the source-configuration scan over a bundle of source files.
//
// A scan that fails to run is an error, not an empty finding list. "It found
// nothing" is only worth saying when the scan actually ran.
func Scan(cfg Config, bundle []byte) (ScanReport, error) {
	raw, err := run(cfg, bundle, ScanQuery)
	if err != nil {
		return ScanReport{}, err
	}
	value, err := expressionValue(raw)
	if err != nil {
		return ScanReport{}, err
	}
	var report ScanReport
	if err := json.Unmarshal(value, &report); err != nil {
		return ScanReport{}, fmt.Errorf("the scan returned a report this runner cannot read: %w", err)
	}
	if len(report.ScannedFiles) == 0 {
		return ScanReport{}, errors.New("the scan reports having read no files at all")
	}
	if report.Findings == nil {
		report.Findings = []ScanFinding{}
	}
	return report, nil
}

// DenylistFinding is one literal a denylist rule matched.
type DenylistFinding struct {
	Rule     string `json:"rule"`
	Resource string `json:"resource"`
	Matched  string `json:"matched"`
	Reason   string `json:"reason"`
}

// DenylistReport is a denylist's account of itself: which rules it has, what
// they matched, and what kind of answer that is.
type DenylistReport struct {
	Rules        []string          `json:"rules"`
	Findings     []DenylistFinding `json:"findings"`
	FindingCount int               `json:"finding_count"`
	Artifact     string            `json:"artifact"`
	Method       string            `json:"method"`
	Limitation   string            `json:"limitation"`
}

// Denylist runs the literal-matching rules over a normalized graph.
//
// A denylist that fails to run is an error, not an empty finding list.
func Denylist(cfg Config, graphJSON []byte) (DenylistReport, error) {
	raw, err := run(cfg, graphJSON, DenylistQuery)
	if err != nil {
		return DenylistReport{}, err
	}
	value, err := expressionValue(raw)
	if err != nil {
		return DenylistReport{}, err
	}
	var report DenylistReport
	if err := json.Unmarshal(value, &report); err != nil {
		return DenylistReport{}, fmt.Errorf("the denylist returned a report this runner cannot read: %w", err)
	}
	if len(report.Rules) == 0 {
		return DenylistReport{}, errors.New("the denylist reports having no rules at all")
	}
	if report.Findings == nil {
		report.Findings = []DenylistFinding{}
	}
	return report, nil
}

// Evaluate asks the policy for a decision about one normalized graph.
func Evaluate(cfg Config, graphJSON []byte) Decision {
	if !json.Valid(graphJSON) {
		return denial(ClassUnparsablePlan, "the policy input is not valid JSON")
	}
	if _, err := os.Stat(cfg.AllowlistPath); err != nil {
		return denial(ClassEngineError, "the reviewed allowlist could not be read")
	}
	raw, err := run(cfg, graphJSON, Query)
	if err != nil {
		return denial(ClassEngineError, err.Error())
	}
	return parse(raw)
}

// run asks the policy engine one query over one input document.
func run(cfg Config, input []byte, query string) ([]byte, error) {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	cmd := exec.Command(cfg.OPA, "eval",
		"--format", "json",
		"--data", cfg.PolicyDir,
		"--data", cfg.AllowlistPath,
		"--stdin-input",
		query,
	)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = []string{"PATH=/usr/local/bin", "HOME=/tmp", "TMPDIR=/tmp"}

	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return nil, errors.New("the policy engine could not be started")
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return nil, fmt.Errorf("the policy engine failed: %s", firstLine(stderr.Bytes()))
		}
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		return nil, errors.New("the policy engine did not finish in time")
	}
	return stdout.Bytes(), nil
}

// expressionValue pulls the single answer out of an engine result.
func expressionValue(raw []byte) (json.RawMessage, error) {
	var out evalOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("the policy engine returned output this runner cannot read: %w", err)
	}
	if len(out.Result) == 0 || len(out.Result[0].Expressions) == 0 {
		return nil, errors.New("the policy returned no answer")
	}
	return out.Result[0].Expressions[0].Value, nil
}

type evalOutput struct {
	Result []struct {
		Expressions []struct {
			Value json.RawMessage `json:"value"`
		} `json:"expressions"`
	} `json:"result"`
}

func parse(raw []byte) Decision {
	var out evalOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return denial(ClassMalformed, "the policy engine returned output this gate cannot read")
	}
	if len(out.Result) == 0 || len(out.Result[0].Expressions) == 0 {
		// An undefined decision is the shape an empty policy bundle takes.
		return denial(ClassNoDecision, "the policy returned no decision")
	}
	var d Decision
	if err := json.Unmarshal(out.Result[0].Expressions[0].Value, &d); err != nil {
		return denial(ClassMalformed, "the policy returned a decision this gate cannot read")
	}
	if d.Result != ResultAdmit && d.Result != ResultDeny {
		return denial(ClassMalformed, "the policy returned an unrecognized result")
	}
	if d.Result == ResultAdmit && len(d.Violations) > 0 {
		return denial(ClassMalformed, "the policy admitted a deployment while reporting violations")
	}
	if d.Violations == nil {
		d.Violations = []Violation{}
	}
	if d.Exposures == nil {
		d.Exposures = []Exposure{}
	}
	return d
}

func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	if len(b) > 200 {
		b = b[:200]
	}
	return string(bytes.TrimSpace(b))
}
