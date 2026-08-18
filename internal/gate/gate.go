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

// Query is the single decision the policy is asked for.
const Query = "data.planless.gate.decision"

// Config locates the engine, the policy body, and the reviewed allowlist.
type Config struct {
	OPA           string
	PolicyDir     string
	AllowlistPath string
	Timeout       time.Duration
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
	Resource   string `json:"resource"`
	Computed   string `json:"computed"`
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

// Evaluate asks the policy for a decision about one normalized graph.
func Evaluate(cfg Config, graphJSON []byte) Decision {
	if !json.Valid(graphJSON) {
		return denial(ClassUnparsablePlan, "the policy input is not valid JSON")
	}
	if _, err := os.Stat(cfg.AllowlistPath); err != nil {
		return denial(ClassEngineError, "the reviewed allowlist could not be read")
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	cmd := exec.Command(cfg.OPA, "eval",
		"--format", "json",
		"--data", cfg.PolicyDir,
		"--data", cfg.AllowlistPath,
		"--stdin-input",
		Query,
	)
	cmd.Stdin = bytes.NewReader(graphJSON)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = []string{"PATH=/usr/local/bin", "HOME=/tmp", "TMPDIR=/tmp"}

	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return denial(ClassEngineError, "the policy engine could not be started")
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return denial(ClassEngineError, fmt.Sprintf("the policy engine failed: %s", firstLine(stderr.Bytes())))
		}
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		return denial(ClassEngineError, "the policy engine did not finish in time")
	}
	return parse(stdout.Bytes())
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
