// Command gate normalizes a resolved plan artifact and asks the deny-by-default
// policy for a decision.
//
// It reads the artifact on standard input and accepts no other input: no
// endpoint, no policy override, no severity threshold, and no mode that turns a
// denial into a warning.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/maximalfocus/planless/internal/fixtures"
	"github.com/maximalfocus/planless/internal/gate"
	"github.com/maximalfocus/planless/internal/graph"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "verify-fixtures" {
		verifyFixtures()
		return
	}
	if len(os.Args) != 2 || (os.Args[1] != "normalize" && os.Args[1] != "evaluate") {
		fmt.Fprintln(os.Stderr,
			"usage: gate <normalize|evaluate|verify-fixtures>  (an artifact is read from standard input)")
		os.Exit(64)
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 32<<20))
	if err != nil {
		fmt.Fprintln(os.Stderr, "gate: reading the artifact:", err)
		os.Exit(2)
	}

	if os.Args[1] == "normalize" {
		normalized, normErr := graph.FromPlan(raw, segments())
		if normErr != nil {
			fmt.Fprintln(os.Stderr, "gate:", normErr)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(normalized, "", "  ")
		fmt.Println(string(out))
		return
	}

	decision := decide(raw)
	out, _ := json.MarshalIndent(decision, "", "  ")
	fmt.Println(string(out))
	if decision.Denied() {
		os.Exit(1)
	}
}

// verifyFixtures decides every checked-in plan artifact and asserts the outcome
// each one is there to prove: the secure artifact is admitted, and every
// modified artifact is refused.
func verifyFixtures() {
	dir := env("PLANLESS_ARTIFACTS", "/testdata/plans")
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gate:", err)
		os.Exit(2)
	}
	type result struct {
		Artifact string `json:"artifact"`
		Expected string `json:"expected"`
		Result   string `json:"result"`
		Class    string `json:"class"`
		Passed   bool   `json:"passed"`
	}
	results := []result{}
	passed := true
	seen := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".json" {
			continue
		}
		seen++
		want := gate.ResultDeny
		if name == "secure.json" {
			want = gate.ResultAdmit
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			fmt.Fprintln(os.Stderr, "gate:", err)
			os.Exit(2)
		}
		decision := decide(raw)
		r := result{Artifact: name, Expected: want, Result: decision.Result, Class: decision.Class}
		r.Passed = decision.Result == want
		passed = passed && r.Passed
		results = append(results, r)
	}
	if seen < 2 {
		fmt.Fprintln(os.Stderr, "gate: no checked-in plan artifacts were found")
		os.Exit(2)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"check":   "checked-in-plan-artifacts",
		"results": results,
		"passed":  passed,
	}, "", "  ")
	fmt.Println(string(out))
	if !passed {
		os.Exit(1)
	}
}

// decide normalizes an artifact and asks the policy about it, refusing anything
// the normalizer cannot read before the policy is ever consulted.
func decide(raw []byte) gate.Decision {
	normalized, err := graph.FromPlan(raw, segments())
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
	return gate.Evaluate(config(), body)
}

func config() gate.Config {
	return gate.Config{
		OPA:           env("PLANLESS_OPA", "/usr/local/bin/opa"),
		PolicyDir:     env("PLANLESS_POLICY", "/policy/rego"),
		AllowlistPath: env("PLANLESS_ALLOWLIST", "/policy/allowlists/default.json"),
		Timeout:       30 * time.Second,
	}
}

func segments() []graph.Segment {
	out := make([]graph.Segment, 0, 2)
	for _, s := range fixtures.Segments() {
		out = append(out, graph.Segment{Name: s.Name, CIDR: s.CIDR})
	}
	return out
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
