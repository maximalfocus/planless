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
	"time"

	"github.com/maximalfocus/planless/internal/fixtures"
	"github.com/maximalfocus/planless/internal/gate"
	"github.com/maximalfocus/planless/internal/graph"
)

func main() {
	if len(os.Args) != 2 || (os.Args[1] != "normalize" && os.Args[1] != "evaluate") {
		fmt.Fprintln(os.Stderr, "usage: gate <normalize|evaluate>  (the artifact is read from standard input)")
		os.Exit(64)
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 32<<20))
	if err != nil {
		fmt.Fprintln(os.Stderr, "gate: reading the artifact:", err)
		os.Exit(2)
	}
	normalized, normErr := graph.FromPlan(raw, segments())

	if os.Args[1] == "normalize" {
		if normErr != nil {
			fmt.Fprintln(os.Stderr, "gate:", normErr)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(normalized, "", "  ")
		fmt.Println(string(out))
		return
	}

	var decision gate.Decision
	if normErr != nil {
		// An artifact the normalizer cannot read is refused before the policy
		// is ever consulted.
		decision = gate.Decision{
			Result: gate.ResultDeny,
			Class:  gate.ClassUnparsablePlan,
			Violations: []gate.Violation{{
				Class:    gate.ClassUnparsablePlan,
				Resource: "<artifact>",
				Reason:   normErr.Error(),
			}},
			Exposures: []gate.Exposure{},
		}
	} else {
		graphJSON, err := json.Marshal(normalized)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gate:", err)
			os.Exit(2)
		}
		decision = gate.Evaluate(config(), graphJSON)
	}
	out, _ := json.MarshalIndent(decision, "", "  ")
	fmt.Println(string(out))
	if decision.Denied() {
		os.Exit(1)
	}
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
