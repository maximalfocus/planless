// Command pipeline is the demonstration's harness. It runs one enumerated
// deployment scenario end to end and records what each stage actually produced.
//
// It accepts a scenario id and nothing else. There is no endpoint, credential,
// region, account, bucket name, address, manifest, policy, allowlist or
// variable-file parameter anywhere on this surface.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/maximalfocus/planless/internal/tofu"
)

func main() {
	switch {
	case len(os.Args) == 3 && os.Args[1] == "emit":
		// `emit` prints only the canonical resolved artifact, so the checked-in
		// policy fixtures can be regenerated from a real plan rather than
		// written by hand.
		emit(os.Args[2])
	case len(os.Args) == 2 && os.Args[1] == "reconcile":
		reconcile()
	case len(os.Args) == 2 && os.Args[1] == "compare-observations":
		if err := tofu.CompareObservations(os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, "pipeline:", err)
			os.Exit(1)
		}
		fmt.Println(`{"document":"planless.comparison","identical":true}`)
	case len(os.Args) == 2:
		run(os.Args[1])
	default:
		fmt.Fprintf(os.Stderr,
			"usage: pipeline <scenario>|reconcile|compare-observations\navailable scenarios: %s\n", available())
		os.Exit(64)
	}
}

// run executes one scenario. The machine-readable transcript goes to standard
// output so it can be reconciled with what each segment observed; the
// human-readable form goes to standard error, where a reader sees it.
func run(name string) {
	scenario, ok := tofu.Scenarios[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown scenario %q; available: %s\n", name, available())
		os.Exit(64)
	}
	transcript, err := tofu.Run(config(), scenario)
	emitTranscript(transcript)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pipeline:", err)
		os.Exit(1)
	}
}

func reconcile() {
	transcript, err := tofu.Reconcile(config(), os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pipeline:", err)
		os.Exit(2)
	}
	emitTranscript(transcript)
	if !transcript.Passed {
		os.Exit(1)
	}
}

func emitTranscript(t *tofu.Transcript) {
	if t == nil {
		return
	}
	out, err := json.Marshal(t)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pipeline:", err)
		os.Exit(2)
	}
	fmt.Println(string(out))
	fmt.Fprintln(os.Stderr, t.Render())
}

func emit(name string) {
	scenario, ok := tofu.Scenarios[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown scenario %q; available: %s\n", name, available())
		os.Exit(64)
	}
	raw, err := tofu.Plan(config(), scenario)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pipeline:", err)
		os.Exit(1)
	}
	os.Stdout.Write(raw)
}

func config() tofu.Config {
	return tofu.Config{
		Tofu:         env("PLANLESS_TOFU", "/usr/local/bin/tofu"),
		InfraDir:     env("PLANLESS_INFRA", "/infra"),
		WorkDir:      env("PLANLESS_WORK", "/artifacts/work"),
		DataDir:      env("PLANLESS_TOFU_DATA", "/plugins/data"),
		TempDir:      env("PLANLESS_TMP", "/tmp"),
		CLIConfig:    env("PLANLESS_TOFU_CLI_CONFIG", "/etc/tofurc"),
		StateAPI:     "http://controlplane:8080",
		OPA:          env("PLANLESS_OPA", "/usr/local/bin/opa"),
		PolicyDir:    env("PLANLESS_POLICY", "/policy/rego"),
		AllowlistDir: env("PLANLESS_ALLOWLISTS", "/policy/allowlists"),
		ArtifactDir:  env("PLANLESS_ARTIFACTS", "/testdata/plans"),
	}
}

func available() string {
	names := make([]string, 0, len(tofu.Scenarios))
	for k := range tofu.Scenarios {
		names = append(names, k)
	}
	sort.Strings(names)
	return fmt.Sprint(names)
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
