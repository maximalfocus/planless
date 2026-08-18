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
	"os/signal"
	"syscall"

	"github.com/maximalfocus/planless/internal/tofu"
)

func main() {
	switch {
	case len(os.Args) == 2 && os.Args[1] == "idle":
		// Keep the harness container alive so the run can exercise it
		// repeatedly. Every pipeline run still begins from its own empty
		// working tree.
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
		<-stop
	case len(os.Args) == 3 && os.Args[1] == "emit":
		// `emit` prints only the canonical resolved artifact, so the checked-in
		// policy fixtures can be regenerated from a real plan rather than
		// written by hand.
		emit(os.Args[2])
	case len(os.Args) == 2 && os.Args[1] == "drift":
		drift()
	case len(os.Args) == 2 && os.Args[1] == "remove-undeclared":
		// An operator acting on what a check reported. No check ever does this.
		removed, err := tofu.RemoveUndeclaredGrants(config().StateAPI)
		if err != nil {
			fmt.Fprintln(os.Stderr, "pipeline:", err)
			os.Exit(1)
		}
		out, _ := json.Marshal(map[string]any{
			"document": "planless.removal",
			"removed":  removed,
		})
		fmt.Println(string(out))
	case len(os.Args) == 2 && os.Args[1] == "reconcile":
		reconcile()
	case len(os.Args) == 2 && os.Args[1] == "compare-exposure":
		if err := tofu.CompareExposures(os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, "pipeline:", err)
			os.Exit(1)
		}
		fmt.Println(`{"document":"planless.comparison","identical_reachability":true}`)
	case len(os.Args) == 2 && os.Args[1] == "compare-builds":
		if err := tofu.CompareBuilds(os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, "pipeline:", err)
			os.Exit(1)
		}
		fmt.Println(`{"document":"planless.comparison","identical":true}`)
	case len(os.Args) == 2 && os.Args[1] == "compare-reachability":
		if err := tofu.CompareReachability(os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, "pipeline:", err)
			os.Exit(1)
		}
		fmt.Println(`{"document":"planless.comparison","identical_reachability_from_the_public_segment":true}`)
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
			"usage: pipeline <scenario>|reconcile|drift|remove-undeclared|"+
				"compare-observations|compare-reachability|compare-builds|compare-exposure\n"+
				"available scenarios: %s\n", available())
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

// drift reports what is actually reachable on the platform right now, whatever
// any repository says. It exits non-zero when it finds something, because a
// detector that reports success on detection is not a detector.
func drift() {
	report, err := tofu.Drift(config(), "")
	if err != nil {
		fmt.Fprintln(os.Stderr, "pipeline:", err)
		os.Exit(2)
	}
	out, err := json.Marshal(report)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pipeline:", err)
		os.Exit(2)
	}
	fmt.Println(string(out))
	fmt.Fprintln(os.Stderr, report.Render())
	if report.DriftDetected {
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
		Surface:         env("PLANLESS_SURFACE", tofu.SurfaceSecure),
		Acknowledgement: os.Getenv("ALLOW_VULNERABLE_DEMO"),

		Tofu:         env("PLANLESS_TOFU", "/usr/local/bin/tofu"),
		InfraDir:     env("PLANLESS_INFRA", "/infra"),
		WorkRoot:     env("PLANLESS_WORK", "/artifacts"),
		DataRoot:     env("PLANLESS_TOFU_DATA", "/plugins"),
		TempDir:      env("PLANLESS_TMP", "/tmp"),
		CLIConfig:    env("PLANLESS_TOFU_CLI_CONFIG", "/etc/tofurc"),
		StateAPI:     "http://controlplane:8080",
		OPA:          env("PLANLESS_OPA", "/usr/local/bin/opa"),
		Kustomize:    env("PLANLESS_KUSTOMIZE", "/usr/local/bin/kustomize"),
		ManifestDir:  env("PLANLESS_MANIFESTS", "/manifests"),
		PolicyDir:    env("PLANLESS_POLICY", "/policy/rego"),
		AllowlistDir: env("PLANLESS_ALLOWLISTS", "/policy/allowlists"),
		ArtifactDir:  env("PLANLESS_ARTIFACTS", "/testdata/plans"),
	}
}

// available lists only what may be started here. A scenario that needs both
// opt-ins is not offered until both are present.
func available() string {
	cfg := config()
	return fmt.Sprint(tofu.AvailableScenarios(cfg.Surface, cfg.Acknowledgement))
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
