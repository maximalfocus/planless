// Command pipeline runs one enumerated deployment scenario end to end: the real
// infrastructure-as-code toolchain, from a local provider mirror, against the
// fictional democloud control plane.
//
// It accepts a scenario id and nothing else. There is no endpoint, credential,
// region, account, bucket name, address, manifest, or variable-file parameter.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/maximalfocus/planless/internal/tofu"
)

func main() {
	// `emit` prints only the canonical resolved artifact, so the checked-in
	// policy fixtures can be regenerated from a real plan rather than written
	// by hand.
	if len(os.Args) == 3 && os.Args[1] == "emit" {
		emit(os.Args[2])
		return
	}
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: pipeline <scenario>\navailable: %s\n", available())
		os.Exit(64)
	}
	scenario, ok := tofu.Scenarios[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown scenario %q; available: %s\n", os.Args[1], available())
		os.Exit(64)
	}
	transcript, err := tofu.Run(config(), scenario)
	out, _ := json.MarshalIndent(transcript, "", "  ")
	fmt.Println(string(out))
	if err != nil {
		fmt.Fprintln(os.Stderr, "pipeline:", err)
		os.Exit(1)
	}
}

func emit(name string) {
	scenario, ok := tofu.Scenarios[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown scenario %q; available: %s\n", name, available())
		os.Exit(64)
	}
	scenario.SkipApply = true
	scenario.SkipRemote = true
	raw, err := tofu.Plan(config(), scenario)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pipeline:", err)
		os.Exit(1)
	}
	os.Stdout.Write(raw)
}

func config() tofu.Config {
	return tofu.Config{
		Tofu:      env("PLANLESS_TOFU", "/usr/local/bin/tofu"),
		InfraDir:  env("PLANLESS_INFRA", "/infra"),
		WorkDir:   env("PLANLESS_WORK", "/artifacts/work"),
		DataDir:   env("PLANLESS_TOFU_DATA", "/plugins/data"),
		TempDir:   env("PLANLESS_TMP", "/tmp"),
		CLIConfig: env("PLANLESS_TOFU_CLI_CONFIG", "/etc/tofurc"),
		StateAPI:  "http://controlplane:8080",
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
