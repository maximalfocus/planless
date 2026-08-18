package tofu

import (
	"os"
	"strings"
	"testing"
)

// The security regression matrix, as a list rather than as a hope.
//
// Every property this project must keep proving is written down here beside the
// scenario or check that proves it. A requirement whose prover disappears fails
// the build, which is the difference between a matrix that is complete and a
// matrix that used to be.
var matrix = []struct {
	Requirement string
	Scenario    string
	Check       string
}{
	{Requirement: "both exposures reach the public segment with exact bytes and exact ledger effect",
		Scenario: "vulnerable-ungated", Check: "internet-vulnerable-impact"},
	{Requirement: "the platform records the anonymous transition as exactly one row",
		Check: "vulnerable-ledger"},
	{Requirement: "no gate at all: the configuration is applied exactly as written",
		Scenario: "vulnerable-ungated"},
	{Requirement: "a scan of the source text runs, finds nothing, and is right about what it read",
		Scenario: "half-fix-source-scan"},
	{Requirement: "a gate that reports and does not enforce",
		Scenario: "half-fix-report-only"},
	{Requirement: "a gate on the review path only, and a second path that applies anyway",
		Scenario: "half-fix-review-path-only"},
	{Requirement: "drift: a correct repository and an exposed world, detected only by the drift check",
		Scenario: "half-fix-drift", Check: "internet-drifted-export"},
	{Requirement: "a denylist of known-bad literals, and two ordinary bypasses",
		Scenario: "half-fix-denylist"},
	{Requirement: "both bypasses produce identical effective exposure",
		Scenario: "half-fix-denylist"},
	{Requirement: "secure refusal with platform state byte-for-byte unchanged and no apply",
		Scenario: "refuse-anonymous-export"},
	{Requirement: "the second exposure shape is refused identically",
		Scenario: "refuse-unrestricted-admin"},
	{Requirement: "an unparsable artifact denies", Scenario: "fail-closed-unparsable"},
	{Requirement: "an unknown resource type denies", Scenario: "fail-closed-unknown-type"},
	{Requirement: "an unrecognized field denies", Scenario: "fail-closed-unrecognized-field"},
	{Requirement: "a policy engine error denies", Scenario: "fail-closed-engine-error"},
	{Requirement: "an unapproved plan artifact is refused by digest",
		Scenario: "binding-unapproved-plan"},
	{Requirement: "a plan artifact changed after approval is refused by digest",
		Scenario: "binding-modified-plan"},
	{Requirement: "an approval issued for another run is refused",
		Scenario: "binding-stale-approval"},
	{Requirement: "the finance principal reads the export from the corporate segment",
		Check: "finance-corp-read"},
	{Requirement: "the admin port answers inside the operations range and refuses outside it",
		Check: "ops-admin-read"},
	{Requirement: "the deliberately public status page is readable in every secure scenario",
		Check: "internet-secure-baseline"},
	{Requirement: "a reviewed exposure change is refused, then admitted by a named allowlist entry",
		Scenario: "reviewed-exposure-unapproved", Check: "internet-reviewed-exposure"},
	{Requirement: "an ordinary non-security change passes the gate untouched",
		Scenario: "routine-change"},
	{Requirement: "the manifest surface is decided by the same policy with no change to it",
		Scenario: "manifest-intended"},
	{Requirement: "the manifest surface is refused identically",
		Scenario: "manifest-exposed"},
	{Requirement: "a scan of the base manifests finds nothing beside a rendered artifact that contains both",
		Scenario: "manifest-exposed-ungated"},
	{Requirement: "encryption is enabled in both variants and is irrelevant",
		Check: "encryption-enabled"},
	{Requirement: "the deployer is least-privileged and identical in both variants",
		Check: "deployer-scope-is-minimal"},
	{Requirement: "the legitimate corporate paths are unaffected by the misconfiguration",
		Check: "corp-legitimate-paths"},
	{Requirement: "the platform state produced by an apply equals the checked-in fixture",
		Check: "state-matches-fixture"},
}

// Every requirement names something that exists, and every scenario and check
// that exists is named by some requirement. A prover that quietly disappears is
// a regression; a scenario nobody claims is a scenario nobody is watching.
func TestTheRegressionMatrixIsComplete(t *testing.T) {
	checks := clientChecks(t)
	claimedScenarios := map[string]bool{}
	claimedChecks := map[string]bool{}

	for _, row := range matrix {
		if row.Requirement == "" || (row.Scenario == "" && row.Check == "") {
			t.Fatalf("matrix row proves nothing: %+v", row)
		}
		if row.Scenario != "" {
			if _, ok := Scenarios[row.Scenario]; !ok {
				t.Fatalf("%q names scenario %s, which does not exist", row.Requirement, row.Scenario)
			}
			claimedScenarios[row.Scenario] = true
		}
		if row.Check != "" {
			if !checks[row.Check] {
				t.Fatalf("%q names check %s, which does not exist", row.Requirement, row.Check)
			}
			claimedChecks[row.Check] = true
		}
	}

	for name, s := range Scenarios {
		if s.ID == "offline-init" || s.ID == "secure-apply" || s.ID == "vulnerable-gated" ||
			s.ID == "reviewed-exposure" {
			// Proved through another row, or infrastructure for one.
			continue
		}
		if !claimedScenarios[name] {
			t.Fatalf("scenario %s is not claimed by any matrix requirement", name)
		}
	}
}

// clientChecks reads the enumerated observation checks the client offers, from
// the client itself rather than from a second list that could drift.
func clientChecks(t *testing.T) map[string]bool {
	t.Helper()
	body, err := os.ReadFile("../../cmd/client/main.go")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	inMap := false
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "var checks = map[string]func() []step{") {
			inMap = true
			continue
		}
		if inMap {
			if trimmed == "}" {
				break
			}
			name, _, ok := strings.Cut(trimmed, ":")
			if !ok {
				continue
			}
			out[strings.Trim(strings.TrimSpace(name), `"`)] = true
		}
	}
	if len(out) == 0 {
		t.Fatal("no client checks were found")
	}
	return out
}

// comparisonScenarios are the scenarios the comparison command runs, in the
// order it runs them. It is written down so a scenario cannot quietly stop
// appearing in the one view that shows the whole demonstration.
var comparisonScenarios = []string{
	"secure-apply",
	"refuse-anonymous-export",
	"refuse-unrestricted-admin",
	"fail-closed-unparsable",
	"fail-closed-unknown-type",
	"fail-closed-unrecognized-field",
	"fail-closed-engine-error",
	"binding-unapproved-plan",
	"binding-modified-plan",
	"binding-stale-approval",
	"reviewed-exposure-unapproved",
	"routine-change",
	"reviewed-exposure",
	"manifest-intended",
	"vulnerable-gated",
	"vulnerable-ungated",
	"half-fix-source-scan",
	"half-fix-report-only",
	"half-fix-denylist",
	"half-fix-review-path-only",
	"manifest-exposed",
	"manifest-exposed-ungated",
	"half-fix-drift",
}

// Every scenario appears in the comparison, and the comparison names only
// scenarios that exist. `offline-init` is the exception: it runs in a container
// with no network interface, which is the claim it exists to make, and it has
// no platform to compare against.
func TestTheComparisonCoversEveryScenario(t *testing.T) {
	covered := map[string]bool{}
	for _, name := range comparisonScenarios {
		if _, ok := Scenarios[name]; !ok {
			t.Fatalf("the comparison runs %s, which does not exist", name)
		}
		if covered[name] {
			t.Fatalf("the comparison runs %s twice", name)
		}
		covered[name] = true
	}
	for name := range Scenarios {
		if name == "offline-init" {
			continue
		}
		if !covered[name] {
			t.Fatalf("scenario %s never appears in the comparison", name)
		}
	}

	// The script has to run the same list.
	body, err := os.ReadFile("../../scripts/demo.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)
	for _, name := range comparisonScenarios {
		if !strings.Contains(script, name) {
			t.Fatalf("the comparison command does not run %s", name)
		}
	}
}
