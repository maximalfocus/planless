package gate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maximalfocus/planless/internal/graph"
)

func config(t *testing.T) Config {
	t.Helper()
	opa := os.Getenv("PLANLESS_OPA")
	if opa == "" {
		opa = "/usr/local/bin/opa"
	}
	if _, err := os.Stat(opa); err != nil {
		t.Fatalf("the policy engine is not available at %s; run the gate through ./scripts/demo.sh", opa)
	}
	return Config{
		OPA:           opa,
		PolicyDir:     "../../policy/rego",
		AllowlistPath: "../../policy/allowlists/default.json",
	}
}

func segments() []graph.Segment {
	return []graph.Segment{
		{Name: "corp", CIDR: "10.20.0.0/16"},
		{Name: "internet", CIDR: "198.51.100.0/24"},
	}
}

func decide(t *testing.T, cfg Config, plan string) Decision {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/plans/" + plan)
	if err != nil {
		t.Fatal(err)
	}
	g, err := graph.FromPlan(raw, segments())
	if err != nil {
		t.Fatalf("%s: %v", plan, err)
	}
	body, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	return Evaluate(cfg, body)
}

func TestSecureArtifactIsAdmittedWithNamedRules(t *testing.T) {
	d := decide(t, config(t), "secure.json")
	if d.Denied() {
		t.Fatalf("the secure artifact was refused: %+v", d.Violations)
	}
	admitted := map[string]string{}
	for _, e := range d.Exposures {
		admitted[e.Resource] = e.AdmittedBy
	}
	want := map[string]string{
		"bucket/fare-exports":          "allow-refund-export-to-finance-from-corp",
		"bucket/status-page":           "allow-status-page-public",
		"workload/fare-engine:service": "allow-fare-engine-service-from-corp",
		"workload/fare-engine:admin":   "allow-fare-engine-admin-from-operations-range",
	}
	for resource, rule := range want {
		if admitted[resource] != rule {
			t.Fatalf("%s: admitted by %q, want %q", resource, admitted[resource], rule)
		}
	}
}

// Each checked-in modified artifact carries one exposure shape, and each is
// refused with a named class, the resource, and the exposure the policy
// computed.
func TestModifiedArtifactsAreRefusedWithNamedReasons(t *testing.T) {
	cfg := config(t)
	cases := []struct {
		plan     string
		class    string
		resource string
		exposure string
	}{
		{"modified-anonymous-export-grant.json", "exposure_not_allowlisted", "bucket/fare-exports", "0.0.0.0/0"},
		{"modified-unrestricted-admin.json", "exposure_not_allowlisted", "workload/fare-engine:admin", "0.0.0.0/0"},
		{"modified-unknown-resource-type.json", "unknown_resource_type", "democloud_firewall", ""},
		{"modified-unrecognized-field.json", "unrecognized_field", "democloud_bucket.fare_exports.public", ""},
		{"modified-empty.json", "empty_artifact", "<artifact>", ""},
		{"modified-invalid-source-range.json", "unparsable_source_range", "network_rule/rule-fare-engine-admin", ""},
	}
	for _, tc := range cases {
		t.Run(tc.plan, func(t *testing.T) {
			d := decide(t, cfg, tc.plan)
			if !d.Denied() {
				t.Fatalf("expected a denial, got %+v", d)
			}
			for _, v := range d.Violations {
				if v.Class != tc.class || v.Resource != tc.resource {
					continue
				}
				if v.Reason == "" {
					t.Fatal("the violation carries no reason")
				}
				if tc.exposure != "" && !strings.Contains(v.Exposure, tc.exposure) {
					t.Fatalf("expected the computed exposure to mention %s, got %q", tc.exposure, v.Exposure)
				}
				return
			}
			t.Fatalf("no violation matched %s on %s: %+v", tc.class, tc.resource, d.Violations)
		})
	}
}

// The split range pair is the shape a literal rule cannot see. The policy must
// compute it to every address and refuse.
func TestSplitRangePairIsComputedNotMatched(t *testing.T) {
	d := decide(t, config(t), "modified-unrestricted-admin.json")
	for _, v := range d.Violations {
		if v.Resource == "workload/fare-engine:admin" && strings.Contains(v.Exposure, "0.0.0.0/0") {
			return
		}
	}
	t.Fatalf("expected the split pair to compute to every address, got %+v", d.Violations)
}

func TestUnreadableArtifactIsRefusedBeforeThePolicy(t *testing.T) {
	d := Evaluate(config(t), []byte("{not json"))
	if !d.Denied() || d.Class != ClassUnparsablePlan {
		t.Fatalf("expected an unparsable-artifact denial, got %+v", d)
	}
}

// An empty policy bundle returns no decision at all, and no decision is a
// denial.
func TestEmptyPolicyBundleDenies(t *testing.T) {
	cfg := config(t)
	cfg.PolicyDir = t.TempDir()
	d := decideRaw(t, cfg, "secure.json")
	if !d.Denied() || d.Class != ClassNoDecision {
		t.Fatalf("expected a no-decision denial, got %+v", d)
	}
}

func TestMissingAllowlistDenies(t *testing.T) {
	cfg := config(t)
	cfg.AllowlistPath = filepath.Join(t.TempDir(), "absent.json")
	d := decideRaw(t, cfg, "secure.json")
	if !d.Denied() || d.Class != ClassEngineError {
		t.Fatalf("expected an engine-error denial, got %+v", d)
	}
}

func TestPolicyEngineFailureDenies(t *testing.T) {
	cfg := config(t)
	cfg.OPA = filepath.Join(t.TempDir(), "no-such-engine")
	d := decideRaw(t, cfg, "secure.json")
	if !d.Denied() || d.Class != ClassEngineError {
		t.Fatalf("expected an engine-error denial, got %+v", d)
	}
}

// A policy body that returns something this gate cannot read is refused rather
// than interpreted generously.
func TestMalformedDecisionsDeny(t *testing.T) {
	for _, raw := range []string{
		`not json`,
		`{"result":[]}`,
		`{"result":[{"expressions":[{"value":{"result":"maybe"}}]}]}`,
		`{"result":[{"expressions":[{"value":{"result":"admit","violations":[{"class":"x"}]}}]}]}`,
		`{"result":[{"expressions":[{"value":"admit"}]}]}`,
	} {
		d := parse([]byte(raw))
		if !d.Denied() {
			t.Fatalf("%s: expected a denial, got %+v", raw, d)
		}
	}
}

func decideRaw(t *testing.T, cfg Config, plan string) Decision {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/plans/" + plan)
	if err != nil {
		t.Fatal(err)
	}
	g, err := graph.FromPlan(raw, segments())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(g)
	return Evaluate(cfg, body)
}
