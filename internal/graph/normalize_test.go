package graph

import (
	"encoding/json"
	"os"
	"testing"
)

func segments() []Segment {
	return []Segment{
		{Name: "corp", CIDR: "10.20.0.0/16"},
		{Name: "internet", CIDR: "198.51.100.0/24"},
	}
}

func load(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/plans/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func normalize(t *testing.T, name string) *Graph {
	t.Helper()
	g, err := FromPlan(load(t, name), segments())
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return g
}

func TestNormalizationIsDeterministic(t *testing.T) {
	raw := load(t, "secure.json")
	first, err := FromPlan(raw, segments())
	if err != nil {
		t.Fatal(err)
	}
	second, err := FromPlan(raw, segments())
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) {
		t.Fatal("two normalizations of the same artifact differed")
	}
}

func TestSecureArtifactNormalizesToTheContract(t *testing.T) {
	g := normalize(t, "secure.json")
	if g.ContractVersion != ContractVersion || g.Surface != SurfaceIaCPlan {
		t.Fatalf("unexpected contract header: %+v", g)
	}
	if len(g.Segments) != 2 {
		t.Fatalf("expected both segments to be carried, got %v", g.Segments)
	}
	if len(g.UnknownResourceTypes) != 0 || len(g.UnrecognizedFields) != 0 {
		t.Fatalf("secure artifact reported unknowns: %v %v", g.UnknownResourceTypes, g.UnrecognizedFields)
	}
	kinds := map[string]int{}
	for _, r := range g.Resources {
		kinds[r.Kind]++
	}
	if kinds["bucket"] != 3 || kinds["object"] != 3 || kinds["workload"] != 1 {
		t.Fatalf("unexpected resource kinds: %v", kinds)
	}
	if len(g.Grants) != 3 || len(g.NetworkRules) != 2 {
		t.Fatalf("expected two grants and two rules, got %d and %d", len(g.Grants), len(g.NetworkRules))
	}
}

// Provenance is the point of the contract: the policy must be able to say where
// an exposure came from, not merely that it exists.
func TestProvenanceDistinguishesVariableFileFromModuleDefault(t *testing.T) {
	g := normalize(t, "secure.json")

	var exportGrant *Grant
	for i := range g.Grants {
		if g.Grants[i].ID == "grant-fare-exports-finance-read" {
			exportGrant = &g.Grants[i]
		}
	}
	if exportGrant == nil {
		t.Fatal("the export grant is missing from the graph")
	}
	for _, attr := range []string{"principals", "source_ranges"} {
		p := exportGrant.Provenance[attr]
		if p.Origin != OriginVariableFile {
			t.Fatalf("grant %s: expected the variable file, got %+v", attr, p)
		}
		if p.Reference == "" {
			t.Fatalf("grant %s: provenance records no reference", attr)
		}
	}
	if got := exportGrant.Provenance["actions"].Origin; got != OriginLiteral {
		t.Fatalf("expected the action list to be a literal, got %s", got)
	}

	var adminRule *NetworkRule
	for i := range g.NetworkRules {
		if g.NetworkRules[i].ID == "rule-fare-engine-admin" {
			adminRule = &g.NetworkRules[i]
		}
	}
	if adminRule == nil {
		t.Fatal("the admin ingress rule is missing from the graph")
	}
	// The addresses live in a module default; the caller only names a profile.
	// Both contributors are recorded, and the least visible one is reported.
	p := adminRule.Provenance["source_ranges"]
	if p.Origin != OriginModuleDefault || p.Reference != "var.admin_profiles" {
		t.Fatalf("expected the ingress ranges to come from a module default, got %+v", p)
	}
	if len(p.Contributors) != 2 {
		t.Fatalf("expected both contributing variables to be recorded, got %+v", p.Contributors)
	}
	selector := false
	for _, c := range p.Contributors {
		if c.Reference == "var.admin_profile" {
			selector = true
			if c.Origin != OriginRootDefault {
				t.Fatalf("the secure run should select the profile from the root default, got %s", c.Origin)
			}
		}
	}
	if !selector {
		t.Fatal("the profile selector was not recorded as a contributor")
	}

	var workload *Resource
	for i := range g.Resources {
		if g.Resources[i].Kind == "workload" {
			workload = &g.Resources[i]
		}
	}
	if workload == nil {
		t.Fatal("the workload is missing from the graph")
	}
	if p := workload.Provenance["ports.admin.bind"]; p.Origin != OriginModuleDefault || p.Reference != "var.admin_profiles" {
		t.Fatalf("expected the admin bind address to come from a module default, got %+v", p)
	}
	if len(workload.Ports) != 2 {
		t.Fatalf("expected two declared ports, got %v", workload.Ports)
	}
}

func TestUnknownShapesAreReportedRatherThanDropped(t *testing.T) {
	g := normalize(t, "modified-unknown-resource-type.json")
	if len(g.UnknownResourceTypes) != 1 || g.UnknownResourceTypes[0] != "democloud_firewall" {
		t.Fatalf("expected the unknown type to be reported, got %v", g.UnknownResourceTypes)
	}
	g = normalize(t, "modified-unrecognized-field.json")
	if len(g.UnrecognizedFields) != 1 {
		t.Fatalf("expected the unrecognized field to be reported, got %v", g.UnrecognizedFields)
	}
}

func TestUnreadableArtifactsAreErrors(t *testing.T) {
	for _, name := range []string{"modified-unparsable.json", "modified-no-format-version.json"} {
		if _, err := FromPlan(load(t, name), segments()); err == nil {
			t.Fatalf("%s: expected an error", name)
		}
	}
}

func TestModifiedArtifactsCarryTheExposureTheyClaim(t *testing.T) {
	g := normalize(t, "modified-anonymous-export-grant.json")
	found := false
	for _, grant := range g.Grants {
		if grant.ResourceName != "fare-exports" {
			continue
		}
		for _, p := range grant.Principals {
			if p == "*" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("the modified artifact does not carry an anonymous grant on the export")
	}

	g = normalize(t, "modified-unrestricted-admin.json")
	for _, r := range g.Resources {
		if r.Kind != "workload" {
			continue
		}
		for _, p := range r.Ports {
			if p.Name == "admin" && p.Bind != "0.0.0.0" {
				t.Fatalf("expected an unrestricted admin bind, got %q", p.Bind)
			}
		}
	}
	for _, rule := range g.NetworkRules {
		if rule.ID != "rule-fare-engine-admin" {
			continue
		}
		if len(rule.SourceRanges) != 2 {
			t.Fatalf("expected the split range pair, got %v", rule.SourceRanges)
		}
	}
}
