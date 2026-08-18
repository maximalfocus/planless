package graph

import (
	"encoding/json"
	"testing"
)

func liveState() State {
	var st State
	body := []byte(`{
		"segments":[{"name":"corp","cidr":"10.20.0.0/16"},{"name":"internet","cidr":"198.51.100.0/24"}],
		"buckets":[{"name":"fare-exports"},{"name":"status-page"}],
		"objects":[{"bucket":"fare-exports","key":"rider-refunds-2026-03.csv"}],
		"grants":[
			{"id":"grant-export","resource_kind":"bucket","resource_name":"fare-exports",
			 "principals":["finance-reporting"],"actions":["read"],"source_ranges":["10.20.0.0/16"]},
			{"id":"grant-status","resource_kind":"bucket","resource_name":"status-page",
			 "principals":["*"],"actions":["read"],"source_ranges":["0.0.0.0/0"]}],
		"workloads":[{"name":"fare-engine","address":"10.20.1.20",
			"ports":[{"name":"admin","number":8081,"bind":"10.20.1.20"}]}],
		"network_rules":[{"id":"rule-admin","workload":"fare-engine","port":"admin",
			"source_ranges":["10.20.7.0/24"]}]
	}`)
	if err := json.Unmarshal(body, &st); err != nil {
		panic(err)
	}
	return st
}

// The drift check must be decided by the same policy the gate uses, which means
// the live-state normalizer has to produce the same contract the plan
// normalizer produces.
func TestLiveStateProducesTheSameContract(t *testing.T) {
	g, err := FromPlatformState(liveState(), segments())
	if err != nil {
		t.Fatal(err)
	}
	if g.ContractVersion != ContractVersion {
		t.Fatalf("contract version %s", g.ContractVersion)
	}
	if g.Surface != SurfacePlatformState {
		t.Fatalf("surface %s", g.Surface)
	}
	plan := normalize(t, "secure.json")
	shape := func(v any) map[string]any {
		body, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	live, planned := shape(g), shape(plan)
	for key := range planned {
		if _, ok := live[key]; !ok {
			t.Fatalf("the live-state contract is missing %s, which the plan contract carries", key)
		}
	}
	for key := range live {
		if _, ok := planned[key]; !ok {
			t.Fatalf("the live-state contract carries %s, which the plan contract does not", key)
		}
	}
}

// Live state carries no configuration provenance, and says so rather than
// inventing one. The value is real whether or not any configuration explains it
// — which is exactly what a drift check is for.
func TestLiveStateProvenanceSaysWhereItCameFrom(t *testing.T) {
	g, err := FromPlatformState(liveState(), segments())
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range g.Grants {
		if p := grant.Provenance["principals"]; p.Origin != OriginLiveState {
			t.Fatalf("grant %s reports origin %s", grant.ID, p.Origin)
		}
	}
	for _, r := range g.Resources {
		if r.Kind != "workload" {
			continue
		}
		if p := r.Provenance["ports.admin.bind"]; p.Origin != OriginLiveState {
			t.Fatalf("workload %s reports origin %s", r.Name, p.Origin)
		}
	}
}

func TestLiveStateNormalizationIsDeterministic(t *testing.T) {
	first, err := FromPlatformState(liveState(), segments())
	if err != nil {
		t.Fatal(err)
	}
	second, err := FromPlatformState(liveState(), segments())
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) {
		t.Fatal("two normalizations of the same live state differed")
	}
}

func TestEmptyLiveStateIsAnError(t *testing.T) {
	if _, err := FromPlatformState(State{}, segments()); err == nil {
		t.Fatal("expected empty live state to be an error")
	}
}
