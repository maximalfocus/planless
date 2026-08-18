package graph

import (
	"encoding/json"
	"testing"
)

func manifestDocs(t *testing.T, raw string) []map[string]any {
	t.Helper()
	var docs []map[string]any
	if err := json.Unmarshal([]byte(raw), &docs); err != nil {
		t.Fatal(err)
	}
	return docs
}

const baseManifests = `[
  {"kind":"Service","metadata":{"name":"fare-exports","annotations":{
    "democloud.example/bucket":"fare-exports","democloud.example/grant":"grant-export",
    "democloud.example/readers":"placeholder","democloud.example/reader-sources":"placeholder"}},
   "spec":{"type":"ClusterIP"}},
  {"kind":"Deployment","metadata":{"name":"fare-engine","annotations":{
    "democloud.example/workload":"fare-engine","democloud.example/address":"10.20.1.20"}},
   "spec":{"template":{"spec":{"hostNetwork":false,"containers":[{"name":"fare-engine","ports":[
     {"name":"admin","containerPort":8081,"hostIP":"placeholder"}]}]}}}},
  {"kind":"NetworkPolicy","metadata":{"name":"fare-engine-admin","annotations":{
    "democloud.example/workload":"fare-engine","democloud.example/port":"admin",
    "democloud.example/rule":"rule-admin"}},
   "spec":{"ingress":[{"from":[{"ipBlock":{"cidr":"placeholder"}}]}]}}
]`

const renderedManifests = `[
  {"kind":"Service","metadata":{"name":"fare-exports","annotations":{
    "democloud.example/bucket":"fare-exports","democloud.example/grant":"grant-export",
    "democloud.example/readers":"*","democloud.example/reader-sources":"0.0.0.0/0"}},
   "spec":{"type":"LoadBalancer"}},
  {"kind":"Deployment","metadata":{"name":"fare-engine","annotations":{
    "democloud.example/workload":"fare-engine","democloud.example/address":"10.20.1.20"}},
   "spec":{"template":{"spec":{"hostNetwork":true,"containers":[{"name":"fare-engine","ports":[
     {"name":"admin","containerPort":8081,"hostIP":"0.0.0.0"}]}]}}}},
  {"kind":"NetworkPolicy","metadata":{"name":"fare-engine-admin","annotations":{
    "democloud.example/workload":"fare-engine","democloud.example/port":"admin",
    "democloud.example/rule":"rule-admin"}},
   "spec":{"ingress":[{"from":[{"ipBlock":{"cidr":"0.0.0.0/1"}},{"ipBlock":{"cidr":"128.0.0.0/1"}}]}]}}
]`

// The whole point of the second surface: one policy contract, two formats. If
// the shapes ever diverge, the policy would need a second body, and the claim
// this surface exists to make would be false.
func TestManifestSurfaceProducesTheSameContract(t *testing.T) {
	g, err := FromManifests(manifestDocs(t, renderedManifests), manifestDocs(t, baseManifests), segments())
	if err != nil {
		t.Fatal(err)
	}
	if g.ContractVersion != ContractVersion || g.Surface != SurfaceManifestSet {
		t.Fatalf("unexpected contract header: %+v", g)
	}
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
	manifest, plan := shape(g), shape(normalize(t, "secure.json"))
	for key := range plan {
		if _, ok := manifest[key]; !ok {
			t.Fatalf("the manifest contract is missing %s, which the plan contract carries", key)
		}
	}
	for key := range manifest {
		if _, ok := plan[key]; !ok {
			t.Fatalf("the manifest contract carries %s, which the plan contract does not", key)
		}
	}
}

func TestRenderedManifestsCarryBothExposures(t *testing.T) {
	g, err := FromManifests(manifestDocs(t, renderedManifests), manifestDocs(t, baseManifests), segments())
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Grants) != 1 || g.Grants[0].Principals[0] != "*" || g.Grants[0].SourceRanges[0] != "0.0.0.0/0" {
		t.Fatalf("the storage exposure is missing: %+v", g.Grants)
	}
	var admin *Port
	for i := range g.Resources {
		for j := range g.Resources[i].Ports {
			if g.Resources[i].Ports[j].Name == "admin" {
				admin = &g.Resources[i].Ports[j]
			}
		}
	}
	if admin == nil || admin.Bind != "0.0.0.0" {
		t.Fatalf("the bind exposure is missing: %+v", admin)
	}
	if len(g.NetworkRules) != 1 || len(g.NetworkRules[0].SourceRanges) != 2 {
		t.Fatalf("the ingress exposure is missing: %+v", g.NetworkRules)
	}
}

// The manifest surface's version of provenance: a value that differs from the
// base came from the overlay, which is the artifact a reviewer does not read.
func TestManifestProvenanceDistinguishesBaseFromOverlay(t *testing.T) {
	g, err := FromManifests(manifestDocs(t, renderedManifests), manifestDocs(t, baseManifests), segments())
	if err != nil {
		t.Fatal(err)
	}
	if got := g.Grants[0].Provenance["principals"].Origin; got != OriginOverlay {
		t.Fatalf("expected the readers to come from the overlay, got %s", got)
	}
	same, err := FromManifests(manifestDocs(t, baseManifests), manifestDocs(t, baseManifests), segments())
	if err != nil {
		t.Fatal(err)
	}
	if got := same.Grants[0].Provenance["principals"].Origin; got != OriginBaseManifest {
		t.Fatalf("expected an unchanged value to come from the base, got %s", got)
	}
}

// Anything the normalizer does not understand is reported, and the policy
// denies on it.
func TestManifestSurfaceFailsClosedOnWhatItDoesNotKnow(t *testing.T) {
	docs := manifestDocs(t, renderedManifests)
	docs = append(docs, map[string]any{
		"kind":     "Ingress",
		"metadata": map[string]any{"name": "edge", "annotations": map[string]any{"democloud.example/wildcard": "yes"}},
	})
	g, err := FromManifests(docs, manifestDocs(t, baseManifests), segments())
	if err != nil {
		t.Fatal(err)
	}
	if len(g.UnknownResourceTypes) != 1 || g.UnknownResourceTypes[0] != "Ingress" {
		t.Fatalf("expected the unknown kind to be reported, got %v", g.UnknownResourceTypes)
	}

	docs = manifestDocs(t, renderedManifests)
	annotations := docs[0]["metadata"].(map[string]any)["annotations"].(map[string]any)
	annotations["democloud.example/allow-everything"] = "yes"
	g, err = FromManifests(docs, manifestDocs(t, baseManifests), segments())
	if err != nil {
		t.Fatal(err)
	}
	if len(g.UnrecognizedFields) != 1 {
		t.Fatalf("expected the unrecognized annotation to be reported, got %v", g.UnrecognizedFields)
	}

	if _, err := FromManifests(nil, nil, segments()); err == nil {
		t.Fatal("expected an empty manifest set to be an error")
	}
}
