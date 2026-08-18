package graph

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// knownAttributes enumerates every attribute each resource type may carry. An
// attribute outside this set is an unrecognized security-relevant field until
// proven otherwise, and the policy denies on it.
var knownAttributes = map[string]map[string]bool{
	"democloud_bucket":       set("name", "encrypted", "log_retention_days", "id"),
	"democloud_object":       set("bucket", "key", "content_type", "content_base64", "id"),
	"democloud_grant":        set("id", "resource_kind", "resource_name", "principals", "actions", "source_ranges"),
	"democloud_workload":     set("name", "address", "ports", "id"),
	"democloud_network_rule": set("id", "workload", "port", "source_ranges"),
}

func set(keys ...string) map[string]bool {
	out := map[string]bool{}
	for _, k := range keys {
		out[k] = true
	}
	return out
}

type planDocument struct {
	FormatVersion string `json:"format_version"`
	PlannedValues struct {
		RootModule planModule `json:"root_module"`
	} `json:"planned_values"`
	Configuration struct {
		RootModule configModule `json:"root_module"`
	} `json:"configuration"`
}

type planModule struct {
	Address      string         `json:"address"`
	Resources    []planResource `json:"resources"`
	ChildModules []planModule   `json:"child_modules"`
}

type planResource struct {
	Address string         `json:"address"`
	Type    string         `json:"type"`
	Name    string         `json:"name"`
	Values  map[string]any `json:"values"`
}

type configModule struct {
	Resources   []configResource      `json:"resources"`
	Variables   map[string]configVar  `json:"variables"`
	ModuleCalls map[string]moduleCall `json:"module_calls"`
}

type configVar struct {
	Default  any  `json:"default"`
	Required bool `json:"required"`
}

type moduleCall struct {
	Expressions map[string]json.RawMessage `json:"expressions"`
	Module      configModule               `json:"module"`
}

type configResource struct {
	Address     string                     `json:"address"`
	Type        string                     `json:"type"`
	Expressions map[string]json.RawMessage `json:"expressions"`
}

type expression struct {
	ConstantValue json.RawMessage `json:"constant_value"`
	References    []string        `json:"references"`
}

// FromPlan normalizes a resolved plan artifact into the policy contract.
//
// An artifact it cannot parse is an error, and the gate denies on it. An
// artifact it can parse but does not fully recognize is normalized with the
// unrecognized parts reported, and the policy denies on those.
func FromPlan(raw []byte, segments []Segment) (*Graph, error) {
	var doc planDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("graph: plan artifact is not valid JSON: %w", err)
	}
	if doc.FormatVersion == "" {
		return nil, fmt.Errorf("graph: plan artifact declares no format version")
	}
	g := &Graph{
		ContractVersion:      ContractVersion,
		Surface:              SurfaceIaCPlan,
		Segments:             append([]Segment(nil), segments...),
		Resources:            []Resource{},
		Grants:               []Grant{},
		NetworkRules:         []NetworkRule{},
		UnknownResourceTypes: []string{},
		UnrecognizedFields:   []string{},
	}
	index := newConfigIndex(doc.Configuration.RootModule)
	unknownTypes := map[string]bool{}
	unrecognized := map[string]bool{}

	var walk func(m planModule, modulePath string)
	walk = func(m planModule, modulePath string) {
		for _, r := range m.Resources {
			known, ok := knownAttributes[r.Type]
			if !ok {
				unknownTypes[r.Type] = true
				continue
			}
			for attr := range r.Values {
				if !known[attr] {
					unrecognized[r.Address+"."+attr] = true
				}
			}
			g.add(r, index.provenanceFor(modulePath, r), index)
		}
		for _, child := range m.ChildModules {
			walk(child, moduleName(child.Address))
		}
	}
	walk(doc.PlannedValues.RootModule, "")

	for t := range unknownTypes {
		g.UnknownResourceTypes = append(g.UnknownResourceTypes, t)
	}
	for f := range unrecognized {
		g.UnrecognizedFields = append(g.UnrecognizedFields, f)
	}
	sort.Strings(g.UnknownResourceTypes)
	sort.Strings(g.UnrecognizedFields)
	g.sortAll()
	return g, nil
}

func moduleName(address string) string {
	return strings.TrimPrefix(address, "module.")
}

func (g *Graph) add(r planResource, prov map[string]Provenance, index *configIndex) {
	switch r.Type {
	case "democloud_bucket":
		g.Resources = append(g.Resources, Resource{
			Kind: "bucket", Name: stringOf(r.Values["name"]), Address: r.Address, Provenance: prov,
		})
	case "democloud_object":
		g.Resources = append(g.Resources, Resource{
			Kind:    "object",
			Name:    stringOf(r.Values["bucket"]) + "/" + stringOf(r.Values["key"]),
			Address: r.Address, Provenance: prov,
		})
	case "democloud_grant":
		g.Grants = append(g.Grants, Grant{
			ID:           stringOf(r.Values["id"]),
			ResourceKind: stringOf(r.Values["resource_kind"]),
			ResourceName: stringOf(r.Values["resource_name"]),
			Principals:   stringsOf(r.Values["principals"]),
			Actions:      stringsOf(r.Values["actions"]),
			SourceRanges: stringsOf(r.Values["source_ranges"]),
			Address:      r.Address,
			Provenance:   prov,
		})
	case "democloud_workload":
		g.Resources = append(g.Resources, Resource{
			Kind: "workload", Name: stringOf(r.Values["name"]), Address: r.Address,
			Ports: portsOf(r.Values["ports"]), Provenance: prov,
		})
	case "democloud_network_rule":
		g.NetworkRules = append(g.NetworkRules, NetworkRule{
			ID:           stringOf(r.Values["id"]),
			Workload:     stringOf(r.Values["workload"]),
			Port:         stringOf(r.Values["port"]),
			SourceRanges: stringsOf(r.Values["source_ranges"]),
			Address:      r.Address,
			Provenance:   prov,
		})
	}
}

func (g *Graph) sortAll() {
	sort.Slice(g.Resources, func(i, j int) bool { return g.Resources[i].Address < g.Resources[j].Address })
	sort.Slice(g.Grants, func(i, j int) bool { return g.Grants[i].ID < g.Grants[j].ID })
	sort.Slice(g.NetworkRules, func(i, j int) bool { return g.NetworkRules[i].ID < g.NetworkRules[j].ID })
	sort.Slice(g.Segments, func(i, j int) bool { return g.Segments[i].Name < g.Segments[j].Name })
}

func stringOf(v any) string {
	s, _ := v.(string)
	return s
}

func stringsOf(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		out = append(out, stringOf(e))
	}
	return out
}

func portsOf(v any) []Port {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]Port, 0, len(list))
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		number, _ := m["number"].(float64)
		out = append(out, Port{
			Name:   stringOf(m["name"]),
			Number: int64(number),
			Bind:   stringOf(m["bind"]),
		})
	}
	return out
}
