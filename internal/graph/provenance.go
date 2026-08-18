package graph

import (
	"encoding/json"
	"strings"
)

// configIndex answers one question: for a resolved value on a resource, where
// did that value come from?
//
// A value written into the resource block is a literal. A value that arrives
// through a module input the caller passes from a root variable came from the
// variable file. A value that arrives from a module variable the caller never
// passes came from that module's own default — which is the case a reader of
// the configuration is least likely to notice.
type configIndex struct {
	root     configModule
	modules  map[string]moduleCall
	resolved map[string]json.RawMessage
}

func newConfigIndex(root configModule, resolved map[string]planVariable) *configIndex {
	idx := &configIndex{root: root, modules: map[string]moduleCall{}, resolved: map[string]json.RawMessage{}}
	for name, call := range root.ModuleCalls {
		idx.modules[name] = call
	}
	for name, v := range resolved {
		idx.resolved[name] = v.Value
	}
	return idx
}

// visibility orders the origins from least visible to most. A module default is
// the least visible thing in a configuration: nobody passes it, nobody writes
// it in the file they are reviewing, and it decides the value anyway.
var visibility = map[Origin]int{
	OriginModuleDefault: 0,
	OriginVariableFile:  1,
	OriginRootDefault:   2,
	OriginLiteral:       3,
	OriginUnknown:       4,
}

// securityRelevant names the attributes whose origin the contract records.
var securityRelevant = map[string][]string{
	"democloud_grant":        {"principals", "actions", "source_ranges", "resource_name"},
	"democloud_network_rule": {"source_ranges", "workload", "port"},
	"democloud_workload":     {"address"},
	"democloud_bucket":       {"encrypted"},
}

func (idx *configIndex) provenanceFor(modulePath string, r planResource) map[string]Provenance {
	attrs, ok := securityRelevant[r.Type]
	if !ok {
		return nil
	}
	cfg, call, found := idx.resource(modulePath, r)
	out := map[string]Provenance{}
	for _, attr := range attrs {
		if !found {
			out[attr] = Provenance{Origin: OriginUnknown}
			continue
		}
		out[attr] = idx.originOf(cfg.Expressions[attr], modulePath, call)
	}
	if r.Type == "democloud_workload" && found {
		for name, prov := range idx.portProvenance(cfg, modulePath, call) {
			out[name] = prov
		}
	}
	return out
}

// portProvenance records the origin of each declared bind address, which is one
// of the two values that decide whether a workload is reachable at all.
func (idx *configIndex) portProvenance(cfg configResource, modulePath string, call *moduleCall) map[string]Provenance {
	out := map[string]Provenance{}
	raw, ok := cfg.Expressions["ports"]
	if !ok {
		return out
	}
	var blocks []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return out
	}
	for _, block := range blocks {
		name := constantString(block["name"])
		if name == "" {
			continue
		}
		out["ports."+name+".bind"] = idx.originOf(block["bind"], modulePath, call)
	}
	return out
}

func constantString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var expr expression
	if err := json.Unmarshal(raw, &expr); err != nil {
		return ""
	}
	var s string
	if err := json.Unmarshal(expr.ConstantValue, &s); err != nil {
		return ""
	}
	return s
}

func (idx *configIndex) resource(modulePath string, r planResource) (configResource, *moduleCall, bool) {
	module := idx.root
	var call *moduleCall
	if modulePath != "" {
		c, ok := idx.modules[modulePath]
		if !ok {
			return configResource{}, nil, false
		}
		module = c.Module
		call = &c
	}
	want := r.Type + "." + r.Name
	for _, cr := range module.Resources {
		if cr.Address == want {
			return cr, call, true
		}
	}
	return configResource{}, call, false
}

// originOf resolves one expression to where its value came from, recording
// every variable that took part.
func (idx *configIndex) originOf(raw json.RawMessage, modulePath string, call *moduleCall) Provenance {
	if len(raw) == 0 {
		return Provenance{Origin: OriginUnknown}
	}
	var expr expression
	if err := json.Unmarshal(raw, &expr); err != nil {
		return Provenance{Origin: OriginUnknown}
	}
	if len(expr.ConstantValue) > 0 {
		return Provenance{Origin: OriginLiteral}
	}
	var contributors []Contribution
	for _, ref := range expr.References {
		if !strings.HasPrefix(ref, "var.") {
			continue
		}
		contributors = append(contributors, idx.contributionOf(strings.TrimPrefix(ref, "var."), modulePath, call))
	}
	if len(contributors) == 0 {
		if len(expr.References) > 0 {
			// A reference to another resource's attribute: the value is
			// decided elsewhere in the same configuration.
			return Provenance{Origin: OriginLiteral, Reference: expr.References[0]}
		}
		return Provenance{Origin: OriginUnknown}
	}
	primary := contributors[0]
	for _, c := range contributors[1:] {
		if visibility[c.Origin] < visibility[primary.Origin] {
			primary = c
		}
	}
	p := Provenance{Origin: primary.Origin, Reference: primary.Reference}
	if len(contributors) > 1 {
		p.Contributors = contributors
	}
	return p
}

// contributionOf resolves one variable reference to its origin.
func (idx *configIndex) contributionOf(variable, modulePath string, call *moduleCall) Contribution {
	reference := "var." + variable
	if modulePath == "" || call == nil {
		return Contribution{Origin: idx.rootOrigin(variable), Reference: reference}
	}
	passed, ok := call.Expressions[variable]
	if !ok {
		// The caller never passes it, so the module's own default decided it.
		return Contribution{Origin: OriginModuleDefault, Reference: reference}
	}
	var outer expression
	if err := json.Unmarshal(passed, &outer); err != nil {
		return Contribution{Origin: OriginUnknown, Reference: reference}
	}
	if len(outer.ConstantValue) > 0 {
		return Contribution{Origin: OriginLiteral, Reference: reference}
	}
	for _, ref := range outer.References {
		if strings.HasPrefix(ref, "var.") {
			rootVar := strings.TrimPrefix(ref, "var.")
			return Contribution{Origin: idx.rootOrigin(rootVar), Reference: ref}
		}
	}
	if len(outer.References) > 0 {
		// The caller passed another resource's attribute: the value is decided
		// inside the configuration itself.
		return Contribution{Origin: OriginLiteral, Reference: outer.References[0]}
	}
	return Contribution{Origin: OriginLiteral, Reference: reference}
}

// rootOrigin decides whether a root variable's value came from the variable
// file the run was given or from the variable's own default.
//
// A variable with no default can only have come from the file. A variable with
// a default came from the file when the value the run resolved is not the
// default — which is exactly the case worth naming.
func (idx *configIndex) rootOrigin(name string) Origin {
	v, ok := idx.root.Variables[name]
	if !ok {
		return OriginUnknown
	}
	if v.Required || v.Default == nil {
		return OriginVariableFile
	}
	resolved, ok := idx.resolved[name]
	if !ok {
		return OriginRootDefault
	}
	def, err := json.Marshal(v.Default)
	if err != nil {
		return OriginRootDefault
	}
	if equalJSON(def, resolved) {
		return OriginRootDefault
	}
	return OriginVariableFile
}

func equalJSON(a, b []byte) bool {
	var av, bv any
	if json.Unmarshal(a, &av) != nil || json.Unmarshal(b, &bv) != nil {
		return false
	}
	x, err1 := json.Marshal(av)
	y, err2 := json.Marshal(bv)
	return err1 == nil && err2 == nil && string(x) == string(y)
}
