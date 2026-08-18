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
	root    configModule
	modules map[string]moduleCall
}

func newConfigIndex(root configModule) *configIndex {
	idx := &configIndex{root: root, modules: map[string]moduleCall{}}
	for name, call := range root.ModuleCalls {
		idx.modules[name] = call
	}
	return idx
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

// originOf resolves one expression to where its value came from.
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
	variable := ""
	for _, ref := range expr.References {
		if strings.HasPrefix(ref, "var.") {
			variable = strings.TrimPrefix(ref, "var.")
			break
		}
	}
	if variable == "" {
		if len(expr.References) > 0 {
			// A reference to another resource's attribute: the value is
			// decided elsewhere in the same configuration.
			return Provenance{Origin: OriginLiteral, Reference: expr.References[0]}
		}
		return Provenance{Origin: OriginUnknown}
	}
	reference := "var." + variable

	if modulePath == "" || call == nil {
		return Provenance{Origin: idx.rootOrigin(variable), Reference: reference}
	}
	passed, ok := call.Expressions[variable]
	if !ok {
		// The caller never passes it, so the module's own default decided it.
		return Provenance{Origin: OriginModuleDefault, Reference: reference}
	}
	var outer expression
	if err := json.Unmarshal(passed, &outer); err != nil {
		return Provenance{Origin: OriginUnknown, Reference: reference}
	}
	if len(outer.ConstantValue) > 0 {
		return Provenance{Origin: OriginLiteral, Reference: reference}
	}
	for _, ref := range outer.References {
		if strings.HasPrefix(ref, "var.") {
			rootVar := strings.TrimPrefix(ref, "var.")
			return Provenance{Origin: idx.rootOrigin(rootVar), Reference: ref}
		}
	}
	if len(outer.References) > 0 {
		// The caller passed another resource's attribute: the value is decided
		// inside the configuration itself.
		return Provenance{Origin: OriginLiteral, Reference: outer.References[0]}
	}
	return Provenance{Origin: OriginLiteral, Reference: reference}
}

func (idx *configIndex) rootOrigin(name string) Origin {
	v, ok := idx.root.Variables[name]
	if !ok {
		return OriginUnknown
	}
	if v.Required || v.Default == nil {
		// No default anywhere in the configuration, so the value was supplied
		// by the variable file the run was given.
		return OriginVariableFile
	}
	return OriginRootDefault
}
