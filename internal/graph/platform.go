package graph

import (
	"errors"
	"sort"
)

// SurfacePlatformState is live platform state normalized into the contract.
const SurfacePlatformState = "platform-state"

// OriginLiveState marks a value read from the platform itself.
//
// A resource that is already there carries no configuration provenance: the
// platform can say what its permissions are, and nothing about which file put
// them there. Saying so is the honest answer, and it is also the point of a
// drift check — the value is real whether or not any configuration explains it.
const OriginLiveState Origin = "live-state"

// State is the shape of live platform state the drift check reads. It mirrors
// the control plane's read-only API and nothing else.
type State struct {
	Segments []struct {
		Name string `json:"name"`
		CIDR string `json:"cidr"`
	} `json:"segments"`
	Buckets []struct {
		Name string `json:"name"`
	} `json:"buckets"`
	Objects []struct {
		Bucket string `json:"bucket"`
		Key    string `json:"key"`
	} `json:"objects"`
	Grants []struct {
		ID           string   `json:"id"`
		ResourceKind string   `json:"resource_kind"`
		ResourceName string   `json:"resource_name"`
		Principals   []string `json:"principals"`
		Actions      []string `json:"actions"`
		SourceRanges []string `json:"source_ranges"`
	} `json:"grants"`
	Workloads []struct {
		Name    string `json:"name"`
		Address string `json:"address"`
		Ports   []struct {
			Name   string `json:"name"`
			Number int64  `json:"number"`
			Bind   string `json:"bind"`
		} `json:"ports"`
	} `json:"workloads"`
	NetworkRules []struct {
		ID           string   `json:"id"`
		Workload     string   `json:"workload"`
		Port         string   `json:"port"`
		SourceRanges []string `json:"source_ranges"`
	} `json:"network_rules"`
}

// FromPlatformState normalizes live platform state into the policy contract.
//
// It produces the same contract the plan normalizer produces, so the same
// policy body decides it without modification. That is the whole reason the
// contract exists: a drift check that needed its own policy would be a second
// opinion, not the same one applied to a different moment.
func FromPlatformState(st State, segments []Segment) (*Graph, error) {
	if len(st.Buckets) == 0 && len(st.Workloads) == 0 {
		return nil, errors.New("graph: live platform state declares no resources")
	}
	g := &Graph{
		ContractVersion:      ContractVersion,
		Surface:              SurfacePlatformState,
		Segments:             append([]Segment(nil), segments...),
		Resources:            []Resource{},
		Grants:               []Grant{},
		NetworkRules:         []NetworkRule{},
		UnknownResourceTypes: []string{},
		UnrecognizedFields:   []string{},
	}
	for _, b := range st.Buckets {
		g.Resources = append(g.Resources, Resource{
			Kind: "bucket", Name: b.Name, Address: "platform/bucket/" + b.Name,
			Attributes: map[string]any{"name": b.Name},
		})
	}
	for _, o := range st.Objects {
		g.Resources = append(g.Resources, Resource{
			Kind: "object", Name: o.Bucket + "/" + o.Key,
			Address: "platform/object/" + o.Bucket + "/" + o.Key,
		})
	}
	for _, w := range st.Workloads {
		ports := make([]Port, 0, len(w.Ports))
		prov := map[string]Provenance{}
		for _, p := range w.Ports {
			ports = append(ports, Port{Name: p.Name, Number: p.Number, Bind: p.Bind})
			prov["ports."+p.Name+".bind"] = Provenance{Origin: OriginLiveState}
		}
		g.Resources = append(g.Resources, Resource{
			Kind: "workload", Name: w.Name, Address: "platform/workload/" + w.Name,
			Ports: ports, Provenance: prov,
		})
	}
	for _, grant := range st.Grants {
		g.Grants = append(g.Grants, Grant{
			ID:           grant.ID,
			ResourceKind: grant.ResourceKind,
			ResourceName: grant.ResourceName,
			Principals:   append([]string(nil), grant.Principals...),
			Actions:      append([]string(nil), grant.Actions...),
			SourceRanges: append([]string(nil), grant.SourceRanges...),
			Address:      "platform/grant/" + grant.ID,
			Provenance: map[string]Provenance{
				"principals":    {Origin: OriginLiveState},
				"source_ranges": {Origin: OriginLiveState},
			},
		})
	}
	for _, r := range st.NetworkRules {
		g.NetworkRules = append(g.NetworkRules, NetworkRule{
			ID:           r.ID,
			Workload:     r.Workload,
			Port:         r.Port,
			SourceRanges: append([]string(nil), r.SourceRanges...),
			Address:      "platform/network_rule/" + r.ID,
			Provenance:   map[string]Provenance{"source_ranges": {Origin: OriginLiveState}},
		})
	}
	sort.Slice(g.Resources, func(i, j int) bool { return g.Resources[i].Address < g.Resources[j].Address })
	sort.Slice(g.Grants, func(i, j int) bool { return g.Grants[i].ID < g.Grants[j].ID })
	sort.Slice(g.NetworkRules, func(i, j int) bool { return g.NetworkRules[i].ID < g.NetworkRules[j].ID })
	sort.Slice(g.Segments, func(i, j int) bool { return g.Segments[i].Name < g.Segments[j].Name })
	return g, nil
}
