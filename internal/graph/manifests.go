package graph

import (
	"fmt"
	"sort"
	"strings"
)

// SurfaceManifestSet is a rendered manifest set normalized into the contract.
const SurfaceManifestSet = "manifest-set"

// Origins particular to the manifest surface.
const (
	// OriginBaseManifest marks a value written in the base manifest set.
	OriginBaseManifest Origin = "base-manifest"

	// OriginOverlay marks a value the overlay resolved. It is the manifest
	// surface's version of a variable file: the value is not in the files a
	// reviewer reads, it is in the thing that patches them.
	OriginOverlay Origin = "overlay"
)

// annotation prefix carrying this demonstration's own semantics.
const annotationPrefix = "democloud.example/"

// knownAnnotations enumerates every annotation the normalizer understands.
// Anything else under the prefix is reported, and the policy denies on it.
var knownAnnotations = map[string]bool{
	"democloud.example/bucket":         true,
	"democloud.example/grant":          true,
	"democloud.example/readers":        true,
	"democloud.example/reader-sources": true,
	"democloud.example/workload":       true,
	"democloud.example/address":        true,
	"democloud.example/port":           true,
	"democloud.example/rule":           true,
}

// knownKinds enumerates the manifest kinds the normalizer understands.
var knownKinds = map[string]bool{
	"Service":       true,
	"Deployment":    true,
	"NetworkPolicy": true,
}

// FromManifests normalizes a rendered manifest set into the policy contract.
//
// The manifests are Kubernetes-shaped, and that is all they are: this
// normalizer feeds this demonstration's own applier. No Kubernetes
// distribution, API server, admission controller or kubelet is implemented or
// emulated anywhere in this project, and nothing here claims to describe how a
// real cluster behaves. The semantics that decide an exposure come from this
// project's own annotations, so no decision rests on such a claim.
//
// base, when given, is the same set rendered without the overlay. Comparing the
// two is how a resolved value's origin is known: a value that differs from the
// base came from the overlay.
func FromManifests(rendered, base []map[string]any, segments []Segment) (*Graph, error) {
	if len(rendered) == 0 {
		return nil, fmt.Errorf("graph: the rendered manifest set is empty")
	}
	g := &Graph{
		ContractVersion:      ContractVersion,
		Surface:              SurfaceManifestSet,
		Segments:             append([]Segment(nil), segments...),
		Resources:            []Resource{},
		Grants:               []Grant{},
		NetworkRules:         []NetworkRule{},
		UnknownResourceTypes: []string{},
		UnrecognizedFields:   []string{},
	}
	baseIndex := indexByIdentity(base)
	unknownKinds := map[string]bool{}
	unrecognized := map[string]bool{}

	for _, doc := range rendered {
		kind := str(doc["kind"])
		if !knownKinds[kind] {
			unknownKinds[kind] = true
			continue
		}
		name := str(mapOf(doc["metadata"])["name"])
		annotations := stringMap(mapOf(mapOf(doc["metadata"])["annotations"]))
		for key := range annotations {
			if strings.HasPrefix(key, annotationPrefix) && !knownAnnotations[key] {
				unrecognized[kind+"/"+name+"."+key] = true
			}
		}
		baseDoc := baseIndex[kind+"/"+name]

		switch kind {
		case "Service":
			g.addService(doc, baseDoc, name, annotations)
		case "Deployment":
			g.addDeployment(doc, baseDoc, name, annotations)
		case "NetworkPolicy":
			g.addNetworkPolicy(doc, baseDoc, name, annotations)
		}
	}

	for k := range unknownKinds {
		g.UnknownResourceTypes = append(g.UnknownResourceTypes, k)
	}
	for f := range unrecognized {
		g.UnrecognizedFields = append(g.UnrecognizedFields, f)
	}
	sort.Strings(g.UnknownResourceTypes)
	sort.Strings(g.UnrecognizedFields)
	sort.Slice(g.Resources, func(i, j int) bool { return g.Resources[i].Address < g.Resources[j].Address })
	sort.Slice(g.Grants, func(i, j int) bool { return g.Grants[i].ID < g.Grants[j].ID })
	sort.Slice(g.NetworkRules, func(i, j int) bool { return g.NetworkRules[i].ID < g.NetworkRules[j].ID })
	sort.Slice(g.Segments, func(i, j int) bool { return g.Segments[i].Name < g.Segments[j].Name })
	return g, nil
}

// A Service carrying a bucket annotation is that bucket's published surface,
// and the permission it declares is a grant.
func (g *Graph) addService(doc, base map[string]any, name string, annotations map[string]string) {
	bucket := annotations[annotationPrefix+"bucket"]
	if bucket == "" {
		return
	}
	address := "manifest/Service/" + name
	g.Resources = append(g.Resources, Resource{
		Kind: "bucket", Name: bucket, Address: address,
		Attributes: map[string]any{
			"name": bucket,
			"type": str(mapOf(doc["spec"])["type"]),
		},
	})
	baseAnnotations := stringMap(mapOf(mapOf(base["metadata"])["annotations"]))
	g.Grants = append(g.Grants, Grant{
		ID:           annotations[annotationPrefix+"grant"],
		ResourceKind: "bucket",
		ResourceName: bucket,
		Principals:   splitList(annotations[annotationPrefix+"readers"]),
		Actions:      []string{"read"},
		SourceRanges: splitList(annotations[annotationPrefix+"reader-sources"]),
		Address:      address,
		Provenance: map[string]Provenance{
			"principals":    manifestOrigin("readers", annotations, baseAnnotations),
			"source_ranges": manifestOrigin("reader-sources", annotations, baseAnnotations),
		},
	})
}

// A Deployment carrying a workload annotation is that workload, and its
// container ports are the listeners it declares.
func (g *Graph) addDeployment(doc, base map[string]any, name string, annotations map[string]string) {
	workload := annotations[annotationPrefix+"workload"]
	if workload == "" {
		return
	}
	podSpec := mapOf(mapOf(mapOf(doc["spec"])["template"])["spec"])
	basePodSpec := mapOf(mapOf(mapOf(base["spec"])["template"])["spec"])

	ports := []Port{}
	prov := map[string]Provenance{}
	for i, raw := range listOf(podSpec["containers"]) {
		container := mapOf(raw)
		baseContainer := map[string]any{}
		if bl := listOf(basePodSpec["containers"]); i < len(bl) {
			baseContainer = mapOf(bl[i])
		}
		baseBinds := map[string]string{}
		for _, bp := range listOf(baseContainer["ports"]) {
			p := mapOf(bp)
			baseBinds[str(p["name"])] = str(p["hostIP"])
		}
		for _, rawPort := range listOf(container["ports"]) {
			p := mapOf(rawPort)
			portName := str(p["name"])
			bind := str(p["hostIP"])
			ports = append(ports, Port{
				Name:   portName,
				Number: intOf(p["containerPort"]),
				Bind:   bind,
			})
			prov["ports."+portName+".bind"] = compare(bind, baseBinds[portName])
		}
	}
	g.Resources = append(g.Resources, Resource{
		Kind: "workload", Name: workload, Address: "manifest/Deployment/" + name,
		Ports: ports,
		Attributes: map[string]any{
			"name":        workload,
			"hostNetwork": podSpec["hostNetwork"],
		},
		Provenance: prov,
	})
}

// A NetworkPolicy carrying workload and port annotations is that port's ingress
// rule, and the address blocks it names are its permitted sources.
func (g *Graph) addNetworkPolicy(doc, base map[string]any, name string, annotations map[string]string) {
	workload := annotations[annotationPrefix+"workload"]
	port := annotations[annotationPrefix+"port"]
	if workload == "" || port == "" {
		return
	}
	sources := ipBlocks(doc)
	g.NetworkRules = append(g.NetworkRules, NetworkRule{
		ID:           annotations[annotationPrefix+"rule"],
		Workload:     workload,
		Port:         port,
		SourceRanges: sources,
		Address:      "manifest/NetworkPolicy/" + name,
		Provenance: map[string]Provenance{
			"source_ranges": compare(strings.Join(sources, ","), strings.Join(ipBlocks(base), ",")),
		},
	})
}

func ipBlocks(doc map[string]any) []string {
	out := []string{}
	for _, rule := range listOf(mapOf(doc["spec"])["ingress"]) {
		for _, from := range listOf(mapOf(rule)["from"]) {
			cidr := str(mapOf(mapOf(from)["ipBlock"])["cidr"])
			if cidr != "" {
				out = append(out, cidr)
			}
		}
	}
	return out
}

// manifestOrigin says whether an annotation's value came from the base manifest
// or from the overlay that patched it.
func manifestOrigin(key string, rendered, base map[string]string) Provenance {
	return compare(rendered[annotationPrefix+key], base[annotationPrefix+key])
}

func compare(rendered, base string) Provenance {
	if base != "" && rendered == base {
		return Provenance{Origin: OriginBaseManifest}
	}
	return Provenance{Origin: OriginOverlay}
}

func indexByIdentity(docs []map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, doc := range docs {
		out[str(doc["kind"])+"/"+str(mapOf(doc["metadata"])["name"])] = doc
	}
	return out
}

func splitList(v string) []string {
	out := []string{}
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func mapOf(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}

func listOf(v any) []any {
	l, _ := v.([]any)
	return l
}

func intOf(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	}
	return 0
}

func stringMap(m map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = str(v)
	}
	return out
}
