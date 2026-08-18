// Package graph defines the policy input contract: a normalized resource graph
// carrying identity, grants, network rules, bind addresses and provenance.
//
// The contract exists so one policy body can decide more than one manifest
// format. Nothing in it is specific to the toolchain that produced it, and the
// policy never reads a plan, a manifest, or a source file directly.
package graph

// ContractVersion is the version of the policy input contract. A policy that
// receives an unfamiliar version denies rather than guesses.
const ContractVersion = "1"

// Surfaces a normalizer can declare.
const (
	SurfaceIaCPlan = "iac-plan"
)

// Origin says where a resolved value came from. The whole demonstration turns
// on the difference between a value written in a resource block and a value
// that arrives from somewhere a reader never opened.
type Origin string

const (
	OriginLiteral       Origin = "literal"
	OriginVariableFile  Origin = "variable-file"
	OriginModuleDefault Origin = "module-default"
	OriginRootDefault   Origin = "root-default"
	OriginUnknown       Origin = "unknown"
)

// Contribution is one variable that took part in deciding a resolved value.
type Contribution struct {
	Origin    Origin `json:"origin"`
	Reference string `json:"reference"`
}

// Provenance records where one resolved value came from.
//
// A value can be decided by more than one variable — a module default holding
// the addresses, selected by a key from the variable file — so every
// contributing reference is recorded. Origin names the least visible of them,
// because that is the one a reader is least likely to have opened.
type Provenance struct {
	Origin       Origin         `json:"origin"`
	Reference    string         `json:"reference,omitempty"`
	Contributors []Contribution `json:"contributors,omitempty"`
}

// Port is a declared listener with the address it binds.
type Port struct {
	Name   string `json:"name"`
	Number int64  `json:"number"`
	Bind   string `json:"bind"`
}

// Resource is one addressable thing on the platform.
type Resource struct {
	Kind       string                `json:"kind"`
	Name       string                `json:"name"`
	Address    string                `json:"address"`
	Ports      []Port                `json:"ports,omitempty"`
	Provenance map[string]Provenance `json:"provenance,omitempty"`
}

// Grant is a standalone permission on a resource.
type Grant struct {
	ID           string                `json:"id"`
	ResourceKind string                `json:"resource_kind"`
	ResourceName string                `json:"resource_name"`
	Principals   []string              `json:"principals"`
	Actions      []string              `json:"actions"`
	SourceRanges []string              `json:"source_ranges"`
	Address      string                `json:"address"`
	Provenance   map[string]Provenance `json:"provenance,omitempty"`
}

// NetworkRule permits ingress to one workload port.
type NetworkRule struct {
	ID           string                `json:"id"`
	Workload     string                `json:"workload"`
	Port         string                `json:"port"`
	SourceRanges []string              `json:"source_ranges"`
	Address      string                `json:"address"`
	Provenance   map[string]Provenance `json:"provenance,omitempty"`
}

// Segment is a network segment the platform runs on. Segments are platform
// facts rather than plan facts; the normalizer supplies them so the policy
// input is self-contained.
type Segment struct {
	Name string `json:"name"`
	CIDR string `json:"cidr"`
}

// Graph is the complete policy input.
type Graph struct {
	ContractVersion string `json:"contract_version"`
	Surface         string `json:"surface"`

	Segments     []Segment     `json:"segments"`
	Resources    []Resource    `json:"resources"`
	Grants       []Grant       `json:"grants"`
	NetworkRules []NetworkRule `json:"network_rules"`

	// Anything the normalizer did not recognize is reported rather than
	// dropped. A policy that cannot see what it failed to understand cannot
	// fail closed.
	UnknownResourceTypes []string `json:"unknown_resource_types"`
	UnrecognizedFields   []string `json:"unrecognized_fields"`
}
