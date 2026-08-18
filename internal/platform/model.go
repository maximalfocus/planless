// Package platform implements democloud: a fictional platform control plane
// that holds resources and authorizes every request against the effective
// permissions those resources produce.
//
// democloud is not an emulator of, and makes no claim about, any real cloud
// provider. It exists only inside this demonstration's container network.
package platform

// Resource kinds held by the control plane.
const (
	KindBucket   = "bucket"
	KindObject   = "object"
	KindWorkload = "workload"
)

// Actions a grant may carry.
const (
	ActionRead  = "read"
	ActionWrite = "write"
)

// Anonymous is the principal of a caller that asserted no identity.
const Anonymous = "*"

// Segment names the network segment a request arrived from.
type Segment struct {
	Name string `json:"name"`
	CIDR string `json:"cidr"`
}

// Bucket holds objects. Its exposure comes from grants, never from a field on
// the bucket itself.
type Bucket struct {
	Name      string `json:"name"`
	Encrypted bool   `json:"encrypted"`

	// LogRetentionDays is an ordinary operational setting with no bearing on
	// who can reach anything.
	LogRetentionDays int `json:"log_retention_days"`
}

// Object is a stored blob. State renders its digest and size, never its bytes.
type Object struct {
	Bucket        string `json:"bucket"`
	Key           string `json:"key"`
	ContentType   string `json:"content_type"`
	Size          int    `json:"size"`
	ContentDigest string `json:"content_digest"`

	body []byte
}

// Body returns a copy of the object's stored bytes.
func (o Object) Body() []byte {
	out := make([]byte, len(o.body))
	copy(out, o.body)
	return out
}

// Grant is a standalone permission resource. Keeping grants separate from the
// resources they apply to is deliberate: a permission can be added by a
// resource a reviewer never looks at.
type Grant struct {
	ID           string   `json:"id"`
	ResourceKind string   `json:"resource_kind"`
	ResourceName string   `json:"resource_name"`
	Principals   []string `json:"principals"`
	Actions      []string `json:"actions"`
	SourceRanges []string `json:"source_ranges"`
}

// Port is a listener a workload declares, with the address it binds.
type Port struct {
	Name   string `json:"name"`
	Number int    `json:"number"`
	Bind   string `json:"bind"`
}

// Workload is a running service registered with the platform.
type Workload struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Ports   []Port `json:"ports"`
}

// NetworkRule permits ingress to one workload port from a set of sources.
type NetworkRule struct {
	ID           string   `json:"id"`
	Workload     string   `json:"workload"`
	Port         string   `json:"port"`
	SourceRanges []string `json:"source_ranges"`
}

// Principal is an identity the platform recognizes.
type Principal struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// LedgerEntry records one accepted mutation of platform state.
type LedgerEntry struct {
	Seq       int    `json:"seq"`
	Action    string `json:"action"`
	Resource  string `json:"resource"`
	Principal string `json:"principal"`
	Segment   string `json:"segment"`
	Detail    string `json:"detail"`
}

// State is the complete, canonically ordered platform state.
type State struct {
	Segments     []Segment     `json:"segments"`
	Principals   []Principal   `json:"principals"`
	Buckets      []Bucket      `json:"buckets"`
	Objects      []Object      `json:"objects"`
	Grants       []Grant       `json:"grants"`
	Workloads    []Workload    `json:"workloads"`
	NetworkRules []NetworkRule `json:"network_rules"`
	Ledger       []LedgerEntry `json:"ledger"`
}
