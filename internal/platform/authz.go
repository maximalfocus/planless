package platform

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/maximalfocus/planless/internal/netset"
)

// Caller is the authenticated view of one request: who asked, from where.
type Caller struct {
	Principal string
	Segment   string
	Addr      netip.Addr
}

// Stable failure classes. They are deliberately coarse: the operator-facing
// result must not reveal whether a resource, grant, or principal exists.
const (
	ReasonAllowed         = "allowed"
	ReasonNoGrant         = "no_effective_grant"
	ReasonNoRule          = "no_effective_ingress_rule"
	ReasonBindUnreachable = "bind_address_unreachable_from_segment"
	ReasonUnknownSegment  = "unknown_segment"
	ReasonNotFound        = "resource_not_found"
	ReasonUnparsable      = "unparsable_permission_input"
)

// Decision is the result of one authorization, with the rule that produced it.
type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
	Rule    string `json:"rule"`
}

func deny(reason string) Decision { return Decision{Allowed: false, Reason: reason} }

// Exposure is the computed effective reachability of one resource: which
// principals can act on it, from which source addresses.
type Exposure struct {
	Principals []string
	Sources    *netset.Set
	Rule       string
}

// EffectiveGrants computes, for a resource and action, the exposure each grant
// contributes. An uninterpretable source range is an error, never an empty set:
// the caller denies rather than guessing.
func EffectiveGrants(grants []Grant, kind, name, action string) ([]Exposure, error) {
	var out []Exposure
	for _, g := range grants {
		if g.ResourceKind != kind || g.ResourceName != name {
			continue
		}
		if !slices.Contains(g.Actions, action) {
			continue
		}
		set, err := netset.Parse(g.SourceRanges)
		if err != nil {
			return nil, fmt.Errorf("grant %s: %w", g.ID, err)
		}
		out = append(out, Exposure{Principals: slices.Clone(g.Principals), Sources: set, Rule: g.ID})
	}
	return out, nil
}

// EffectiveIngress computes which source addresses can actually reach a
// workload port: the union of every permitting rule, intersected with the set
// of addresses the declared bind address can serve.
func EffectiveIngress(rules []NetworkRule, w Workload, p Port, segments []Segment) (*netset.Set, string, error) {
	permitted := netset.Empty()
	rule := ""
	for _, r := range rules {
		if r.Workload != w.Name || r.Port != p.Name {
			continue
		}
		set, err := netset.Parse(r.SourceRanges)
		if err != nil {
			return nil, "", fmt.Errorf("network rule %s: %w", r.ID, err)
		}
		permitted = permitted.Union(set)
		if rule == "" {
			rule = r.ID
		} else {
			rule += "+" + r.ID
		}
	}
	reach, err := BindReach(p.Bind, segments)
	if err != nil {
		return nil, "", err
	}
	return permitted.Intersect(reach), rule, nil
}

// BindReach computes which addresses a listener bound to a given address can
// serve. A loopback bind serves nobody off-host; a segment address serves that
// segment; the unspecified address serves every segment.
//
// The routing consequence of a bind address is democloud's own model of a
// platform network. It is labelled `simulated: platform-fabric-routing` in
// transcripts and asserts nothing about any real platform.
func BindReach(bind string, segments []Segment) (*netset.Set, error) {
	if bind == "" {
		return nil, fmt.Errorf("%w: empty bind address", netset.ErrUnsupported)
	}
	addr, err := netip.ParseAddr(bind)
	if err != nil || !addr.Is4() {
		return nil, fmt.Errorf("%w: bind address %q", netset.ErrUnsupported, bind)
	}
	if addr.IsLoopback() {
		return netset.Empty(), nil
	}
	if addr.IsUnspecified() {
		return netset.All(), nil
	}
	for _, s := range segments {
		set, err := netset.Parse([]string{s.CIDR})
		if err != nil {
			return nil, err
		}
		if set.Contains(addr) {
			return set, nil
		}
	}
	// A bind address in no known segment can serve nobody. Fail closed.
	return netset.Empty(), nil
}

// AuthorizeObjectRead decides one storage read at request time.
func AuthorizeObjectRead(st State, c Caller, bucket, key string) Decision {
	if c.Segment == "" {
		return deny(ReasonUnknownSegment)
	}
	found := false
	for _, o := range st.Objects {
		if o.Bucket == bucket && o.Key == key {
			found = true
			break
		}
	}
	if !found {
		return deny(ReasonNotFound)
	}
	exposures, err := EffectiveGrants(st.Grants, KindBucket, bucket, ActionRead)
	if err != nil {
		return deny(ReasonUnparsable)
	}
	principal := c.Principal
	if principal == "" {
		principal = Anonymous
	}
	for _, e := range exposures {
		if !slices.Contains(e.Principals, principal) && !slices.Contains(e.Principals, Anonymous) {
			continue
		}
		if e.Sources.Contains(c.Addr) {
			return Decision{Allowed: true, Reason: ReasonAllowed, Rule: e.Rule}
		}
	}
	return deny(ReasonNoGrant)
}

// AuthorizeConnect decides one network connect to a workload port at request
// time, from the caller's originating address.
func AuthorizeConnect(st State, c Caller, workload, port string) (Decision, Workload, Port) {
	if c.Segment == "" {
		return deny(ReasonUnknownSegment), Workload{}, Port{}
	}
	var w Workload
	var p Port
	okWorkload, okPort := false, false
	for _, cand := range st.Workloads {
		if cand.Name != workload {
			continue
		}
		w, okWorkload = cand, true
		for _, cp := range cand.Ports {
			if cp.Name == port {
				p, okPort = cp, true
			}
		}
	}
	if !okWorkload || !okPort {
		return deny(ReasonNotFound), Workload{}, Port{}
	}
	permitted, rule, err := EffectiveIngress(st.NetworkRules, w, p, st.Segments)
	if err != nil {
		return deny(ReasonUnparsable), w, p
	}
	if permitted.Contains(c.Addr) {
		return Decision{Allowed: true, Reason: ReasonAllowed, Rule: rule}, w, p
	}
	reach, err := BindReach(p.Bind, st.Segments)
	if err != nil {
		return deny(ReasonUnparsable), w, p
	}
	if !reach.Contains(c.Addr) {
		return deny(ReasonBindUnreachable), w, p
	}
	return deny(ReasonNoRule), w, p
}
