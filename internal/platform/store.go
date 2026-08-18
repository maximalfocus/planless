package platform

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/maximalfocus/planless/internal/canon"
	"github.com/maximalfocus/planless/internal/netset"
)

// ErrNotFound reports a missing resource to the typed operation surface.
var ErrNotFound = errors.New("platform: resource not found")

// Store holds platform state. All mutation goes through typed operations so
// there is no path that writes state without the platform observing it.
type Store struct {
	mu    sync.RWMutex
	state State
	seq   int
}

// New returns an empty control plane holding only its segment definitions.
func New(segments []Segment) *Store {
	s := &Store{}
	s.state.Segments = slices.Clone(segments)
	s.normalize()
	return s
}

// Load replaces the whole state, as a seed does. It is not reachable from the
// request surface.
func (s *Store) Load(st State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = cloneState(st)
	s.seq = 0
	for _, e := range s.state.Ledger {
		if e.Seq > s.seq {
			s.seq = e.Seq
		}
	}
	s.normalize()
}

// State returns a canonically ordered copy of platform state.
func (s *Store) State() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneState(s.state)
}

// resourceView is platform state without its change ledger: what the platform
// is configured to be, rather than what has happened to it.
type resourceView struct {
	Segments     []Segment     `json:"segments"`
	Principals   []Principal   `json:"principals"`
	Buckets      []Bucket      `json:"buckets"`
	Objects      []Object      `json:"objects"`
	Grants       []Grant       `json:"grants"`
	Workloads    []Workload    `json:"workloads"`
	NetworkRules []NetworkRule `json:"network_rules"`
}

// Digest returns the canonical digest of the platform's configured state.
//
// The change ledger is deliberately outside this digest. Two things the
// demonstration must be able to say apart: "the declared infrastructure is
// identical" and "nothing has happened". A platform whose configuration is
// unchanged while its world has moved is exactly the shape of drift.
func (s *Store) Digest() (string, error) {
	st := s.State()
	return canon.DigestOf(resourceView{
		Segments:     st.Segments,
		Principals:   st.Principals,
		Buckets:      st.Buckets,
		Objects:      st.Objects,
		Grants:       st.Grants,
		Workloads:    st.Workloads,
		NetworkRules: st.NetworkRules,
	})
}

// LedgerDigest returns the canonical digest of the change ledger.
func (s *Store) LedgerDigest() (string, error) {
	return canon.DigestOf(s.State().Ledger)
}

// Segment classifies a source address into a network segment. An address in no
// declared segment is not classified, and every authorization denies it.
func (s *Store) Segment(addr netip.Addr) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, seg := range s.state.Segments {
		set, err := netset.Parse([]string{seg.CIDR})
		if err != nil {
			continue
		}
		if set.Contains(addr) {
			return seg.Name
		}
	}
	return ""
}

// KnownPrincipal reports whether a principal name is declared on the platform.
func (s *Store) KnownPrincipal(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.state.Principals {
		if p.Name == name {
			return true
		}
	}
	return false
}

// Object returns one stored object.
func (s *Store) Object(bucket, key string) (Object, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, o := range s.state.Objects {
		if o.Bucket == bucket && o.Key == key {
			return o, nil
		}
	}
	return Object{}, ErrNotFound
}

// PutObject stores an object, recomputing its digest and size.
func (s *Store) PutObject(o Object, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o.body = slices.Clone(body)
	o.Size = len(body)
	o.ContentDigest = canon.Digest(body)
	s.state.Objects = upsert(s.state.Objects, o, func(a, b Object) bool {
		return a.Bucket == b.Bucket && a.Key == b.Key
	})
	s.normalize()
}

// PutBucket, PutGrant, PutWorkload, PutNetworkRule and PutPrincipal are the
// typed create/update operations the applier uses.
func (s *Store) PutBucket(b Bucket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Buckets = upsert(s.state.Buckets, b, func(a, c Bucket) bool { return a.Name == c.Name })
	s.normalize()
}

func (s *Store) PutGrant(g Grant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Grants = upsert(s.state.Grants, g, func(a, c Grant) bool { return a.ID == c.ID })
	s.normalize()
}

func (s *Store) PutWorkload(w Workload) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Workloads = upsert(s.state.Workloads, w, func(a, c Workload) bool { return a.Name == c.Name })
	s.normalize()
}

func (s *Store) PutNetworkRule(r NetworkRule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.NetworkRules = upsert(s.state.NetworkRules, r, func(a, c NetworkRule) bool { return a.ID == c.ID })
	s.normalize()
}

func (s *Store) PutPrincipal(p Principal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Principals = upsert(s.state.Principals, p, func(a, c Principal) bool { return a.Name == c.Name })
	s.normalize()
}

// Delete removes one resource by kind and identity.
func (s *Store) Delete(kind, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := 0
	switch kind {
	case "bucket":
		before = len(s.state.Buckets)
		s.state.Buckets = slices.DeleteFunc(s.state.Buckets, func(b Bucket) bool { return b.Name == id })
		if len(s.state.Buckets) == before {
			return ErrNotFound
		}
	case "grant":
		before = len(s.state.Grants)
		s.state.Grants = slices.DeleteFunc(s.state.Grants, func(g Grant) bool { return g.ID == id })
		if len(s.state.Grants) == before {
			return ErrNotFound
		}
	case "network_rule":
		before = len(s.state.NetworkRules)
		s.state.NetworkRules = slices.DeleteFunc(s.state.NetworkRules, func(r NetworkRule) bool { return r.ID == id })
		if len(s.state.NetworkRules) == before {
			return ErrNotFound
		}
	case "workload":
		before = len(s.state.Workloads)
		s.state.Workloads = slices.DeleteFunc(s.state.Workloads, func(w Workload) bool { return w.Name == id })
		if len(s.state.Workloads) == before {
			return ErrNotFound
		}
	case "object":
		bucket, key, ok := strings.Cut(id, "/")
		if !ok {
			return fmt.Errorf("%w: object id %q", ErrNotFound, id)
		}
		before = len(s.state.Objects)
		s.state.Objects = slices.DeleteFunc(s.state.Objects, func(o Object) bool { return o.Bucket == bucket && o.Key == key })
		if len(s.state.Objects) == before {
			return ErrNotFound
		}
	default:
		return fmt.Errorf("%w: unknown kind %q", ErrNotFound, kind)
	}
	s.normalize()
	return nil
}

// Record appends one ledger row for an accepted mutation.
func (s *Store) Record(action, resource string, c Caller, detail string) LedgerEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	principal := c.Principal
	if principal == "" {
		principal = Anonymous
	}
	e := LedgerEntry{
		Seq:       s.seq,
		Action:    action,
		Resource:  resource,
		Principal: principal,
		Segment:   c.Segment,
		Detail:    detail,
	}
	s.state.Ledger = append(s.state.Ledger, e)
	return e
}

func upsert[T any](list []T, v T, same func(a, b T) bool) []T {
	for i := range list {
		if same(list[i], v) {
			list[i] = v
			return list
		}
	}
	return append(list, v)
}

func cloneState(st State) State {
	out := State{
		Segments:     slices.Clone(st.Segments),
		Principals:   slices.Clone(st.Principals),
		Buckets:      slices.Clone(st.Buckets),
		Objects:      slices.Clone(st.Objects),
		Grants:       slices.Clone(st.Grants),
		Workloads:    slices.Clone(st.Workloads),
		NetworkRules: slices.Clone(st.NetworkRules),
		Ledger:       slices.Clone(st.Ledger),
	}
	for i := range out.Objects {
		out.Objects[i].body = slices.Clone(st.Objects[i].body)
	}
	for i := range out.Grants {
		out.Grants[i].Principals = slices.Clone(st.Grants[i].Principals)
		out.Grants[i].Actions = slices.Clone(st.Grants[i].Actions)
		out.Grants[i].SourceRanges = slices.Clone(st.Grants[i].SourceRanges)
	}
	for i := range out.Workloads {
		out.Workloads[i].Ports = slices.Clone(st.Workloads[i].Ports)
	}
	for i := range out.NetworkRules {
		out.NetworkRules[i].SourceRanges = slices.Clone(st.NetworkRules[i].SourceRanges)
	}
	return out
}

// normalize keeps every collection in a stable order so that two runs which
// applied the same resources produce the same state digest.
func (s *Store) normalize() {
	sort.Slice(s.state.Segments, func(i, j int) bool { return s.state.Segments[i].Name < s.state.Segments[j].Name })
	sort.Slice(s.state.Principals, func(i, j int) bool { return s.state.Principals[i].Name < s.state.Principals[j].Name })
	sort.Slice(s.state.Buckets, func(i, j int) bool { return s.state.Buckets[i].Name < s.state.Buckets[j].Name })
	sort.Slice(s.state.Objects, func(i, j int) bool {
		if s.state.Objects[i].Bucket != s.state.Objects[j].Bucket {
			return s.state.Objects[i].Bucket < s.state.Objects[j].Bucket
		}
		return s.state.Objects[i].Key < s.state.Objects[j].Key
	})
	sort.Slice(s.state.Grants, func(i, j int) bool { return s.state.Grants[i].ID < s.state.Grants[j].ID })
	sort.Slice(s.state.Workloads, func(i, j int) bool { return s.state.Workloads[i].Name < s.state.Workloads[j].Name })
	sort.Slice(s.state.NetworkRules, func(i, j int) bool { return s.state.NetworkRules[i].ID < s.state.NetworkRules[j].ID })
	sort.Slice(s.state.Ledger, func(i, j int) bool { return s.state.Ledger[i].Seq < s.state.Ledger[j].Seq })
}
