// Package netset computes coverage over sets of IPv4 CIDR ranges.
//
// The demonstration depends on the difference between matching a literal range
// and computing the addresses a set of ranges actually covers, so coverage is
// always resolved into merged intervals rather than compared as strings.
package netset

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// ErrUnsupported reports an input this package refuses to interpret. Callers
// treat it as a denial rather than as an empty set.
var ErrUnsupported = errors.New("netset: unsupported range")

type interval struct {
	lo, hi uint32
}

// Set is a normalized, merged, sorted collection of IPv4 intervals.
type Set struct {
	intervals []interval
}

// Parse builds a Set from CIDR strings. A malformed, non-IPv4, or otherwise
// uninterpretable entry is an error; nothing is silently skipped.
func Parse(cidrs []string) (*Set, error) {
	s := &Set{}
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrUnsupported, c, err)
		}
		if !p.Addr().Is4() {
			return nil, fmt.Errorf("%w: %q is not IPv4", ErrUnsupported, c)
		}
		p = p.Masked()
		lo := toU32(p.Addr())
		hi := lo + (uint32(1)<<(32-p.Bits()) - 1)
		s.intervals = append(s.intervals, interval{lo, hi})
	}
	s.normalize()
	return s, nil
}

// MustParse is Parse for checked-in constants; it panics on bad input.
func MustParse(cidrs []string) *Set {
	s, err := Parse(cidrs)
	if err != nil {
		panic(err)
	}
	return s
}

// Empty returns a set covering nothing.
func Empty() *Set { return &Set{} }

// All returns a set covering every IPv4 address.
func All() *Set { return MustParse([]string{"0.0.0.0/0"}) }

func toU32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func fromU32(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func (s *Set) normalize() {
	if len(s.intervals) == 0 {
		return
	}
	sort.Slice(s.intervals, func(i, j int) bool {
		if s.intervals[i].lo != s.intervals[j].lo {
			return s.intervals[i].lo < s.intervals[j].lo
		}
		return s.intervals[i].hi < s.intervals[j].hi
	})
	merged := []interval{s.intervals[0]}
	for _, iv := range s.intervals[1:] {
		last := &merged[len(merged)-1]
		// Adjacent intervals merge too: 0.0.0.0/1 and 128.0.0.0/1 are one range.
		if iv.lo <= last.hi || (last.hi != ^uint32(0) && iv.lo == last.hi+1) {
			if iv.hi > last.hi {
				last.hi = iv.hi
			}
			continue
		}
		merged = append(merged, iv)
	}
	s.intervals = merged
}

// Contains reports whether addr falls inside the covered set.
func (s *Set) Contains(addr netip.Addr) bool {
	if s == nil || !addr.Is4() {
		return false
	}
	v := toU32(addr)
	for _, iv := range s.intervals {
		if v >= iv.lo && v <= iv.hi {
			return true
		}
	}
	return false
}

// IsEmpty reports whether the set covers no address at all.
func (s *Set) IsEmpty() bool { return s == nil || len(s.intervals) == 0 }

// CoversAll reports whether the set covers every IPv4 address, however the
// caller chose to express it.
func (s *Set) CoversAll() bool {
	return s != nil && len(s.intervals) == 1 && s.intervals[0].lo == 0 && s.intervals[0].hi == ^uint32(0)
}

// Union returns the coverage of both sets.
func (s *Set) Union(o *Set) *Set {
	out := &Set{}
	if s != nil {
		out.intervals = append(out.intervals, s.intervals...)
	}
	if o != nil {
		out.intervals = append(out.intervals, o.intervals...)
	}
	out.normalize()
	return out
}

// Intersect returns the coverage present in both sets.
func (s *Set) Intersect(o *Set) *Set {
	out := &Set{}
	if s == nil || o == nil {
		return out
	}
	for _, a := range s.intervals {
		for _, b := range o.intervals {
			lo, hi := a.lo, a.hi
			if b.lo > lo {
				lo = b.lo
			}
			if b.hi < hi {
				hi = b.hi
			}
			if lo <= hi {
				out.intervals = append(out.intervals, interval{lo, hi})
			}
		}
	}
	out.normalize()
	return out
}

// Equal reports whether two sets cover exactly the same addresses.
func (s *Set) Equal(o *Set) bool {
	a, b := s.Prefixes(), o.Prefixes()
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Prefixes renders the merged coverage as a canonical, sorted list of CIDR
// strings, so two different spellings of the same coverage render identically.
func (s *Set) Prefixes() []string {
	out := []string{}
	if s == nil {
		return out
	}
	for _, iv := range s.intervals {
		lo, hi := uint64(iv.lo), uint64(iv.hi)
		for lo <= hi {
			bits := 32
			for b := 0; b <= 32; b++ {
				size := uint64(1) << b
				if size > hi-lo+1 || lo%size != 0 {
					break
				}
				bits = 32 - b
			}
			out = append(out, netip.PrefixFrom(fromU32(uint32(lo)), bits).String())
			lo += uint64(1) << (32 - bits)
		}
	}
	return out
}

// String renders the canonical coverage for transcripts and decisions.
func (s *Set) String() string {
	p := s.Prefixes()
	if len(p) == 0 {
		return "none"
	}
	return strings.Join(p, ",")
}
