package netset

import (
	"net/netip"
	"testing"
)

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a
}

func TestContains(t *testing.T) {
	s := MustParse([]string{"10.20.7.0/24"})
	if !s.Contains(addr(t, "10.20.7.40")) {
		t.Fatal("expected 10.20.7.40 inside the operations range")
	}
	if s.Contains(addr(t, "10.20.5.30")) {
		t.Fatal("expected 10.20.5.30 outside the operations range")
	}
	if s.Contains(addr(t, "198.51.100.50")) {
		t.Fatal("expected a public-segment address outside the operations range")
	}
}

// The split pair is the teaching bypass: two ranges that no literal rule for
// "0.0.0.0/0" matches, whose union is nevertheless every address.
func TestSplitPairCoversEveryAddress(t *testing.T) {
	split := MustParse([]string{"0.0.0.0/1", "128.0.0.0/1"})
	if !split.CoversAll() {
		t.Fatalf("expected the split pair to cover every address, got %s", split)
	}
	if !split.Equal(All()) {
		t.Fatalf("expected the split pair to equal 0.0.0.0/0, got %s", split)
	}
	for _, ip := range []string{"0.0.0.0", "10.20.7.40", "127.255.255.255", "128.0.0.0", "198.51.100.50", "255.255.255.255"} {
		if !split.Contains(addr(t, ip)) {
			t.Fatalf("expected %s to be covered by the split pair", ip)
		}
	}
	if split.String() != "0.0.0.0/0" {
		t.Fatalf("expected canonical rendering 0.0.0.0/0, got %s", split)
	}
}

func TestMergeAdjacentAndOverlapping(t *testing.T) {
	s := MustParse([]string{"10.0.0.0/24", "10.0.1.0/24"})
	if got, want := s.String(), "10.0.0.0/23"; got != want {
		t.Fatalf("merge adjacent: got %s want %s", got, want)
	}
	o := MustParse([]string{"10.0.0.0/16", "10.0.5.0/24"})
	if got, want := o.String(), "10.0.0.0/16"; got != want {
		t.Fatalf("merge overlapping: got %s want %s", got, want)
	}
}

func TestUnionIntersectEmpty(t *testing.T) {
	corp := MustParse([]string{"10.20.0.0/16"})
	pub := MustParse([]string{"198.51.100.0/24"})
	u := corp.Union(pub)
	if !u.Contains(addr(t, "10.20.1.10")) || !u.Contains(addr(t, "198.51.100.50")) {
		t.Fatal("union must cover both segments")
	}
	if i := corp.Intersect(pub); !i.IsEmpty() {
		t.Fatalf("segments must not intersect, got %s", i)
	}
	if i := All().Intersect(MustParse([]string{"10.20.7.0/24"})); i.String() != "10.20.7.0/24" {
		t.Fatalf("intersect with everything must be the narrower set, got %s", i)
	}
	if !Empty().IsEmpty() || Empty().CoversAll() {
		t.Fatal("empty set must cover nothing")
	}
}

func TestParseFailsClosed(t *testing.T) {
	for _, bad := range []string{"", "10.20.7.0", "not-a-cidr", "::/0", "2001:db8::/32", "10.20.7.0/33"} {
		if _, err := Parse([]string{bad}); err == nil {
			t.Fatalf("expected %q to be refused", bad)
		}
	}
}

func TestPrefixesRoundTrip(t *testing.T) {
	for _, in := range [][]string{
		{"0.0.0.0/0"},
		{"10.20.7.0/24"},
		{"10.20.7.0/24", "198.51.100.0/24"},
		{"10.20.0.0/16", "10.21.0.0/16"},
		{"192.0.2.1/32"},
	} {
		s := MustParse(in)
		round := MustParse(s.Prefixes())
		if !s.Equal(round) {
			t.Fatalf("round trip of %v changed coverage: %s vs %s", in, s, round)
		}
	}
}
