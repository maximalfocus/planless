package platform

import (
	"net/netip"
	"testing"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a
}

func segments() []Segment {
	return []Segment{
		{Name: "corp", CIDR: "10.20.0.0/16"},
		{Name: "internet", CIDR: "198.51.100.0/24"},
	}
}

func secureState() State {
	return State{
		Segments: segments(),
		Buckets:  []Bucket{{Name: "fare-exports", Encrypted: true}, {Name: "status-page", Encrypted: true}},
		Objects: []Object{
			{Bucket: "fare-exports", Key: "rider-refunds-2026-03.csv"},
			{Bucket: "status-page", Key: "status.json"},
		},
		Grants: []Grant{
			{ID: "g-finance", ResourceKind: KindBucket, ResourceName: "fare-exports",
				Principals: []string{"finance-reporting"}, Actions: []string{ActionRead}, SourceRanges: []string{"10.20.0.0/16"}},
			{ID: "g-status", ResourceKind: KindBucket, ResourceName: "status-page",
				Principals: []string{Anonymous}, Actions: []string{ActionRead}, SourceRanges: []string{"0.0.0.0/0"}},
		},
		Workloads: []Workload{{Name: "fare-engine", Address: "10.20.1.20", Ports: []Port{
			{Name: "service", Number: 8080, Bind: "10.20.1.20"},
			{Name: "admin", Number: 8081, Bind: "10.20.1.20"},
		}}},
		NetworkRules: []NetworkRule{
			{ID: "r-service", Workload: "fare-engine", Port: "service", SourceRanges: []string{"10.20.0.0/16"}},
			{ID: "r-admin", Workload: "fare-engine", Port: "admin", SourceRanges: []string{"10.20.7.0/24"}},
		},
	}
}

func TestObjectReadIsAuthorizedPerCallerAndSegment(t *testing.T) {
	st := secureState()
	cases := []struct {
		name    string
		caller  Caller
		bucket  string
		key     string
		allowed bool
		reason  string
	}{
		{"finance from corp", Caller{Principal: "finance-reporting", Segment: "corp", Addr: mustAddr(t, "10.20.5.30")}, "fare-exports", "rider-refunds-2026-03.csv", true, ReasonAllowed},
		{"anonymous from corp", Caller{Segment: "corp", Addr: mustAddr(t, "10.20.5.30")}, "fare-exports", "rider-refunds-2026-03.csv", false, ReasonNoGrant},
		{"anonymous from internet", Caller{Segment: "internet", Addr: mustAddr(t, "198.51.100.50")}, "fare-exports", "rider-refunds-2026-03.csv", false, ReasonNoGrant},
		{"public status from internet", Caller{Segment: "internet", Addr: mustAddr(t, "198.51.100.50")}, "status-page", "status.json", true, ReasonAllowed},
		{"unknown segment", Caller{Addr: mustAddr(t, "203.0.113.9")}, "status-page", "status.json", false, ReasonUnknownSegment},
		{"missing object", Caller{Segment: "corp", Addr: mustAddr(t, "10.20.5.30")}, "fare-exports", "no-such-object", false, ReasonNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := AuthorizeObjectRead(st, tc.caller, tc.bucket, tc.key)
			if got.Allowed != tc.allowed || got.Reason != tc.reason {
				t.Fatalf("got %+v, want allowed=%v reason=%s", got, tc.allowed, tc.reason)
			}
		})
	}
}

// A principal claim from outside the corporate segment must not help: the grant
// still names a corporate source range.
func TestClaimedPrincipalDoesNotCrossTheSegmentBoundary(t *testing.T) {
	st := secureState()
	c := Caller{Principal: "finance-reporting", Segment: "internet", Addr: mustAddr(t, "198.51.100.50")}
	if d := AuthorizeObjectRead(st, c, "fare-exports", "rider-refunds-2026-03.csv"); d.Allowed {
		t.Fatalf("expected refusal, got %+v", d)
	}
}

func TestConnectIsAuthorizedPerSourceAddress(t *testing.T) {
	st := secureState()
	cases := []struct {
		name    string
		addr    string
		segment string
		port    string
		allowed bool
		reason  string
	}{
		{"operations range reaches admin", "10.20.7.40", "corp", "admin", true, ReasonAllowed},
		{"corporate outside operations range", "10.20.5.30", "corp", "admin", false, ReasonNoRule},
		{"corporate reaches service", "10.20.5.30", "corp", "service", true, ReasonAllowed},
		{"internet reaches nothing", "198.51.100.50", "internet", "admin", false, ReasonBindUnreachable},
		{"internet reaches no service port", "198.51.100.50", "internet", "service", false, ReasonBindUnreachable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Caller{Segment: tc.segment, Addr: mustAddr(t, tc.addr)}
			got, _, _ := AuthorizeConnect(st, c, "fare-engine", tc.port)
			if got.Allowed != tc.allowed || got.Reason != tc.reason {
				t.Fatalf("got %+v, want allowed=%v reason=%s", got, tc.allowed, tc.reason)
			}
		})
	}
	if d, _, _ := AuthorizeConnect(st, Caller{Segment: "corp", Addr: mustAddr(t, "10.20.7.40")}, "fare-engine", "no-such-port"); d.Reason != ReasonNotFound {
		t.Fatalf("expected an unknown port to be refused as not found, got %+v", d)
	}
}

// Effective exposure is computed, not matched. A grant that names every address
// through a pair of half-ranges exposes exactly as much as 0.0.0.0/0 does, and
// a separate grant resource exposes a bucket its own definition never mentions.
func TestEffectiveExposureIsComputedNotMatched(t *testing.T) {
	st := secureState()
	st.Grants = append(st.Grants, Grant{
		ID: "g-split", ResourceKind: KindBucket, ResourceName: "fare-exports",
		Principals: []string{Anonymous}, Actions: []string{ActionRead},
		SourceRanges: []string{"0.0.0.0/1", "128.0.0.0/1"},
	})
	c := Caller{Segment: "internet", Addr: mustAddr(t, "198.51.100.50")}
	d := AuthorizeObjectRead(st, c, "fare-exports", "rider-refunds-2026-03.csv")
	if !d.Allowed || d.Rule != "g-split" {
		t.Fatalf("expected the split-range grant to expose the export, got %+v", d)
	}

	exposures, err := EffectiveGrants(st.Grants, KindBucket, "fare-exports", ActionRead)
	if err != nil {
		t.Fatal(err)
	}
	if len(exposures) != 2 {
		t.Fatalf("expected two grants on the export, got %d", len(exposures))
	}
	for _, e := range exposures {
		if e.Rule == "g-split" && !e.Sources.CoversAll() {
			t.Fatalf("expected the split pair to cover every address, got %s", e.Sources)
		}
	}
}

func TestIngressUnionAndBindReach(t *testing.T) {
	st := secureState()
	st.NetworkRules = append(st.NetworkRules, NetworkRule{
		ID: "r-admin-split", Workload: "fare-engine", Port: "admin",
		SourceRanges: []string{"0.0.0.0/1", "128.0.0.0/1"},
	})
	// The union now covers every address, but the declared bind still only
	// serves the corporate segment.
	set, rule, err := EffectiveIngress(st.NetworkRules, st.Workloads[0], st.Workloads[0].Ports[1], st.Segments)
	if err != nil {
		t.Fatal(err)
	}
	if rule != "r-admin+r-admin-split" {
		t.Fatalf("expected both rules named, got %q", rule)
	}
	if set.String() != "10.20.0.0/16" {
		t.Fatalf("expected the bind address to cap the exposure at the corporate segment, got %s", set)
	}

	// An unrestricted bind removes that cap entirely.
	w := st.Workloads[0]
	w.Ports[1].Bind = "0.0.0.0"
	set, _, err = EffectiveIngress(st.NetworkRules, w, w.Ports[1], st.Segments)
	if err != nil {
		t.Fatal(err)
	}
	if !set.CoversAll() {
		t.Fatalf("expected an unrestricted bind with an unrestricted rule to expose every address, got %s", set)
	}
}

func TestBindReach(t *testing.T) {
	segs := segments()
	cases := map[string]string{
		"127.0.0.1":     "none",
		"0.0.0.0":       "0.0.0.0/0",
		"10.20.1.20":    "10.20.0.0/16",
		"198.51.100.10": "198.51.100.0/24",
		"203.0.113.7":   "none",
	}
	for bind, want := range cases {
		got, err := BindReach(bind, segs)
		if err != nil {
			t.Fatalf("%s: %v", bind, err)
		}
		if got.String() != want {
			t.Fatalf("bind %s: got %s want %s", bind, got, want)
		}
	}
	for _, bad := range []string{"", "not-an-address", "::1"} {
		if _, err := BindReach(bad, segs); err == nil {
			t.Fatalf("expected %q to be refused", bad)
		}
	}
}

// An uninterpretable permission input denies. It never becomes an empty set
// that silently allows or silently refuses for the wrong reason.
func TestUnparsableInputsFailClosed(t *testing.T) {
	st := secureState()
	st.Grants[1].SourceRanges = []string{"not-a-cidr"}
	c := Caller{Segment: "internet", Addr: mustAddr(t, "198.51.100.50")}
	if d := AuthorizeObjectRead(st, c, "status-page", "status.json"); d.Allowed || d.Reason != ReasonUnparsable {
		t.Fatalf("expected an unparsable grant to deny, got %+v", d)
	}
	st = secureState()
	st.NetworkRules[1].SourceRanges = []string{"10.20.7.0/99"}
	cc := Caller{Segment: "corp", Addr: mustAddr(t, "10.20.7.40")}
	if d, _, _ := AuthorizeConnect(st, cc, "fare-engine", "admin"); d.Allowed || d.Reason != ReasonUnparsable {
		t.Fatalf("expected an unparsable rule to deny, got %+v", d)
	}
	st = secureState()
	st.Workloads[0].Ports[1].Bind = "not-an-address"
	if d, _, _ := AuthorizeConnect(st, cc, "fare-engine", "admin"); d.Allowed || d.Reason != ReasonUnparsable {
		t.Fatalf("expected an unparsable bind to deny, got %+v", d)
	}
}
