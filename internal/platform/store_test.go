package platform

import (
	"net/netip"
	"testing"
)

func TestDigestIsDeterministicAndOrderIndependent(t *testing.T) {
	a := New(segments())
	a.Load(secureState())
	b := New(segments())
	st := secureState()
	st.Grants[0], st.Grants[1] = st.Grants[1], st.Grants[0]
	st.NetworkRules[0], st.NetworkRules[1] = st.NetworkRules[1], st.NetworkRules[0]
	b.Load(st)

	da, err := a.Digest()
	if err != nil {
		t.Fatal(err)
	}
	db, err := b.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if da != db {
		t.Fatalf("declaration order changed the state digest:\n%s\n%s", da, db)
	}
}

func TestDigestChangesWithExposure(t *testing.T) {
	s := New(segments())
	s.Load(secureState())
	before, _ := s.Digest()
	s.PutGrant(Grant{
		ID: "g-anonymous", ResourceKind: KindBucket, ResourceName: "fare-exports",
		Principals: []string{Anonymous}, Actions: []string{ActionRead}, SourceRanges: []string{"0.0.0.0/0"},
	})
	after, _ := s.Digest()
	if before == after {
		t.Fatal("adding an anonymous grant did not change the state digest")
	}
}

func TestObjectBodiesAreDigestedAndNotSerialized(t *testing.T) {
	s := New(segments())
	s.PutObject(Object{Bucket: "fare-exports", Key: "rider-refunds-2026-03.csv", ContentType: "text/csv"}, []byte("a,b\n1,2\n"))
	obj, err := s.Object("fare-exports", "rider-refunds-2026-03.csv")
	if err != nil {
		t.Fatal(err)
	}
	if obj.Size != 8 || obj.ContentDigest == "" {
		t.Fatalf("expected size and digest to be recomputed, got %+v", obj)
	}
	if string(obj.Body()) != "a,b\n1,2\n" {
		t.Fatalf("unexpected body %q", obj.Body())
	}
}

func TestSegmentClassification(t *testing.T) {
	s := New(segments())
	cases := map[string]string{
		"10.20.7.40":    "corp",
		"198.51.100.50": "internet",
		"203.0.113.9":   "",
	}
	for addr, want := range cases {
		a, err := netip.ParseAddr(addr)
		if err != nil {
			t.Fatal(err)
		}
		if got := s.Segment(a); got != want {
			t.Fatalf("%s: got %q want %q", addr, got, want)
		}
	}
}

func TestLedgerRecordsMutations(t *testing.T) {
	s := New(segments())
	s.Load(secureState())
	c := Caller{Segment: "corp", Addr: netip.MustParseAddr("10.20.7.40")}
	first := s.Record("workload.change", "fare-engine:admin", c, "fare-cap=400")
	second := s.Record("resource.put", "bucket/status-page", Caller{Principal: "platform-deployer", Segment: "corp"}, "")
	if first.Seq != 1 || second.Seq != 2 {
		t.Fatalf("expected sequential rows, got %d and %d", first.Seq, second.Seq)
	}
	if first.Principal != Anonymous || first.Segment != "corp" {
		t.Fatalf("expected an anonymous corporate caller, got %+v", first)
	}
	if rows := s.State().Ledger; len(rows) != 2 {
		t.Fatalf("expected two ledger rows, got %d", len(rows))
	}
}

func TestDeleteAndUpsert(t *testing.T) {
	s := New(segments())
	s.Load(secureState())
	s.PutBucket(Bucket{Name: "fare-exports", Encrypted: false})
	if got := s.State().Buckets; len(got) != 2 {
		t.Fatalf("expected an update rather than an insert, got %d buckets", len(got))
	}
	if err := s.Delete("grant", "g-status"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("grant", "g-status"); err == nil {
		t.Fatal("expected a second delete to report the resource missing")
	}
	if err := s.Delete("unknown-kind", "x"); err == nil {
		t.Fatal("expected an unknown kind to be refused")
	}
}
