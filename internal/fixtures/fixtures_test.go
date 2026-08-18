package fixtures

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/maximalfocus/planless/internal/canon"
	"github.com/maximalfocus/planless/internal/netset"
	"github.com/maximalfocus/planless/internal/platform"
)

// Pinned identities of the checked-in fixture set. A fresh run recreates
// byte-identical platform state, and any change to a fixture has to be a
// deliberate edit here rather than an accident.
const (
	SecureBaselineDigest = "sha256:8e5a3ce7912039e6559bf1bbeb2395d84d4023390b70247c82f6874307346114"
	RefundsDigest        = "sha256:ec93c341749acf6d1b134f2baa23c9b0d72a9a99cf9c4e7b33ab98927890e1b0"
	StatusDigest         = "sha256:b827350682ee1f1ad1391b236f159e0bfe6b605f2f0783936a7adb18e7163061"
)

func seeded(t *testing.T) *platform.Store {
	t.Helper()
	s := platform.New(Segments())
	Seed(s, SecureBaseline())
	return s
}

func TestSeededStateIsByteIdentical(t *testing.T) {
	first, err := seeded(t).Digest()
	if err != nil {
		t.Fatal(err)
	}
	second, err := seeded(t).Digest()
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("two fresh seeds disagreed:\n%s\n%s", first, second)
	}
	if first != SecureBaselineDigest {
		t.Fatalf("the secure baseline changed:\n got %s\nwant %s", first, SecureBaselineDigest)
	}
	if got := canon.Digest(RefundsCSV()); got != RefundsDigest {
		t.Fatalf("refund export changed: got %s want %s", got, RefundsDigest)
	}
	if got := canon.Digest(StatusJSON()); got != StatusDigest {
		t.Fatalf("status page changed: got %s want %s", got, StatusDigest)
	}
}

func TestSecureBaselinePosture(t *testing.T) {
	st := SecureBaseline()
	for _, b := range st.Buckets {
		if !b.Encrypted {
			t.Fatalf("bucket %s is not encrypted; encryption is enabled in every variant", b.Name)
		}
	}
	public := 0
	for _, g := range st.Grants {
		anonymous := false
		for _, p := range g.Principals {
			if p == platform.Anonymous {
				anonymous = true
			}
		}
		if !anonymous {
			continue
		}
		public++
		if g.ResourceName != BucketStatusPage {
			t.Fatalf("grant %s exposes %s anonymously; only the status page is deliberately public", g.ID, g.ResourceName)
		}
	}
	if public != 1 {
		t.Fatalf("expected exactly one deliberately public grant, got %d", public)
	}
}

// The deployer's scope is identical in every variant and never widens: it may
// write exactly the three fixture resources, from the corporate segment only.
func TestDeployerScopeIsMinimal(t *testing.T) {
	scoped := map[string]bool{}
	for _, g := range Bootstrap().Grants {
		for _, p := range g.Principals {
			if p != PrincipalDeployer {
				t.Fatalf("grant %s names %s beside the deployer", g.ID, p)
			}
		}
		for _, a := range g.Actions {
			if a != platform.ActionWrite {
				t.Fatalf("deployer grant %s carries action %s", g.ID, a)
			}
		}
		if len(g.SourceRanges) != 1 || g.SourceRanges[0] != CorpCIDR {
			t.Fatalf("deployer grant %s is reachable from %v", g.ID, g.SourceRanges)
		}
		scoped[g.ResourceKind+"/"+g.ResourceName] = true
	}
	want := []string{
		platform.KindBucket + "/" + BucketFareExports,
		platform.KindBucket + "/" + BucketStatusPage,
		platform.KindWorkload + "/" + WorkloadFareEngine,
	}
	if len(scoped) != len(want) {
		t.Fatalf("deployer scope covers %v", scoped)
	}
	for _, w := range want {
		if !scoped[w] {
			t.Fatalf("deployer scope is missing %s", w)
		}
	}
	if len(Bootstrap().Buckets) != 0 || len(Bootstrap().Workloads) != 0 {
		t.Fatal("bootstrap state must declare no infrastructure of its own")
	}
}

func TestTopologyInvariants(t *testing.T) {
	corp := netset.MustParse([]string{CorpCIDR})
	internet := netset.MustParse([]string{InternetCIDR})
	ops := netset.MustParse([]string{OperationsCIDR})
	if !corp.Intersect(internet).IsEmpty() {
		t.Fatal("the two segments must not overlap")
	}
	if !ops.Intersect(corp).Equal(ops) {
		t.Fatal("the operations range must sit inside the corporate segment")
	}
	for _, addr := range []string{ControlPlaneCorpAddr, FareEngineAddr} {
		if !corp.Contains(netip.MustParseAddr(addr)) {
			t.Fatalf("%s must sit inside the corporate segment", addr)
		}
	}
	if corp.Contains(netip.MustParseAddr("198.51.100.50")) {
		t.Fatal("the probe address must not sit inside the corporate segment")
	}
}

// Every public-facing name is conspicuously fictional and uses ranges reserved
// for documentation or private use, so nothing here can collide with, or be
// mistaken for, a real target.
func TestFixturesAreConspicuouslyFictional(t *testing.T) {
	body := string(RefundsCSV()) + string(StatusJSON())
	for _, forbidden := range []string{
		"amazonaws", "s3.", "azure", "blob.core", "googleapis", "gcp", "cloudfront",
		"http://", "https://", "arn:", "AKIA", "secret", "token", "password",
	} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Fatalf("fixture content contains %q", forbidden)
		}
	}
	if !strings.Contains(string(StatusJSON()), "fictional") {
		t.Fatal("the public status page must label itself as fictional demonstration data")
	}
	// 10.20.0.0/16 is private and 198.51.100.0/24 is TEST-NET-2, reserved for
	// documentation.
	if !netip.MustParseAddr("10.20.1.10").IsPrivate() {
		t.Fatal("the corporate segment must use a private range")
	}
	if !strings.HasPrefix(InternetCIDR, "198.51.100.") {
		t.Fatalf("the public segment must use a reserved documentation range, got %s", InternetCIDR)
	}
}
