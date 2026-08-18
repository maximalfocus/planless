// Package fixtures holds the Halloway Transit Authority fixture set.
//
// Every organization, person, rider, refund, bucket, object, principal,
// address, workload and policy here is invented. The address ranges are
// reserved documentation and private ranges, and the names are chosen so they
// cannot collide with any real global namespace.
package fixtures

import (
	_ "embed"

	"github.com/maximalfocus/planless/internal/platform"
)

// Fixture identities used across the demonstration.
const (
	OrgLabel = "halloway"

	BucketFareExports = "fare-exports"
	BucketStatusPage  = "status-page"

	// BucketStatusAssets holds a second status asset. Publishing it is the
	// demonstration's reviewed exposure change: refused by the current
	// allowlist, admitted only by an allowlist that names it.
	BucketStatusAssets = "status-assets"

	ObjectRefunds = "rider-refunds-2026-03.csv"
	ObjectStatus  = "status.json"
	ObjectAssets  = "assets.json"

	WorkloadFareEngine = "fare-engine"
	PortService        = "service"
	PortAdmin          = "admin"

	PrincipalFinance  = "finance-reporting"
	PrincipalDeployer = "platform-deployer"

	SegmentCorp     = "corp"
	SegmentInternet = "internet"

	CorpCIDR       = "10.20.0.0/16"
	InternetCIDR   = "198.51.100.0/24"
	OperationsCIDR = "10.20.7.0/24"

	ControlPlaneCorpAddr = "10.20.1.10"
	FareEngineAddr       = "10.20.1.20"

	// DefaultLogRetentionDays is an ordinary operational setting with no
	// security meaning at all. Changing it is the demonstration's proof that
	// the gate is not an obstacle to routine work.
	DefaultLogRetentionDays = 30

	// RoutineLogRetentionDays is what the routine-change scenario sets it to.
	RoutineLogRetentionDays = 90

	// ProbeAddress is where the public-segment probe client sits. It is used to
	// ask whether a reviewed exposure actually reaches the public segment.
	ProbeAddress = "198.51.100.50"
)

//go:embed data/rider-refunds-2026-03.csv
var refundsCSV []byte

//go:embed data/status.json
var statusJSON []byte

//go:embed data/assets.json
var assetsJSON []byte

// RefundsCSV returns the exact fictional refund export bytes.
func RefundsCSV() []byte { return append([]byte(nil), refundsCSV...) }

// StatusJSON returns the exact fictional status page bytes.
func StatusJSON() []byte { return append([]byte(nil), statusJSON...) }

// AssetsJSON returns the exact fictional second status asset bytes.
func AssetsJSON() []byte { return append([]byte(nil), assetsJSON...) }

// Segments returns the two network segments the demonstration runs on.
func Segments() []platform.Segment {
	return []platform.Segment{
		{Name: SegmentCorp, CIDR: CorpCIDR},
		{Name: SegmentInternet, CIDR: InternetCIDR},
	}
}

// Bootstrap is the platform as it exists before any infrastructure is
// declared: its segments, its principals, and the deployer's scope.
//
// The deployer's scope is named here rather than declared by infrastructure,
// because a deployment principal that could widen its own permissions would
// make every later claim about least privilege meaningless. It is identical in
// every variant of the demonstration.
func Bootstrap() platform.State {
	st := platform.State{
		Segments: Segments(),
		Principals: []platform.Principal{
			{Name: PrincipalFinance, Description: "reads the quarterly refund export from the corporate segment"},
			{Name: PrincipalDeployer, Description: "applies infrastructure changes to exactly the fixture resources"},
		},
		Grants: []platform.Grant{
			deployScope("grant-deploy-fare-exports", platform.KindBucket, BucketFareExports),
			deployScope("grant-deploy-status-page", platform.KindBucket, BucketStatusPage),
			deployScope("grant-deploy-status-assets", platform.KindBucket, BucketStatusAssets),
			deployScope("grant-deploy-fare-engine", platform.KindWorkload, WorkloadFareEngine),
		},
	}
	return st
}

func deployScope(id, kind, name string) platform.Grant {
	return platform.Grant{
		ID:           id,
		ResourceKind: kind,
		ResourceName: name,
		Principals:   []string{PrincipalDeployer},
		Actions:      []string{platform.ActionWrite},
		SourceRanges: []string{CorpCIDR},
	}
}

// SecureBaseline is the intended posture: the refund export readable only by
// the finance principal from the corporate segment, the status page
// deliberately public, and the fare engine's admin port reachable only from the
// operations range.
func SecureBaseline() platform.State {
	st := Bootstrap()
	st.Buckets = []platform.Bucket{
		{Name: BucketFareExports, Encrypted: true, LogRetentionDays: DefaultLogRetentionDays},
		{Name: BucketStatusPage, Encrypted: true, LogRetentionDays: DefaultLogRetentionDays},
		{Name: BucketStatusAssets, Encrypted: true, LogRetentionDays: DefaultLogRetentionDays},
	}
	st.Objects = []platform.Object{
		{Bucket: BucketFareExports, Key: ObjectRefunds, ContentType: "text/csv"},
		{Bucket: BucketStatusPage, Key: ObjectStatus, ContentType: "application/json"},
		{Bucket: BucketStatusAssets, Key: ObjectAssets, ContentType: "application/json"},
	}
	st.Grants = append(st.Grants,
		platform.Grant{
			ID:           "grant-fare-exports-finance-read",
			ResourceKind: platform.KindBucket,
			ResourceName: BucketFareExports,
			Principals:   []string{PrincipalFinance},
			Actions:      []string{platform.ActionRead},
			SourceRanges: []string{CorpCIDR},
		},
		platform.Grant{
			ID:           "grant-status-assets-read",
			ResourceKind: platform.KindBucket,
			ResourceName: BucketStatusAssets,
			Principals:   []string{PrincipalFinance},
			Actions:      []string{platform.ActionRead},
			SourceRanges: []string{CorpCIDR},
		},
		platform.Grant{
			ID:           "grant-status-page-public-read",
			ResourceKind: platform.KindBucket,
			ResourceName: BucketStatusPage,
			Principals:   []string{platform.Anonymous},
			Actions:      []string{platform.ActionRead},
			SourceRanges: []string{"0.0.0.0/0"},
		},
	)
	st.Workloads = []platform.Workload{{
		Name:    WorkloadFareEngine,
		Address: FareEngineAddr,
		Ports: []platform.Port{
			{Name: PortService, Number: 8080, Bind: FareEngineAddr},
			{Name: PortAdmin, Number: 8081, Bind: FareEngineAddr},
		},
	}}
	st.NetworkRules = []platform.NetworkRule{
		{ID: "rule-fare-engine-service", Workload: WorkloadFareEngine, Port: PortService, SourceRanges: []string{CorpCIDR}},
		{ID: "rule-fare-engine-admin", Workload: WorkloadFareEngine, Port: PortAdmin, SourceRanges: []string{OperationsCIDR}},
	}
	return st
}

// Bodies returns the object bytes for each seeded object key.
func Bodies() map[string][]byte {
	return map[string][]byte{
		BucketFareExports + "/" + ObjectRefunds: RefundsCSV(),
		BucketStatusPage + "/" + ObjectStatus:   StatusJSON(),
		BucketStatusAssets + "/" + ObjectAssets: AssetsJSON(),
	}
}

// Seed loads a state into a store together with the object bodies, so a fresh
// run always recreates byte-identical platform state.
func Seed(store *platform.Store, st platform.State) {
	store.Load(st)
	bodies := Bodies()
	for _, o := range st.Objects {
		body, ok := bodies[o.Bucket+"/"+o.Key]
		if !ok {
			continue
		}
		store.PutObject(platform.Object{
			Bucket:      o.Bucket,
			Key:         o.Key,
			ContentType: o.ContentType,
		}, body)
	}
}
