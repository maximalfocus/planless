// Command client runs the demonstration's enumerated observations from inside
// one network segment.
//
// It accepts no host, URL, port, path, method or payload: every request it can
// issue is a checked-in constant, and the endpoint it talks to is fixed by the
// role of the check being run. It holds no credential. It has no scanning,
// sweeping, enumeration or retry-search capability.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/maximalfocus/planless/internal/canon"
	"github.com/maximalfocus/planless/internal/fixtures"
	"github.com/maximalfocus/planless/internal/platform"
	"github.com/maximalfocus/planless/internal/selfcheck"
	"github.com/maximalfocus/planless/internal/tofu"
)

// The only two endpoints that exist. Neither is configurable.
const (
	corpEndpoint = "http://controlplane:8080"
	edgeEndpoint = "http://controlplane:9000"
)

// The only requests this client can issue.
const (
	pathRefundExport = "/v1/storage/fare-exports/rider-refunds-2026-03.csv"
	pathStatusPage   = "/v1/storage/status-page/status.json"
	pathStatusAssets = "/v1/storage/status-assets/assets.json"
	pathFareService  = "/v1/net/fare-engine/service/fares"
	pathAdminStatus  = "/v1/net/fare-engine/admin/admin/status"
	pathAdminFareCap = "/v1/net/fare-engine/admin/admin/fare-cap"
	pathState        = "/v1/state"
	pathStateDigest  = "/v1/state/digest"
	pathWhoami       = "/v1/whoami"
)

type role struct {
	endpoint  string
	principal string
}

var (
	outsideRole = role{endpoint: edgeEndpoint}
	financeRole = role{endpoint: corpEndpoint, principal: fixtures.PrincipalFinance}
	corpRole    = role{endpoint: corpEndpoint}
)

type digestPayload struct {
	Digest       string `json:"digest"`
	LedgerDigest string `json:"ledger_digest"`
}

type step struct {
	Name     string `json:"name"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
	Passed   bool   `json:"passed"`
}

type report struct {
	Check  string             `json:"check"`
	Steps  []step             `json:"steps"`
	Self   []selfcheck.Result `json:"selfcheck,omitempty"`
	Passed bool               `json:"passed"`
}

var checks = map[string]func() []step{
	"internet-secure-baseline":   internetSecureBaseline,
	"internet-reviewed-exposure": internetReviewedExposure,
	"finance-corp-read":          financeCorpRead,
	"ops-admin-read":             opsAdminRead,
	"state-matches-fixture":      stateMatchesFixture,
	"ops-admin-change":           opsAdminChange,
	"ledger-records-one-change":  ledgerRecordsOneChange,
}

func main() {
	if len(os.Args) != 2 {
		fail("usage: client <check>; available: " + strings.Join(checkNames(), ", "))
	}
	name := os.Args[1]
	if name == "selfcheck" {
		runSelfcheck()
		return
	}
	if name == "observe" {
		observe()
		return
	}
	fn, ok := checks[name]
	if !ok {
		fail(fmt.Sprintf("unknown check %q; available: %s", name, strings.Join(checkNames(), ", ")))
	}
	emit(report{Check: name, Steps: fn()})
}

// observe records what this client can and cannot reach, without judging any
// of it. The segment it reports is the one the platform saw the request arrive
// from, not one the client asserted about itself.
func observe() {
	role := outsideRole
	segment, err := whoami(role)
	if err != nil || segment != fixtures.SegmentInternet {
		role = financeRole
		segment, err = whoami(role)
		if err != nil {
			fail("observe: the control plane did not report this client's segment: " + err.Error())
		}
	}
	set := tofu.ObservationSet{
		Document: tofu.ObservationDocument,
		Segment:  segment,
		Observations: []tofu.Observation{
			observation(role, segment, "bucket/status-page", pathStatusPage),
			observation(role, segment, "bucket/status-assets", pathStatusAssets),
			observation(role, segment, "bucket/fare-exports", pathRefundExport),
			observation(role, segment, "workload/fare-engine:admin", pathAdminStatus),
			observation(role, segment, "workload/fare-engine:service", pathFareService),
		},
	}
	out, _ := json.Marshal(set)
	fmt.Println(string(out))
}

func whoami(ro role) (string, error) {
	status, body, err := do(ro, http.MethodGet, pathWhoami, nil)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("the control plane returned %d", status)
	}
	var payload struct {
		Segment string `json:"segment"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", err
	}
	return payload.Segment, nil
}

func observation(ro role, segment, resource, path string) tofu.Observation {
	status, body, err := do(ro, http.MethodGet, path, nil)
	o := tofu.Observation{Segment: segment, Resource: resource, Status: status}
	if err != nil {
		return o
	}
	if status == http.StatusOK {
		o.Reachable = true
		o.Digest = canon.Digest(body)
	}
	return o
}

func checkNames() []string {
	names := []string{"selfcheck", "observe"}
	for k := range checks {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func runSelfcheck() {
	var tmpfs []string
	if v := strings.TrimSpace(os.Getenv("PLANLESS_TMPFS")); v != "" {
		tmpfs = strings.Split(v, ",")
	}
	results := selfcheck.Run(tmpfs)
	r := report{Check: "selfcheck", Self: results, Passed: len(selfcheck.Failed(results)) == 0}
	out, _ := json.MarshalIndent(r, "", "  ")
	fmt.Println(string(out))
	if !r.Passed {
		os.Exit(1)
	}
}

func emit(r report) {
	r.Passed = true
	for _, s := range r.Steps {
		if !s.Passed {
			r.Passed = false
		}
	}
	out, _ := json.MarshalIndent(r, "", "  ")
	fmt.Println(string(out))
	if !r.Passed {
		os.Exit(1)
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(2)
}

// internetSecureBaseline is the observation that matters most in this slice:
// from the simulated public segment, only the deliberately public status page
// is reachable.
func internetSecureBaseline() []step {
	return []step{
		expectStatusAndBody(outsideRole, http.MethodGet, pathStatusPage, http.StatusOK,
			canon.Digest(fixtures.StatusJSON()), "public status page is readable from the internet segment"),
		expectStatus(outsideRole, http.MethodGet, pathRefundExport, http.StatusForbidden,
			"refund export is refused from the internet segment"),
		expectStatus(outsideRole, http.MethodGet, pathStatusAssets, http.StatusForbidden,
			"the unpublished second status asset is refused from the internet segment"),
		expectStatus(outsideRole, http.MethodGet, pathAdminStatus, http.StatusForbidden,
			"fare engine admin port is refused from the internet segment"),
		expectStatus(outsideRole, http.MethodGet, pathFareService, http.StatusForbidden,
			"fare engine service port is refused from the internet segment"),
	}
}

// internetReviewedExposure is the other half of the reviewed exposure change:
// once an allowlist entry names it, the second asset is public, and the probe
// client reads exactly the checked-in bytes.
func internetReviewedExposure() []step {
	return []step{
		expectStatusAndBody(outsideRole, http.MethodGet, pathStatusAssets, http.StatusOK,
			canon.Digest(fixtures.AssetsJSON()), "the reviewed second status asset is readable from the internet segment"),
		expectStatusAndBody(outsideRole, http.MethodGet, pathStatusPage, http.StatusOK,
			canon.Digest(fixtures.StatusJSON()), "the status page is still readable from the internet segment"),
		expectStatus(outsideRole, http.MethodGet, pathRefundExport, http.StatusForbidden,
			"the refund export is still refused from the internet segment"),
		expectStatus(outsideRole, http.MethodGet, pathAdminStatus, http.StatusForbidden,
			"the fare engine admin port is still refused from the internet segment"),
	}
}

func financeCorpRead() []step {
	return []step{
		expectStatusAndBody(financeRole, http.MethodGet, pathRefundExport, http.StatusOK,
			canon.Digest(fixtures.RefundsCSV()), "finance principal reads the refund export from the corporate segment"),
		expectStatusAndBody(financeRole, http.MethodGet, pathStatusAssets, http.StatusOK,
			canon.Digest(fixtures.AssetsJSON()), "finance reads the unpublished second status asset from the corporate segment"),
		expectStatus(financeRole, http.MethodGet, pathFareService, http.StatusOK,
			"fare engine service port answers the corporate segment"),
		expectStatus(financeRole, http.MethodGet, pathAdminStatus, http.StatusForbidden,
			"fare engine admin port is refused outside the operations range"),
		expectStatus(corpRole, http.MethodGet, pathRefundExport, http.StatusForbidden,
			"an anonymous corporate caller is refused the refund export"),
	}
}

func opsAdminRead() []step {
	return []step{
		expectStatus(corpRole, http.MethodGet, pathAdminStatus, http.StatusOK,
			"fare engine admin port answers inside the operations range"),
		expectStatus(corpRole, http.MethodGet, pathRefundExport, http.StatusForbidden,
			"the operations range carries no grant on the refund export"),
	}
}

// stateMatchesFixture compares live platform state, read through the control
// plane's own read-only API, against the state the checked-in fixture produces.
func stateMatchesFixture() []step {
	store := platform.New(fixtures.Segments())
	fixtures.Seed(store, fixtures.SecureBaseline())
	want, err := store.Digest()
	if err != nil {
		return []step{{Name: "fixture digest", Expected: "computable", Observed: err.Error()}}
	}
	status, body, err := do(corpRole, http.MethodGet, pathStateDigest, nil)
	if err != nil {
		return []step{{Name: "read state digest", Expected: "200", Observed: err.Error()}}
	}
	var payload digestPayload
	_ = json.Unmarshal(body, &payload)
	return []step{{
		Name:     "live platform state equals the checked-in fixture",
		Expected: want,
		Observed: fmt.Sprintf("status=%d digest=%s", status, payload.Digest),
		Passed:   status == http.StatusOK && payload.Digest == want,
	}}
}

// opsAdminChange performs the single enumerated, documented, non-destructive
// transition the admin surface offers, from inside the operations range.
func opsAdminChange() []step {
	return []step{
		expectStatus(corpRole, http.MethodPost, pathAdminFareCap, http.StatusOK,
			"the operations range performs the one enumerated admin transition"),
	}
}

// ledgerRecordsOneChange proves the platform observed that transition: exactly
// one ledger row, attributed to the caller and the segment it came from, and a
// state digest that is no longer the fixture's.
func ledgerRecordsOneChange() []step {
	store := platform.New(fixtures.Segments())
	fixtures.Seed(store, fixtures.SecureBaseline())
	fixtureDigest, _ := store.Digest()

	status, body, err := do(corpRole, http.MethodGet, pathState, nil)
	if err != nil || status != http.StatusOK {
		return []step{{Name: "read platform state", Expected: "200", Observed: fmt.Sprintf("status=%d err=%v", status, err)}}
	}
	var st platform.State
	if err := json.Unmarshal(body, &st); err != nil {
		return []step{{Name: "parse platform state", Expected: "parsable", Observed: err.Error()}}
	}
	var changes []platform.LedgerEntry
	deployerOnly := true
	for _, row := range st.Ledger {
		if row.Action == "workload.change" {
			changes = append(changes, row)
			continue
		}
		// Everything else in the ledger is infrastructure the deployer applied,
		// from the corporate segment, within its scope.
		if row.Principal != fixtures.PrincipalDeployer || row.Segment != fixtures.SegmentCorp {
			deployerOnly = false
		}
	}
	steps := []step{
		{
			Name:     "exactly one ledger row records the admin transition",
			Expected: "1 row: workload.change fare-engine:admin by * from corp (fare-cap=400)",
			Observed: renderLedger(changes),
			Passed: len(changes) == 1 &&
				changes[0].Resource == "fare-engine:admin" &&
				changes[0].Principal == platform.Anonymous &&
				changes[0].Segment == fixtures.SegmentCorp &&
				changes[0].Detail == "fare-cap=400",
		},
		{
			Name:     "every other ledger row is an infrastructure change by the deployer",
			Expected: "all remaining rows attributed to " + fixtures.PrincipalDeployer + " from " + fixtures.SegmentCorp,
			Observed: fmt.Sprintf("%d rows total, %d admin transitions", len(st.Ledger), len(changes)),
			Passed:   deployerOnly,
		},
	}

	dstatus, dbody, err := do(corpRole, http.MethodGet, pathStateDigest, nil)
	var payload digestPayload
	_ = json.Unmarshal(dbody, &payload)
	emptyLedger := canon.Digest([]byte("[]"))
	steps = append(steps,
		step{
			// The admin transition changed the world without changing the
			// declared infrastructure. That gap is the shape drift takes.
			Name:     "the configured platform state is unchanged by the transition",
			Expected: "digest == " + fixtureDigest,
			Observed: fmt.Sprintf("status=%d digest=%s err=%v", dstatus, payload.Digest, err),
			Passed:   err == nil && dstatus == http.StatusOK && payload.Digest == fixtureDigest,
		},
		step{
			Name:     "the change ledger digest moved",
			Expected: "ledger digest != " + emptyLedger,
			Observed: fmt.Sprintf("ledger_digest=%s", payload.LedgerDigest),
			Passed:   payload.LedgerDigest != "" && payload.LedgerDigest != emptyLedger,
		},
	)
	return steps
}

func renderLedger(rows []platform.LedgerEntry) string {
	if len(rows) == 0 {
		return "no ledger rows"
	}
	parts := make([]string, 0, len(rows))
	for _, r := range rows {
		parts = append(parts, fmt.Sprintf("%d:%s %s by %s from %s (%s)", r.Seq, r.Action, r.Resource, r.Principal, r.Segment, r.Detail))
	}
	return strings.Join(parts, "; ")
}

func expectStatus(ro role, method, path string, want int, name string) step {
	status, _, err := do(ro, method, path, nil)
	return step{
		Name:     name,
		Expected: fmt.Sprintf("status %d", want),
		Observed: fmt.Sprintf("status=%d err=%v", status, err),
		Passed:   err == nil && status == want,
	}
}

func expectStatusAndBody(ro role, method, path string, want int, wantDigest, name string) step {
	status, body, err := do(ro, method, path, nil)
	got := canon.Digest(body)
	return step{
		Name:     name,
		Expected: fmt.Sprintf("status %d with body %s", want, wantDigest),
		Observed: fmt.Sprintf("status=%d body=%s err=%v", status, got, err),
		Passed:   err == nil && status == want && got == wantDigest,
	}
}

func do(ro role, method, path string, body []byte) (int, []byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(method, ro.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	if ro.principal != "" {
		req.Header.Set("X-Democloud-Principal", ro.principal)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, out, nil
}
