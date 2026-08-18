package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/maximalfocus/planless/internal/canon"
	"github.com/maximalfocus/planless/internal/fixtures"
	"github.com/maximalfocus/planless/internal/platform"
)

func newServer(t *testing.T) (*Server, *platform.Store) {
	t.Helper()
	store := platform.New(fixtures.Segments())
	fixtures.Seed(store, fixtures.SecureBaseline())
	return New(store, slog.New(slog.NewTextHandler(io.Discard, nil)), "test"), store
}

func request(t *testing.T, h http.Handler, method, path, from, principal string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = from + ":40000"
	if principal != "" {
		req.Header.Set("X-Democloud-Principal", principal)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const (
	refundPath = "/v1/storage/fare-exports/rider-refunds-2026-03.csv"
	statusPath = "/v1/storage/status-page/status.json"
	adminPath  = "/v1/net/fare-engine/admin/admin/status"
)

func TestEdgeServesOnlyTheDeliberatelyPublicObject(t *testing.T) {
	s, _ := newServer(t)
	edge := s.EdgeHandler()

	rec := request(t, edge, http.MethodGet, statusPath, "198.51.100.50", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status page: got %d want 200", rec.Code)
	}
	if got := canon.Digest(rec.Body.Bytes()); got != canon.Digest(fixtures.StatusJSON()) {
		t.Fatalf("status page bytes differ: %s", got)
	}

	rec = request(t, edge, http.MethodGet, refundPath, "198.51.100.50", "", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("refund export from the internet segment: got %d want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ACCESS_REFUSED") {
		t.Fatalf("expected a generic refusal, got %s", rec.Body.String())
	}
}

// A caller on the public segment is anonymous whatever it claims: the edge does
// not honour a principal assertion at all.
func TestEdgeIgnoresClaimedPrincipals(t *testing.T) {
	s, _ := newServer(t)
	rec := request(t, s.EdgeHandler(), http.MethodGet, refundPath, "198.51.100.50", fixtures.PrincipalFinance, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d want 403", rec.Code)
	}
}

// The edge carries no state inspection and no resource operations at all.
func TestEdgeDoesNotExposeControlSurfaces(t *testing.T) {
	s, _ := newServer(t)
	edge := s.EdgeHandler()
	for _, path := range []string{"/v1/state", "/v1/state/digest", "/v1/resources/bucket"} {
		rec := request(t, edge, http.MethodGet, path, "198.51.100.50", "", "")
		if rec.Code == http.StatusOK {
			t.Fatalf("%s answered the public edge with 200", path)
		}
	}
}

func TestCorpSurfaceAuthorizesPerCaller(t *testing.T) {
	s, _ := newServer(t)
	corp := s.CorpHandler()

	rec := request(t, corp, http.MethodGet, refundPath, "10.20.5.30", fixtures.PrincipalFinance, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("finance read: got %d want 200", rec.Code)
	}
	if got := canon.Digest(rec.Body.Bytes()); got != canon.Digest(fixtures.RefundsCSV()) {
		t.Fatalf("refund export bytes differ: %s", got)
	}

	rec = request(t, corp, http.MethodGet, refundPath, "10.20.5.30", "", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("anonymous corporate read: got %d want 403", rec.Code)
	}

	rec = request(t, corp, http.MethodGet, refundPath, "10.20.5.30", "no-such-principal", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unknown principal: got %d want 403", rec.Code)
	}
}

func TestUnknownSegmentIsRefused(t *testing.T) {
	s, _ := newServer(t)
	rec := request(t, s.CorpHandler(), http.MethodGet, statusPath, "203.0.113.9", "", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d want 403", rec.Code)
	}
}

// The fabric refuses the connect before it ever reaches the workload, so an
// unreachable workload address cannot be mistaken for a permitted connect.
func TestConnectIsRefusedBeforeReachingTheWorkload(t *testing.T) {
	s, _ := newServer(t)
	rec := request(t, s.EdgeHandler(), http.MethodGet, adminPath, "198.51.100.50", "", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("admin from the internet segment: got %d want 403", rec.Code)
	}
	rec = request(t, s.CorpHandler(), http.MethodGet, adminPath, "10.20.5.30", "", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("admin from outside the operations range: got %d want 403", rec.Code)
	}
	// From inside the operations range the fabric permits the connect and
	// carries it to the workload. Whether the workload answers depends on
	// whether it is running, which is not what this test is about: what matters
	// is that the request was not refused.
	rec = request(t, s.CorpHandler(), http.MethodGet, adminPath, "10.20.7.40", "", "")
	if rec.Code == http.StatusForbidden {
		t.Fatalf("admin from the operations range was refused: %s", rec.Body.String())
	}
}

func TestStateSurfaceIsReadOnlyAndDigested(t *testing.T) {
	s, store := newServer(t)
	corp := s.CorpHandler()

	rec := request(t, corp, http.MethodGet, "/v1/state/digest", "10.20.5.30", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("state digest: got %d want 200", rec.Code)
	}
	var payload struct {
		Digest string `json:"digest"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	want, err := store.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if payload.Digest != want {
		t.Fatalf("got %s want %s", payload.Digest, want)
	}

	// The refund export's bytes are never rendered into platform state.
	rec = request(t, corp, http.MethodGet, "/v1/state", "10.20.5.30", "", "")
	if strings.Contains(rec.Body.String(), "HTA-RF-2026-03-0001") {
		t.Fatal("state inspection rendered stored object content")
	}
	if !strings.Contains(rec.Body.String(), canon.Digest(fixtures.RefundsCSV())) {
		t.Fatal("state inspection did not render the object's content digest")
	}
}

// The typed operation surface is the deployer's, and only within its scope.
func TestResourceWritesRequireTheDeployerScope(t *testing.T) {
	s, store := newServer(t)
	corp := s.CorpHandler()
	body := `{"grant":{"id":"g-new","resource_kind":"bucket","resource_name":"fare-exports","principals":["*"],"actions":["read"],"source_ranges":["0.0.0.0/0"]}}`

	rec := request(t, corp, http.MethodPost, "/v1/resources/grant", "10.20.5.30", "", body)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("anonymous write: got %d want 403", rec.Code)
	}
	rec = request(t, corp, http.MethodPost, "/v1/resources/grant", "10.20.5.30", fixtures.PrincipalFinance, body)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("finance write: got %d want 403", rec.Code)
	}
	rec = request(t, corp, http.MethodPost, "/v1/resources/grant", "10.20.5.30", fixtures.PrincipalDeployer, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("deployer write: got %d want 200: %s", rec.Code, rec.Body.String())
	}
	if rows := store.State().Ledger; len(rows) != 1 || rows[0].Principal != fixtures.PrincipalDeployer {
		t.Fatalf("expected one ledger row attributed to the deployer, got %+v", rows)
	}

	// Outside its scope the deployer is refused like anyone else.
	outOfScope := `{"bucket":{"name":"unscoped-bucket","encrypted":true}}`
	rec = request(t, corp, http.MethodPost, "/v1/resources/bucket", "10.20.5.30", fixtures.PrincipalDeployer, outOfScope)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("out-of-scope write: got %d want 403", rec.Code)
	}
}

func TestResourceSurfaceRejectsUnknownShapes(t *testing.T) {
	s, _ := newServer(t)
	corp := s.CorpHandler()
	for _, body := range []string{`{"unexpected":{}}`, `not json`, `{"bucket":{"name":""}}`} {
		rec := request(t, corp, http.MethodPost, "/v1/resources/bucket", "10.20.5.30", fixtures.PrincipalDeployer, body)
		if rec.Code == http.StatusOK {
			t.Fatalf("accepted %s", body)
		}
	}
	rec := request(t, corp, http.MethodPost, "/v1/resources/unknown-kind", "10.20.5.30", fixtures.PrincipalDeployer, `{}`)
	if rec.Code == http.StatusOK {
		t.Fatal("accepted an unknown resource kind")
	}
}
