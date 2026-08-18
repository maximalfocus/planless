// Package api exposes the democloud control plane over HTTP.
//
// Two listeners are served from one control plane: a corporate listener
// carrying the full surface, and a public edge carrying only the storage reads
// and workload connects an outside caller could ever attempt. Neither listener
// grants anything by itself: every request is authorized at request time
// against the effective permissions the platform's own resources produce.
package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/maximalfocus/planless/internal/platform"
)

// maxBody bounds every request and proxied response the control plane reads.
const maxBody = 1 << 20

// Server serves the control plane surfaces over one platform store.
type Server struct {
	store    *platform.Store
	log      *slog.Logger
	scenario string
	seq      atomic.Uint64
	client   *http.Client
}

// New returns a server over the given store.
func New(store *platform.Store, log *slog.Logger, scenario string) *Server {
	return &Server{
		store:    store,
		log:      log,
		scenario: scenario,
		client: &http.Client{
			Timeout: 3 * time.Second,
			Transport: &http.Transport{
				DialContext:         (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
				DisableKeepAlives:   true,
				MaxIdleConnsPerHost: 1,
			},
		},
	}
}

// CorpHandler serves the full control-plane surface to the corporate segment.
func (s *Server) CorpHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /v1/state", s.getState)
	mux.HandleFunc("GET /v1/state/digest", s.getStateDigest)
	mux.HandleFunc("GET /v1/storage/{bucket}/{key}", s.getObject)
	mux.HandleFunc("/v1/net/{workload}/{port}/{path...}", s.connect)
	mux.HandleFunc("POST /v1/resources/{kind}", s.putResource)
	mux.HandleFunc("DELETE /v1/resources/{kind}/{id...}", s.deleteResource)
	return s.withCaller(mux, true)
}

// EdgeHandler serves the public edge. It carries no state inspection and no
// typed resource operations at all.
func (s *Server) EdgeHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /v1/storage/{bucket}/{key}", s.getObject)
	mux.HandleFunc("/v1/net/{workload}/{port}/{path...}", s.connect)
	return s.withCaller(mux, false)
}

// withCaller resolves the caller once per request. A principal assertion is
// only honoured on the corporate listener: the platform models identity as
// something the internal network supplies, so a caller on the public segment is
// always anonymous no matter what it claims.
func (s *Server) withCaller(next http.Handler, allowPrincipal bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			s.refuse(w, r, platform.Caller{}, "unparsable_source_address", "")
			return
		}
		if addr.Is4In6() {
			addr = addr.Unmap()
		}
		c := platform.Caller{Addr: addr, Segment: s.store.Segment(addr)}
		if allowPrincipal {
			if p := strings.TrimSpace(r.Header.Get("X-Democloud-Principal")); p != "" && s.store.KnownPrincipal(p) {
				c.Principal = p
			}
		}
		if c.Segment == "" {
			s.refuse(w, r, c, platform.ReasonUnknownSegment, "")
			return
		}
		next.ServeHTTP(w, r.WithContext(withCaller(r, c)))
	})
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) getState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.State())
}

func (s *Server) getStateDigest(w http.ResponseWriter, r *http.Request) {
	digest, err := s.store.Digest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"result": "state_digest_failed"})
		return
	}
	ledger, err := s.store.LedgerDigest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"result": "state_digest_failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"digest": digest, "ledger_digest": ledger})
}

func (s *Server) getObject(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	bucket, key := r.PathValue("bucket"), r.PathValue("key")
	decision := platform.AuthorizeObjectRead(s.store.State(), c, bucket, key)
	if !decision.Allowed {
		s.refuse(w, r, c, decision.Reason, bucket+"/"+key)
		return
	}
	obj, err := s.store.Object(bucket, key)
	if err != nil {
		s.refuse(w, r, c, platform.ReasonNotFound, bucket+"/"+key)
		return
	}
	w.Header().Set("Content-Type", obj.ContentType)
	w.Header().Set("X-Democloud-Content-Digest", obj.ContentDigest)
	w.Header().Set("X-Democloud-Rule", decision.Rule)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(obj.Body())
}

// connect is the platform's network fabric. It authorizes the connect against
// the workload port's effective ingress and only then carries the request to
// the workload.
func (s *Server) connect(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	workload, port := r.PathValue("workload"), r.PathValue("port")
	decision, wl, p := platform.AuthorizeConnect(s.store.State(), c, workload, port)
	if !decision.Allowed {
		s.refuse(w, r, c, decision.Reason, workload+":"+port)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"result": "unreadable_request"})
		return
	}
	path := r.PathValue("path")
	target := fmt.Sprintf("http://%s:%d/%s", wl.Address, p.Number, path)
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, strings.NewReader(string(body)))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"result": "workload_unreachable"})
		return
	}
	principal := c.Principal
	if principal == "" {
		principal = platform.Anonymous
	}
	req.Header.Set("X-Democloud-Caller-Principal", principal)
	req.Header.Set("X-Democloud-Caller-Segment", c.Segment)
	if ct := r.Header.Get("Content-Type"); ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"result": "workload_unreachable"})
		return
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"result": "workload_unreachable"})
		return
	}
	change := resp.Header.Get("X-Democloud-Change")
	if change != "" && resp.StatusCode < 300 && r.Method != http.MethodGet && r.Method != http.MethodHead {
		entry := s.store.Record("workload.change", workload+":"+port, c, change)
		s.log.Info("platform.change",
			"scenario", s.scenario, "seq", entry.Seq, "resource", entry.Resource,
			"principal", entry.Principal, "segment", entry.Segment, "detail", entry.Detail)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.Header().Set("X-Democloud-Rule", decision.Rule)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(out)
}

type resourcePayload struct {
	Bucket      *platform.Bucket      `json:"bucket,omitempty"`
	Object      *objectPayload        `json:"object,omitempty"`
	Grant       *platform.Grant       `json:"grant,omitempty"`
	Workload    *platform.Workload    `json:"workload,omitempty"`
	NetworkRule *platform.NetworkRule `json:"network_rule,omitempty"`
}

type objectPayload struct {
	Bucket      string `json:"bucket"`
	Key         string `json:"key"`
	ContentType string `json:"content_type"`
	BodyBase64  string `json:"body_base64"`
}

// putResource is the typed create/update surface the applier uses. It carries
// no free-form write path: every kind is enumerated, and every write is
// authorized against the deployer's scope for the target resource.
func (s *Server) putResource(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	kind := r.PathValue("kind")
	var payload resourcePayload
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"result": "unparsable_resource"})
		return
	}
	target, err := targetOf(kind, payload)
	if err != nil {
		s.refuse(w, r, c, platform.ReasonNotFound, kind)
		return
	}
	if !s.authorizeWrite(c, target.kind, target.name) {
		s.refuse(w, r, c, platform.ReasonNoGrant, target.kind+"/"+target.name)
		return
	}
	switch kind {
	case "bucket":
		s.store.PutBucket(*payload.Bucket)
	case "object":
		body, decErr := base64.StdEncoding.DecodeString(payload.Object.BodyBase64)
		if decErr != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"result": "unparsable_resource"})
			return
		}
		s.store.PutObject(platform.Object{
			Bucket:      payload.Object.Bucket,
			Key:         payload.Object.Key,
			ContentType: payload.Object.ContentType,
		}, body)
	case "grant":
		s.store.PutGrant(*payload.Grant)
	case "workload":
		s.store.PutWorkload(*payload.Workload)
	case "network_rule":
		s.store.PutNetworkRule(*payload.NetworkRule)
	default:
		s.refuse(w, r, c, platform.ReasonNotFound, kind)
		return
	}
	entry := s.store.Record("resource.put", kind+"/"+target.identity, c, "")
	s.log.Info("platform.change",
		"scenario", s.scenario, "seq", entry.Seq, "resource", entry.Resource,
		"principal", entry.Principal, "segment", entry.Segment)
	writeJSON(w, http.StatusOK, map[string]any{"result": "applied", "kind": kind, "id": target.identity})
}

func (s *Server) deleteResource(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	kind, id := r.PathValue("kind"), r.PathValue("id")
	target, err := targetOfExisting(s.store.State(), kind, id)
	if err != nil {
		s.refuse(w, r, c, platform.ReasonNotFound, kind+"/"+id)
		return
	}
	if !s.authorizeWrite(c, target.kind, target.name) {
		s.refuse(w, r, c, platform.ReasonNoGrant, target.kind+"/"+target.name)
		return
	}
	if err := s.store.Delete(kind, id); err != nil {
		s.refuse(w, r, c, platform.ReasonNotFound, kind+"/"+id)
		return
	}
	entry := s.store.Record("resource.delete", kind+"/"+id, c, "")
	s.log.Info("platform.change",
		"scenario", s.scenario, "seq", entry.Seq, "resource", entry.Resource,
		"principal", entry.Principal, "segment", entry.Segment)
	writeJSON(w, http.StatusOK, map[string]any{"result": "deleted", "kind": kind, "id": id})
}

func (s *Server) authorizeWrite(c platform.Caller, kind, name string) bool {
	st := s.store.State()
	exposures, err := platform.EffectiveGrants(st.Grants, kind, name, platform.ActionWrite)
	if err != nil {
		return false
	}
	principal := c.Principal
	if principal == "" {
		principal = platform.Anonymous
	}
	for _, e := range exposures {
		if !contains(e.Principals, principal) {
			continue
		}
		if e.Sources.Contains(c.Addr) {
			return true
		}
	}
	return false
}

func contains(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}

type target struct {
	kind     string
	name     string
	identity string
}

func targetOf(kind string, p resourcePayload) (target, error) {
	switch kind {
	case "bucket":
		if p.Bucket == nil || p.Bucket.Name == "" {
			return target{}, errors.New("missing bucket")
		}
		return target{platform.KindBucket, p.Bucket.Name, p.Bucket.Name}, nil
	case "object":
		if p.Object == nil || p.Object.Bucket == "" || p.Object.Key == "" {
			return target{}, errors.New("missing object")
		}
		return target{platform.KindBucket, p.Object.Bucket, p.Object.Bucket + "/" + p.Object.Key}, nil
	case "grant":
		if p.Grant == nil || p.Grant.ID == "" || p.Grant.ResourceName == "" {
			return target{}, errors.New("missing grant")
		}
		return target{p.Grant.ResourceKind, p.Grant.ResourceName, p.Grant.ID}, nil
	case "workload":
		if p.Workload == nil || p.Workload.Name == "" {
			return target{}, errors.New("missing workload")
		}
		return target{platform.KindWorkload, p.Workload.Name, p.Workload.Name}, nil
	case "network_rule":
		if p.NetworkRule == nil || p.NetworkRule.ID == "" || p.NetworkRule.Workload == "" {
			return target{}, errors.New("missing network rule")
		}
		return target{platform.KindWorkload, p.NetworkRule.Workload, p.NetworkRule.ID}, nil
	}
	return target{}, fmt.Errorf("unknown kind %q", kind)
}

func targetOfExisting(st platform.State, kind, id string) (target, error) {
	switch kind {
	case "bucket":
		return target{platform.KindBucket, id, id}, nil
	case "workload":
		return target{platform.KindWorkload, id, id}, nil
	case "object":
		bucket, _, ok := strings.Cut(id, "/")
		if !ok {
			return target{}, errors.New("malformed object id")
		}
		return target{platform.KindBucket, bucket, id}, nil
	case "grant":
		for _, g := range st.Grants {
			if g.ID == id {
				return target{g.ResourceKind, g.ResourceName, id}, nil
			}
		}
		return target{}, errors.New("unknown grant")
	case "network_rule":
		for _, r := range st.NetworkRules {
			if r.ID == id {
				return target{platform.KindWorkload, r.Workload, id}, nil
			}
		}
		return target{}, errors.New("unknown network rule")
	}
	return target{}, fmt.Errorf("unknown kind %q", kind)
}

// refuse returns one generic result to the caller and records one structured
// audit event. The caller learns only that the platform refused: not whether
// the resource, the grant, or the principal exists.
func (s *Server) refuse(w http.ResponseWriter, r *http.Request, c platform.Caller, class, resource string) {
	seq := s.seq.Add(1)
	s.log.Info("platform.access_refused",
		"scenario", s.scenario,
		"correlation_id", fmt.Sprintf("%s-%04d", s.scenario, seq),
		"class", class,
		"resource", resource,
		"principal", principalOf(c),
		"segment", c.Segment,
		"path", r.URL.Path,
	)
	writeJSON(w, http.StatusForbidden, map[string]any{"result": "ACCESS_REFUSED"})
}

func principalOf(c platform.Caller) string {
	if c.Principal == "" {
		return platform.Anonymous
	}
	return c.Principal
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
