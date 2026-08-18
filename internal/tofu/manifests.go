package tofu

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/maximalfocus/planless/internal/canon"
	"github.com/maximalfocus/planless/internal/graph"
)

// Overlays the manifest surface can render. Nothing else can be rendered: there
// is no path that accepts a manifest, a directory, or a patch from anywhere.
var Overlays = map[string]bool{
	"intended": true,
	"exposed":  true,
}

// RenderManifests renders one overlay with the real renderer, entirely offline,
// and returns the rendered documents together with a canonical form of the set.
//
// The rendered YAML is parsed by the policy engine's own reader rather than by
// something written here. A demonstration about a control that misread its
// artifact should not hand-roll a parser for the artifact it is about to make
// claims about.
func RenderManifests(cfg Config, overlay string) ([]map[string]any, []byte, error) {
	if overlay != "base" && !Overlays[overlay] {
		return nil, nil, fmt.Errorf("unknown overlay %q", overlay)
	}
	source := filepath.Join(cfg.ManifestDir, "overlays", overlay)
	if overlay == "base" {
		source = filepath.Join(cfg.ManifestDir, "base")
	}
	out := filepath.Join(cfg.WorkDir, "rendered-"+overlay)
	if err := os.MkdirAll(out, 0o700); err != nil {
		return nil, nil, err
	}
	cmd := exec.Command(cfg.Kustomize, "build", source, "-o", out)
	cmd.Env = []string{"HOME=" + cfg.WorkDir, "TMPDIR=" + cfg.TempDir, "PATH=/usr/local/bin"}
	if raw, err := cmd.CombinedOutput(); err != nil {
		return nil, nil, fmt.Errorf("rendering %s: %w: %s", overlay, err, firstLine(raw))
	}

	entries, err := os.ReadDir(out)
	if err != nil {
		return nil, nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, nil, fmt.Errorf("rendering %s produced no manifests", overlay)
	}

	docs := make([]map[string]any, 0, len(names))
	for _, name := range names {
		doc, err := readManifest(cfg, filepath.Join(out, name))
		if err != nil {
			return nil, nil, err
		}
		docs = append(docs, doc)
	}
	canonical, err := canon.Marshal(docs)
	if err != nil {
		return nil, nil, err
	}
	return docs, canonical, nil
}

// readManifest parses one rendered manifest with the policy engine's reader.
func readManifest(cfg Config, path string) (map[string]any, error) {
	cmd := exec.Command(cfg.OPA, "eval", "--format", "json", "--data", path, "data")
	cmd.Env = []string{"HOME=" + cfg.TempDir, "TMPDIR=" + cfg.TempDir, "PATH=/usr/local/bin"}
	raw, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", filepath.Base(path), err)
	}
	var out struct {
		Result []struct {
			Expressions []struct {
				Value map[string]any `json:"value"`
			} `json:"expressions"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("reading %s: %w", filepath.Base(path), err)
	}
	if len(out.Result) == 0 || len(out.Result[0].Expressions) == 0 {
		return nil, fmt.Errorf("reading %s: the manifest parsed to nothing", filepath.Base(path))
	}
	return out.Result[0].Expressions[0].Value, nil
}

// ApplyManifestGraph translates a normalized manifest set into the same typed
// control-plane operations the infrastructure applier uses.
//
// It applies the access configuration the manifests declare — permissions,
// workloads and ingress rules — over a platform whose stores and their contents
// already exist. The manifests describe who can reach what, which is the part
// the policy decides.
func ApplyManifestGraph(api string, g *graph.Graph) error {
	for _, grant := range g.Grants {
		if err := putResource(api, "grant", map[string]any{"grant": map[string]any{
			"id":            grant.ID,
			"resource_kind": grant.ResourceKind,
			"resource_name": grant.ResourceName,
			"principals":    grant.Principals,
			"actions":       grant.Actions,
			"source_ranges": grant.SourceRanges,
		}}); err != nil {
			return err
		}
	}
	for _, r := range g.Resources {
		if r.Kind != "workload" {
			continue
		}
		ports := make([]map[string]any, 0, len(r.Ports))
		for _, p := range r.Ports {
			ports = append(ports, map[string]any{"name": p.Name, "number": p.Number, "bind": p.Bind})
		}
		if err := putResource(api, "workload", map[string]any{"workload": map[string]any{
			"name":    r.Name,
			"address": "10.20.1.20",
			"ports":   ports,
		}}); err != nil {
			return err
		}
	}
	for _, rule := range g.NetworkRules {
		if err := putResource(api, "network_rule", map[string]any{"network_rule": map[string]any{
			"id":            rule.ID,
			"workload":      rule.Workload,
			"port":          rule.Port,
			"source_ranges": rule.SourceRanges,
		}}); err != nil {
			return err
		}
	}
	return nil
}

func putResource(api, kind string, payload map[string]any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := newJSONRequest(api+"/v1/resources/"+kind, body)
	if err != nil {
		return err
	}
	client := &httpDoer{timeout: 10 * time.Second}
	return client.do(req)
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// TextBundle reads the rendered files of one overlay as plain text, which is
// what a scan of manifests reads.
func TextBundle(cfg Config, overlay string) (*SourceBundle, error) {
	dir := filepath.Join(cfg.WorkDir, "rendered-"+overlay)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	bundle := &SourceBundle{Files: []SourceFile{}}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		bundle.Files = append(bundle.Files, SourceFile{Path: e.Name(), Text: string(body)})
	}
	if len(bundle.Files) == 0 {
		return nil, fmt.Errorf("no rendered manifests found for %s", overlay)
	}
	sort.Slice(bundle.Files, func(i, j int) bool { return bundle.Files[i].Path < bundle.Files[j].Path })
	return bundle, nil
}
