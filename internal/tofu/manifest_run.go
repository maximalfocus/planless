package tofu

import (
	"encoding/json"
	"fmt"

	"github.com/maximalfocus/planless/internal/canon"
	"github.com/maximalfocus/planless/internal/gate"
	"github.com/maximalfocus/planless/internal/graph"
)

// runManifest is the manifest surface's pipeline: render an overlay with the
// real renderer, normalize the rendered set into the same policy contract, and
// decide it with the same policy body and the same reviewed allowlist.
//
// Nothing about the policy changes here. That is the claim this surface exists
// to make good on, so the code path deliberately shares the evaluation with the
// infrastructure surface rather than re-implementing it.
func (t *Transcript) runManifest(cfg Config, scenario Scenario) (*Transcript, error) {
	cfg, err := newRun(cfg)
	if err != nil {
		return t, err
	}
	base, baseCanonical, err := RenderManifests(cfg, "base")
	if err != nil {
		return t, err
	}
	rendered, renderedCanonical, err := RenderManifests(cfg, scenario.Manifest)
	if err != nil {
		return t, err
	}
	t.Artifacts.SourceConfiguration = canon.Digest(baseCanonical)
	t.Artifacts.ResolvedDesiredState = canon.Digest(renderedCanonical)

	normalized, err := graph.FromManifests(rendered, base, segments())
	if err != nil {
		return t, err
	}
	body, err := json.Marshal(normalized)
	if err != nil {
		return t, err
	}
	t.Provenance = manifestOrigins(normalized)

	// A scan of the base manifests: an honest control over the artifact a
	// reviewer opens, which is not the artifact the overlay renders.
	if scenario.Scan {
		bundle, err := TextBundle(cfg, "base")
		if err != nil {
			return t, err
		}
		raw, err := json.Marshal(bundle)
		if err != nil {
			return t, err
		}
		report, err := gate.ScanWith(gateConfig(cfg, scenario), raw, gate.ManifestScanQuery)
		if err != nil {
			return t, fmt.Errorf("the manifest scan did not run: %w", err)
		}
		t.Scan = &report
		t.Artifacts.EvaluatedByPolicy = canon.Digest(raw)
		t.Artifacts.EvaluatedBy = "a policy scan over the base manifest set"
	}

	decision := gate.Evaluate(gateConfig(cfg, scenario), body)
	if scenario.Gated {
		t.Artifacts.EvaluatedByPolicy = canon.Digest(body)
		t.Artifacts.EvaluatedBy = "the deny-by-default policy, over the rendered manifest set"
		t.Decision = &decision
	} else {
		t.WouldHaveDecided = &decision
	}

	if scenario.Gated && decision.Denied() {
		t.refuse(StagePolicy, classOf(decision), "deny-by-default")
	} else {
		if err := ApplyManifestGraph(cfg.StateAPI, normalized); err != nil {
			return t, err
		}
		t.Enforcement.Applied = true
		t.Enforcement.OperatorResult = ResultDeployed
	}

	after, err := stateDigest(cfg.StateAPI)
	if err != nil {
		return t, err
	}
	t.StateAfter = after
	if t.Enforcement.Applied {
		t.Artifacts.AppliedState = after
	}
	if build, err := applicationBuild(cfg.StateAPI); err == nil {
		t.ApplicationBuild = build
	}

	t.Passed = t.assert(scenario)
	if !t.Passed {
		return t, fmt.Errorf("scenario %s did not meet its declared outcome", scenario.ID)
	}
	return t, nil
}

// manifestOrigins reports where each security-relevant value came from: the
// base manifests a reviewer reads, or the overlay that patched them.
func manifestOrigins(g *graph.Graph) []ValueOrigin {
	out := []ValueOrigin{}
	for _, grant := range g.Grants {
		for _, field := range []string{"principals", "source_ranges"} {
			p, ok := grant.Provenance[field]
			if !ok {
				continue
			}
			out = append(out, ValueOrigin{
				Resource: "grant/" + grant.ID, Field: field, Origin: string(p.Origin),
			})
		}
	}
	for _, rule := range g.NetworkRules {
		if p, ok := rule.Provenance["source_ranges"]; ok {
			out = append(out, ValueOrigin{
				Resource: "network_rule/" + rule.ID, Field: "source_ranges", Origin: string(p.Origin),
			})
		}
	}
	for _, r := range g.Resources {
		if r.Kind != "workload" {
			continue
		}
		for _, port := range r.Ports {
			field := "ports." + port.Name + ".bind"
			if p, ok := r.Provenance[field]; ok {
				out = append(out, ValueOrigin{
					Resource: "workload/" + r.Name, Field: field, Origin: string(p.Origin),
				})
			}
		}
	}
	return out
}
