package tofu

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/maximalfocus/planless/internal/fixtures"
	"github.com/maximalfocus/planless/internal/netset"
)

// Verdicts the reconciliation reports.
const (
	VerdictPass = "PASS"
	VerdictFail = "FAIL"
)

type allowlistDocument struct {
	Allowlist struct {
		Name    string `json:"name"`
		Entries []struct {
			Rule       string   `json:"rule"`
			Kind       string   `json:"kind"`
			Name       string   `json:"name"`
			Principals []string `json:"principals"`
			Sources    []string `json:"sources"`
		} `json:"entries"`
	} `json:"allowlist"`
}

// PublicEntries returns the resources a reviewed allowlist names as reachable
// from the public segment. It is computed from the entry's own address ranges,
// never from a label somebody wrote next to it.
func PublicEntries(allowlistPath string) ([]string, error) {
	body, err := os.ReadFile(allowlistPath)
	if err != nil {
		return nil, err
	}
	var doc allowlistDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("the reviewed allowlist could not be read: %w", err)
	}
	if len(doc.Allowlist.Entries) == 0 {
		return nil, errors.New("the reviewed allowlist names no entries")
	}
	publicProbe, err := netip.ParseAddr(fixtures.ProbeAddress)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, entry := range doc.Allowlist.Entries {
		set, err := netset.Parse(entry.Sources)
		if err != nil {
			return nil, fmt.Errorf("allowlist entry %s: %w", entry.Rule, err)
		}
		if !set.Contains(publicProbe) {
			continue
		}
		if entry.Kind == "bucket" && !anonymous(entry.Principals) {
			continue
		}
		out = append(out, entry.Kind+"/"+entry.Name)
	}
	sort.Strings(out)
	return out, nil
}

func anonymous(principals []string) bool {
	for _, p := range principals {
		if p == "*" {
			return true
		}
	}
	return false
}

// Reconcile merges a transcript with the observations each segment reported and
// answers the only question that matters: is anything reachable from the public
// segment that nobody reviewed?
//
// It never reads the gate's verdict to answer that. A policy decision is not
// evidence of exposure state.
func Reconcile(cfg Config, r io.Reader) (*Transcript, error) {
	transcript, observations, err := readStream(r)
	if err != nil {
		return nil, err
	}
	transcript.Observations = sortObservations(observations)

	scenario, ok := Scenarios[transcript.Scenario]
	if !ok {
		return nil, fmt.Errorf("the transcript names an unknown scenario %q", transcript.Scenario)
	}
	allowed, err := PublicEntries(filepath.Join(cfg.AllowlistDir, scenario.AllowlistOf()))
	if err != nil {
		return nil, err
	}

	reachable := []string{}
	for _, o := range transcript.Observations {
		if o.Segment != fixtures.SegmentInternet || !o.Reachable {
			continue
		}
		reachable = append(reachable, o.Resource)
	}
	sort.Strings(reachable)

	unreviewed := []string{}
	for _, r := range reachable {
		if !contains(allowed, r) {
			unreviewed = append(unreviewed, r)
		}
	}

	rec := &Reconciliation{
		Verdict:           VerdictPass,
		Reason:            "no resource is reachable from the public segment except those the allowlist names",
		PubliclyReachable: reachable,
		AllowedPublic:     allowed,
	}
	if len(unreviewed) > 0 {
		rec.Verdict = VerdictFail
		rec.Reason = "reachable from the public segment with no policy decision permitting it: " +
			strings.Join(unreviewed, ", ")
	}
	rec.Expected = scenario.ExpectReconciliationOf()
	transcript.Reconcile = rec
	transcript.Passed = transcript.Passed && rec.Verdict == rec.Expected
	return transcript, nil
}

func contains(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}

// readStream reads one transcript and any number of observation sets from a
// stream of JSON documents.
func readStream(r io.Reader) (*Transcript, []Observation, error) {
	dec := json.NewDecoder(r)
	var transcript *Transcript
	var observations []Observation
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, nil, fmt.Errorf("the input stream could not be read: %w", err)
		}
		var head struct {
			Document string `json:"document"`
		}
		if err := json.Unmarshal(raw, &head); err != nil {
			return nil, nil, err
		}
		switch head.Document {
		case TranscriptDocument:
			if transcript != nil {
				return nil, nil, errors.New("the input stream carries more than one transcript")
			}
			var t Transcript
			if err := json.Unmarshal(raw, &t); err != nil {
				return nil, nil, err
			}
			transcript = &t
		case ObservationDocument:
			var set ObservationSet
			if err := json.Unmarshal(raw, &set); err != nil {
				return nil, nil, err
			}
			observations = append(observations, set.Observations...)
		default:
			return nil, nil, fmt.Errorf("the input stream carries an unrecognized document %q", head.Document)
		}
	}
	if transcript == nil {
		return nil, nil, errors.New("the input stream carries no transcript")
	}
	if len(observations) == 0 {
		return nil, nil, errors.New("the input stream carries no observations")
	}
	return transcript, observations, nil
}

// CompareObservations requires every observation set on the stream to report
// exactly the same reachability.
//
// It is how "this change altered nothing about who can reach what" is proved:
// not by reading a policy verdict, but by observing the same thing twice and
// requiring the two observations to be identical.
func CompareObservations(r io.Reader) error {
	dec := json.NewDecoder(r)
	var first []Observation
	sets := 0
	for {
		var set ObservationSet
		if err := dec.Decode(&set); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("the input stream could not be read: %w", err)
		}
		if set.Document != ObservationDocument {
			return fmt.Errorf("the input stream carries an unrecognized document %q", set.Document)
		}
		sets++
		current := sortObservations(set.Observations)
		if len(current) == 0 {
			return errors.New("an observation set reports nothing at all")
		}
		if first == nil {
			first = current
			continue
		}
		if err := sameObservations(first, current); err != nil {
			return err
		}
	}
	if sets < 2 {
		return fmt.Errorf("comparison needs at least two observation sets, got %d", sets)
	}
	return nil
}

func sameObservations(want, got []Observation) error {
	if len(want) != len(got) {
		return fmt.Errorf("observation sets report %d and %d results", len(want), len(got))
	}
	for i := range want {
		if want[i] != got[i] {
			return fmt.Errorf("reachability changed: %+v became %+v", want[i], got[i])
		}
	}
	return nil
}

// CompareBuilds requires every transcript on the stream to report the same
// application build.
//
// The application is identical in every variant of this demonstration: no
// request handler, authorization check or response differs between the secure
// and the misconfigured platform. This is how that is checked rather than
// asserted.
func CompareBuilds(r io.Reader) error {
	dec := json.NewDecoder(r)
	first := ""
	seen := 0
	for {
		var t Transcript
		if err := dec.Decode(&t); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("the input stream could not be read: %w", err)
		}
		if t.Document != TranscriptDocument {
			return fmt.Errorf("the input stream carries an unrecognized document %q", t.Document)
		}
		if t.ApplicationBuild == "" {
			return fmt.Errorf("transcript %s reports no application build", t.Scenario)
		}
		seen++
		if first == "" {
			first = t.ApplicationBuild
			continue
		}
		if t.ApplicationBuild != first {
			return fmt.Errorf("the application build changed between variants: %s became %s",
				first, t.ApplicationBuild)
		}
	}
	if seen < 2 {
		return fmt.Errorf("comparison needs at least two transcripts, got %d", seen)
	}
	return nil
}

// CompareExposures requires every transcript on the stream to have computed the
// same effective reachability for every resource they have in common.
//
// It is how "these are two spellings of one desired state" stops being an
// argument. The rules that produced the exposure differ; who can reach what
// does not.
func CompareExposures(r io.Reader) error {
	dec := json.NewDecoder(r)
	first := map[string]string{}
	firstScenario := ""
	seen := 0
	for {
		var t Transcript
		if err := dec.Decode(&t); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("the input stream could not be read: %w", err)
		}
		if t.Document != TranscriptDocument {
			return fmt.Errorf("the input stream carries an unrecognized document %q", t.Document)
		}
		decision := t.WouldHaveDecided
		if decision == nil {
			decision = t.Decision
		}
		if decision == nil || len(decision.Exposures) == 0 {
			return fmt.Errorf("transcript %s computed no exposure at all", t.Scenario)
		}
		current := map[string]string{}
		for _, e := range decision.Exposures {
			if e.Reachability == "" {
				return fmt.Errorf("transcript %s reports no reachability for %s", t.Scenario, e.Resource)
			}
			current[e.Resource] = e.Reachability
		}
		seen++
		if seen == 1 {
			first, firstScenario = current, t.Scenario
			continue
		}
		shared := 0
		for resource, reach := range current {
			want, ok := first[resource]
			if !ok {
				continue
			}
			shared++
			if want != reach {
				return fmt.Errorf("%s and %s computed different reachability for %s: %s vs %s",
					firstScenario, t.Scenario, resource, want, reach)
			}
		}
		if shared == 0 {
			return fmt.Errorf("%s and %s have no resource in common", firstScenario, t.Scenario)
		}
	}
	if seen < 2 {
		return fmt.Errorf("comparison needs at least two transcripts, got %d", seen)
	}
	return nil
}
