package tofu

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Row is one scenario's line in the comparison.
type Row struct {
	Scenario     string `json:"scenario"`
	Evaluated    string `json:"artifact_evaluated"`
	Decision     string `json:"gate_decision"`
	Enforcement  string `json:"enforcement"`
	Applied      string `json:"applied_exposure"`
	Reachable    string `json:"public_segment_reachability"`
	StateChanged string `json:"platform_state_change"`
	Reconciled   string `json:"reconciliation"`
	Vulnerable   bool   `json:"vulnerable"`
}

// Table is the whole demonstration in one view.
type Table struct {
	Document string `json:"document"`
	Warning  string `json:"warning,omitempty"`
	Rows     []Row  `json:"rows"`
}

// TableDocument identifies a comparison table.
const TableDocument = "planless.comparison-table"

// Columns are the table's columns, in order. They are named here so a test can
// assert none of them quietly disappears.
var Columns = []string{
	"scenario",
	"artifact evaluated",
	"gate decision",
	"enforcement",
	"applied exposure",
	"reachable from internet",
	"platform state",
	"reconciliation",
}

// BuildTable turns a stream of reconciled transcripts into the comparison.
func BuildTable(r io.Reader) (*Table, error) {
	dec := json.NewDecoder(r)
	table := &Table{Document: TableDocument, Rows: []Row{}}
	for {
		var t Transcript
		if err := dec.Decode(&t); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("the input stream could not be read: %w", err)
		}
		if t.Document != TranscriptDocument {
			return nil, fmt.Errorf("the input stream carries an unrecognized document %q", t.Document)
		}
		if t.Reconcile == nil {
			return nil, fmt.Errorf("transcript %s was never reconciled", t.Scenario)
		}
		table.Rows = append(table.Rows, rowOf(t))
		if t.Warning != "" {
			table.Warning = t.Warning
		}
	}
	if len(table.Rows) == 0 {
		return nil, errors.New("the input stream carries no transcripts")
	}
	return table, nil
}

func rowOf(t Transcript) Row {
	row := Row{
		Scenario:     t.Scenario,
		Evaluated:    evaluatedBy(t),
		Decision:     decisionOf(t),
		Enforcement:  enforcementOf(t),
		Applied:      appliedExposure(t),
		Reachable:    reachableFromInternet(t),
		StateChanged: stateChange(t),
		Reconciled:   t.Reconcile.Verdict,
		Vulnerable:   t.Warning != "",
	}
	return row
}

func evaluatedBy(t Transcript) string {
	switch {
	case t.Scan != nil && strings.Contains(t.Scan.Artifact, "manifest"):
		return "base manifests"
	case t.Scan != nil:
		return "source text"
	case t.Denylist != nil:
		return "resolved state (literals)"
	case t.Decision != nil:
		return "resolved state"
	default:
		return "nothing"
	}
}

func decisionOf(t Transcript) string {
	switch {
	case t.Scan != nil:
		return fmt.Sprintf("%d findings", t.Scan.FindingCount)
	case t.Denylist != nil:
		return fmt.Sprintf("%d findings", t.Denylist.FindingCount)
	case t.Decision != nil:
		return t.Decision.Result
	default:
		return "none"
	}
}

func enforcementOf(t Transcript) string {
	switch {
	case t.Enforcement.OutOfBand:
		return "refused, applied anyway"
	case t.Enforcement.Advisory:
		return "advisory, applied"
	case t.Enforcement.Applied:
		return "applied"
	default:
		return "refused"
	}
}

// appliedExposure names what the applied state exposes, taken from the policy's
// own computation over the artifact that was applied.
func appliedExposure(t Transcript) string {
	decision := t.Decision
	if decision == nil {
		decision = t.WouldHaveDecided
	}
	if decision == nil || !t.Enforcement.Applied {
		return "—"
	}
	exposed := []string{}
	for _, v := range decision.Violations {
		if v.Class == "exposure_not_allowlisted" {
			exposed = append(exposed, short(v.Resource))
		}
	}
	if len(exposed) == 0 {
		return "reviewed only"
	}
	return strings.Join(exposed, " ")
}

// reachableFromInternet is taken from what a client on the public segment
// actually observed. A policy decision is not evidence of exposure state, so it
// is never used here.
func reachableFromInternet(t Transcript) string {
	reached := []string{}
	for _, o := range t.Observations {
		if o.Segment != "internet" || !o.Reachable {
			continue
		}
		reached = append(reached, short(o.Resource))
	}
	if len(reached) == 0 {
		return "nothing"
	}
	return strings.Join(reached, " ")
}

func stateChange(t Transcript) string {
	if t.StateBefore == "" || t.StateAfter == "" {
		return "—"
	}
	if t.StateBefore == t.StateAfter {
		return "unchanged"
	}
	return "changed"
}

// short trims a resource identifier to what fits a table without losing which
// resource it is.
func short(resource string) string {
	resource = strings.TrimPrefix(resource, "bucket/")
	resource = strings.TrimPrefix(resource, "workload/")
	resource = strings.TrimPrefix(resource, "fare-engine:")
	return resource
}

// Render draws the comparison. It is the one view where the whole class is
// visible: read down the decisions, then across to what the public segment
// could actually reach.
func (t *Table) Render() string {
	widths := make([]int, len(Columns))
	for i, c := range Columns {
		widths[i] = len(c)
	}
	cells := make([][]string, 0, len(t.Rows))
	for _, r := range t.Rows {
		row := []string{
			r.Scenario, r.Evaluated, r.Decision, r.Enforcement,
			r.Applied, r.Reachable, r.StateChanged, r.Reconciled,
		}
		for i, v := range row {
			if len(v) > widths[i] {
				widths[i] = len(v)
			}
		}
		cells = append(cells, row)
	}

	var b strings.Builder
	if t.Warning != "" {
		fmt.Fprintf(&b, "*** %s ***\n\n", t.Warning)
	}
	writeRow(&b, widths, Columns)
	rule := make([]string, len(Columns))
	for i := range rule {
		rule[i] = strings.Repeat("-", widths[i])
	}
	writeRow(&b, widths, rule)
	for _, row := range cells {
		writeRow(&b, widths, row)
	}
	fmt.Fprintln(&b, "\nreachability is what a client on the internet segment observed, never a policy verdict.")
	return b.String()
}

func writeRow(b *strings.Builder, widths []int, cells []string) {
	for i, c := range cells {
		if i > 0 {
			b.WriteString("  ")
		}
		fmt.Fprintf(b, "%-*s", widths[i], c)
	}
	b.WriteString("\n")
}
