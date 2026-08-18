# The scan must be shown to work before "it found nothing" means anything.

package planless.source_scan_test

import data.planless.source_scan
import rego.v1

# A configuration that spells the exposure in the resource itself. A scanner
# that cannot see this one is broken, not defeated.
exposed := {"files": [{
	"path": "main.tf",
	"resource_blocks": [`
  id = "grant-export"
  principals = ["*"]
  source_ranges = ["0.0.0.0/0"]
`],
}]}

# The configuration this project actually ships: every security-relevant value
# is a variable reference, so there is nothing here for the scan to find.
resolved_elsewhere := {"files": [{
	"path": "main.tf",
	"resource_blocks": [`
  id = "grant-export"
  principals = var.export_readers
  source_ranges = var.export_reader_sources
`],
}]}

test_scan_finds_an_exposure_written_in_the_resource if {
	report := source_scan.report with input as exposed
	report.finding_count == 2
	rules := {f.rule | some f in report.findings}
	rules == {"anonymous-principal", "unrestricted-source-range"}
}

test_scan_finds_an_unrestricted_bind if {
	doc := {"files": [{"path": "main.tf", "resource_blocks": [`bind = "0.0.0.0"`]}]}
	report := source_scan.report with input as doc
	report.finding_count == 1
}

test_scan_reports_nothing_when_the_values_are_not_in_the_resource if {
	report := source_scan.report with input as resolved_elsewhere
	report.finding_count == 0
	count(report.scanned_files) == 1
}

# The scan names what it did not read. A control that overstates its own reach
# is worse than one that fails.
test_scan_says_what_it_did_not_read if {
	report := source_scan.report with input as resolved_elsewhere
	contains(report.did_not_read, "resolved desired state")
}

test_scan_reports_every_file_it_read if {
	doc := {"files": [
		{"path": "b.tf", "resource_blocks": []},
		{"path": "a.tf", "resource_blocks": []},
	]}
	report := source_scan.report with input as doc
	report.scanned_files == ["a.tf", "b.tf"]
}
