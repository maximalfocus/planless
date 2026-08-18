package planless.manifest_scan_test

import data.planless.manifest_scan
import rego.v1

# The rendered overlay, where the values actually are.
rendered := {"files": [
	{"path": "v1_service_fare-exports.yaml", "text": "metadata:\n  annotations:\n    democloud.example/readers: '*'\n"},
	{"path": "apps_v1_deployment_fare-engine.yaml", "text": "      hostNetwork: true\n        - hostIP: 0.0.0.0\n"},
]}

# The base, where a reviewer looks.
base := {"files": [
	{"path": "service-fare-exports.yaml", "text": "    democloud.example/readers: placeholder\n"},
	{"path": "deployment-fare-engine.yaml", "text": "      hostNetwork: false\n        - hostIP: placeholder\n"},
]}

test_scan_finds_the_values_in_the_rendered_set if {
	report := manifest_scan.report with input as rendered
	rules := {f.rule | some f in report.findings}
	rules == {"anonymous-readers", "unrestricted-host-bind", "shared-host-network"}
}

test_scan_finds_an_unrestricted_ip_block if {
	doc := {"files": [{"path": "np.yaml", "text": "        - ipBlock:\n            cidr: 0.0.0.0/0\n"}]}
	manifest_scan.report.finding_count == 1 with input as doc
}

test_scan_reports_nothing_against_the_base if {
	report := manifest_scan.report with input as base
	report.finding_count == 0
	count(report.scanned_files) == 2
}

test_scan_says_what_it_did_not_read if {
	report := manifest_scan.report with input as base
	contains(report.did_not_read, "rendered manifest set")
}
