# Both denylist rules must be shown to work before "they found nothing" means
# anything. Then the same effective exposure, spelled two other ordinary ways,
# must slip past both — while the deny-by-default policy refuses every spelling
# identically.

package planless.denylist_test

import data.planless.denylist
import data.planless.gate
import rego.v1

allowlist := {"entries": [{
	"rule": "allow-fare-engine-admin-from-operations-range",
	"kind": "workload_port",
	"name": "fare-engine:admin",
	"sources": ["10.20.7.0/24"],
}]}

segments := [
	{"name": "corp", "cidr": "10.20.0.0/16"},
	{"name": "internet", "cidr": "198.51.100.0/24"},
]

base := {
	"contract_version": "1",
	"surface": "iac-plan",
	"segments": segments,
	"unknown_resource_types": [],
	"unrecognized_fields": [],
	"resources": [
		{"kind": "bucket", "name": "fare-exports", "address": "a", "attributes": {"name": "fare-exports"}},
		{
			"kind": "workload",
			"name": "fare-engine",
			"address": "c",
			"ports": [{"name": "admin", "number": 8081, "bind": "0.0.0.0"}],
		},
	],
	"grants": [],
	"network_rules": [],
}

# The obvious spelling: the bucket says it is public, the rule says every
# address, the grant names everyone from everywhere.
literal := object.union(base, {
	"resources": [
		{
			"kind": "bucket",
			"name": "fare-exports",
			"address": "a",
			"attributes": {"name": "fare-exports", "public": true},
		},
		{
			"kind": "workload",
			"name": "fare-engine",
			"address": "c",
			"ports": [{"name": "admin", "number": 8081, "bind": "0.0.0.0"}],
		},
	],
	"grants": [{
		"id": "grant-export",
		"resource_kind": "bucket",
		"resource_name": "fare-exports",
		"principals": ["*"],
		"actions": ["read"],
		"source_ranges": ["0.0.0.0/0"],
	}],
	"network_rules": [{
		"id": "rule-admin",
		"workload": "fare-engine",
		"port": "admin",
		"source_ranges": ["0.0.0.0/0"],
	}],
})

# The same desired state, two ordinary ways. The bucket's own grant is untouched
# and a separate grant resource carries the exposure; the ingress names two
# halves of the address space instead of one range.
bypassed := object.union(base, {
	"grants": [
		{
			"id": "grant-export",
			"resource_kind": "bucket",
			"resource_name": "fare-exports",
			"principals": ["finance-reporting"],
			"actions": ["read"],
			"source_ranges": ["10.20.0.0/16"],
		},
		{
			"id": "grant-export-anonymous",
			"resource_kind": "bucket",
			"resource_name": "fare-exports",
			"principals": ["*"],
			"actions": ["read"],
			"source_ranges": ["0.0.0.0/1", "128.0.0.0/1"],
		},
	],
	"network_rules": [{
		"id": "rule-admin",
		"workload": "fare-engine",
		"port": "admin",
		"source_ranges": ["0.0.0.0/1", "128.0.0.0/1"],
	}],
})

test_every_denylist_rule_fires_on_the_obvious_spelling if {
	report := denylist.report with input as literal
	fired := {f.rule | some f in report.findings}
	fired == {"deny-public-bucket", "deny-unrestricted-ingress"}
}

test_denylist_reports_nothing_against_the_bypassed_spelling if {
	report := denylist.report with input as bypassed
	report.finding_count == 0
}

# The bypasses are not clever. They are ordinary. The deny-by-default policy
# refuses both spellings, because it computes what they mean.
test_deny_by_default_refuses_both_spellings if {
	literal_decision := gate.decision with input as literal with data.allowlist as allowlist
	bypassed_decision := gate.decision with input as bypassed with data.allowlist as allowlist
	literal_decision.result == "deny"
	bypassed_decision.result == "deny"
}

# And it computes the same exposure for both, which is the whole claim: these
# are two spellings of one desired state.
test_computed_exposure_is_identical_for_both_spellings if {
	literal_decision := gate.decision with input as literal with data.allowlist as allowlist
	bypassed_decision := gate.decision with input as bypassed with data.allowlist as allowlist
	literal_exposures := {e.resource: e.computed | some e in literal_decision.exposures}
	bypassed_exposures := {e.resource: e.computed | some e in bypassed_decision.exposures}
	literal_exposures["workload/fare-engine:admin"] == bypassed_exposures["workload/fare-engine:admin"]
	contains(literal_exposures["workload/fare-engine:admin"], "0.0.0.0/0")
	contains(bypassed_exposures["bucket/fare-exports"], "0.0.0.0/0")
	contains(bypassed_exposures["bucket/fare-exports"], "*")
}

# The deliberately public status page is written the obvious way, and these
# rules still say nothing about it: they inspect the bucket and the ingress
# rule, and its exposure lives in a permission resource. A denylist extended to
# inspect permissions would flag the one resource that is *supposed* to be
# public, and still miss both of the ones that are not.
test_denylist_is_silent_about_the_deliberately_public_bucket if {
	doc := object.union(bypassed, {"grants": array.concat(bypassed.grants, [{
		"id": "grant-status-public",
		"resource_kind": "bucket",
		"resource_name": "status-page",
		"principals": ["*"],
		"actions": ["read"],
		"source_ranges": ["0.0.0.0/0"],
	}])})
	report := denylist.report with input as doc
	report.finding_count == 0
}

test_denylist_says_what_it_is if {
	report := denylist.report with input as bypassed
	report.method == "matching literal values"
	contains(report.limitation, "only the spelling it was shown")
}
