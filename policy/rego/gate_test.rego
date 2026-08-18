# Unit tests for the deployment gate.
#
# The tests that matter most are the ones where the same reachability is spelled
# two different ways. A policy that passes only the first spelling is a denylist
# wearing a deny-by-default costume.

package planless.gate_test

import data.planless.gate
import rego.v1

allowlist := {"entries": [
	{
		"rule": "allow-refund-export-to-finance-from-corp",
		"kind": "bucket",
		"name": "fare-exports",
		"principals": ["finance-reporting"],
		"sources": ["10.20.0.0/16"],
	},
	{
		"rule": "allow-status-page-public",
		"kind": "bucket",
		"name": "status-page",
		"principals": ["*"],
		"sources": ["0.0.0.0/0"],
	},
	{
		"rule": "allow-fare-engine-admin-from-operations-range",
		"kind": "workload_port",
		"name": "fare-engine:admin",
		"sources": ["10.20.7.0/24"],
	},
]}

segments := [
	{"name": "corp", "cidr": "10.20.0.0/16"},
	{"name": "internet", "cidr": "198.51.100.0/24"},
]

secure_input := {
	"contract_version": "1",
	"surface": "iac-plan",
	"segments": segments,
	"resources": [
		{"kind": "bucket", "name": "fare-exports", "address": "a"},
		{"kind": "bucket", "name": "status-page", "address": "b"},
		{
			"kind": "workload",
			"name": "fare-engine",
			"address": "c",
			"ports": [{"name": "admin", "number": 8081, "bind": "10.20.1.20"}],
		},
	],
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
			"id": "grant-status",
			"resource_kind": "bucket",
			"resource_name": "status-page",
			"principals": ["*"],
			"actions": ["read"],
			"source_ranges": ["0.0.0.0/0"],
		},
	],
	"network_rules": [{
		"id": "rule-admin",
		"workload": "fare-engine",
		"port": "admin",
		"source_ranges": ["10.20.7.0/24"],
	}],
	"unknown_resource_types": [],
	"unrecognized_fields": [],
}

test_secure_artifact_is_admitted if {
	d := gate.decision with input as secure_input with data.allowlist as allowlist
	d.result == "admit"
	count(d.violations) == 0
}

test_deliberately_public_bucket_is_admitted_by_its_named_entry if {
	d := gate.decision with input as secure_input with data.allowlist as allowlist
	some e in d.exposures
	e.resource == "bucket/status-page"
	e.admitted_by == "allow-status-page-public"
}

# A grant resource the bucket's own definition never mentions still decides who
# can read it. This is the whole reason the policy resolves grants instead of
# reading a field.
test_separate_grant_resource_exposes_the_bucket if {
	doc := object.union(secure_input, {"grants": array.concat(secure_input.grants, [{
		"id": "grant-anonymous",
		"resource_kind": "bucket",
		"resource_name": "fare-exports",
		"principals": ["*"],
		"actions": ["read"],
		"source_ranges": ["10.20.0.0/16"],
	}])})
	d := gate.decision with input as doc with data.allowlist as allowlist
	d.result == "deny"
	some v in d.violations
	v.class == "exposure_not_allowlisted"
	v.resource == "bucket/fare-exports"
}

# The identical effective exposure, spelled as a pair of half-ranges that no
# rule matching "0.0.0.0/0" would ever see.
test_split_range_pair_is_computed_as_every_address if {
	doc := object.union(secure_input, {"network_rules": [{
		"id": "rule-admin",
		"workload": "fare-engine",
		"port": "admin",
		"source_ranges": ["0.0.0.0/1", "128.0.0.0/1"],
	}]})
	unrestricted := object.union(doc, {"resources": [
		{"kind": "bucket", "name": "fare-exports", "address": "a"},
		{"kind": "bucket", "name": "status-page", "address": "b"},
		{
			"kind": "workload",
			"name": "fare-engine",
			"address": "c",
			"ports": [{"name": "admin", "number": 8081, "bind": "0.0.0.0"}],
		},
	]})
	d := gate.decision with input as unrestricted with data.allowlist as allowlist
	d.result == "deny"
	some v in d.violations
	v.class == "exposure_not_allowlisted"
	v.resource == "workload/fare-engine:admin"
	contains(v.exposure, "0.0.0.0/0")
}

# An unrestricted ingress rule on a privately bound listener exposes nothing
# beyond that segment: reachability is both halves, not either one.
test_bind_address_caps_an_unrestricted_rule if {
	doc := object.union(secure_input, {"network_rules": [{
		"id": "rule-admin",
		"workload": "fare-engine",
		"port": "admin",
		"source_ranges": ["0.0.0.0/0"],
	}]})
	d := gate.decision with input as doc with data.allowlist as allowlist
	some v in d.violations
	v.resource == "workload/fare-engine:admin"
	contains(v.exposure, "10.20.0.0/16")
	not contains(v.exposure, "0.0.0.0/0")
}

test_loopback_bind_exposes_nothing if {
	doc := object.union(secure_input, {"resources": [
		{"kind": "bucket", "name": "fare-exports", "address": "a"},
		{"kind": "bucket", "name": "status-page", "address": "b"},
		{
			"kind": "workload",
			"name": "fare-engine",
			"address": "c",
			"ports": [{"name": "admin", "number": 8081, "bind": "127.0.0.1"}],
		},
	]})
	d := gate.decision with input as doc with data.allowlist as allowlist
	d.result == "admit"
}

# A narrower exposure than the allowlist entry permits is still admitted;
# a wider one is not.
test_narrower_exposure_is_admitted if {
	doc := object.union(secure_input, {"network_rules": [{
		"id": "rule-admin",
		"workload": "fare-engine",
		"port": "admin",
		"source_ranges": ["10.20.7.0/25"],
	}]})
	d := gate.decision with input as doc with data.allowlist as allowlist
	d.result == "admit"
}

test_unknown_resource_type_denies if {
	d := gate.decision with input as object.union(secure_input, {"unknown_resource_types": ["democloud_firewall"]}) with data.allowlist as allowlist
	d.result == "deny"
	some v in d.violations
	v.class == "unknown_resource_type"
}

test_unrecognized_field_denies if {
	d := gate.decision with input as object.union(secure_input, {"unrecognized_fields": ["democloud_bucket.fare_exports.public"]}) with data.allowlist as allowlist
	d.result == "deny"
	some v in d.violations
	v.class == "unrecognized_field"
}

test_empty_artifact_denies if {
	d := gate.decision with input as object.union(secure_input, {"resources": []}) with data.allowlist as allowlist
	d.result == "deny"
	some v in d.violations
	v.class == "empty_artifact"
}

test_unfamiliar_contract_version_denies if {
	d := gate.decision with input as object.union(secure_input, {"contract_version": "99"}) with data.allowlist as allowlist
	d.result == "deny"
	some v in d.violations
	v.class == "contract_version_mismatch"
}

test_missing_allowlist_denies if {
	d := gate.decision with input as secure_input with data.allowlist as {}
	d.result == "deny"
	some v in d.violations
	v.class == "missing_allowlist"
}

test_empty_allowlist_denies_every_exposure if {
	d := gate.decision with input as secure_input with data.allowlist as {"entries": []}
	d.result == "deny"
	some v in d.violations
	v.class == "exposure_not_allowlisted"
}

test_unparsable_source_range_denies if {
	doc := object.union(secure_input, {"network_rules": [{
		"id": "rule-admin",
		"workload": "fare-engine",
		"port": "admin",
		"source_ranges": ["10.20.7.0/99"],
	}]})
	d := gate.decision with input as doc with data.allowlist as allowlist
	d.result == "deny"
	classes := {v.class | some v in d.violations}
	"unparsable_source_range" in classes
	"uncomputable_exposure" in classes
}

test_unparsable_bind_address_denies if {
	doc := object.union(secure_input, {"resources": [
		{"kind": "bucket", "name": "fare-exports", "address": "a"},
		{"kind": "bucket", "name": "status-page", "address": "b"},
		{
			"kind": "workload",
			"name": "fare-engine",
			"address": "c",
			"ports": [{"name": "admin", "number": 8081, "bind": "not-an-address"}],
		},
	]})
	d := gate.decision with input as doc with data.allowlist as allowlist
	d.result == "deny"
	some v in d.violations
	v.class == "unparsable_bind_address"
}

# A grant on a bucket the artifact never declares must not quietly pass: the
# bucket it names is decided when the bucket appears, and an exposure with no
# entry is refused wherever it is found.
test_wider_principal_set_denies if {
	doc := object.union(secure_input, {"grants": [
		{
			"id": "grant-export",
			"resource_kind": "bucket",
			"resource_name": "fare-exports",
			"principals": ["finance-reporting", "contractor-reporting"],
			"actions": ["read"],
			"source_ranges": ["10.20.0.0/16"],
		},
		{
			"id": "grant-status",
			"resource_kind": "bucket",
			"resource_name": "status-page",
			"principals": ["*"],
			"actions": ["read"],
			"source_ranges": ["0.0.0.0/0"],
		},
	]})
	d := gate.decision with input as doc with data.allowlist as allowlist
	d.result == "deny"
	some v in d.violations
	v.resource == "bucket/fare-exports"
}
