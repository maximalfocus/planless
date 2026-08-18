# The deployment gate.
#
# This policy decides one question: given the resolved desired state, which
# principals and which source addresses can actually reach each resource, and is
# that exposure one somebody reviewed and wrote down?
#
# It never matches a field value or a literal string. Two configurations that
# spell the same reachability differently must be decided identically, because
# an attacker — or, far more often, an ordinary engineer in a hurry — will spell
# it the second way.
#
# It denies by default. Every path that cannot reach a conclusion is a denial:
# an unfamiliar contract, an empty artifact, an unknown resource type, an
# unrecognized field, an exposure that cannot be computed, or an allowlist that
# is missing or does not cover what was computed. There is deliberately no
# option, threshold or mode that turns any of them into a warning.

package planless.gate

import rego.v1

contract_version := "1"

artifact := "<artifact>"

# ---------------------------------------------------------------------------
# The reviewed allowlist. It is data, and it is short on purpose: every entry is
# a decision somebody made in the open.
# ---------------------------------------------------------------------------

allowlist_entries := data.allowlist.entries

# ---------------------------------------------------------------------------
# Effective exposure
# ---------------------------------------------------------------------------

# A bucket's readers are whatever the grant resources say, wherever they live.
# Nothing about a bucket's own definition reveals this.
bucket_grants(name) := [g |
	some g in input.grants
	g.resource_kind == "bucket"
	g.resource_name == name
	"read" in g.actions
]

bucket_exposure(name) := exposure if {
	grants := bucket_grants(name)
	count(grants) > 0
	principals := {p | some g in grants; some p in g.principals}
	sources := net.cidr_merge({c | some g in grants; some c in g.source_ranges})
	exposure := {
		"principals": principals,
		"sources": sources,
		"rules": {g.id | some g in grants},
	}
}

# A workload port is reachable from the union of its ingress rules, capped by
# the addresses its declared bind can serve. Both halves matter: an unrestricted
# rule on a privately bound listener exposes nothing, and an unrestricted bind
# with no rule permits nothing.
port_rules(workload, port) := [r |
	some r in input.network_rules
	r.workload == workload
	r.port == port
]

bind_reach(bind) := {"0.0.0.0/0"} if {
	bind == "0.0.0.0"
}

bind_reach(bind) := set() if {
	bind != "0.0.0.0"
	net.cidr_contains("127.0.0.0/8", bind)
}

bind_reach(bind) := reach if {
	bind != "0.0.0.0"
	not net.cidr_contains("127.0.0.0/8", bind)
	reach := {s.cidr | some s in input.segments; net.cidr_contains(s.cidr, bind)}
}

# Two address blocks are either disjoint or one contains the other, so their
# intersection is simply the narrower of the two.
intersection(a, b) := a if {
	net.cidr_contains(b, a)
}

intersection(a, b) := b if {
	net.cidr_contains(a, b)
	not net.cidr_contains(b, a)
}

port_exposure(workload, port, bind) := exposure if {
	rules := port_rules(workload, port)
	permitted := net.cidr_merge({c | some r in rules; some c in r.source_ranges})
	reach := bind_reach(bind)
	sources := net.cidr_merge({i |
		some p in permitted
		some r in reach
		i := intersection(p, r)
	})
	exposure := {
		"sources": sources,
		"rules": {r.id | some r in rules},
	}
}

# ---------------------------------------------------------------------------
# Admission
# ---------------------------------------------------------------------------

principals_covered(got, allowed) if {
	every p in got {
		p in allowed
	}
}

sources_covered(got, allowed) if {
	every c in got {
		some a in allowed
		net.cidr_contains(a, c)
	}
}

admitted_bucket(name) := entry.rule if {
	exposure := bucket_exposure(name)
	some entry in allowlist_entries
	entry.kind == "bucket"
	entry.name == name
	principals_covered(exposure.principals, entry.principals)
	sources_covered(exposure.sources, entry.sources)
}

admitted_port(workload, port, bind) := entry.rule if {
	exposure := port_exposure(workload, port, bind)
	some entry in allowlist_entries
	entry.kind == "workload_port"
	entry.name == sprintf("%s:%s", [workload, port])
	sources_covered(exposure.sources, entry.sources)
}

# ---------------------------------------------------------------------------
# Violations. Every one of them denies.
# ---------------------------------------------------------------------------

violation(class, resource, exposure, reason) := {
	"class": class,
	"resource": resource,
	"exposure": exposure,
	"reason": reason,
}

violations contains violation(
	"contract_version_mismatch", artifact, "",
	sprintf("the artifact declares contract version %v, which this policy does not decide", [object.get(input, "contract_version", "<none>")]),
) if {
	object.get(input, "contract_version", "") != contract_version
}

violations contains violation(
	"empty_artifact", artifact, "",
	"the artifact declares no resources at all",
) if {
	count(object.get(input, "resources", [])) == 0
}

violations contains violation(
	"missing_allowlist", artifact, "",
	"no reviewed allowlist was supplied, so no exposure can be admitted",
) if {
	not data.allowlist.entries
}

violations contains violation(
	"unknown_resource_type", t, "",
	"the normalizer did not recognize this resource type, so its exposure is unknown",
) if {
	some t in object.get(input, "unknown_resource_types", [])
}

violations contains violation(
	"unrecognized_field", f, "",
	"the normalizer did not recognize this field, so it may carry exposure the policy cannot see",
) if {
	some f in object.get(input, "unrecognized_fields", [])
}

violations contains violation(
	"unparsable_source_range", sprintf("grant/%s", [g.id]), c,
	"a permission names a source range that is not a valid address block",
) if {
	some g in input.grants
	some c in g.source_ranges
	not net.cidr_is_valid(c)
}

violations contains violation(
	"unparsable_source_range", sprintf("network_rule/%s", [r.id]), c,
	"an ingress rule names a source range that is not a valid address block",
) if {
	some r in input.network_rules
	some c in r.source_ranges
	not net.cidr_is_valid(c)
}

# A bind address the policy cannot read would otherwise compute as "reaches
# nobody", which is an admission. It is a denial instead.
violations contains violation(
	"unparsable_bind_address", sprintf("workload/%s:%s", [r.name, p.name]), p.bind,
	"a workload port declares a bind address that is not a valid address",
) if {
	some r in input.resources
	r.kind == "workload"
	some p in r.ports
	not net.cidr_is_valid(sprintf("%s/32", [p.bind]))
}

# A bucket that carries read grants must have its computed exposure covered by a
# named allowlist entry. If the exposure cannot be computed at all, that is also
# a denial: the policy never admits what it could not evaluate.
violations contains violation(
	"exposure_not_allowlisted", sprintf("bucket/%s", [r.name]),
	render_exposure(bucket_exposure(r.name)),
	"the computed exposure of this bucket matches no reviewed allowlist entry",
) if {
	some r in input.resources
	r.kind == "bucket"
	count(bucket_grants(r.name)) > 0
	not admitted_bucket(r.name)
	bucket_exposure(r.name)
}

violations contains violation(
	"uncomputable_exposure", sprintf("bucket/%s", [r.name]), "",
	"the exposure of this bucket could not be computed from the artifact",
) if {
	some r in input.resources
	r.kind == "bucket"
	count(bucket_grants(r.name)) > 0
	not bucket_exposure(r.name)
}

violations contains violation(
	"exposure_not_allowlisted", sprintf("workload/%s:%s", [r.name, p.name]),
	render_exposure(port_exposure(r.name, p.name, p.bind)),
	"the computed reachability of this workload port matches no reviewed allowlist entry",
) if {
	some r in input.resources
	r.kind == "workload"
	some p in r.ports
	exposure := port_exposure(r.name, p.name, p.bind)
	count(exposure.sources) > 0
	not admitted_port(r.name, p.name, p.bind)
}

violations contains violation(
	"uncomputable_exposure", sprintf("workload/%s:%s", [r.name, p.name]), "",
	"the reachability of this workload port could not be computed from the artifact",
) if {
	some r in input.resources
	r.kind == "workload"
	some p in r.ports
	not port_exposure(r.name, p.name, p.bind)
}

# render_reachability is the exposure without the rules that produced it: who
# can reach this, from where. Two configurations that spell the same desired
# state differently produce different rules and the same reachability, and that
# equality is the whole claim about the bypasses.
render_reachability(exposure) := sprintf("principals=%v sources=%v", [
	effective_principals(object.get(exposure, "principals", set())),
	sort_or_empty(object.get(exposure, "sources", set())),
])

# Once every principal is admitted, naming any other one adds nothing. The
# effective principal set is "everyone", and a reachability that listed the
# named principals beside it would make two spellings of the same access look
# different. This is the same "compute, do not match" idea applied to
# principals rather than to addresses.
effective_principals(principals) := ["*"] if {
	"*" in principals
}

effective_principals(principals) := sort_or_empty(principals) if {
	not "*" in principals
}

render_exposure(exposure) := sprintf("principals=%v sources=%v rules=%v", [
	sort_or_empty(object.get(exposure, "principals", set())),
	sort_or_empty(object.get(exposure, "sources", set())),
	sort_or_empty(object.get(exposure, "rules", set())),
])

sort_or_empty(s) := sort([v | some v in s])

# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------

default decision := {
	"result": "deny",
	"class": "no_decision",
	"violations": [],
	"exposures": [],
}

decision := {
	"result": result,
	"class": "evaluated",
	"violations": sort([v | some v in violations]),
	"exposures": sort([e | some e in exposures]),
}

result := "deny" if {
	count(violations) > 0
}

result := "admit" if {
	count(violations) == 0
}

exposures contains e if {
	some r in input.resources
	r.kind == "bucket"
	exposure := bucket_exposure(r.name)
	e := {
		"resource": sprintf("bucket/%s", [r.name]),
		"computed": render_exposure(exposure),
		"reachability": render_reachability(exposure),
		"admitted_by": object.get(admitted, sprintf("bucket/%s", [r.name]), ""),
	}
}

exposures contains e if {
	some r in input.resources
	r.kind == "workload"
	some p in r.ports
	exposure := port_exposure(r.name, p.name, p.bind)
	e := {
		"resource": sprintf("workload/%s:%s", [r.name, p.name]),
		"computed": render_exposure(exposure),
		"reachability": render_reachability(exposure),
		"admitted_by": object.get(admitted, sprintf("workload/%s:%s", [r.name, p.name]), ""),
	}
}

admitted[key] := rule if {
	some r in input.resources
	r.kind == "bucket"
	key := sprintf("bucket/%s", [r.name])
	rule := admitted_bucket(r.name)
}

admitted[key] := rule if {
	some r in input.resources
	r.kind == "workload"
	some p in r.ports
	key := sprintf("workload/%s:%s", [r.name, p.name])
	rule := admitted_port(r.name, p.name, p.bind)
}
