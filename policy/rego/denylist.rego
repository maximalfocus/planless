# A denylist of known-bad literals.
#
# These are the two rules a reviewer writes first, and they are written the way
# a reviewer writes them: flag a bucket marked public, flag an ingress rule that
# permits every address. They run against the resolved desired state — not the
# source text — so this is not the earlier mistake repeated. They read the right
# artifact and ask the wrong question.
#
# Both rules work. Each is tested firing against a configuration that spells the
# exposure the obvious way. They report nothing here because the same desired
# state can be written two other ordinary ways, and a rule that matches a value
# only matches the value it was shown.
#
# That is the pivot to the fix: reachability has to be computed over the
# resolved graph, not matched against a list of spellings somebody thought of.

package planless.denylist

import rego.v1

rules := [
	{
		"id": "deny-public-bucket",
		"reason": "a bucket whose own definition marks it public",
	},
	{
		"id": "deny-unrestricted-ingress",
		"reason": "an ingress rule that names every address",
	},
]

# A bucket that says it is public. Nothing about a bucket's own definition says
# who can read it on this platform — permissions are separate resources — so a
# rule that inspects the bucket inspects the wrong thing.
findings contains finding if {
	some r in input.resources
	r.kind == "bucket"
	object.get(r, ["attributes", "public"], false) == true
	finding := {
		"rule": "deny-public-bucket",
		"resource": sprintf("bucket/%s", [r.name]),
		"matched": "public = true",
		"reason": "a bucket whose own definition marks it public",
	}
}

# An ingress rule naming every address, spelled the way everybody spells it.
findings contains finding if {
	some r in input.network_rules
	some c in r.source_ranges
	c == "0.0.0.0/0"
	finding := {
		"rule": "deny-unrestricted-ingress",
		"resource": sprintf("network_rule/%s", [r.id]),
		"matched": c,
		"reason": "an ingress rule that names every address",
	}
}

# The denylist's own account of itself: what it matched, and what it is.
report := {
	"rules": sort([r.id | some r in rules]),
	"findings": sort([f | some f in findings]),
	"finding_count": count(findings),
	"artifact": "the resolved desired state",
	"method": "matching literal values",
	"limitation": "a rule matches only the spelling it was shown; the same desired state has others",
}
