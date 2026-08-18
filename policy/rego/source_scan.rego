# A policy scan over the source configuration files.
#
# This is an honest implementation of a control that sounds sufficient. It reads
# the configuration a reviewer would read, matches the patterns a reviewer would
# look for, and reports what it finds. It is not sabotaged, and it is not a straw
# man: run it against a configuration that spells an exposure in a resource
# block and it says so.
#
# It is defeated anyway, and not by cleverness. The dangerous values are not in
# the files. They arrive from a variable file and a module default, so they exist
# only in the resolved plan — an artifact this scan never opens. Its answer is
# correct about what it read. That is the whole problem.

package planless.source_scan

import rego.v1

# The patterns a reviewer would look for in a resource definition. Whitespace is
# already normalized by the time the scan sees a block, so these are the shapes
# themselves rather than one spelling of them.
patterns := [
	{
		"id": "anonymous-principal",
		"needle": "principals = [\"*\"]",
		"reason": "a permission written in the resource names every principal",
	},
	{
		"id": "unrestricted-source-range",
		"needle": "source_ranges = [\"0.0.0.0/0\"]",
		"reason": "an address range written in the resource covers every address",
	},
	{
		"id": "unrestricted-bind",
		"needle": "bind = \"0.0.0.0\"",
		"reason": "a listener written in the resource binds every address",
	},
	{
		"id": "public-flag",
		"needle": "public = true",
		"reason": "a resource written in the source is marked public",
	},
]

# The scan reads resource definitions, which is what a scanner of configuration
# files reads. A value that reaches a resource through a variable is not in the
# resource, and this scan does not pretend otherwise.
findings contains finding if {
	some file in input.files
	some block in file.resource_blocks
	some pattern in patterns
	contains(block, pattern.needle)
	finding := {
		"rule": pattern.id,
		"file": file.path,
		"reason": pattern.reason,
	}
}

# The scan's own account of itself. It reports what it read, how much of it, and
# what it found — and it does not claim to have read anything else.
report := {
	"scanned_files": sort([f.path | some f in input.files]),
	"findings": sort([f | some f in findings]),
	"finding_count": count(findings),
	"artifact": "the source configuration files",
	"correct_about": "the artifact it read: the resource definitions in the configuration",
	"did_not_read": "the resolved desired state, which is the artifact that gets applied",
}
