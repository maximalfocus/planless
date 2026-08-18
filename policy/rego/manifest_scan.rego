# A policy scan over the base manifest set.
#
# The manifest surface's version of the same honest mistake. These are the
# patterns a reviewer looks for in a manifest, and they work: run them against
# the rendered overlay and they fire. Run them against the base — the files a
# reviewer opens — and they find nothing, because the base holds placeholders
# and the values arrive when the overlay is rendered.
#
# The artifact a reviewer reads is not the artifact that gets applied. That is
# true of a variable file and a module default on the infrastructure surface,
# and it is true of an overlay here. The invariant is not about a format.

package planless.manifest_scan

import rego.v1

patterns := [
	{
		"id": "anonymous-readers",
		"needle": "democloud.example/readers: '*'",
		"reason": "a published surface whose readers are every principal",
	},
	{
		"id": "unrestricted-ip-block",
		"needle": "cidr: 0.0.0.0/0",
		"reason": "an ingress block naming every address",
	},
	{
		"id": "unrestricted-host-bind",
		"needle": "hostIP: 0.0.0.0",
		"reason": "a listener bound to every address on its host",
	},
	{
		"id": "shared-host-network",
		"needle": "hostNetwork: true",
		"reason": "a workload sharing its host's network",
	},
]

findings contains finding if {
	some file in input.files
	some pattern in patterns
	contains(file.text, pattern.needle)
	finding := {
		"rule": pattern.id,
		"file": file.path,
		"reason": pattern.reason,
	}
}

report := {
	"scanned_files": sort([f.path | some f in input.files]),
	"findings": sort([f | some f in findings]),
	"finding_count": count(findings),
	"artifact": "the base manifest set",
	"correct_about": "the artifact it read: the manifests before the overlay is applied",
	"did_not_read": "the rendered manifest set, which is the artifact that gets applied",
}
