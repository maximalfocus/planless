package fixtures

// The taxonomy boundary, as data rather than as prose.
//
// A demonstration that names a weakness is making a claim, and a claim that
// drifts is worse than no claim at all. So what this project claims — and what
// it deliberately does not — is checked in, machine-checkable, and asserted by
// the same gate as everything else.

// Claim is one taxonomy identifier this project asserts or refuses to assert.
//
// Abstraction, MappingUsage and InA05Mapping are recorded from the
// authoritative pages rather than from memory, and rechecked before they are
// quoted publicly. RecheckedOn names when that last happened.
type Claim struct {
	ID           string
	Title        string
	Claimed      bool
	Abstraction  string
	MappingUsage string
	InA05Mapping bool
	URL          string
	Rationale    string
}

// RecheckedOn is when every title, abstraction, mapping-usage note and the
// A05:2021 mapping list below was last confirmed against the authoritative
// pages.
const RecheckedOn = "2026-08-18"

// A05MappedCWECount is the number of CWEs in A05:2021's published mapping, as
// the category's own Factors table states.
const A05MappedCWECount = 20

// Taxonomy is the complete, closed set. Nothing outside it may be claimed, and
// every entry carries the reason it is or is not.
var Taxonomy = []Claim{
	{
		ID:           "A05:2021",
		Title:        "Security Misconfiguration",
		Claimed:      true,
		Abstraction:  "OWASP Top 10 category",
		MappingUsage: "n/a",
		URL:          "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
		Rationale: "claimed on the category's own description, which names improperly configured " +
			"permissions on cloud services and directs reviewers to review cloud storage permissions",
	},
	{
		ID:           "CWE-732",
		Abstraction:  "Class",
		MappingUsage: "ALLOWED-WITH-REVIEW",
		InA05Mapping: false,
		URL:          "https://cwe.mitre.org/data/definitions/732.html",
		Title:        "Incorrect Permission Assignment for Critical Resource",
		Claimed:      true,
		Rationale: "the storage shape. Its own examples are a blob container opened to public access " +
			"and a bucket policy granting every user. Its ALLOWED-WITH-REVIEW note warns it is often " +
			"misused where an authorization check is missing; nothing here fails to check anything, " +
			"the permission was assigned, deliberately and successfully, to everyone",
	},
	{
		ID:           "CWE-1327",
		Abstraction:  "Base",
		MappingUsage: "ALLOWED",
		InA05Mapping: false,
		URL:          "https://cwe.mitre.org/data/definitions/1327.html",
		Title:        "Binding to an Unrestricted IP Address",
		Claimed:      true,
		Rationale: "the network shape: an ingress rule whose permitted source set is every address, " +
			"and a workload that binds the unrestricted address",
	},
	{
		ID:           "CWE-1032",
		Abstraction:  "Category",
		MappingUsage: "PROHIBITED",
		InA05Mapping: true,
		URL:          "https://cwe.mitre.org/data/definitions/1032.html",
		Title:        "OWASP Top Ten 2017 Category A6 - Security Misconfiguration",
		Claimed:      false,
		Rationale: "a CWE Category whose mapping usage is Prohibited: such an identifier must not be " +
			"used to map to real-world vulnerabilities. Not claimed, and not restored to fill a " +
			"coverage square",
	},
	{
		ID:           "CWE-16",
		Abstraction:  "Category",
		MappingUsage: "PROHIBITED",
		InA05Mapping: true,
		URL:          "https://cwe.mitre.org/data/definitions/16.html",
		Title:        "Configuration",
		Claimed:      false,
		Rationale: "also a Category with mapping usage Prohibited. With CWE-1032 it is one of the only " +
			"two general-purpose members of A05:2021's published mapping, which is why no CWE in that " +
			"mapping is the precise weakness here",
	},
	{
		ID:           "CWE-668",
		Abstraction:  "Class",
		MappingUsage: "DISCOURAGED",
		InA05Mapping: false,
		URL:          "https://cwe.mitre.org/data/definitions/668.html",
		Title:        "Exposure of Resource to Wrong Sphere",
		Claimed:      false,
		Rationale: "named as the shared conceptual root of both shapes and deliberately not claimed: " +
			"its mapping usage is Discouraged as a catch-all",
	},
	{
		ID:           "CWE-276",
		Abstraction:  "Base",
		MappingUsage: "ALLOWED",
		InA05Mapping: false,
		URL:          "https://cwe.mitre.org/data/definitions/276.html",
		Title:        "Incorrect Default Permissions",
		Claimed:      false,
		Rationale: "defined over installed file permissions, not provisioned platform resources. " +
			"Stretching it would trade precision for a familiar number",
	},
	{
		ID:      "A06:2021",
		URL:     "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
		Title:   "Vulnerable and Outdated Components",
		Claimed: false,
		Rationale: "nothing here is vulnerable, outdated, deprecated or unmaintained, and no component " +
			"version, patch level or CVE is a variable in any test. This demonstration does not close " +
			"that gap",
	},
	{
		ID:      "API8:2023",
		URL:     "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
		Title:   "Security Misconfiguration",
		Claimed: false,
		Rationale: "the affected surface is a platform's resource configuration rather than an API's " +
			"security configuration",
	},
}

// Claimed returns the identifiers this project asserts.
func Claimed() []string {
	out := []string{}
	for _, c := range Taxonomy {
		if c.Claimed {
			out = append(out, c.ID)
		}
	}
	return out
}

// NotClaimed returns the identifiers this project deliberately refuses.
func NotClaimed() []string {
	out := []string{}
	for _, c := range Taxonomy {
		if !c.Claimed {
			out = append(out, c.ID)
		}
	}
	return out
}
