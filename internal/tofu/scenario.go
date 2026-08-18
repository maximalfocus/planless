package tofu

// Expected outcomes a scenario declares. The harness asserts the outcome it
// declared, so a scenario that starts passing for the wrong reason fails.
const (
	ExpectApplied = "applied"
	ExpectRefused = "refused"
)

// Binding rehearsals: the ways a plan artifact can fail to be the one the gate
// approved.
const (
	BindingHonest     = ""
	BindingUnapproved = "unapproved"
	BindingModified   = "modified"
	BindingStale      = "stale"
)

// Scenario is one enumerated pipeline run. Nothing else can be started: there
// is no free-form configuration, variable file, policy, resource or address
// input anywhere in this project.
type Scenario struct {
	ID          string
	Description string
	VarFile     string
	Allowlist   string
	Expect      string

	// Artifact feeds a checked-in plan artifact to the gate instead of
	// producing one. It is how refusal is proved while no vulnerable
	// configuration exists in the repository.
	Artifact string

	// Gated runs the policy and binds its approval to the plan artifact.
	Gated bool

	// Binding names a deliberate rehearsal of a broken gate-to-apply binding.
	Binding string

	// BreakEngine points the gate at a policy engine that is not there, which
	// is how "the policy engine errored" is proved to deny.
	BreakEngine bool

	SkipApply  bool
	SkipRemote bool
}

// Scenarios is the complete set of runs this harness offers.
var Scenarios = map[string]Scenario{
	"offline-init": {
		ID:          "offline-init",
		Description: "initialize and plan with no network interface at all",
		VarFile:     "secure.tfvars",
		Expect:      ExpectApplied,
		SkipApply:   true,
		SkipRemote:  true,
	},
	"secure-apply": {
		ID:          "secure-apply",
		Description: "the gate admits the secure plan and the apply consumes exactly what it approved",
		VarFile:     "secure.tfvars",
		Gated:       true,
		Expect:      ExpectApplied,
	},
	"refuse-anonymous-export": {
		ID:          "refuse-anonymous-export",
		Description: "a plan whose resolved state grants anonymous read on the refund export",
		VarFile:     "secure.tfvars",
		Artifact:    "modified-anonymous-export-grant.json",
		Gated:       true,
		Expect:      ExpectRefused,
	},
	"refuse-unrestricted-admin": {
		ID:          "refuse-unrestricted-admin",
		Description: "a plan whose admin port is bound to every address and permitted from every address",
		VarFile:     "secure.tfvars",
		Artifact:    "modified-unrestricted-admin.json",
		Gated:       true,
		Expect:      ExpectRefused,
	},
	"fail-closed-unparsable": {
		ID:          "fail-closed-unparsable",
		Description: "an artifact the normalizer cannot read",
		VarFile:     "secure.tfvars",
		Artifact:    "modified-unparsable.json",
		Gated:       true,
		Expect:      ExpectRefused,
	},
	"fail-closed-unknown-type": {
		ID:          "fail-closed-unknown-type",
		Description: "an artifact carrying a resource type the normalizer does not know",
		VarFile:     "secure.tfvars",
		Artifact:    "modified-unknown-resource-type.json",
		Gated:       true,
		Expect:      ExpectRefused,
	},
	"fail-closed-unrecognized-field": {
		ID:          "fail-closed-unrecognized-field",
		Description: "an artifact carrying a field the normalizer does not know",
		VarFile:     "secure.tfvars",
		Artifact:    "modified-unrecognized-field.json",
		Gated:       true,
		Expect:      ExpectRefused,
	},
	"fail-closed-engine-error": {
		ID:          "fail-closed-engine-error",
		Description: "the policy engine fails to run at all",
		VarFile:     "secure.tfvars",
		Gated:       true,
		BreakEngine: true,
		Expect:      ExpectRefused,
	},
	"binding-unapproved-plan": {
		ID:          "binding-unapproved-plan",
		Description: "an apply attempted with no approval at all",
		VarFile:     "secure.tfvars",
		Gated:       true,
		Binding:     BindingUnapproved,
		Expect:      ExpectRefused,
	},
	"binding-modified-plan": {
		ID:          "binding-modified-plan",
		Description: "an apply attempted with a plan artifact changed after the gate approved it",
		VarFile:     "secure.tfvars",
		Gated:       true,
		Binding:     BindingModified,
		Expect:      ExpectRefused,
	},
	"binding-stale-approval": {
		ID:          "binding-stale-approval",
		Description: "an apply attempted with an approval issued for a different run",
		VarFile:     "secure.tfvars",
		Gated:       true,
		Binding:     BindingStale,
		Expect:      ExpectRefused,
	},
}

// AllowlistOf returns the reviewed allowlist a scenario is decided against.
func (s Scenario) AllowlistOf() string {
	if s.Allowlist == "" {
		return "default.json"
	}
	return s.Allowlist
}
