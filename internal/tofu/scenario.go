package tofu

import "sort"

// Expected outcomes a scenario declares. The harness asserts the outcome it
// declared, so a scenario that starts passing for the wrong reason fails.
const (
	ExpectApplied = "applied"
	ExpectRefused = "refused"

	// ExpectAppliedOutOfBand is the shape where the gate refused and the change
	// landed anyway. The operator was told one thing; the platform did another.
	ExpectAppliedOutOfBand = "applied-out-of-band"
)

// Binding rehearsals: the ways a plan artifact can fail to be the one the gate
// approved.
const (
	BindingHonest     = ""
	BindingUnapproved = "unapproved"
	BindingModified   = "modified"
	BindingStale      = "stale"
)

// VulnerableWarning labels everything the vulnerable path produces.
const VulnerableWarning = "INTENTIONALLY VULNERABLE — local educational material, not a real platform"

// Surfaces the harness can run on. The vulnerable surface exists only on a
// service that a non-default Compose profile brings up.
const (
	SurfaceSecure     = "secure"
	SurfaceVulnerable = "vulnerable"
)

// Acknowledgement is the explicit opt-in a vulnerable run additionally needs.
const Acknowledgement = "true"

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

	// ExpectReconciliation is the verdict the reconciliation must reach. A run
	// that lands an exposure is expected to fail it: that failure is the
	// demonstration, and a run where it stopped failing would be a regression.
	ExpectReconciliation string

	// Scan replaces the deployment gate with a scan of the source
	// configuration files: an honest control over the wrong artifact.
	Scan bool

	// Manifest names the overlay of the Kubernetes-shaped manifest surface this
	// scenario renders. The manifests are manifest-shaped input to this
	// demonstration's own applier: no Kubernetes distribution, API server,
	// admission controller or kubelet is implemented or emulated anywhere.
	Manifest string

	// Denylist runs the literal-matching rules over the resolved plan instead
	// of the deny-by-default policy. A denylist that matches nothing cannot
	// stop anything, so the pipeline carries on.
	Denylist bool

	// Advisory runs the deployment gate and then does not obey it. A finding
	// without authority is a log line.
	Advisory bool

	// OutOfBand applies the plan through a second path after the gate refused
	// it on the review path. A gate is worth exactly the paths it stands on.
	OutOfBand bool

	// DriftMutation changes one live resource directly at the control plane
	// after a compliant apply, so the repository stays correct while the world
	// does not.
	DriftMutation bool

	// Vulnerable marks a run that applies, or evaluates, a deliberately
	// misconfigured value set. Such a run needs both opt-ins and everything it
	// produces is labelled.
	Vulnerable bool

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
	"reviewed-exposure-unapproved": {
		ID:          "reviewed-exposure-unapproved",
		Description: "publishing a second status asset, against the allowlist that does not name it",
		VarFile:     "reviewed-exposure.tfvars",
		Gated:       true,
		Expect:      ExpectRefused,
	},
	"reviewed-exposure": {
		ID:          "reviewed-exposure",
		Description: "the same change, against a reviewed allowlist that names the new exposure",
		VarFile:     "reviewed-exposure.tfvars",
		Allowlist:   "reviewed-exposure.json",
		Gated:       true,
		Expect:      ExpectApplied,
	},
	"routine-change": {
		ID:          "routine-change",
		Description: "an ordinary non-security change: keep access logs for longer",
		VarFile:     "routine-change.tfvars",
		Gated:       true,
		Expect:      ExpectApplied,
	},
	"vulnerable-gated": {
		ID:          "vulnerable-gated",
		Description: "the misconfigured value set, with the gate standing on the path to apply",
		VarFile:     "vulnerable.tfvars",
		Gated:       true,
		Vulnerable:  true,
		Expect:      ExpectRefused,
	},
	"vulnerable-ungated": {
		ID:                   "vulnerable-ungated",
		Description:          "the misconfigured value set, applied by a path no gate stands on",
		VarFile:              "vulnerable.tfvars",
		Vulnerable:           true,
		Expect:               ExpectApplied,
		ExpectReconciliation: VerdictFail,
	},
	"half-fix-source-scan": {
		ID:                   "half-fix-source-scan",
		Description:          "a policy scan reads the configuration files, finds nothing, and is right about what it read",
		VarFile:              "vulnerable.tfvars",
		Scan:                 true,
		Vulnerable:           true,
		Expect:               ExpectApplied,
		ExpectReconciliation: VerdictFail,
	},
	"half-fix-report-only": {
		ID:                   "half-fix-report-only",
		Description:          "the gate reads the resolved plan, reports both findings correctly, and does not stop the pipeline",
		VarFile:              "vulnerable.tfvars",
		Gated:                true,
		Advisory:             true,
		Vulnerable:           true,
		Expect:               ExpectApplied,
		ExpectReconciliation: VerdictFail,
	},
	"manifest-intended": {
		ID:          "manifest-intended",
		Description: "the intended posture, rendered from manifests and decided by the same policy",
		VarFile:     "secure.tfvars",
		Manifest:    "intended",
		Gated:       true,
		Expect:      ExpectApplied,
	},
	"manifest-exposed": {
		ID:          "manifest-exposed",
		Description: "the exposed overlay, refused by the same policy with no change to it",
		VarFile:     "secure.tfvars",
		Manifest:    "exposed",
		Gated:       true,
		Vulnerable:  true,
		Expect:      ExpectRefused,
	},
	"manifest-exposed-ungated": {
		ID:                   "manifest-exposed-ungated",
		Description:          "the exposed overlay applied with no policy step, and a scan of the base that finds nothing",
		VarFile:              "secure.tfvars",
		Manifest:             "exposed",
		Scan:                 true,
		Vulnerable:           true,
		Expect:               ExpectApplied,
		ExpectReconciliation: VerdictFail,
	},
	"half-fix-denylist": {
		ID:                   "half-fix-denylist",
		Description:          "two literal rules over the resolved plan, and the same exposure written two other ways",
		VarFile:              "denylist.tfvars",
		Denylist:             true,
		Vulnerable:           true,
		Expect:               ExpectApplied,
		ExpectReconciliation: VerdictFail,
	},
	"half-fix-review-path-only": {
		ID:                   "half-fix-review-path-only",
		Description:          "the gate blocks on the review path and the change reaches the platform by another",
		VarFile:              "vulnerable.tfvars",
		Gated:                true,
		OutOfBand:            true,
		Vulnerable:           true,
		Expect:               ExpectAppliedOutOfBand,
		ExpectReconciliation: VerdictFail,
	},
	"half-fix-drift": {
		ID:                   "half-fix-drift",
		Description:          "a compliant state, changed directly at the control plane afterwards",
		VarFile:              "secure.tfvars",
		Gated:                true,
		DriftMutation:        true,
		Vulnerable:           true,
		Expect:               ExpectApplied,
		ExpectReconciliation: VerdictFail,
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

// Available reports whether a scenario may be started here.
//
// A vulnerable scenario needs both opt-ins: a surface that only a non-default
// Compose profile brings up, and an explicit acknowledgement supplied by the
// operator. Either one alone is not enough, and neither can be supplied by the
// scenario itself.
func (s Scenario) Available(surface, acknowledgement string) bool {
	if !s.Vulnerable {
		return true
	}
	return surface == SurfaceVulnerable && acknowledgement == Acknowledgement
}

// AvailableScenarios lists what may be started on this surface.
func AvailableScenarios(surface, acknowledgement string) []string {
	out := []string{}
	for name, s := range Scenarios {
		if s.Available(surface, acknowledgement) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// ExpectReconciliationOf returns the verdict this scenario must reach.
func (s Scenario) ExpectReconciliationOf() string {
	if s.ExpectReconciliation == "" {
		return VerdictPass
	}
	return s.ExpectReconciliation
}

// AllowlistOf returns the reviewed allowlist a scenario is decided against.
func (s Scenario) AllowlistOf() string {
	if s.Allowlist == "" {
		return "default.json"
	}
	return s.Allowlist
}
