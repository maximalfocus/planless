#!/bin/sh
# planless — the whole demonstration, through one container boundary.
#
# The host needs Docker and a POSIX shell and nothing else. Every assertion in
# this script is made by a container about itself or about what it can reach:
# the script only orders the steps and reports the first failure.
set -eu

cd "$(dirname "$0")/.."
COMPOSE="docker compose -f deploy/compose.yaml --profile checks"
COMPOSE_ALL="docker compose -f deploy/compose.yaml --profile checks --profile vulnerable"

usage() {
	cat <<'USAGE'
usage: scripts/demo.sh <command>

  verify     build, check containment, apply the configuration, run every check, tear down
  vulnerable run the intentionally vulnerable demonstration (needs ALLOW_VULNERABLE_DEMO=true)
  build      build the container images
  up         start the platform and apply the checked-in configuration
  apply      run the pipeline against a running platform
  down       stop everything and remove the segments
  state      print live platform state through the control plane's read-only API
  checks     run the observation checks against an already running platform
  policy     run the deployment gate over the checked-in plan artifacts
  refusals   run every refusal scenario against a running platform
  paths      run the five secure legitimate paths against a running platform
  manifests  render and apply the Kubernetes-shaped manifest surface

The secure platform is the default. The intentionally vulnerable demonstration
needs two separate opt-in actions and neither alone is enough.

Nothing in this project accepts a cloud endpoint, credential, region, account,
bucket name, address or manifest.
USAGE
}

step() { printf '\n=== %s\n' "$1"; }

build() {
	step "build images"
	$COMPOSE build --quiet
}

go_gate() {
	step "go test, go vet and formatting"
	$COMPOSE exec -T tests sh -c '
		set -e
		unformatted="$(gofmt -l .)"
		if [ -n "$unformatted" ]; then
			echo "unformatted files:"; echo "$unformatted"; exit 1
		fi
		go vet ./...
		go test ./...
		opa fmt --fail --list policy/rego
		opa test policy/rego
		cd provider
		go vet ./...
		go test ./...
	'
}

policy_gate() {
	step "the deployment gate decides every checked-in plan artifact"
	$COMPOSE exec -T pipeline /usr/local/bin/gate verify-fixtures
}

offline_init() {
	step "provider installation and planning, with no network interface at all"
	$COMPOSE run --rm -T pipeline-offline offline-init
}

# One scenario, end to end: the harness runs it, each segment reports what it
# could reach, and the reconciliation compares the two. Every assertion is made
# inside a container; this function only orders the steps.
scenario() {
	step "scenario: $1" >&2
	transcript="$($COMPOSE exec -T pipeline /usr/local/bin/pipeline "$1")"
	# Both segments report at once: neither observation depends on the other.
	work="$(mktemp -d)"
	$COMPOSE exec -T outside /usr/local/bin/client observe >"$work/internet" &
	internet_probe=$!
	$COMPOSE exec -T finance /usr/local/bin/client observe >"$work/corp" &
	corp_probe=$!
	wait "$internet_probe"
	wait "$corp_probe"
	printf '%s\n' "$transcript" | cat - "$work/internet" "$work/corp" |
		$COMPOSE exec -T pipeline /usr/local/bin/pipeline reconcile >/dev/null
	rm -rf "$work"
	printf '%s\n' "$transcript"
}

apply() {
	scenario secure-apply
}

# The Kubernetes-shaped manifest surface: the same policy contract, a different
# input format.
manifest_surface() {
	step "a second manifest format, decided by the same policy with no change to it"
	scenario manifest-intended >/dev/null
	$COMPOSE exec -T verifier /usr/local/bin/client state-matches-fixture
}

# The five legitimate paths. A deny-by-default policy is only worth having if
# the legitimate work still goes through.
legitimate() {
	step "a reviewed exposure change, against the allowlist that does not name it"
	scenario reviewed-exposure-unapproved
	$COMPOSE exec -T outside /usr/local/bin/client internet-secure-baseline

	step "an ordinary non-security change must alter nothing about reachability"
	before="$($COMPOSE exec -T outside /usr/local/bin/client observe)"
	scenario routine-change
	after="$($COMPOSE exec -T outside /usr/local/bin/client observe)"
	printf '%s\n%s\n' "$before" "$after" |
		$COMPOSE exec -T pipeline /usr/local/bin/pipeline compare-observations

	step "the same exposure change, against a reviewed allowlist that names it"
	scenario reviewed-exposure
	$COMPOSE exec -T outside /usr/local/bin/client internet-reviewed-exposure
}

# INTENTIONALLY VULNERABLE — local educational material.
#
# Two opt-in actions are required and neither alone is enough: the non-default
# compose profile that brings up the vulnerable surface, and this explicit
# acknowledgement. The default pipeline offers no misconfigured scenario at all.
vulnerable() {
	if [ "${ALLOW_VULNERABLE_DEMO:-}" != "true" ]; then
		cat >&2 <<'REFUSED'
Refusing to start the intentionally vulnerable demonstration.

It needs two separate opt-in actions:

  1. the non-default compose profile that brings up the vulnerable surface, and
  2. an explicit acknowledgement:

      ALLOW_VULNERABLE_DEMO=true ./scripts/demo.sh vulnerable

Everything it applies is deliberately misconfigured local educational material.
It contacts no cloud provider, cluster, account or real API.
REFUSED
		exit 1
	fi

	build
	step "fresh platform: every vulnerable run starts from empty state"
	down
	up
	$COMPOSE_ALL up -d vulnerable-pipeline

	step "the intended posture, applied through the gate"
	scenario secure-apply >/dev/null
	$COMPOSE exec -T outside /usr/local/bin/client internet-secure-baseline
	$COMPOSE exec -T finance /usr/local/bin/client observe >"$SECURE_OBSERVATION"

	step "the misconfigured value set, with the gate standing on the path"
	vulnerable_scenario vulnerable-gated >/dev/null
	$COMPOSE exec -T outside /usr/local/bin/client internet-secure-baseline

	step "the same value set, applied by a path no gate stands on"
	vulnerable_scenario vulnerable-ungated >"$VULNERABLE_TRANSCRIPT"

	step "what the public segment can now reach"
	$COMPOSE exec -T outside /usr/local/bin/client observe >"$IAC_OBSERVATION"
	# Captured before the one enumerated admin transition, so the comparison is
	# of the same request against the same application rather than of a fictional
	# fare cap somebody moved.
	$COMPOSE exec -T finance /usr/local/bin/client observe >"$VULNERABLE_OBSERVATION"
	$COMPOSE exec -T outside /usr/local/bin/client internet-vulnerable-impact

	step "the platform recorded the anonymous transition"
	$COMPOSE exec -T verifier /usr/local/bin/client vulnerable-ledger

	step "what this flaw is not: six controls, present, correct and irrelevant"
	$COMPOSE exec -T verifier /usr/local/bin/client encryption-enabled
	$COMPOSE exec -T verifier /usr/local/bin/client deployer-scope-is-minimal
	cat "$SECURE_OBSERVATION" "$VULNERABLE_OBSERVATION" |
		$COMPOSE exec -T pipeline /usr/local/bin/pipeline compare-application

	step "every legitimate corporate path is unaffected"
	$COMPOSE exec -T finance /usr/local/bin/client corp-legitimate-paths

	restore

	step "a control that runs honestly and reads the wrong artifact"
	vulnerable_scenario half-fix-source-scan >/dev/null
	$COMPOSE exec -T outside /usr/local/bin/client internet-vulnerable-reach
	restore

	step "a control that reads the right artifact and is not obeyed"
	vulnerable_scenario half-fix-report-only >/dev/null
	$COMPOSE exec -T outside /usr/local/bin/client internet-vulnerable-reach
	restore

	step "a denylist of known-bad literals, and the same desired state written two other ways"
	vulnerable_scenario half-fix-denylist >"$DENYLIST_TRANSCRIPT"
	$COMPOSE exec -T outside /usr/local/bin/client internet-vulnerable-reach

	step "the two spellings compute to identical reachability"
	cat "$VULNERABLE_TRANSCRIPT" "$DENYLIST_TRANSCRIPT" |
		$COMPOSE exec -T pipeline /usr/local/bin/pipeline compare-exposure
	restore

	step "a gate that stands on the review path, and a second path that does not go through it"
	vulnerable_scenario half-fix-review-path-only >/dev/null
	$COMPOSE exec -T outside /usr/local/bin/client internet-vulnerable-reach
	restore

	step "a compliant apply, and a change made directly at the control plane afterwards"
	vulnerable_scenario half-fix-drift >/dev/null
	$COMPOSE exec -T outside /usr/local/bin/client internet-drifted-export

	# Re-applying the configuration does not close this one: the exposure is a
	# resource no configuration describes. Somebody has to act on what the
	# drift check reported.
	step "the fix for drift: an operator removes what the check reported"
	$COMPOSE exec -T pipeline /usr/local/bin/pipeline remove-undeclared
	$COMPOSE exec -T pipeline /usr/local/bin/pipeline drift >/dev/null
	restore

	step "the same invariant, a different input format"
	vulnerable_scenario manifest-exposed >/dev/null
	$COMPOSE exec -T outside /usr/local/bin/client internet-secure-baseline
	vulnerable_scenario manifest-exposed-ungated >/dev/null
	$COMPOSE exec -T outside /usr/local/bin/client internet-vulnerable-reach
	$COMPOSE exec -T outside /usr/local/bin/client observe >"$MANIFEST_OBSERVATION"

	step "both surfaces expose the same thing to the public segment"
	cat "$IAC_OBSERVATION" "$MANIFEST_OBSERVATION" |
		$COMPOSE exec -T pipeline /usr/local/bin/pipeline compare-reachability
	restore

	step "the application build is identical in both variants"
	cat "$VULNERABLE_TRANSCRIPT" "$SECURE_TRANSCRIPT" |
		$COMPOSE exec -T pipeline /usr/local/bin/pipeline compare-builds

	down
	printf '\n=== planless: the vulnerable demonstration completed\n'
}

# restore applies the secure value set again and requires the public segment to
# be closed once more. The fix is shown after every shape, not only described.
restore() {
	step "the fix: applying the secure value set closes it again"
	# Each pipeline run starts from empty toolchain state, so an apply creates
	# and updates but never destroys. A permission the secure value set does not
	# declare has to be removed deliberately — which is exactly true of one that
	# no configuration ever described.
	$COMPOSE exec -T pipeline /usr/local/bin/pipeline remove-undeclared
	scenario secure-apply >"$SECURE_TRANSCRIPT"
	$COMPOSE exec -T outside /usr/local/bin/client internet-secure-baseline
}

# vulnerable_scenario runs one misconfigured scenario on the vulnerable surface
# and reconciles it against the verdict that scenario declared.
vulnerable_scenario() {
	name="$1"
	transcript="$($COMPOSE_ALL exec -T vulnerable-pipeline /usr/local/bin/pipeline "$name")"
	work="$(mktemp -d)"
	$COMPOSE exec -T outside /usr/local/bin/client observe >"$work/internet" &
	internet_probe=$!
	$COMPOSE exec -T finance /usr/local/bin/client observe >"$work/corp" &
	corp_probe=$!
	wait "$internet_probe"
	wait "$corp_probe"

	# The reconciliation asserts the verdict the scenario declared. A run that
	# lands an exposure must fail it; a run the gate refused must not.
	printf '%s\n' "$transcript" | cat - "$work/internet" "$work/corp" |
		$COMPOSE_ALL exec -T vulnerable-pipeline /usr/local/bin/pipeline reconcile >/dev/null
	rm -rf "$work"
	printf '%s\n' "$transcript"
}

refusals() {
	for name in \
		refuse-anonymous-export \
		refuse-unrestricted-admin \
		fail-closed-unparsable \
		fail-closed-unknown-type \
		fail-closed-unrecognized-field \
		fail-closed-engine-error \
		binding-unapproved-plan \
		binding-modified-plan \
		binding-stale-approval; do
		scenario "$name"
	done
}

containment_gate() {
	step "static containment assertions over the resolved compose configuration"
	$COMPOSE_ALL config --format json | $COMPOSE exec -T tests go run ./cmd/contain
}

up() {
	step "start the platform and the containers the run exercises"
	$COMPOSE up -d --wait controlplane fare-engine
	# The clients, the harness and the Go gate stay up for the whole run, so a
	# step costs an exec rather than a container. They are recreated whenever
	# the image changed, so a run never execs into stale code.
	$COMPOSE up -d outside finance ops verifier pipeline tests
}

down() {
	step "tear down"
	# Every profile, so nothing from the vulnerable surface is left behind.
	$COMPOSE_ALL down -v --remove-orphans
}

selfchecks() {
	step "runtime hardening and isolation assertions, from inside each container"
	# Each assertion is made by a container that actually serves the
	# demonstration, about itself.
	for service in controlplane fare-engine outside finance ops verifier pipeline; do
		$COMPOSE exec -T "$service" /usr/local/bin/client selfcheck
	done
	$COMPOSE exec -T tests go run ./cmd/client selfcheck
}

checks() {
	step "from the internet segment: only the deliberately public status page"
	$COMPOSE exec -T outside /usr/local/bin/client internet-secure-baseline

	step "from the corporate segment: the finance principal reads the refund export"
	$COMPOSE exec -T finance /usr/local/bin/client finance-corp-read

	step "from the operations range: the fare engine admin port answers"
	$COMPOSE exec -T ops /usr/local/bin/client ops-admin-read

	step "the applied platform state equals the checked-in fixture, byte for byte"
	$COMPOSE exec -T verifier /usr/local/bin/client state-matches-fixture

	step "what this flaw is not: encryption on, deployer minimal"
	$COMPOSE exec -T verifier /usr/local/bin/client encryption-enabled
	$COMPOSE exec -T verifier /usr/local/bin/client deployer-scope-is-minimal

	step "the drift check finds nothing against a compliant platform"
	$COMPOSE exec -T pipeline /usr/local/bin/pipeline drift >/dev/null

	step "the one enumerated admin transition, from the operations range"
	$COMPOSE exec -T ops /usr/local/bin/client ops-admin-change

	step "the platform recorded exactly one change"
	$COMPOSE exec -T verifier /usr/local/bin/client ledger-records-one-change
}

state() {
	$COMPOSE exec -T verifier /usr/local/bin/client state-matches-fixture
}

VULNERABLE_TRANSCRIPT="${TMPDIR:-/tmp}/planless-vulnerable-transcript.json"
SECURE_TRANSCRIPT="${TMPDIR:-/tmp}/planless-secure-transcript.json"
DENYLIST_TRANSCRIPT="${TMPDIR:-/tmp}/planless-denylist-transcript.json"
IAC_OBSERVATION="${TMPDIR:-/tmp}/planless-iac-observation.json"
MANIFEST_OBSERVATION="${TMPDIR:-/tmp}/planless-manifest-observation.json"
SECURE_OBSERVATION="${TMPDIR:-/tmp}/planless-secure-observation.json"
VULNERABLE_OBSERVATION="${TMPDIR:-/tmp}/planless-vulnerable-observation.json"

case "${1:-}" in
verify)
	build
	# The containers the run exercises come up first: from here on a step costs
	# an exec rather than a container.
	up
	go_gate
	containment_gate
	offline_init
	policy_gate
	selfchecks
	refusals
	apply
	checks
	manifest_surface
	legitimate
	down
	printf '\n=== planless: every check passed\n'
	;;
build) build ;;
up) build; up; apply ;;
down) down ;;
apply) apply ;;
policy) policy_gate ;;
vulnerable) vulnerable ;;
refusals) refusals ;;
paths) legitimate ;;
manifests) manifest_surface ;;
checks) checks ;;
state) state ;;
*) usage; exit 64 ;;
esac
