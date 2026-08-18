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
	$COMPOSE run --rm -T tests sh -c '
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
	$COMPOSE run --rm -T --entrypoint /usr/local/bin/gate pipeline-offline verify-fixtures
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
	transcript="$($COMPOSE run --rm -T pipeline "$1")"
	# Both segments report at once: neither observation depends on the other.
	work="$(mktemp -d)"
	$COMPOSE run --rm -T outside observe >"$work/internet" &
	internet_probe=$!
	$COMPOSE run --rm -T finance observe >"$work/corp" &
	corp_probe=$!
	wait "$internet_probe"
	wait "$corp_probe"
	printf '%s\n' "$transcript" | cat - "$work/internet" "$work/corp" |
		$COMPOSE run --rm -T pipeline reconcile >/dev/null
	rm -rf "$work"
	printf '%s\n' "$transcript"
}

apply() {
	scenario secure-apply
}

# The five legitimate paths. A deny-by-default policy is only worth having if
# the legitimate work still goes through.
legitimate() {
	step "a reviewed exposure change, against the allowlist that does not name it"
	scenario reviewed-exposure-unapproved
	$COMPOSE run --rm -T outside internet-secure-baseline

	step "an ordinary non-security change must alter nothing about reachability"
	before="$($COMPOSE run --rm -T outside observe)"
	scenario routine-change
	after="$($COMPOSE run --rm -T outside observe)"
	printf '%s\n%s\n' "$before" "$after" |
		$COMPOSE run --rm -T pipeline compare-observations

	step "the same exposure change, against a reviewed allowlist that names it"
	scenario reviewed-exposure
	$COMPOSE run --rm -T outside internet-reviewed-exposure
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

	step "the intended posture, applied through the gate"
	scenario secure-apply >/dev/null
	$COMPOSE run --rm -T outside internet-secure-baseline

	step "the misconfigured value set, with the gate standing on the path"
	vulnerable_scenario vulnerable-gated >/dev/null
	$COMPOSE run --rm -T outside internet-secure-baseline

	step "the same value set, applied by a path no gate stands on"
	vulnerable_scenario vulnerable-ungated >"$VULNERABLE_TRANSCRIPT"

	step "what the public segment can now reach"
	$COMPOSE run --rm -T outside internet-vulnerable-impact

	step "the platform recorded the anonymous transition"
	$COMPOSE run --rm -T verifier vulnerable-ledger

	step "every legitimate corporate path is unaffected"
	$COMPOSE run --rm -T finance corp-legitimate-paths

	step "the fix: applying the secure value set closes it again"
	scenario secure-apply >"$SECURE_TRANSCRIPT"
	$COMPOSE run --rm -T outside internet-secure-baseline

	step "the application build is identical in both variants"
	cat "$VULNERABLE_TRANSCRIPT" "$SECURE_TRANSCRIPT" |
		$COMPOSE run --rm -T pipeline compare-builds

	down
	printf '\n=== planless: the vulnerable demonstration completed\n'
}

# vulnerable_scenario runs one misconfigured scenario on the vulnerable surface
# and reconciles it against the verdict that scenario declared.
vulnerable_scenario() {
	name="$1"
	transcript="$($COMPOSE_ALL run --rm -T vulnerable-pipeline "$name")"
	work="$(mktemp -d)"
	$COMPOSE run --rm -T outside observe >"$work/internet" &
	internet_probe=$!
	$COMPOSE run --rm -T finance observe >"$work/corp" &
	corp_probe=$!
	wait "$internet_probe"
	wait "$corp_probe"

	# The reconciliation asserts the verdict the scenario declared. A run that
	# lands an exposure must fail it; a run the gate refused must not.
	printf '%s\n' "$transcript" | cat - "$work/internet" "$work/corp" |
		$COMPOSE_ALL run --rm -T vulnerable-pipeline reconcile >/dev/null
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
	$COMPOSE_ALL config --format json | $COMPOSE run --rm -T tests go run ./cmd/contain
}

up() {
	step "start the control plane and the fare engine"
	$COMPOSE up -d --wait controlplane fare-engine
}

down() {
	step "tear down"
	$COMPOSE down -v --remove-orphans
}

selfchecks() {
	step "runtime hardening and isolation assertions, from inside each container"
	$COMPOSE exec -T controlplane /usr/local/bin/client selfcheck
	$COMPOSE exec -T fare-engine /usr/local/bin/client selfcheck
	$COMPOSE run --rm -T outside selfcheck
	$COMPOSE run --rm -T finance selfcheck
	$COMPOSE run --rm -T ops selfcheck
	$COMPOSE run --rm -T verifier selfcheck
	$COMPOSE run --rm -T --entrypoint /usr/local/bin/client pipeline selfcheck
	$COMPOSE run --rm -T tests go run ./cmd/client selfcheck
}

checks() {
	step "from the internet segment: only the deliberately public status page"
	$COMPOSE run --rm -T outside internet-secure-baseline

	step "from the corporate segment: the finance principal reads the refund export"
	$COMPOSE run --rm -T finance finance-corp-read

	step "from the operations range: the fare engine admin port answers"
	$COMPOSE run --rm -T ops ops-admin-read

	step "the applied platform state equals the checked-in fixture, byte for byte"
	$COMPOSE run --rm -T verifier state-matches-fixture

	step "the one enumerated admin transition, from the operations range"
	$COMPOSE run --rm -T ops ops-admin-change

	step "the platform recorded exactly one change"
	$COMPOSE run --rm -T verifier ledger-records-one-change
}

state() {
	$COMPOSE run --rm -T verifier state-matches-fixture
}

VULNERABLE_TRANSCRIPT="${TMPDIR:-/tmp}/planless-vulnerable-transcript.json"
SECURE_TRANSCRIPT="${TMPDIR:-/tmp}/planless-secure-transcript.json"

case "${1:-}" in
verify)
	build
	go_gate
	containment_gate
	offline_init
	policy_gate
	up
	selfchecks
	refusals
	apply
	checks
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
checks) checks ;;
state) state ;;
*) usage; exit 64 ;;
esac
