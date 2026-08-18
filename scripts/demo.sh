#!/bin/sh
# planless — the whole demonstration, through one container boundary.
#
# The host needs Docker and a POSIX shell and nothing else. Every assertion in
# this script is made by a container about itself or about what it can reach:
# the script only orders the steps and reports the first failure.
set -eu

cd "$(dirname "$0")/.."
COMPOSE="docker compose -f deploy/compose.yaml --profile checks"

usage() {
	cat <<'USAGE'
usage: scripts/demo.sh <command>

  verify     build, check containment, apply the configuration, run every check, tear down
  build      build the container images
  up         start the platform and apply the checked-in configuration
  apply      run the pipeline against a running platform
  down       stop everything and remove the segments
  state      print live platform state through the control plane's read-only API
  checks     run the observation checks against an already running platform
  policy     run the deployment gate over the checked-in plan artifacts
  refusals   run every refusal scenario against a running platform

The secure platform is the default. Nothing in this project accepts a cloud
endpoint, credential, region, account, bucket name, address or manifest.
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
	step "the deployment gate decides the checked-in plan artifacts"
	$COMPOSE run --rm -T --entrypoint /usr/local/bin/gate pipeline-offline evaluate \
		< testdata/plans/secure.json
	for artifact in testdata/plans/modified-*.json; do
		printf '\n--- %s must be refused\n' "$artifact"
		if $COMPOSE run --rm -T --entrypoint /usr/local/bin/gate pipeline-offline evaluate \
			< "$artifact"; then
			echo "the gate admitted $artifact" >&2
			exit 1
		fi
	done
}

offline_init() {
	step "provider installation and planning, with no network interface at all"
	$COMPOSE run --rm -T pipeline-offline offline-init
}

# One scenario, end to end: the harness runs it, each segment reports what it
# could reach, and the reconciliation compares the two. Every assertion is made
# inside a container; this function only orders the steps.
scenario() {
	step "scenario: $1"
	transcript="$($COMPOSE run --rm -T pipeline "$1")"
	internet="$($COMPOSE run --rm -T outside observe)"
	corp="$($COMPOSE run --rm -T finance observe)"
	printf '%s\n%s\n%s\n' "$transcript" "$internet" "$corp" |
		$COMPOSE run --rm -T pipeline reconcile >/dev/null
}

apply() {
	scenario secure-apply
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
	$COMPOSE config --format json | $COMPOSE run --rm -T tests go run ./cmd/contain
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
	down
	printf '\n=== planless: every check passed\n'
	;;
build) build ;;
up) build; up; apply ;;
down) down ;;
apply) apply ;;
policy) policy_gate ;;
refusals) refusals ;;
checks) checks ;;
state) state ;;
*) usage; exit 64 ;;
esac
