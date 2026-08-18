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

  verify     build, check containment, start the platform, run every check, tear down
  build      build the container images
  up         start the control plane and the fare engine
  down       stop everything and remove the segments
  state      print live platform state through the control plane's read-only API
  checks     run the observation checks against an already running platform

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
	'
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
	$COMPOSE run --rm -T tests go run ./cmd/client selfcheck
}

checks() {
	step "from the internet segment: only the deliberately public status page"
	$COMPOSE run --rm -T outside internet-secure-baseline

	step "from the corporate segment: the finance principal reads the refund export"
	$COMPOSE run --rm -T finance finance-corp-read

	step "from the operations range: the fare engine admin port answers"
	$COMPOSE run --rm -T ops ops-admin-read

	step "live platform state equals the checked-in fixture"
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
	up
	selfchecks
	checks
	down
	printf '\n=== planless: every check passed\n'
	;;
build) build ;;
up) build; up ;;
down) down ;;
checks) checks ;;
state) state ;;
*) usage; exit 64 ;;
esac
