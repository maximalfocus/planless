#!/bin/sh
# Regenerate the checked-in plan artifacts the refusal scenarios are proved
# against.
#
# The base artifact comes from a real plan, produced offline, so the fixtures
# are the toolchain's own output rather than something hand-written. Each
# modified artifact then carries exactly one exposure or malformation.
set -eu

cd "$(dirname "$0")/.."
COMPOSE="docker compose -f deploy/compose.yaml --profile checks"
PLANS=testdata/plans

$COMPOSE build --quiet
$COMPOSE run --rm -T pipeline-offline emit offline-init >"$PLANS/secure.json"

# A separate grant resource makes the refund export anonymously readable. The
# bucket's own definition says nothing about it.
jq '
  .planned_values.root_module.child_modules[0].resources += [{
    "address": "module.platform.democloud_grant.export_anonymous",
    "mode": "managed",
    "type": "democloud_grant",
    "name": "export_anonymous",
    "provider_name": "democloud.example/planless/democloud",
    "schema_version": 0,
    "values": {
      "actions": ["read"],
      "id": "grant-fare-exports-anonymous-read",
      "principals": ["*"],
      "resource_kind": "bucket",
      "resource_name": "fare-exports",
      "source_ranges": ["0.0.0.0/0"]
    }
  }]' "$PLANS/secure.json" >"$PLANS/modified-anonymous-export-grant.json"

# The admin port bound to every address, permitted from a pair of half-ranges
# whose union is every address and which no literal rule matches.
jq '
  (.planned_values.root_module.child_modules[0].resources[]
    | select(.values.id=="rule-fare-engine-admin") | .values.source_ranges) = ["0.0.0.0/1","128.0.0.0/1"] |
  (.planned_values.root_module.child_modules[0].resources[]
    | select(.type=="democloud_workload") | .values.ports[1].bind) = "0.0.0.0"
  ' "$PLANS/secure.json" >"$PLANS/modified-unrestricted-admin.json"

jq '
  .planned_values.root_module.resources += [{
    "address": "democloud_firewall.edge",
    "mode": "managed",
    "type": "democloud_firewall",
    "name": "edge",
    "values": {"name": "edge", "allow": ["0.0.0.0/0"]}
  }]' "$PLANS/secure.json" >"$PLANS/modified-unknown-resource-type.json"

jq '
  (.planned_values.root_module.resources[] | select(.values.name=="fare-exports") | .values.public) = true
  ' "$PLANS/secure.json" >"$PLANS/modified-unrecognized-field.json"

jq '
  (.planned_values.root_module.child_modules[0].resources[]
    | select(.values.id=="rule-fare-engine-admin") | .values.source_ranges) = ["10.20.7.0/99"]
  ' "$PLANS/secure.json" >"$PLANS/modified-invalid-source-range.json"

jq '.planned_values.root_module.resources = [] | .planned_values.root_module.child_modules = []' \
  "$PLANS/secure.json" >"$PLANS/modified-empty.json"

jq 'del(.format_version)' "$PLANS/secure.json" >"$PLANS/modified-no-format-version.json"

printf '{"format_version": "1.2", "planned_values": {' >"$PLANS/modified-unparsable.json"

echo "regenerated $PLANS"
