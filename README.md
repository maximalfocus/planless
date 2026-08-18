# planless

An educational demonstration of **Infrastructure-as-Code misconfiguration**: infrastructure that is
*declared* insecure reaching a running platform through a pipeline whose policy gate was real, ran, and
reported nothing.

Everything here is fictional, local, and container-only. The project contacts no cloud provider,
cluster, account or real API, and it accepts no endpoint, credential, region, bucket name, address or
manifest from anyone.

> **Status:** two delivery slices are in. The fictional platform and its two-segment network are
> built, and a real infrastructure-as-code toolchain now plans and applies the checked-in
> configuration to it. There is no policy gate and no misconfigured variant in the repository yet.

## What this slice establishes

The whole demonstration turns on one sentence: *an anonymous client on a public network segment reads
data it should never have reached.* That sentence is only worth anything if "reached" is an
observation. So the first thing built is the thing that makes it observable:

- **`democloud`** — a fictional platform control plane holding buckets, objects, grants, network rules,
  workloads and a change ledger. Every read, connect and mutation is authorized *at request time*, from
  the caller's principal and originating segment, against the **effective** permissions those resources
  produce. Permissions are computed — grant resolution, rule unions, CIDR coverage — never matched as
  literal strings.
- **Two segments** — `corp` and `internet`, both hermetic, with the control plane's public edge as the
  only member of both.
- **An `outside` probe** on the `internet` segment that can reach nothing but that edge, and whose
  entire vocabulary is a fixed set of checked-in requests.

`democloud` is not an emulator of any real cloud provider, and no claim is made here about how any real
provider, IaC tool, policy engine or scanner behaves.

## The four artifacts

The demonstration will eventually turn on a gate that read the wrong thing. So the pipeline keeps four
artifacts apart from the very beginning, each with its own digest:

| Artifact | What it is |
|---|---|
| source configuration | the `.tf` files as written |
| resolved desired state | the machine-readable plan: every variable, value and module default already applied |
| artifact the policy evaluated | in this slice, **nothing evaluates anything**, and the transcript says so |
| applied state | what the platform actually holds afterwards |

Read `infra/` and you will not find out who may read the refund export, or from where. The grant's
principals and source ranges resolve from `infra/secure.tfvars`; the fare engine's ingress ranges and
bind addresses resolve from defaults inside `infra/modules/platform`. They exist only in the resolved
plan. A test asserts exactly that, in both directions: no security-relevant value appears in any
resource block, and every one of them appears in the resolved artifact.

The resolved-desired-state digest is deterministic: the same configuration and values always produce
the same artifact. The binary plan file's digest is not, because the toolchain's plan format carries
run-specific data — which is what makes it a good per-run identity for binding an approved artifact to
an applied one, and a bad thing to compare across runs. The transcript reports both, labelled.

## The toolchain

**OpenTofu**, pinned by checksum and fetched once at image build time, with a `democloud` provider
built from source in this repository and installed through a **local filesystem mirror**. Every other
installation method is excluded, so initialization needs no network at all — and that is proved by
running it in a container with `network_mode: none`, which has no network interface whatsoever.

The provider has no configurable attributes. There is no endpoint, host, region, account, project,
credential or token to set: it talks to one in-network service named by a compile-time constant. Its
resource surface is exactly five types, and it offers no data sources at all.

## The fixtures

Halloway Transit Authority is invented, as is every rider, refund, bucket, address and workload.

| Fixture | Intended posture |
|---|---|
| `fare-exports` bucket, holding `rider-refunds-2026-03.csv` | readable only by `finance-reporting`, only from the corporate segment |
| `status-page` bucket, holding `status.json` | **deliberately public** — proof that the fix is not "nothing may be public" |
| `fare-engine` workload, service port and admin port | admin port reachable only from the operations range `10.20.7.0/24` |
| `platform-deployer` principal | scoped to exactly these resources, identical in every variant |

Addresses use a private range (`10.20.0.0/16`) and a reserved documentation range
(`198.51.100.0/24`, TEST-NET-2). Nothing here can collide with, or be mistaken for, a real target.

## Running it

A clean checkout needs only Docker and a POSIX shell.

```sh
./scripts/demo.sh verify
```

That builds the images, runs the Go test, vet and formatting gate, asserts the containment rules over
the resolved Compose configuration, starts the platform, asserts hardening and isolation from inside
every container, runs the observation checks from each segment, and tears down. It takes a few minutes
and needs no network access at runtime.

Other commands: `./scripts/demo.sh up`, `checks`, `state`, `down`.

## What the checks prove

| Check | Segment | Observation |
|---|---|---|
| `internet-secure-baseline` | `internet` | the status page is readable; the refund export, the admin port and the service port are all refused |
| `finance-corp-read` | `corp` | the finance principal reads the export; an anonymous corporate caller does not; the admin port refuses a caller outside the operations range |
| `ops-admin-read` | `corp`, `10.20.7.0/24` | the admin port answers inside the operations range, and that range carries no grant on the export |
| `state-matches-fixture` | `corp` | the state a real apply produced, read through the control plane's own read-only API, digests identically to the checked-in fixture |
| `ops-admin-change` / `ledger-records-one-change` | `corp` | the one enumerated, documented, non-destructive admin transition is recorded as exactly one ledger row attributed to its caller and segment |

The configured-state digest deliberately excludes the change ledger. After the admin transition the
platform's configuration digest is **unchanged** while its ledger has moved — a world that has drifted
from the infrastructure that describes it. That distinction is load-bearing later.

Every claim about platform state is made through the control plane's read-only API or through a probe's
observed result, and compared by canonical digest. Nothing inspects a container's filesystem, database
or memory.

## Containment

- Both segments are internal: there is no route out of either, and no container has a default route.
- No port is published to the host, no container is privileged, none has a host mount, host namespace
  or container runtime socket.
- Every container runs as a non-root user with all capabilities dropped, `no-new-privileges`, and a
  read-only root filesystem except explicit tmpfs.
- These properties are asserted twice: statically over the resolved Compose configuration, and at
  runtime by each container about itself.

## Simulation boundaries

Where the demonstration models something rather than reproducing it, it says so:

- `democloud` is a fictional control plane. It is not any real cloud provider, and nothing here claims
  a real provider behaves this way.
- The consequence of a workload's declared **bind address** — which segments the platform's fabric will
  carry traffic from — is `democloud`'s own model of a platform network.
- Principal identity is asserted by the corporate network and is never honoured on the public edge. It
  is not an authentication protocol, and no credential exists anywhere in this project.

## Scope

Out of scope, deliberately and permanently: any real cloud provider, account, cluster, credential,
kubeconfig or endpoint; any cloud-asset discovery, bucket enumeration, permission brute-forcing or
scanner-evasion capability; and executing anything supplied to the demonstration as content.
