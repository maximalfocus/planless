# planless

An educational demonstration of **Infrastructure-as-Code misconfiguration**: infrastructure that is
*declared* insecure reaching a running platform through a pipeline whose policy gate was real, ran, and
reported nothing.

Everything here is fictional, local, and container-only. The project contacts no cloud provider,
cluster, account or real API, and it accepts no endpoint, credential, region, bucket name, address or
manifest from anyone.

> **Status:** the demonstration is complete and can be read as one table. The secure pipeline is the
> default; everything misconfigured is behind two separate opt-in actions. Still to come: the
> educational walkthrough and publication.

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

## The gate

One policy input contract — a normalized resource graph carrying identity, grants, network rules, bind
addresses and **provenance** — and one policy body written in the engine's own language. The policy
never reads a plan, a manifest, or a source file directly, so a second manifest format can arrive later
without the policy changing.

The policy answers one question: *which principals and which source addresses can actually reach each
resource, and is that exposure one somebody reviewed and wrote down?* It computes the answer. It never
matches a field value or a literal string, because the same reachability can be spelled more than one
way:

| Spelled | Computed |
|---|---|
| `source_ranges = ["0.0.0.0/1", "128.0.0.0/1"]` | `0.0.0.0/0` — every address |
| a separate `democloud_grant` resource naming `*` | the bucket is anonymously readable, though its own definition says nothing |
| an unrestricted ingress rule on a listener bound to a private address | reachable from that segment only — both halves decide |
| an unrestricted bind with no ingress rule | reachable by nobody |

Exposure is admitted only when it is covered by an entry in `policy/allowlists/default.json`, and each
admission names the entry that permitted it. Narrower than the entry is admitted; wider is not.

**It denies by default, and every unfinished path is a denial:** an unfamiliar contract version, an
empty artifact, an unknown resource type, an unrecognized field, an unparsable source range or bind
address, an exposure that cannot be computed, a missing or empty allowlist, a policy engine that fails,
an empty policy bundle, a decision that is missing or malformed. There is deliberately no option,
severity threshold, or advisory mode that turns any of them into a warning.

Refusal is proved against **checked-in modified plan artifacts** under `testdata/plans/`. No vulnerable
configuration exists in the repository.

## The gate's authority

A decision nobody has to obey is a log line. So the gate's approval names the exact plan artifact by
digest, and the apply step re-reads that artifact, recomputes its digest, and refuses on any mismatch
**before contacting the control plane at all**. Three refusals are rehearsed as scenarios:

| Scenario | What it rehearses |
|---|---|
| `binding-unapproved-plan` | an apply with no approval at all |
| `binding-modified-plan` | an artifact changed after the gate approved it — one appended byte is enough |
| `binding-stale-approval` | an approval issued for a different run |

Every refusal returns the identical generic `DEPLOY_REFUSED` result. An operator learns that the
deployment was refused and nothing about whether a resource, field, allowlist entry or principal
exists. Exactly one structured audit event is emitted per refusal, carrying a deterministic correlation
id, the scenario, a stable failure class, the rule and the stage — and nothing else. The detail lives
in the transcript, which is material for a reviewer, not a response to a caller.

Every refusal scenario additionally asserts that the platform state digest before and after the run is
identical. Nothing refused ever changes anything.

## The harness and the transcript

`./scripts/demo.sh verify` runs each scenario through the harness, then asks each segment what it could
actually reach, then reconciles the two. The reconciliation never reads the gate's verdict: a policy
decision is not evidence of exposure state, so the question "is anything reachable from the public
segment that nobody reviewed?" is answered from observations alone.

Each scenario declares its expected outcome, and the harness fails if the outcome differs — so a
scenario that starts passing for the wrong reason fails.

```
scenario secure-apply (secure-apply-...)

artifacts
  source configuration               sha256:…
  resolved desired state             sha256:…
  plan artifact (apply input)        sha256:…
  artifact the policy evaluated      sha256:…
  evaluated by                       the deny-by-default policy, over the resolved desired state
  applied state                      sha256:…

computed effective exposure
  bucket/status-page                 principals=["*"] sources=["0.0.0.0/0"]  [allow-status-page-public]
  …

enforcement / audit / observations / reconciliation
```

The transcript exists in two deterministic forms: JSON on standard output, the human-readable form on
standard error.

## The whole thing in one table

```sh
ALLOW_VULNERABLE_DEMO=true ./scripts/demo.sh compare
```

Every scenario, from fresh state, in about 80 seconds. Read down the decisions, then across to what a
client on the public segment could actually reach.

```
scenario                        artifact evaluated         gate decision  enforcement              applied exposure    reachable from internet         platform state  reconciliation
------------------------------  -------------------------  -------------  -----------------------  ------------------  ------------------------------  --------------  --------------
secure-apply                    resolved state             admit          applied                  reviewed only       status-page                     changed         PASS
refuse-anonymous-export         resolved state             deny           refused                  —                   status-page                     unchanged       PASS
fail-closed-unparsable          resolved state             deny           refused                  —                   status-page                     unchanged       PASS
binding-modified-plan           resolved state             admit          refused                  —                   status-page                     unchanged       PASS
reviewed-exposure               resolved state             admit          applied                  reviewed only       status-assets status-page       changed         PASS
manifest-intended               resolved state             admit          applied                  reviewed only       status-page                     unchanged       PASS
vulnerable-ungated              nothing                    none           applied                  fare-exports admin  fare-exports status-page admin  changed         FAIL
half-fix-source-scan            source text                0 findings     applied                  fare-exports admin  fare-exports status-page admin  changed         FAIL
half-fix-report-only            resolved state             deny           advisory, applied        fare-exports admin  fare-exports status-page admin  changed         FAIL
half-fix-denylist               resolved state (literals)  0 findings     applied                  fare-exports admin  fare-exports status-page admin  changed         FAIL
half-fix-review-path-only       resolved state             deny           refused, applied anyway  fare-exports admin  fare-exports status-page admin  changed         FAIL
manifest-exposed-ungated        base manifests             0 findings     applied                  fare-exports admin  fare-exports status-page admin  changed         FAIL
half-fix-drift                  resolved state             admit          applied                  reviewed only       fare-exports status-page        changed         FAIL

reachability is what a client on the internet segment observed, never a policy verdict.
```

Every `FAIL` row is a control that ran. The last one is the sharpest: the gate **admitted**, the applied
state was compliant, the exposure is real anyway — because it arrived after the apply, and nothing
re-evaluates the world.

## Exploring it by hand

The secure pipeline and the control plane are the default services.

```sh
./scripts/demo.sh up                       # start the platform and apply the intended posture
./scripts/demo.sh run reviewed-exposure    # run any named secure scenario and read its transcript
./scripts/demo.sh state                    # compare live platform state against the fixture
./scripts/demo.sh down
```

No command anywhere accepts a cloud endpoint, credential, region, account, bucket name, address or
manifest. Scenario names are the only input, and the list is closed.

## The demonstration

```sh
ALLOW_VULNERABLE_DEMO=true ./scripts/demo.sh vulnerable
```

Against a platform in its intended posture, one value set is proposed twice. The gate refuses it. Then
the same value set is applied by a pipeline path the gate does not stand on, and:

- an anonymous client on the simulated public segment retrieves `rider-refunds-2026-03.csv`, byte for
  byte;
- it reaches the fare engine's admin port and performs one enumerated, documented, non-destructive
  transition, recorded in the platform's change ledger as **an anonymous caller from `internet`**;
- reconciliation fails honestly, naming the resource, the computed effective exposure and where the
  value came from;
- every legitimate corporate path is unaffected, and the application build is byte-identical.

Nothing was broken and nothing was exploited. `validate` passed, the plan was clean, the apply reported
success. The configuration said the world may read this, and the platform did exactly as it was asked.

Read the value set in `infra/vulnerable.tfvars`. It says `"*"` and `"0.0.0.0/0"` for the export — and
for the admin surface it says only `shared-host`, a profile name. The addresses that make the admin
port reachable from every source are in a **module default**, on a page nobody opens. The transcript
attributes each value to where it came from:

```
where the exposure values came from
  grant/grant-fare-exports-finance-read.principals    variable-file (var.export_readers)
  network_rule/rule-fare-engine-admin.source_ranges   module-default (var.admin_profiles)
  workload/fare-engine.ports.admin.bind               module-default (var.admin_profiles)
```

### Five controls that sound sufficient

Each is honestly implemented, genuinely runs, and is defeated. Each is a separate scenario with its own
evidence line, and each ends in the same reachability from the public segment.

| Shape | What it does | Why it fails |
|---|---|---|
| **no gate at all** | plans and applies with no policy step | baseline: the configuration is applied exactly as written |
| **scan the source text** | reads the `.tf` resource definitions, completes, reports **zero findings** | the values are not in the resource definitions. They arrive from a variable file and a module default, so they exist only in the resolved plan — which the scan never opened |
| **report, do not enforce** | reads the *resolved* plan, produces **both** findings correctly, exits zero | a finding without authority is a log line; the apply proceeds unchanged |
| **guard the review path only** | the enforcing gate blocks, and a second path applies the change anyway | a gate is worth exactly the paths it stands on. The operator is told `DEPLOY_REFUSED`; the platform has the change; no audit event describes what landed |
| **denylist the known-bad literals** | two rules over the *resolved* plan — flag a bucket marked public, flag an ingress rule naming `0.0.0.0/0` — report **zero findings** | the same desired state has other ordinary spellings, and a rule matches only the one it was shown |

The second is worth dwelling on, because the scan is not a straw man. Its policy is tested against a
configuration that *does* spell the exposure in a resource block, and it finds it. Against this
project's configuration it finds nothing, and it is right. The transcript renders the artifact it read
and the artifact that was applied as separate digested fields, says what it did not read, and then
shows what a policy reading the resolved artifact would have decided:

```
source configuration scan
  files read      4
  findings        0
  correct about   the artifact it read: the resource definitions in the configuration
  did not read    the resolved desired state, which is the artifact that gets applied

a policy reading the resolved desired state would have decided deny
  exposure_not_allowlisted  bucket/fare-exports:        principals=["*"] sources=["0.0.0.0/0"]
  exposure_not_allowlisted  workload/fare-engine:admin: sources=["0.0.0.0/0"]
```

### A denylist is not a policy

The fifth shape is the pivot to the fix, so it is worth being precise about. Both rules work — each is
tested firing against a configuration that spells the exposure the obvious way. Against the bypassed
configuration they find nothing, and they are right about what they matched:

```
denylist of known-bad literals
  rules        deny-public-bucket, deny-unrestricted-ingress
  artifact     the resolved desired state
  method       matching literal values
  findings     0
  limitation   a rule matches only the spelling it was shown; the same desired state has others

a policy reading the resolved desired state would have decided deny
  exposure_not_allowlisted  bucket/fare-exports:        principals=["*", "finance-reporting"] sources=["0.0.0.0/0"]
  exposure_not_allowlisted  workload/fare-engine:admin: sources=["0.0.0.0/0"]
```

Two ordinary spellings, neither of them clever:

- the refund export's own permission is **untouched** — finance only, from the corporate segment — and
  a **separate permission resource** carries the exposure. A rule that inspects the bucket learns
  nothing, because on this platform permissions are separate resources;
- the addresses are written as `0.0.0.0/1` + `128.0.0.0/1`. Their union is every address, and no rule
  matching the string `0.0.0.0/0` sees it.

And the claim that these are *the same desired state* is compared rather than argued: the run computes
the reachability of the literal spelling and of the bypassed one and requires them to be identical.

```
{"document":"planless.comparison","identical_reachability":true}
```

The two bypasses are a fixed, enumerated teaching pair. This project ships nothing that discovers more
of them.

### Drift, and the fourth control

The out-of-band apply has a twin. Apply a **compliant** configuration through the gate, then change one
live resource directly at the control plane. The repository is correct. The approved plan is correct.
The world is not, and nothing re-evaluates it.

That is why drift detection is a necessary fourth control rather than a duplicate of the gate. The
drift check reads live platform state through the control plane's read-only API, normalizes it into the
**same** contract, and evaluates it with the **same** policy and allowlist:

```
drift check
  read from                      the control plane's read-only state API
  platform state                 sha256:fe20e7d5…
  reviewed allowlist             default.json
  remediated anything            false

drift detected
  bucket/fare-exports            principals=["*", "finance-reporting"] sources=["0.0.0.0/0"]
                                 rules=["grant-fare-exports-console-read", "grant-fare-exports-finance-read"]

the repository may be entirely correct. this is what is actually there.
```

It reports and repairs nothing — and re-applying the configuration does not close this one, because the
exposure is a resource no configuration describes. Somebody has to act on the report. The demonstration
does exactly that, as a separate, clearly labelled operator step.

The advisory setting exists only on the misconfigured scenarios. There is no option, environment
variable or severity threshold that turns the enforcing gate into a reporting one, and a test fails if
one ever appears.

### Two opt-ins, and neither alone is enough

The vulnerable configurations and the ungated path are absent from the default workflow. Starting them
needs a non-default Compose profile **and** an explicit `ALLOW_VULNERABLE_DEMO=true` acknowledgement:
the default pipeline offers no misconfigured scenario at all, whatever is acknowledged, and the
profile-gated one refuses without the acknowledgement. Everything the vulnerable path produces —
transcript, probe report, log line — is labelled as intentionally vulnerable local educational
material.

## One policy contract, two formats

The invariant is not about a format, so there is a second one: a Kubernetes-**shaped** manifest set, a
base plus overlays, rendered by a real, pinned, offline renderer.

### What this is not

**No Kubernetes distribution, API server, admission controller or kubelet is implemented or emulated
anywhere in this project. There is no cluster of any kind. Nothing here describes how real Kubernetes
behaves, and no claim about it is made or implied.** These are manifest-shaped inputs to this
demonstration's own applier. The semantics that decide an exposure come from this project's own
`democloud.example/…` annotations, so no decision rests on an assertion about what a real cluster would
do with a field.

### What it demonstrates

The rendered set is normalized into the **same** policy contract and decided by the **unmodified**
policy body and allowlist. Nothing about the policy changes for the second format; a test compares the
two contracts field by field in both directions, and would fail if they ever diverged.

| Scenario | Result |
|---|---|
| `manifest-intended` | admitted — and the platform state digest afterwards is **identical** to the one the infrastructure surface produced |
| `manifest-exposed` | refused by the same policy, platform state unchanged |
| `manifest-exposed-ungated` | applied with no policy step, and the public segment can reach exactly what the infrastructure surface exposed |

That last equality is compared rather than asserted:

```
{"document":"planless.comparison","identical_reachability_from_the_public_segment":true}
```

And the surface carries its own version of the resolved-artifact lesson: a scan of the **base**
manifests reports zero findings, while the **rendered** overlay contains both exposures. The base holds
placeholders; the values arrive when the overlay is rendered. A variable file, a module default, an
overlay — the shape of the mistake is the same in every format.

The rendered YAML is parsed by the policy engine's own reader rather than by something written here. A
demonstration about a control that misread its artifact should not hand-roll a parser for the artifact
it is about to make claims about.

## The gate is not an obstacle

A deny-by-default policy is only worth having if the legitimate work still goes through. Five paths
prove it:

| Path | What it shows |
|---|---|
| the finance principal reads the refund export from `corp` | the intended access is untouched; an anonymous corporate caller still is not |
| the admin port answers inside `10.20.7.0/24` and refuses outside it | the operations range works, and only it |
| the probe client reads the status page in every secure scenario | the fix is **not** "nothing may be public" |
| `reviewed-exposure-unapproved` → refused; `reviewed-exposure` → admitted | publishing a second status asset is refused by the current allowlist, and admitted only under a scenario whose own checked-in allowlist names it |
| `routine-change` | an ordinary change — keep access logs for longer — is admitted, applied, and alters nothing about who can reach what |

The fourth is the one worth reading twice. **No runtime flag, environment variable or severity setting
can widen exposure.** The only way is to write the entry down in an allowlist and have somebody review
it — and the two allowlists differ in exactly that one entry, which a test asserts.

The fifth is proved by observation rather than by argument: the probe client reports what it can reach
before the change and after it, and the two reports must be **byte-identical**.

## The fixtures

Halloway Transit Authority is invented, as is every rider, refund, bucket, address and workload.

| Fixture | Intended posture |
|---|---|
| `fare-exports` bucket, holding `rider-refunds-2026-03.csv` | readable only by `finance-reporting`, only from the corporate segment |
| `status-page` bucket, holding `status.json` | **deliberately public** — proof that the fix is not "nothing may be public" |
| `status-assets` bucket, holding `assets.json` | unpublished; publishing it is the reviewed exposure change |
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

## What this is, in the taxonomy

The class is **Infrastructure-as-Code misconfiguration**, and the claim is deliberately narrow. It is
checked in as data, and a test fails if it drifts.

| Identifier | | Why |
|---|---|---|
| **A05:2021** Security Misconfiguration | claimed | on the category's own description, which names improperly configured permissions on cloud services and directs reviewers to review cloud storage permissions |
| **CWE-732** Incorrect Permission Assignment for Critical Resource | claimed | the storage shape. Its `ALLOWED-WITH-REVIEW` note warns it is often misused where an authorization *check* is missing — nothing here fails to check anything; the permission was assigned, deliberately and successfully, to everyone |
| **CWE-1327** Binding to an Unrestricted IP Address | claimed | the network shape, twice: an ingress rule whose permitted source set is every address, and a workload that binds the unrestricted address |
| **CWE-1032** OWASP Top Ten 2017 Category A6 | **not** claimed | a CWE *Category* whose mapping usage is **Prohibited** — such an identifier must not be used to map to real-world vulnerabilities |
| **CWE-16** Configuration | **not** claimed | also a Category with mapping usage Prohibited |
| **CWE-668** Exposure of Resource to Wrong Sphere | **not** claimed | named as the shared root of both shapes, and refused: its mapping usage is Discouraged as a catch-all |
| **CWE-276** Incorrect Default Permissions | **not** claimed | defined over installed file permissions, not provisioned platform resources |
| **A06:2021** Vulnerable and Outdated Components | **not** claimed | nothing here is vulnerable, outdated or unmaintained, and no version, patch level or CVE is a variable in any test |
| **API8:2023** Security Misconfiguration | **not** claimed | the affected surface is a platform's resource configuration, not an API's security configuration |

The uncomfortable part, stated rather than hidden: **no CWE in A05:2021's published mapping is the
precise weakness here.** That list is dominated by XXE, cookie, .NET, error-page and cross-domain
entries, and its only two general-purpose members — `CWE-16` and `CWE-1032` — are both
mapping-prohibited Categories. That is a gap in the mapping, reported honestly, not a defect in the
demonstration.

## What this flaw is not

Six things a reader might reasonably expect to be the explanation. Each is present, correct, and
irrelevant — and each is automated, so it fails if it stops being true.

| Control | Evidence |
|---|---|
| no vulnerable, outdated or unmaintained component | no component version, patch level or CVE is a variable anywhere |
| no code execution, no hostile input | nothing in the configuration or the manifests executes; the applier calls a fixed set of typed operations |
| the application is identical and correct | the same build serves both variants, compared by the digest it reports of its own executable |
| correctness tooling is green | `validate`, plan, apply and the smoke checks all pass in the misconfigured variant |
| encryption at rest is enabled and irrelevant | every store is encrypted in both variants, and the anonymous client reads the export anyway |
| the deployer is least-privileged and it does not help | its permissions are identical and minimal in both variants |

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
