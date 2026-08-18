# planless — a walkthrough

Five minutes, one command, and a class of failure you will recognise afterwards.

Everything here is fictional and local. The demonstration contacts no cloud provider, cluster, account
or real API; it executes nothing supplied to it as content; and it mutates only a disposable fictional
platform inside its own container network.

---

## 1. The five minutes

```sh
ALLOW_VULNERABLE_DEMO=true ./scripts/demo.sh compare
```

You need Docker and a POSIX shell. Nothing else. It runs every scenario from fresh state and prints one
table.

> **The misconfigured scenarios need two separate opt-in actions**, and neither alone is enough: a
> non-default Compose profile brings up a surface that offers them, and an explicit
> `ALLOW_VULNERABLE_DEMO=true` acknowledges what you are starting. The default workflow —
> `./scripts/demo.sh verify` — offers no misconfigured scenario at all.

Read the table down the `gate decision` column, then across to `reachable from internet`:

```
scenario                    artifact evaluated         gate decision  enforcement              reachable from internet
--------------------------  -------------------------  -------------  -----------------------  ------------------------------
secure-apply                resolved state             admit          applied                  status-page
vulnerable-ungated          nothing                    none           applied                  fare-exports status-page admin
half-fix-source-scan        source text                0 findings     applied                  fare-exports status-page admin
half-fix-report-only        resolved state             deny           advisory, applied        fare-exports status-page admin
half-fix-denylist           resolved state (literals)  0 findings     applied                  fare-exports status-page admin
half-fix-review-path-only   resolved state             deny           refused, applied anyway  fare-exports status-page admin
half-fix-drift              resolved state             admit          applied                  fare-exports status-page
manifest-exposed-ungated    base manifests             0 findings     applied                  fare-exports status-page admin
```

`fare-exports` is a fictional quarterly refund export. `admin` is a fare engine's administrative port.
`status-page` is deliberately public and should be there.

Every row after the first has a control in it. Every one of those controls ran.

---

## 2. What actually happened

Nothing was broken and nothing was exploited. No request was malformed, no input was hostile, no code
was injected, and no control was bypassed.

The exposure is the faithful execution of what the configuration asked for. The refund export's
permission said *every principal, from every address*. The platform did exactly that.

Look at where that value came from:

```
where the exposure values came from
  grant/grant-fare-exports-finance-read.principals     variable-file  (var.export_readers)
  network_rule/rule-fare-engine-admin.source_ranges    module-default (var.admin_profiles)
  workload/fare-engine.ports.admin.bind                module-default (var.admin_profiles)
```

Open `infra/main.tf` and `infra/modules/platform/main.tf`. Every security-relevant value in a resource
block is a variable reference. The export's readers arrive from a variable file. The admin port's
addresses arrive from a **module default** — the variable file only names a profile, `shared-host`, and
the ranges that make the port reachable from everywhere are on a page nobody opens.

---

## 3. The four artifacts

This is the distinction the whole class rests on. A pipeline has four of them, and a gate can confuse
any one for another:

| Artifact | What it is | In the transcript |
|---|---|---|
| **source configuration** | the files as written | `source_configuration_digest` |
| **resolved desired state** | the plan: every variable, value and module default already applied | `resolved_desired_state_digest` |
| **the artifact the policy evaluated** | whatever the control actually read | `artifact_evaluated_by_policy_digest`, `artifact_evaluated_by` |
| **the state that was applied** | what the platform holds afterwards | `applied_state_digest` |

They are four separate fields with four separate digests, always, in every transcript. The entire
vulnerability class lives in the gaps between them.

Run one and read it:

```sh
./scripts/demo.sh up
./scripts/demo.sh run secure-apply
```

---

## 4. Five controls that sound sufficient

Each is honestly implemented, genuinely runs, and is defeated. Each is a separate scenario with its own
evidence line.

### 1 — No gate at all
`vulnerable-ungated`. The baseline: the configuration is applied exactly as written.

### 2 — Scan the source text
`half-fix-source-scan`. A policy reads the `.tf` resource definitions, completes, and reports **zero
findings**. It is entirely correct about what it read: the dangerous values are not in the resource
definitions, they arrive from a variable file and a module default, so they exist only in the resolved
plan — which the scan never opened.

The scan is not a straw man. Its policy is tested against a configuration that *does* spell the exposure
in a resource block, and it finds it. Whitespace is normalised first, so a value cannot escape by having
its equals sign lined up.

The transcript then shows what a policy reading the resolved artifact **would** have decided, so you can
see the gap rather than take it on trust.

### 3 — Report, do not enforce
`half-fix-report-only`. The gate reads the *right* artifact and produces **both** findings correctly.
Under an advisory setting the job exits zero, the apply proceeds, and the exposure lands. A finding
without authority is a log line.

### 4 — Guard the review path only, and drift
`half-fix-review-path-only` and `half-fix-drift`. One failure seen from two directions.

In the first, the gate blocks on the path a change is reviewed through, and the change reaches the
platform by a second, out-of-band apply. The operator is told `DEPLOY_REFUSED`. The platform has the
change. **No audit event describes what landed.**

In the second, a compliant configuration is applied *through* the gate, and the live resource is then
changed directly at the control plane. The repository is correct. The approved plan is correct. The
world is not, and nothing re-evaluates it.

A gate is worth exactly the paths it stands on.

### 5 — Denylist the known-bad literals
`half-fix-denylist`. Two rules any reviewer would write — flag a bucket marked public, flag an ingress
rule naming `0.0.0.0/0` — run against the resolved plan and report **zero findings**, while the same
effective exposure arrives two ordinary ways:

- the refund export's own permission is **untouched**, and a **separate permission resource** carries the
  exposure. A rule that inspects the bucket learns nothing, because permissions are separate resources;
- the addresses are written `0.0.0.0/1` + `128.0.0.0/1`. Their union is every address, and no rule
  matching the string `0.0.0.0/0` sees it.

Neither is clever evasion. Both are how people write these things. The run proves they are the same
desired state by computing the reachability of each spelling and requiring the two to be identical.

**These two bypasses are a fixed, enumerated teaching pair.** This project ships nothing that discovers
more of them.

---

## 5. The fix, in four parts

The secure pipeline applies four independent controls. Miss any one and the demonstration works again.

1. **Evaluate the resolved desired state.** The policy input is the machine-readable plan the real
   toolchain produced — never the source files. Every variable, value and module default is already
   applied inside it.
2. **Compute effective exposure.** For each resource, work out *which principals and which source
   addresses can actually reach it*, resolving grant resources, rule unions and CIDR coverage. Never
   match a field value; two spellings of one desired state must decide identically.
3. **Deny by default, against a short reviewed allowlist.** An unknown resource type, an unrecognised
   field, an unparsable artifact, a missing decision or an engine error is a **deny**, never a skip.
   There is no option, threshold or mode that turns any of them into a warning.
4. **Bind the approved artifact to the applied artifact.** The apply consumes the exact plan the gate
   approved, identified by digest. A plan that was not approved cannot be applied, so a second path to
   apply cannot exist.

And a fourth control beside the gate, not a duplicate of it:

5. **Drift detection.** Read live platform state, normalise it into the same contract, evaluate it with
   the same policy, and report anything reachable that nobody allowlisted — regardless of whether the
   repository is right. It reports and repairs nothing; re-applying the configuration does not close a
   resource no configuration describes.

The gate is not an obstacle. `./scripts/demo.sh verify` shows the finance principal still reading the
export, the admin port still answering inside the operations range, the status page still deliberately
public, an ordinary log-retention change passing untouched, and a **reviewed exposure change** refused
until somebody writes the allowlist entry — because that is the only way to widen exposure here.

---

## 6. The same invariant, a second format

`manifest-intended`, `manifest-exposed`, `manifest-exposed-ungated`.

A Kubernetes-**shaped** manifest set — a base plus overlays, rendered by a real, pinned, offline
renderer — is normalized into the **same** policy contract and decided by the **unmodified** policy body
and allowlist. The intended overlay leaves the platform state digest identical to the one the
infrastructure surface produced; the exposed one is refused identically; applied without a policy step,
it exposes exactly what the infrastructure surface exposed.

And the same lesson in a third spelling: a scan of the **base** manifests reports zero findings while the
**rendered** overlay contains both exposures. A variable file, a module default, an overlay — the shape
of the mistake does not depend on the format.

> **No Kubernetes distribution, API server, admission controller or kubelet is implemented or emulated
> anywhere in this project. There is no cluster of any kind. Nothing here describes how real Kubernetes
> behaves.** These are manifest-shaped inputs to this demonstration's own applier, and the semantics
> that decide an exposure come from this project's own annotations.

---

## 7. What this flaw is not

Six things you might reasonably suspect. Each is present, correct, and irrelevant — and each is
automated, so it fails if it stops being true.

1. **No vulnerable, outdated or unmaintained component.** No component version, patch level or advisory
   identifier is a variable anywhere. This is why `A06:2021` and `CWE-1104` are not claimed.
2. **No code execution and no hostile input.** Nothing in the configuration or the manifests executes.
   The attacker's entire contribution is an ordinary unauthenticated HTTP request the platform is
   configured to accept.
3. **The application is identical and correct.** The same build serves both variants — compared by the
   digest it reports of its own executable, and by its answer to the same request.
4. **Correctness tooling is green.** `validate`, plan, apply and the smoke checks all pass in the
   misconfigured variant. A green pipeline is not evidence for this class.
5. **Encryption at rest is enabled and irrelevant.** Every store is encrypted in both variants. The
   platform decrypts for whoever it authorizes, and the misconfiguration authorizes everyone.
6. **The deployer is least-privileged and it does not help.** It writes exactly the fixture resources,
   from the corporate segment only, identically in both variants. It was authorized to create precisely
   what it created.

---

## 8. Where this sits in the taxonomy

Rechecked against the authoritative pages on **2026-08-18**.

**[A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)**
is claimed on the category's own words. Its description names *"improperly configured permissions on
cloud services"*; its prevention guidance says *"Review cloud storage permissions (e.g., S3 bucket
permissions)"*; and its Scenario #4 is a cloud provider's default sharing permissions open to the
Internet. This demonstration is that scenario almost verbatim.

| Identifier | | Abstraction / mapping usage | Why |
|---|---|---|---|
| [CWE-732](https://cwe.mitre.org/data/definitions/732.html) Incorrect Permission Assignment for Critical Resource | claimed | Class · `ALLOWED-WITH-REVIEW` | the storage shape. Its own examples are a blob container opened to public access and a bucket policy granting every user. Its review note warns it is often misused where an authorization *check* is missing — nothing here fails to check anything; the permission was assigned, deliberately and successfully, to everyone |
| [CWE-1327](https://cwe.mitre.org/data/definitions/1327.html) Binding to an Unrestricted IP Address | claimed | Base · `ALLOWED` | the network shape, twice: an ingress rule whose permitted source set is every address, and a workload binding the unrestricted address |
| [CWE-1032](https://cwe.mitre.org/data/definitions/1032.html) OWASP Top Ten 2017 Category A6 | **not** claimed | **Category** · `PROHIBITED` | a Category, and MITRE states such an identifier must not be used to map to real-world vulnerabilities |
| [CWE-16](https://cwe.mitre.org/data/definitions/16.html) Configuration | **not** claimed | **Category** · `PROHIBITED` | likewise |
| [CWE-668](https://cwe.mitre.org/data/definitions/668.html) Exposure of Resource to Wrong Sphere | **not** claimed | Class · `DISCOURAGED` | named as the shared conceptual root of both shapes, and refused as a catch-all |
| [CWE-276](https://cwe.mitre.org/data/definitions/276.html) Incorrect Default Permissions | **not** claimed | Base · `ALLOWED` | defined over installed file permissions, not provisioned platform resources. Stretching it would trade precision for a familiar number |
| [A06:2021](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/) Vulnerable and Outdated Components | **not** claimed | — | nothing here is vulnerable, outdated or unmaintained, and no version, patch level or CVE is a variable in any test |
| [API8:2023](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/) Security Misconfiguration | **not** claimed | — | the affected surface is a platform's resource configuration, not an API's security configuration |

### The uncomfortable part

**No CWE in A05:2021's published mapping is the precise weakness here.** The category's Factors table
maps **20** CWEs, and the list is dominated by XXE, cookie, .NET, error-page and cross-domain entries:
CWE-2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004, 1032 and 1174.
Neither `CWE-732` nor `CWE-1327` is among them, and the only two general-purpose members — `CWE-16` and
`CWE-1032` — are both mapping-**prohibited** Categories.

That is a gap in the mapping, reported honestly, not a defect in this demonstration. It is also why the
claimed CWEs are stated as the precise weaknesses *and* as non-members of the claimed category, rather
than implied to be both.

---

## 9. Boundaries

- **`democloud` is a fictional platform.** It is not an emulator of, and makes no claim about, any real
  cloud provider. It exists only inside this demonstration's container network.
- **Nothing supplied as content is executed.** No provisioner, exec, shell, template-shell or
  plugin-fetch path exists; the applier calls a fixed set of typed platform operations.
- **No real provider, cluster or account is contacted**, and no credential, kubeconfig or endpoint
  exists anywhere in the system or its dependency tree.
- **No finding is made about any real cloud service, IaC tool, Kubernetes distribution, policy engine or
  scanner.** Where a real product's documented behaviour is cited it is cited, never simulated as
  authoritative. The lesson is a pipeline invariant, and it holds across clouds, tools and engines.
- **Nothing accepts an arbitrary target.** No cloud endpoint, credential, region, account, bucket name,
  address, URL or manifest can be supplied anywhere. Scenario names are the only input, and the list is
  closed.
