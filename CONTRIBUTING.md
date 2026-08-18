# Contributing

Thanks for reading it closely enough to want to change something.

## What this project is

An educational demonstration of infrastructure-as-code misconfiguration, run entirely locally in
containers against a fictional platform. Start with [the walkthrough](docs/WALKTHROUGH.md).

## Verifying a change

A clean checkout needs only Docker and a POSIX shell.

```sh
./scripts/demo.sh verify                                   # the whole secure gate
ALLOW_VULNERABLE_DEMO=true ./scripts/demo.sh vulnerable     # the demonstration itself
ALLOW_VULNERABLE_DEMO=true ./scripts/demo.sh compare        # every scenario, one table
```

`verify` runs the Go tests, `go vet`, formatting, the policy tests, static containment assertions over
the resolved Compose configuration, an offline initialization proof in a container with no network
interface, runtime hardening self-checks inside every container, and every secure scenario with its
observations and reconciliation. It is the same thing CI runs.

Everything runs through the same container boundary locally and in CI. No verification step depends on a
host tool, wall-clock timing, external DNS or network availability.

## What a change has to keep true

These are asserted by tests, so you will find out quickly — but knowing why helps:

- **Every unfinished path denies.** A policy that cannot reach a conclusion refuses. There is no option,
  threshold or mode that turns a denial into a warning, and adding one to the enforcing gate is not a
  feature.
- **Nothing accepts an arbitrary target.** Scenario names are the only input anywhere. No cloud
  endpoint, credential, region, account, bucket name, address, URL or manifest is accepted by anything.
- **Nothing supplied as content is executed.** Anywhere. Including inside a container.
- **Reachability is observed, never asserted.** A policy decision is not evidence of exposure state. If
  a claim is about what can reach something, it has to come from a client that tried.
- **The misconfigured scenarios need both opt-in actions**, and everything they produce is labelled.
- **No claim is made about any real cloud provider, IaC tool, Kubernetes distribution, policy engine or
  scanner**, and no real target is ever contacted.
- **The demonstration ships no discovery capability.** The two denylist bypasses are a fixed, enumerated
  teaching pair.
- **A defeated control must be honestly implemented.** If you change one, keep the test that proves it
  fires against a configuration that does spell the exposure. A control that is quietly broken proves
  nothing.

## Style

Match the surrounding code. Comments explain *why* something is the way it is — especially where the
obvious implementation would have been subtly dishonest. There are several of those, and they are worth
reading before changing the code near them.

## Reporting a security problem

See [SECURITY.md](SECURITY.md). The intentional misconfiguration is the product; an unintended way for
this project to affect anything real is a bug, and should be reported privately.
