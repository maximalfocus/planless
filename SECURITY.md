# Security policy

## This repository contains an intentional misconfiguration

`planless` is an educational demonstration. It deliberately ships infrastructure value sets that expose
a fictional data export and a fictional administrative port, and it deliberately ships controls that run
honestly and fail to stop them. **That is the product, not a bug.**

Everything intentional is:

- behind **two separate opt-in actions**, and neither alone is enough — a non-default Compose profile
  brings up a surface that offers the misconfigured scenarios, and an explicit
  `ALLOW_VULNERABLE_DEMO=true` acknowledges what you are starting;
- labelled in every transcript, probe report and log line it produces;
- confined to a hermetic container network with no route out, mutating only a disposable fictional
  platform that is recreated from scratch on every run.

The default workflow — `./scripts/demo.sh verify` — offers no misconfigured scenario at all.

## What is worth reporting

An **unintended** security bug: something that lets this project affect anything outside its own
containers, or that makes it useful for attacking something real. Concretely:

- a way to reach a network outside the demonstration's own segments, or to resolve or contact any real
  host;
- a way to make any component accept an arbitrary target — a cloud endpoint, credential, region,
  account, bucket name, address, URL or manifest — where the design says only enumerated scenarios are
  accepted;
- a way to execute content supplied to the demonstration, anywhere, including inside a container;
- a container escape, a host filesystem write, or any use of a privileged capability, host namespace or
  container runtime socket;
- a real credential, token, personal datum or account identifier anywhere in the repository or its
  history;
- any capability that would help discover, enumerate or brute-force real cloud resources, or evade a
  real scanner. This project ships a **fixed, enumerated pair** of teaching bypasses and nothing that
  finds more of them;
- a way to start the misconfigured scenarios with fewer than both opt-in actions.

## What is not worth reporting

The demonstration working as designed: the refund export being readable by an anonymous client after you
explicitly opted in twice, the admin port answering, the scans finding nothing, the gate being ignored
under its advisory setting. Every one of those is the lesson.

## How to report

Please report privately, through GitHub's **Report a vulnerability** flow on this repository's Security
tab, rather than by opening a public issue. Include what you ran and what happened; a transcript is
ideal, and every run produces one.

There is no deployment to protect, no service to take down and no user data anywhere: everything here is
local, fictional, and disposable. A fix will be an ordinary pull request.

## What this project never does

It contacts no cloud provider, cluster, account or real API. It publishes no package, container image,
provider artifact or policy bundle. It operates no hosted endpoint. It is never run in production, and
there is nothing in it that would be useful there.
