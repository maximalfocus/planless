# Exposure review

Publication is one way. A pull-request ref outlives any history rewrite, so anything that has reached a
provider surface is permanent — which is why every surface is reviewed *before* the transition, and the
result is written down rather than remembered.

**Last reviewed: 2026-08-18**, against the default-branch commit prepared for publication.

## What is reviewed, and how

| Surface | How | Result |
|---|---|---|
| every tracked file | `internal/publication` — runs in the ordinary verification gate, in a container | clean |
| every commit message in the history | `scripts/exposure-review.sh` | clean |
| every blob ever committed, including on deleted branches | `scripts/exposure-review.sh` | clean |
| branch and tag names | `scripts/exposure-review.sh` | clean |
| no discovery or dialling capability | `scripts/exposure-review.sh`, with the two deliberate exceptions named in it | clean |
| issues, pull requests and their comments | read, and searched for every pattern below | clean |
| releases and tags | none exist | clean |
| workflow logs and artifacts | the workflow runs `./scripts/demo.sh`; its output is transcripts of fictional fixtures, and it uploads no artifact | clean |
| repository metadata | read: name, description, homepage, topics | see note |

> **Note on metadata.** The repository description read *"Private implementation repository for
> planless."* — accurate while private, wrong and misleading once public. It is updated as part of this
> preparation.

## What is looked for

- credentials and tokens: AWS access key ids, private keys, Slack tokens, GitHub personal access tokens;
- real cloud or cluster targets: provider hostnames, kubeconfig artifacts, credential environment
  variables;
- **any reference to a private companion repository.** A public artifact must never name one, and a
  commit message or branch name naming one could not be taken back;
- any capability that would help against something real: name resolution or socket opening outside the
  two places that need it, which are named with their reasons in the review script.

## The two deliberate exceptions

Both resolve names or open sockets on purpose, and both are named rather than excluded quietly:

- `internal/api` — the platform's own network fabric, carrying a permitted connect to a workload inside
  the demonstration's network;
- `internal/selfcheck` — proves that a reserved documentation address does not connect and a reserved
  name does not resolve, which requires it to try.

## What this repository never publishes

No package, container image, provider artifact or policy bundle, and no hosted endpoint. Only the source
is published, under [MIT](../LICENSE).

## Running it

```sh
./scripts/exposure-review.sh     # needs git; reviews the full history and refs
./scripts/demo.sh verify         # includes the working-tree review, in a container
```

The review runs in CI on every change, over a full-depth checkout.
