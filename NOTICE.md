# Third-party notices

`planless` is licensed under the [MIT License](LICENSE). It vendors nothing, and it publishes no
package, container image, provider artifact or policy bundle.

The following third-party software is **fetched at image build time**, pinned by checksum or immutable
digest, and used inside the demonstration's containers. Each remains under its own licence; none is
redistributed by this repository.

| Software | Version | Licence | Used for |
|---|---|---|---|
| [OpenTofu](https://github.com/opentofu/opentofu) | 1.12.5 | MPL-2.0 | the real infrastructure-as-code toolchain: `validate`, `plan`, the plan artifact, `apply` |
| [Open Policy Agent](https://github.com/open-policy-agent/opa) | v1.19.1 | Apache-2.0 | the policy engine, and the YAML reader for rendered manifests |
| [Kustomize](https://github.com/kubernetes-sigs/kustomize) | v5.8.1 | Apache-2.0 | the real, offline overlay renderer for the manifest surface |
| [`golang:1.26-alpine`](https://hub.docker.com/_/golang) | pinned by digest | see image | the build and test image, and the only base image in the project |

One direct Go dependency, resolved at build time and verified against the committed `go.sum`:

| Module | Licence | Used for |
|---|---|---|
| [`github.com/hashicorp/terraform-plugin-framework`](https://github.com/hashicorp/terraform-plugin-framework) | MPL-2.0 | building a real provider for the toolchain |

It is a dependency of the provider module only. The platform, the applier, the normalizers, the harness,
the probe and the tests use the Go standard library alone.

OpenTofu was chosen over Terraform because MPL-2.0 sits cleanly beside a public MIT repository while the
machine-readable plan format this demonstration depends on is the same. That is a licensing observation,
not a claim of parity between the two tools.
