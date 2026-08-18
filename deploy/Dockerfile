# syntax=docker/dockerfile:1

# One pinned base image, by immutable digest. It is the only third-party image
# in the project.
FROM golang:1.26-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS base

# Third-party tool binaries are fetched once, here, and verified against
# checksums pinned in this file. Nothing is fetched at run time: the
# demonstration's networks have no route out.
FROM base AS toolchain
ARG TARGETARCH
ARG TOFU_VERSION=1.12.5
ARG TOFU_SHA256_AMD64=dade9650e6b74fc7a8b986bd8717497d32f9e09cf82e479afef4977fa3085536
ARG TOFU_SHA256_ARM64=528f4eea63452bbddb30fa4f1780b57fac8d7676f9dda0f772e847bb62c1260a
ARG OPA_VERSION=v1.19.1
ARG OPA_SHA256_AMD64=c9f985ce0d345f5484006ade2c695ed9e3f308e4441139e46695c5c182ac0839
ARG OPA_SHA256_ARM64=19dcb5186fd394c32023918c53eaacda55f835abb05e13e0f9a766dd1429494f
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) tofu_sum="${TOFU_SHA256_AMD64}"; opa_sum="${OPA_SHA256_AMD64}" ;; \
      arm64) tofu_sum="${TOFU_SHA256_ARM64}"; opa_sum="${OPA_SHA256_ARM64}" ;; \
      *) echo "unsupported architecture ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    wget -q -O /tmp/tofu.zip \
      "https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}/tofu_${TOFU_VERSION}_linux_${TARGETARCH}.zip"; \
    echo "${tofu_sum}  /tmp/tofu.zip" | sha256sum -c -; \
    unzip -o -q /tmp/tofu.zip tofu -d /out; \
    wget -q -O /out/opa \
      "https://github.com/open-policy-agent/opa/releases/download/${OPA_VERSION}/opa_linux_${TARGETARCH}_static"; \
    echo "${opa_sum}  /out/opa" | sha256sum -c -; \
    chmod +x /out/opa; \
    /out/tofu version; \
    /out/opa version

# The builder compiles every binary and runs the whole Go and policy gate. It
# carries the toolchain binaries so the tests can exercise the real policy
# engine rather than a stand-in for it.
FROM base AS builder
COPY --from=toolchain /out/tofu /usr/local/bin/tofu
COPY --from=toolchain /out/opa /usr/local/bin/opa
WORKDIR /src
COPY . .
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-trimpath
RUN go build -o /out/controlplane ./cmd/controlplane \
 && go build -o /out/fare-engine ./cmd/fare-engine \
 && go build -o /out/client ./cmd/client \
 && go build -o /out/contain ./cmd/contain \
 && go build -o /out/pipeline ./cmd/pipeline \
 && go build -o /out/gate ./cmd/gate \
 && (cd provider && go mod download && go build ./...)

# The provider is a separate module so the platform itself stays on the standard
# library alone. Its one direct dependency is the plugin framework a real
# provider needs, verified against the committed checksums.
FROM builder AS provider-builder
ARG PROVIDER_VERSION=0.1.0
WORKDIR /src/provider
RUN go build -o "/out/terraform-provider-democloud_v${PROVIDER_VERSION}" .

# Runtime images carry static binaries and nothing else: no shell, no package
# manager, no certificate bundle, no cloud SDK, no credential.
FROM scratch AS runtime
COPY --from=builder /out/controlplane /usr/local/bin/controlplane
COPY --from=builder /out/fare-engine /usr/local/bin/fare-engine
COPY --from=builder /out/client /usr/local/bin/client
COPY --from=builder /out/contain /usr/local/bin/contain
USER 65532:65532

# The pipeline runner: the real toolchain, the provider served from a local
# filesystem mirror, the checked-in configuration, the policy engine, and the
# policy body with its reviewed allowlist.
FROM scratch AS pipeline
ARG TARGETARCH
ARG PROVIDER_VERSION=0.1.0
COPY --from=builder /out/pipeline /usr/local/bin/pipeline
COPY --from=builder /out/gate /usr/local/bin/gate
COPY --from=builder /out/client /usr/local/bin/client
COPY --from=toolchain /out/tofu /usr/local/bin/tofu
COPY --from=toolchain /out/opa /usr/local/bin/opa
COPY --from=provider-builder "/out/terraform-provider-democloud_v${PROVIDER_VERSION}" \
     "/opt/tofu-mirror/democloud.example/planless/democloud/${PROVIDER_VERSION}/linux_${TARGETARCH}/terraform-provider-democloud_v${PROVIDER_VERSION}"
COPY deploy/tofurc /etc/tofurc
COPY infra /infra
COPY policy /policy
# The checked-in plan artifacts the refusal scenarios are proved against. No
# vulnerable configuration exists in this repository, so refusal is proved
# against artifacts rather than against a value set that could be applied.
COPY testdata/plans /testdata/plans
USER 65532:65532
