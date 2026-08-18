# syntax=docker/dockerfile:1

# The builder is pinned by immutable digest. It compiles every binary and runs
# the Go test, vet and formatting gate through the same container boundary a
# contributor uses locally.
FROM golang:1.26-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS builder
WORKDIR /src
COPY . .
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-trimpath
RUN go build -o /out/controlplane ./cmd/controlplane \
 && go build -o /out/fare-engine ./cmd/fare-engine \
 && go build -o /out/client ./cmd/client \
 && go build -o /out/contain ./cmd/contain \
 && go build -o /out/pipeline ./cmd/pipeline \
 && (cd provider && go mod download && go build ./...)

# The provider is a separate module so the platform itself stays on the standard
# library alone. Its one direct dependency is the plugin framework a real
# provider needs, and it is verified against the committed checksums.
FROM builder AS provider-builder
ARG PROVIDER_VERSION=0.1.0
WORKDIR /src/provider
RUN go build -o "/out/terraform-provider-democloud_v${PROVIDER_VERSION}" .

# The infrastructure toolchain is fetched once, at image build time, and
# verified against a checksum pinned in this file. Nothing is fetched at run
# time: the demonstration's networks have no route out.
FROM builder AS toolchain
ARG TARGETARCH
ARG TOFU_VERSION=1.12.5
ARG TOFU_SHA256_AMD64=dade9650e6b74fc7a8b986bd8717497d32f9e09cf82e479afef4977fa3085536
ARG TOFU_SHA256_ARM64=528f4eea63452bbddb30fa4f1780b57fac8d7676f9dda0f772e847bb62c1260a
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) sum="${TOFU_SHA256_AMD64}" ;; \
      arm64) sum="${TOFU_SHA256_ARM64}" ;; \
      *) echo "unsupported architecture ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    wget -q -O /tmp/tofu.zip \
      "https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}/tofu_${TOFU_VERSION}_linux_${TARGETARCH}.zip"; \
    echo "${sum}  /tmp/tofu.zip" | sha256sum -c -; \
    unzip -o -q /tmp/tofu.zip tofu -d /out; \
    /out/tofu version

# Runtime images carry static binaries and nothing else: no shell, no package
# manager, no certificate bundle, no cloud SDK, no credential.
FROM scratch AS runtime
COPY --from=builder /out/controlplane /usr/local/bin/controlplane
COPY --from=builder /out/fare-engine /usr/local/bin/fare-engine
COPY --from=builder /out/client /usr/local/bin/client
COPY --from=builder /out/contain /usr/local/bin/contain
USER 65532:65532

# The pipeline runner: the real toolchain, the provider served from a local
# filesystem mirror, and the checked-in configuration.
FROM scratch AS pipeline
ARG TARGETARCH
ARG PROVIDER_VERSION=0.1.0
COPY --from=builder /out/pipeline /usr/local/bin/pipeline
COPY --from=builder /out/client /usr/local/bin/client
COPY --from=toolchain /out/tofu /usr/local/bin/tofu
COPY --from=provider-builder "/out/terraform-provider-democloud_v${PROVIDER_VERSION}" \
     "/opt/tofu-mirror/democloud.example/planless/democloud/${PROVIDER_VERSION}/linux_${TARGETARCH}/terraform-provider-democloud_v${PROVIDER_VERSION}"
COPY deploy/tofurc /etc/tofurc
COPY infra /infra
USER 65532:65532
