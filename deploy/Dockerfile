# syntax=docker/dockerfile:1

# The builder is pinned by immutable digest. It is the only third-party image in
# the project, and it is used both to compile the binaries and to run the Go
# test, vet and formatting gate through the same container boundary.
FROM golang:1.26-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS builder
WORKDIR /src
COPY . .
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-trimpath
RUN go build -o /out/controlplane ./cmd/controlplane \
 && go build -o /out/fare-engine ./cmd/fare-engine \
 && go build -o /out/client ./cmd/client \
 && go build -o /out/contain ./cmd/contain

# Runtime images carry static binaries and nothing else: no shell, no package
# manager, no certificate bundle, no cloud SDK, no credential.
FROM scratch AS runtime
COPY --from=builder /out/controlplane /usr/local/bin/controlplane
COPY --from=builder /out/fare-engine /usr/local/bin/fare-engine
COPY --from=builder /out/client /usr/local/bin/client
COPY --from=builder /out/contain /usr/local/bin/contain
USER 65532:65532
