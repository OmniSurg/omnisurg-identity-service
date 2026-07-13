# Deploy image for omnisurg-identity-service. Built by the CI image job
# (reusable-go-service-ci.yml) from the SINGLE-repo context and pushed to
# ghcr.io/omnisurg/omnisurg-identity-service. The runtime mirrors the local
# Dockerfile.compose exactly (migrate then serve via entrypoint.sh) so the
# deployed container is behaviorally identical to the proven local stack; the
# only differences are the build context (this repo alone) and how the shared
# modules resolve.
#
# SHARED MODULES: developer builds use `replace ... => ../omnisurg-*` against the
# sibling checkouts, which do not exist here. So drop those local replaces and
# pin the published versions (the libraries are published before any service).
# This also normalizes any placeholder proto pseudo-version to a real tag.
ARG GO_COMMON_VERSION=v0.2.3
ARG PROTO_VERSION=v0.8.0

FROM golang:1.26-alpine AS builder
RUN apk add --no-cache git
WORKDIR /app
ARG GO_COMMON_VERSION
ARG PROTO_VERSION
COPY . .
# Resolve shared modules on the FINAL source tree (after COPY, so nothing
# clobbers the edited go.mod). Drop both local replaces together, pin the
# published versions, then tidy against the real source imports.
RUN go mod edit -dropreplace=github.com/OmniSurg/omnisurg-go-common \
                -dropreplace=github.com/OmniSurg/omnisurg-proto/gen/go && \
    go get github.com/OmniSurg/omnisurg-go-common@${GO_COMMON_VERSION} && \
    go get github.com/OmniSurg/omnisurg-proto/gen/go@${PROTO_VERSION} && \
    go mod tidy
# The server, the per-service seed helper, and the golang-migrate CLI so the
# entrypoint can migrate without a host toolchain (version matches the Makefile).
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/server ./cmd/server
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/seed ./cmd/seed
RUN CGO_ENABLED=0 GOOS=linux go install -tags 'postgres' \
    github.com/golang-migrate/migrate/v4/cmd/migrate@v4.17.1

FROM alpine:3.19
RUN apk add --no-cache ca-certificates wget && \
    addgroup -S omnisurg && adduser -S omnisurg -G omnisurg
WORKDIR /app
COPY --from=builder /bin/server ./server
COPY --from=builder /bin/seed ./seed
COPY --from=builder /go/bin/migrate ./migrate
COPY --from=builder /app/migrations ./migrations
COPY --from=builder /app/docker/entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh ./migrate ./server ./seed
USER omnisurg
EXPOSE 8081 9081
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:8081/api/v1/identity/health || exit 1
ENTRYPOINT ["/app/entrypoint.sh"]
