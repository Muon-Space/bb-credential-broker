# syntax=docker/dockerfile:1.7

# Build stage. Uses the standard Go toolchain image; CGO is disabled
# so the resulting binary is statically linked and able to run on the
# distroless/static base.
FROM golang:1.25-bookworm AS builder

WORKDIR /src

# Cache module downloads in a separate layer so that source-only
# rebuilds do not invalidate the dependency cache.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags='-s -w' \
    -o /out/bb-credential-broker ./cmd/bb-credential-broker

# Runtime stage. distroless/static contains only ca-certificates,
# /etc/passwd entries for the nonroot user and tzdata. There is no
# shell and no package manager; the broker binary is the only
# executable in the image.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/bb-credential-broker /usr/local/bin/bb-credential-broker

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/bb-credential-broker"]
