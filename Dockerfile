# syntax=docker/dockerfile:1

################################################################################
# Builder stage
################################################################################
ARG GO_VERSION=1.25
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder
WORKDIR /src

# Install git for commit hash retrieval
RUN apk add --no-cache git

# Copy project files
COPY . .

# Cache Go modules
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download -x

# Build binary with custom version: YYMMDDHHMM-<commit[:6]>
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=bind,target=. \
    --mount=type=bind,source=.git,target=.git \
    VERSION="$(date -u +'%y%m%d%H%M')-$(git rev-parse --short=6 HEAD)" && \
    CGO_ENABLED=0 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
        -o /bin/server ./...

################################################################################
# Final runtime stage
################################################################################
FROM alpine:latest AS final

# Install runtime dependencies
RUN --mount=type=cache,target=/var/cache/apk \
    apk add --no-cache ca-certificates tzdata && \
    update-ca-certificates

# Create non-root user
ARG UID=10001
RUN adduser -S -u ${UID} appuser
USER appuser

# Copy binary and data
COPY --from=builder /bin/server /bin/server
COPY --from=builder /src/data /data

# Remove any stray .git directories (safety net)
RUN rm -rf /data/.git /src/.git || true

EXPOSE 8080
ENV GIN_MODE=release
ENTRYPOINT ["/bin/server"]
