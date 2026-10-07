# syntax=docker/dockerfile:1

################################################################################
# Builder stage
################################################################################
ARG GO_VERSION=1.26.8
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder
WORKDIR /src

# Install git for commit hash retrieval
RUN apk add --no-cache git

# Copy project files
COPY . .

# 地理位置数据库不入 git。CI 构建前已运行 scripts/fetch-geo-data.sh；
# 其它场景（如 Portainer 从 Git 直接构建）缺失的文件从 Release geo-data 下载并校验 SHA256。
# 每个文件最多尝试 5 次（间隔递增，共约 50s）：覆盖网络抖动，以及 CI 正在 --clobber 覆盖
# Release 时的短暂 404 / 新旧文件与 SHA256SUMS 不一致。每次重试都重新获取 SHA256SUMS。
ARG GEO_DATA_URL=https://github.com/binaryYuki/riskAPI/releases/download/geo-data
RUN set -eu; \
    for f in maxmind/GeoLite2-Country.mmdb maxmind/GeoLite2-ASN.mmdb qqwry/qqwry.dat \
             ipinfo/ipinfo-asn.mmdb ipinfo/ipinfo-country.mmdb \
             iplocate/iplocate-asn.mmdb iplocate/iplocate-country.mmdb; do \
      test -s "providers/$f" && continue; \
      name="${f#*/}"; \
      mkdir -p "providers/${f%/*}"; \
      ok=0; \
      for attempt in 1 2 3 4 5; do \
        echo "downloading providers/$f (attempt $attempt)"; \
        if ! wget -q -T 60 -O /tmp/SHA256SUMS "$GEO_DATA_URL/SHA256SUMS"; then \
          echo "  cannot fetch $GEO_DATA_URL/SHA256SUMS" >&2; \
        elif ! sum="$(awk -v n="$name" '{f=$2; sub(/^\.\//, "", f)} f == n {print $1}' /tmp/SHA256SUMS)" || [ -z "$sum" ]; then \
          echo "  $name not listed in SHA256SUMS" >&2; \
        elif ! wget -q -T 120 -O "providers/$f" "$GEO_DATA_URL/$name"; then \
          echo "  cannot fetch $GEO_DATA_URL/$name" >&2; \
        elif ! echo "$sum  providers/$f" | sha256sum -c -s; then \
          echo "  checksum mismatch: $name" >&2; \
        else \
          ok=1; break; \
        fi; \
        if [ "$attempt" -lt 5 ]; then sleep $((attempt * 5)); fi; \
      done; \
      [ "$ok" = 1 ] || { echo "giving up on $name after 5 attempts" >&2; exit 1; }; \
    done; \
    rm -f /tmp/SHA256SUMS

# Cache Go modules
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download -x

# Build binary with custom version: YYMMDDHHMM-<commit[:6]>
# 构建上下文可能不含 .git（如 Portainer 从 Git 部署），此时 commit 记为 unknown
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=bind,target=. \
    COMMIT="$(git rev-parse --short=6 HEAD 2>/dev/null || echo unknown)" && \
    VERSION="$(date -u +'%y%m%d%H%M')-${COMMIT}" && \
    CGO_ENABLED=0 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
        -o /bin/server ./cmd/server

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
COPY --from=builder /src/providers /providers

# Remove any stray .git directories (safety net)
RUN rm -rf /data/.git /src/.git || true

EXPOSE 8080
ENV GIN_MODE=release
ENTRYPOINT ["/bin/server"]
