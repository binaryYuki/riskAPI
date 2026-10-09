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
# 其它场景（如 Portainer 从 Git 直接构建）缺失的文件从 Release geo-data 下载并校验 SHA256
ARG GEO_DATA_URL=https://github.com/binaryYuki/riskAPI/releases/download/geo-data
RUN set -eu; \
    for f in maxmind/GeoLite2-Country.mmdb maxmind/GeoLite2-ASN.mmdb qqwry/qqwry.dat \
             ipinfo/ipinfo-asn.mmdb ipinfo/ipinfo-country.mmdb \
             iplocate/iplocate-asn.mmdb iplocate/iplocate-country.mmdb; do \
      test -s "providers/$f" && continue; \
      name="${f#*/}"; \
      [ -s /tmp/SHA256SUMS ] || wget -q -O /tmp/SHA256SUMS "$GEO_DATA_URL/SHA256SUMS"; \
      sum="$(awk -v n="$name" '{f=$2; sub(/^\.\//, "", f)} f == n {print $1}' /tmp/SHA256SUMS)"; \
      [ -n "$sum" ] || { echo "$name not listed in $GEO_DATA_URL/SHA256SUMS" >&2; exit 1; }; \
      echo "downloading providers/$f"; \
      mkdir -p "providers/${f%/*}"; \
      wget -q -O "providers/$f" "$GEO_DATA_URL/$name"; \
      echo "$sum  providers/$f" | sha256sum -c -s || { echo "checksum mismatch: $name" >&2; exit 1; }; \
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
# 蜜罐标记文件所在目录（compose 中挂载为卷）；预先创建并交给 appuser，新建的卷会沿用这个属主
RUN mkdir -p /var/lib/riskapi && chown appuser /var/lib/riskapi
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
