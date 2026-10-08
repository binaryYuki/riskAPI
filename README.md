# Risky IP Filter & Geolocation Service

[中文文档 / Chinese Documentation](README_cn.md)

## Project Overview
A high-performance Go-based service providing comprehensive IP risk detection, geolocation queries, and CDN/IDC identification. Features enterprise-grade capabilities including multi-source data fusion, intelligent caching, honeypot protection, and more. Perfect for security protection, proxy filtering, and IP intelligence analysis.

## Core Features

### 🔍 Risk IP Detection
- **Multi-source Blacklists**: Integrates 20+ public blacklist sources including Tor exit nodes, malicious IPs, and datacenter IPs
- **Real-time Updates**: Automatically updates risk IP lists periodically to ensure data freshness
- **CIDR Support**: Fast lookups for both individual IPs and CIDR network ranges
- **Private Network Filtering**: Automatically identifies and skips private/bogon addresses

### 🌍 Geolocation Query (`/api/v1/info`)
- **Multi-source Data Fusion**: Integrates 7 geolocation databases
  - MaxMind GeoLite2 (Country/ASN)
  - IPInfo (Country/ASN)
  - IPLocate (Country/ASN)
  - QQWry Database (High accuracy for Chinese regions)
  - Meituan API (China IP specialized)
  - IP.SB API (International IP specialized)
- **Intelligent Routing**: Smart selection of optimal query sources based on IP geolocation
- **Result Aggregation**: Unified format output from multiple data sources

### 🛡️ Honeypot Protection System
- **Suspicious Path Detection**: Identifies access attempts to sensitive paths
- **Adaptive Delays**: Progressive delay penalties for suspicious requests
- **Soft Blocking**: Temporary blocking based on frequency thresholds
- **Decoy Routes**: Optional honeypot route deployment

### 🚀 CDN/IDC Identification
- **Major CDNs**: Supports Cloudflare, Fastly, Tencent EdgeOne, etc.
- **Cloud Providers**: AWS, Azure, GCP, Alibaba Cloud, and other IDC IP identification
- **Real-time Sync**: Regular updates of major service provider IP ranges

### ⚡ Performance Optimization
- **Radix Tree Caching**: Efficient prefix-matching cache system
- **Concurrent Processing**: Optimized goroutine pools and connection reuse
- **Smart Timeouts**: Layered timeout control to prevent request pile-up
- **Memory Optimization**: Efficient memory usage for large-scale IP lists

## Tech Stack
- **Language**: Go 1.26+
- **Framework**: Gin Web Framework
- **Cache**: Radix Tree (prefix-matching cache)
- **Databases**: MaxMind MMDB, QQWry IP Database
- **Deployment**: Docker, Docker Compose

## Quick Start

### Requirements
- Go 1.26+
- Docker (optional)
- 8GB+ RAM (recommended for large-scale IP list caching)

### Local Development
```bash
# 1. Clone the repository
git clone https://github.com/your-repo/riskAPI.git
cd riskAPI

# 2. Install dependencies
go mod tidy

# 3. Download geolocation databases (not stored in git)
# Pulls the last known good set from the `geo-data` GitHub Release (needs `gh auth login`),
# then refreshes from upstream; MaxMind / IPinfo refresh only when their tokens are set.
# MaxMind accepts several comma-separated keys and falls back to the next one when a key
# is rejected or hits its download limit: MAXMIND_LICENSE_KEY=keyA,keyB with
# MAXMIND_ACCOUNT_ID=111,222 (paired by position; a single account ID is shared by all keys)
./scripts/fetch-geo-data.sh

# 4. Configure environment variables (optional)
export ALLOWED_CORS="yourdomain.com,anotherdomain.com"
export HONEYTRAP_ENABLED=true
export HONEYTRAP_DECOYS=true

# 5. Start the service
go run ./cmd/server
```

### Docker Deployment
```bash
# Build image
./scripts/fetch-geo-data.sh   # the image build expects databases in providers/
docker build -t riskapi .

# Run container
docker run -d \
  -p 8080:8080 \
  -e ALLOWED_CORS="yourdomain.com" \
  -e HONEYTRAP_ENABLED=true \
  --name riskapi \
  riskapi
```

### Docker Compose Deployment
```bash
# Use the provided compose.yaml
docker-compose up -d
```

## Configuration

### Environment Variables
| Variable | Description | Default |
|----------|-------------|---------|
| `ALLOWED_CORS` | Allowed CORS domains, comma-separated | `catyuki.com,tzpro.xyz` |
| `HONEYTRAP_ENABLED` | Enable honeypot protection | `false` |
| `HONEYTRAP_DECOYS` | Enable decoy routes | `false` |
| `HONEYTRAP_BASE_DELAY_MIN_MS` | Minimum honeypot delay (ms) | `100` |
| `HONEYTRAP_BASE_DELAY_MAX_MS` | Maximum honeypot delay (ms) | `500` |
| `HONEYTRAP_BLOCK_THRESHOLD` | Block threshold (attempts) | `5` |
| `HONEYTRAP_BLOCK_DURATION` | Block duration (seconds) | `300` |
| `HONEYTRAP_MAX_OFFENDERS` | Max tracked honeypot offenders | `100000` |
| `ADMIN_TOKEN` | Bearer token for `/api/cache/flush*`; admin endpoints are disabled when unset | _(unset)_ |
| `TRUSTED_PROXIES` | Comma-separated CIDRs/IPs whose forwarding headers are trusted (known CDN ranges are always trusted) | loopback + private ranges |
| `PARSE_VV_SECRET` | HMAC secret for `/api/v1/parse`; the endpoint returns 503 when unset | _(unset)_ |
| `PARSE_WORKER_BASE` | Upstream parse worker base URL | `https://xhs-proxy.tzpro.workers.dev` |
| `PARSE_RATE_LIMIT_PER_MIN` | Per-client-IP limit for `/api/v1/parse` (`0` disables) | `30` |
| `INFO_CACHE_MAX_ENTRIES` | Max `/api/v1/info` cache entries (1h TTL) | `20000` |
| `LISTEN_ADDR` | Listen address | `:8080` |
| `LOG_FORMAT` | Log format: `text` or `json` | `text` |
| `LOG_LEVEL` | Log level: `debug`, `info`, `warn`, `error` | `info` |
| `OPENTELEMETRY` | Set to `1` to export logs and traces over OTLP/HTTP; when unset no OpenTelemetry component is created | _(unset)_ |
| `OPENTELEMETRY_LOG_LEVEL` | Minimum level of logs exported over OTLP | same as `LOG_LEVEL` |
| `BETTERSTACK_SOURCE_TOKEN` | Send directly to Better Stack (overrides `OTEL_EXPORTER_OTLP_*`); when unset the standard `OTEL_*` variables apply (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_TRACES_SAMPLER`, …) | _(unset)_ |
| `BETTERSTACK_INGESTING_HOST` | Better Stack ingesting host (hostname only) | `s2788200.us-west-2a.betterstackdata.com` |
| `QQWRY_PATH` | Path to `qqwry.dat` | `providers/qqwry/qqwry.dat` |

## API Documentation

### 1. Risk IP Detection
```bash
# Check individual IP
GET /api/v1/ip/{ip}
POST /api/v1/ip/{ip}

# Check requester IP
GET /api/v1/ip
```

**Response Example**:
```json
{
  "status": "risky",
  "message": "IP is in risky list: tor_exit_node",
  "ip": "1.2.3.4",
  "isRisky": true,
  "isIdc": false,
  "isProxy": true
}
```

`isRisky` is true only for risk-list hits. `isIdc` / `isProxy` are independent flags: `isIdc` covers data/idc cloud ranges and datacenter feeds; `isProxy` covers VPN/Tor/iCloud Private Relay and public proxy lists (public proxies only set the flag, they do not make an IP risky).

### 2. Geolocation Query (New Feature)
```bash
# Query specific IP geolocation
GET /api/v1/info/{ip}

# Query requester IP geolocation
GET /api/v1/info
```

**Response Example**:
```json
{
  "status": "ok",
  "ip": "8.8.8.8",
  "results": {
    "maxmind": {
      "country": {
        "iso_code": "US",
        "names": {
          "en": "United States"
        }
      },
      "autonomous_system_number": 15169,
      "autonomous_system_organization": "Google LLC"
    },
    "ipinfo": {
      "country": "US",
      "asn": "AS15169",
      "org": "Google LLC"
    },
    "qqwry": {
      "data": "United States",
      "area": "Google DNS Server"
    }
  }
}
```

### 3. Proxy Filtering
```bash
POST /filter-proxies
```

**Request Body**:
```json
[
  {
    "name": "Safe Proxy",
    "server": "1.2.3.4:8080"
  },
  {
    "name": "Risky Proxy",
    "server": "5.6.7.8:8080"
  }
]
```

### 4. CDN/IDC Query (New Feature)
```bash
# Query specific CDN IP ranges
GET /cdn/{provider}  # cloudflare, fastly, edgeone

# Query all CDN information
GET /cdn/all
```

### 5. Service Monitoring
```bash
# Service status
GET /api/status

# Readiness: 503 until risk IP lists finish their first load, then 200.
# Use this as the platform HTTP health check so new instances do not take traffic with empty lists.
GET /api/ready

# Monitoring metrics
GET /api/metrics

# Prometheus text format
GET /metrics

# QQWry database status (New Feature)
GET /api/qqwry/stats

# Version information
GET /version
```

### 6. Cache Management (New Feature)
Requires `ADMIN_TOKEN` to be set and the header `Authorization: Bearer <ADMIN_TOKEN>`.
```bash
# Flush cache index
GET /api/cache/flush

# Flush specific cache
POST /api/cache/flush/{method}/{range}
```

## Performance Features

### Caching Strategy
- **IP Query Cache**: 1-hour TTL, reduces duplicate queries
- **Geolocation Cache**: 1-hour TTL, multi-source result caching
- **CDN/IDC Cache**: 6-hour update cycle
- **Radix Tree Index**: O(k) complexity prefix matching

### Concurrency Optimization
- **Connection Pooling**: Maximum 1000 idle connections
- **Goroutine Control**: Smart goroutine pool management
- **Timeout Control**: Multi-layer timeout protection
- **Memory Reuse**: Efficient memory allocation strategies

### Monitoring Metrics
- Request statistics (total, success rate, latency distribution)
- Cache hit rates
- Honeypot trigger statistics
- Data source health status

## Security Features

### Honeypot Protection
- **Path Detection**: Automatically identifies admin panel access attempts
- **Behavioral Analysis**: Anomaly detection based on User-Agent and access patterns
- **Progressive Penalties**: Initial warnings, escalating delays for repeat access
- **Smart Blocking**: Short-term soft blocking to avoid blocking legitimate users

### Access Control
- **CORS Policy**: Strict cross-origin access control
- **Rate Limiting**: IP-based request frequency limiting
- **Security Headers**: Security-related HTTP header configuration

## Data Sources

### Risk IP Sources (20+)
- Official Tor Project exit node lists
- X4BNet VPN/datacenter IP lists
- Project Honeypot malicious IPs
- Dan.me.uk Tor lists
- Spamhaus DROP (IPv4 + IPv6), AbuseIPDB (confidence 100, 30d mirror), Binary Defense, StopForumSpam toxic CIDRs
- Public proxy lists (monosans, TheSpeedX), flag-only (`isProxy`)
- Other open-source threat intelligence sources

### Geolocation Data Sources
- **MaxMind GeoLite2**: Global coverage, high accuracy
- **IPInfo**: Commercial-grade precision
- **IPLocate**: Open-source alternative
- **QQWry IP**: High accuracy for Chinese regions
- **Meituan API**: China IP specialized service
- **IP.SB**: International IP query service

## Deployment Recommendations

### Production Environment
- **Resource Configuration**: Minimum 4C8G, recommended 8C16G
- **Storage**: SSD storage, reserve 20GB space for database files
- **Network**: Recommended CDN and load balancer configuration
- **Monitoring**: Integrate Prometheus/Grafana monitoring

### High Availability Deployment
```yaml
# docker-compose.yml example
version: '3.8'
services:
  riskapi:
    image: riskapi:latest
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '2'
          memory: 4G
    ports:
      - "8080-8082:8080"
    environment:
      - HONEYTRAP_ENABLED=true
    restart: unless-stopped
```

## Development Guide

### Project Structure
```
├── cmd/server/          # Entry point: wiring, startup, graceful shutdown
├── internal/
│   ├── config/          # All configuration, loaded from environment variables
│   ├── httpapi/         # HTTP server: routes, handlers, middleware, client IP resolution
│   ├── feeds/           # Risk IP feeds: fetching, parsing, last-good fallback, readiness
│   ├── ipset/           # Longest-prefix-match IP table (bart), bogon checks
│   ├── netlists/        # CDN / IDC (cloud provider) lists
│   ├── geo/             # Geolocation aggregation (MMDB, QQWry, Meituan, IP.SB)
│   ├── honeytrap/       # Honeypot middleware and decoy routes
│   └── cache/           # TTL + size-bounded cache
├── providers/           # Geolocation databases (MMDB, qqwry.dat; updated daily by CI)
└── data/                # Static data
    ├── cdn/             # CDN IP ranges
    ├── idc/             # IDC IP ranges
    └── pages/           # 403 page
```

### Adding New Data Sources
1. Create new provider in `providers/` directory
2. Implement standard query interface
3. Integrate in `info_handler.go`
4. Add corresponding configuration options

### Contributing
1. Fork this repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push branch (`git push origin feature/amazing-feature`)
5. Create Pull Request

## FAQ

**Q: Why are geolocation query results inconsistent?**  
A: Different data sources have varying update frequencies and data origins. We recommend considering multiple results for comprehensive judgment.

**Q: Will the honeypot system affect normal users?**  
A: The honeypot only affects requests to sensitive paths. Normal API calls are unaffected.

**Q: How can I customize the risk IP list?**  
A: You can add custom data sources by modifying `ipListAPIs` in `config.go`.

**Q: What's the memory usage of the service?**  
A: Typically 2-4GB in common scenarios, mainly used for IP list and geolocation data caching.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact
- GitHub Issues: Report issues or feature requests
- Email: [Maintainer Email]
- Documentation: [Project Wiki]
