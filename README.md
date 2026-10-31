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
  - MaxMind GeoLite2 (Country/City/ASN)
  - IPInfo (Country/ASN)
  - IPLocate (Country/ASN)
  - QQWry Database (High accuracy for Chinese regions)
  - Meituan API (China IP specialized)
  - IP.SB API (International IP specialized)
- **Intelligent Routing**: Smart selection of optimal query sources based on IP geolocation
- **Result Aggregation**: Unified format output from multiple data sources

### 🛡️ Honeypot Protection System
- **Weighted Rule Table**: One table of commonly scanned paths, each with a weight (credentials and repositories high, admin panels and scripts medium, unknown 404s low)
- **Per-Source Scoring**: A weighted leaky bucket per source that counts distinct paths; IPv4 per address, IPv6 per /64
- **Adaptive Delays**: Random base delay plus an exponential penalty that grows with the source's score
- **Realistic Fake Content**: Matched requests get content that looks like the real thing (`.env`, Git metadata, WordPress / phpMyAdmin login pages, SQL dumps, ...)
- **Multi-Step Deception**: Fake login pages accept submissions; logging in with a credential taken from the fake content "succeeds" and leads to a fake admin area
- **Credential Tracking**: Every fake credential handed out is registered, so its later use in any honeypot request is recognised and traced back to the source that harvested it
- **Flagging**: Sources that reach the flag threshold are reported as risky by the IP check API
- **Soft Blocking**: Returns 429 once a source reaches the block threshold

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
export HONEYTRAP_FLAG_THRESHOLD=8

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
| `HONEYTRAP_ENABLED` | Enable honeypot protection | `true` |
| `HONEYTRAP_BASE_DELAY_MIN_MS` | Minimum base delay on a rule hit (ms) | `40` |
| `HONEYTRAP_BASE_DELAY_MAX_MS` | Maximum base delay on a rule hit (ms) | `220` |
| `HONEYTRAP_MAX_PENALTY_MS` | Cap on the extra delay added as a source's score grows (ms) | `1200` |
| `HONEYTRAP_FAKEOK` | Probability (0-1) of answering a rule hit with fake content; decided per source and path, so repeats get the same answer. `0` falls back to the real 403/404. Keep it low on a production domain: many fake login pages can get the domain flagged as phishing by browsers' safe-browsing lists | `0.2` |
| `HONEYTRAP_LOG` | Log every honeypot hit (flagging is always logged) | `true` |
| `HONEYTRAP_FLAG_THRESHOLD` | Score at which a source is flagged (high-weight rule = 8, medium = 4, unknown 404 = 1); only a rule hit can flag, 404s alone never do | `8` |
| `HONEYTRAP_FLAG_DURATION_SEC` | How long a source stays flagged after its last qualifying hit (seconds) | `3600` |
| `HONEYTRAP_BLOCK_THRESHOLD` | Score at which a source is soft-blocked | `16` |
| `HONEYTRAP_BLOCK_WINDOW_SEC` | Time for a score equal to the block threshold to leak away (seconds) | `60` |
| `HONEYTRAP_BLOCK_DURATION_SEC` | Soft block duration (seconds) | `180` |
| `HONEYTRAP_AFFECTS_VERDICT` | Report flagged sources as risky (source `honeytrap`) in `/api/v1/ip`, `/api/v2/*` and `/filter-proxies`. Off by default: the client IP comes from proxy headers, so anyone who can reach the origin directly could forge it and get arbitrary IPs reported as risky. Only enable when the origin cannot be reached around the CDN. With `CLUSTER_MODE=1` it also requires `HONEYTRAP_SECRET` | `false` |
| `HONEYTRAP_MAX_OFFENDERS` | Max tracked sources; when full the least recently active one is evicted | `100000` |
| `HONEYTRAP_SECRET` | Key used to obfuscate source addresses in honeypot logs and in the flag file, and to seal access log lines of honeypot hits. When unset a random key is used: source ids and sealed lines cannot be revealed after a restart and the flag file is not written | _(unset)_ |
| `HONEYTRAP_FLAG_FILE` | File (JSON Lines) that stores flagged sources so they survive restarts; requires `HONEYTRAP_SECRET`. Instances sharing the secret and the file share their flags | _(unset; `compose.yaml` sets it to a volume path)_ |
| `ADMIN_TOKEN` | Bearer token for `/api/cache/flush*` and `/api/honeytrap/*`; admin endpoints are disabled when unset | _(unset)_ |
| `TRUSTED_PROXIES` | Comma-separated CIDRs/IPs whose forwarding headers are trusted (known CDN ranges are always trusted) | loopback + private ranges |
| `PARSE_VV_SECRET` | HMAC secret for `/api/v1/parse`; the endpoint returns 503 when unset | _(unset)_ |
| `PARSE_WORKER_BASE` | Upstream parse worker base URL | `https://xhs-proxy.tzpro.workers.dev` |
| `PARSE_RATE_LIMIT_PER_MIN` | Per-client-IP limit for `/api/v1/parse` (`0` disables) | `30` |
| `INFO_CACHE_MAX_ENTRIES` | Max `/api/v1/info` cache entries (1h TTL) | `20000` |
| `CLUSTER_MODE` | Set to `1` for multi-replica cluster mode: shares the risk list snapshot via Redis/Valkey (feeds fetched once per hour cluster-wide), a second-level `/api/v1/info` cache and the ip.sb rate limit, and broadcasts admin operations to every instance. When off, instances run independently and never connect to Redis. See [Multi-replica deployment](#multi-replica-deployment-k8s--k3s) | _(unset)_ |
| `REDIS_URL` | Redis/Valkey URL (`redis://` or `rediss://`). Required with `CLUSTER_MODE=1` (startup fails if missing or invalid); ignored otherwise | _(unset)_ |
| `REDIS_KEY_PREFIX` | Redis key prefix, to isolate deployments sharing one Redis | `riskapi:` |
| `IPSB_RATE_PER_SEC` | ip.sb request rate limit (the free API allows 5/s per egress IP); cluster-wide total in cluster mode, otherwise per instance; `0` disables | `5` |
| `IPSB_FALLBACK_RATE_PER_SEC` | Per-instance ip.sb rate while Redis is unreachable in cluster mode (suggested: `IPSB_RATE_PER_SEC / replicas`) | same as `IPSB_RATE_PER_SEC` |
| `RISK_SIGNING_KEY` | Ed25519 private key for `/api/v2` tokens: PEM (PKCS#8) or base64 of the 32-byte seed / PKCS#8 DER (`openssl genpkey -algorithm ed25519 -outform DER \| base64`). Startup fails if it is invalid | _(unset: v2 issues no tokens)_ |
| `RISK_SIGNING_KID` | Key id written into tokens and `/.well-known/risk-keys.json` | public-key fingerprint |
| `RISK_PUBLISHED_KEYS` | Old public keys to keep publishing during rotation, `kid=base64` comma-separated | _(unset)_ |
| `RISK_TOKEN_TTL_SEC` | Token lifetime (seconds) | `120` |
| `RISK_TOKEN_AUDIENCES` | Allowed `aud` host names, comma-separated; `*.example.com` matches any subdomain but not `example.com` itself, so list both for apex + subdomains (empty = any) | _(unset)_ |
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

`isRisky` is true for risk-list hits, and, with `HONEYTRAP_AFFECTS_VERDICT=true`, for sources flagged by this service's own honeypot (reported with source `honeytrap`). `isIdc` / `isProxy` are independent flags: `isIdc` covers data/idc cloud ranges and datacenter feeds; `isProxy` covers VPN/Tor/iCloud Private Relay and public proxy lists (public proxies only set the flag, they do not make an IP risky).

### 1.1 Signed Results (v2)
```bash
# Requester IP verdict, signed
GET /api/v2/ip?aud={site host}&nonce={one-time random string}

# Requester IP geolocation + verdict, signed (requester only, no /{ip} form)
GET /api/v2/info?aud={site host}&nonce={one-time random string}

# Verification public keys (JWK Set, OKP/Ed25519, by kid)
GET /.well-known/risk-keys.json
```

The browser calls v2 and forwards `token` unchanged to the integrating site's backend, which verifies it with the published public key, so tampering with any field invalidates the signature. v2 responses are the v1 bodies plus `token` (`/api/v2/info` also carries `isRisky` / `isIdc` / `isProxy`):

```json
{
  "status": "ok", "message": "IP is not listed as risky.", "ip": "2a00:…",
  "isRisky": false, "isIdc": false, "isProxy": false,
  "token": "<base64url(payload)>.<base64url(Ed25519 signature)>"
}
```

The signature covers the ASCII bytes of the first segment (both segments unpadded base64url). Payload:

```json
{ "v": 1, "kid": "2026-10", "ip": "2a00:…", "status": "ok", "isRisky": false, "isIdc": false, "isProxy": false,
  "aud": "gdue-ca.paperee.guru", "nonce": "…", "iat": 1791979000, "exp": 1791979120 }
```

The verifier must check: signature (key chosen by `kid`), `exp`, `aud` equals its own host, `nonce` equals the one it issued and has not been used, and `ip` matches the visitor IP it sees (compare IPv6 by /64).

- `aud` and `nonce` are optional together: without both, no token is issued. Only one of them → 400. `aud` must be a bare host name; `nonce` must be 8–128 chars of `[A-Za-z0-9._~-]`.
- Signing not configured → 503; `aud` outside `RISK_TOKEN_AUDIENCES` → 403; 403 also when:
  - Neither `Origin` nor `Referer` is present (e.g. curl or a server-side call).
  - The host of `Origin` or `Referer` differs from `aud`; when both are sent, both must match.
  - `Sec-Fetch-Mode: navigate`, meaning the URL was opened in the address bar, followed as a link, or loaded in an iframe.

  Tokens can only be requested by `fetch`/XHR from the integrating site's pages.
- v2 and `/.well-known/risk-keys.json` send `Access-Control-Allow-Origin: *` without credentials; v1 CORS is unchanged. The key set is cacheable for 5 minutes.
- Key rotation: switch `RISK_SIGNING_KEY` / `RISK_SIGNING_KID` to the new key and list the old public key in `RISK_PUBLISHED_KEYS` for at least the token TTL plus the key-set cache time.

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

### 3.1 WebRTC Leak Detection
```bash
POST /api/v1/webrtc   # detection
GET  /api/v1/webrtc   # browser script
```
The browser gathers ICE candidates against a public STUN server and posts them here. The service compares every WebRTC address with the HTTP source IP: a public address of the same family that differs from the request IP means HTTP went through a proxy/VPN while WebRTC exposed the real egress (`leak: true`). Private `host` candidates, mDNS (`*.local`) names and cross-family addresses (dual stack) are not counted as leaks. At most 32 addresses are processed; body limit 16KB. `requestInfo` and each candidate's `info` carry the same geolocation `results` as `/api/v1/info` (shared cache); private/bogon addresses are not looked up.

**Request Body** (`candidates` are raw `RTCIceCandidate.candidate` strings, `ips` are plain addresses; either or both):
```json
{
  "candidates": ["candidate:842163049 1 udp 1677729535 45.10.10.10 54321 typ srflx raddr 0.0.0.0 rport 0"],
  "ips": []
}
```

**Response**:
```json
{
  "status": "leak",
  "requestIp": "154.3.3.3",
  "requestStatus": "idc",
  "requestInfo": {"ipinfo": {"country": "US", "asn": "AS0000"}, "ipsb": {"...": "..."}},
  "leak": true,
  "isRisky": false,
  "candidates": [
    {"ip": "45.10.10.10", "type": "srflx", "status": "ok", "isRisky": false, "sameAsRequest": false,
     "info": {"ipinfo": {"country": "DE"}, "ipsb": {"...": "..."}}}
  ]
}
```

**Browser script** (recommended): `GET /api/v1/webrtc` serves an obfuscated client script (source: `web/webrtc/src/index.ts`) that exposes `window.RiskWebRTC`. It gathers candidates, posts them, and by default calls the API on the origin it was loaded from. The page origin must be in `ALLOWED_CORS`.
```html
<script src="https://your-api/api/v1/webrtc"></script>
<script>
  RiskWebRTC.check({ timeoutMs: 5000 }).then((r) => {
    // r.status: "ok" | "leak" | "unsupported" (WebRTC blocked by the browser/extension: no leak possible, API not called)
    console.log(r.status, r);
  });
</script>
```
Options: `endpoint` (override API URL), `stunServers`, `timeoutMs` (default 5000), `ips`, `signal`. Also exported: `isSupported()` and `gather()`.

The script response is CDN-cacheable: `Cache-Control: public, max-age=600, s-maxage=3600, stale-while-revalidate=86400`, `CDN-Cache-Control: max-age=3600`, plus a content-hash `ETag` (`If-None-Match` → 304). The URL is unversioned, so after a deploy CDNs serve the old script for up to an hour unless purged. Rebuild after editing the source with `cd web/webrtc && npm ci && npm run build` and commit `internal/httpapi/assets/webrtc.js`; CI fails if the committed bundle is stale.

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

### 7. Honeypot Log Lookup
Honeypot log lines identify sources by an obfuscated id, and access log lines of requests that hit a honeypot rule are sealed. These endpoints reverse both. Same authentication as cache management; they only work for values created with the current `HONEYTRAP_SECRET`.
```bash
# Flagged sources on this instance (obfuscated ids and expiry)
GET /api/honeytrap/flagged

# Obfuscated source id -> address (IPv4) or network (IPv6 /64)
GET /api/honeytrap/source/{id}

# Sealed access log lines -> original fields (body: one sealed value per line)
POST /api/honeytrap/unseal
```

#### Offline: `scripts/honeytrap-reveal.py`
Whoever holds `HONEYTRAP_SECRET` can do the same without a running server and without the admin token. The script is a text filter: it copies its input to standard output, replacing every source id and sealed line it recognises with the original, and leaves everything else untouched. Line count, order and (for JSON logs) JSON validity are preserved, so the output can be piped into the tools you already use.

**Requirements**: Python 3.8+ and the `cryptography` package (`pip install cryptography`).

**Key**: read from the `HONEYTRAP_SECRET` environment variable, or from the deployment's `.env` with `--env-file`. It is never taken from the command line. It must be the secret the server was using when the data was written.

```bash
export HONEYTRAP_SECRET=...                  # or add --env-file .env to each command

# Logs: honeypot event lines get real sources, sealed request lines get their fields back
docker compose logs --no-log-prefix server | scripts/honeytrap-reveal.py > revealed.log

# Only the honeypot activity
docker compose logs --no-log-prefix server | scripts/honeytrap-reveal.py | grep -E 'honeytrap |/\.env'

# The flagged-source list, from the flag file or from the export
docker compose exec server cat /var/lib/riskapi/honeytrap-flagged.jsonl | scripts/honeytrap-reveal.py
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" https://your-host/api/honeytrap/flagged | scripts/honeytrap-reveal.py

# Files instead of standard input
scripts/honeytrap-reveal.py --env-file .env app.log.1 app.log.2
```

What changes in the output:

| Input | Output |
|---|---|
| `"source":"803c4091c04865c83877ddd1dbc1d70f"` | `"source":"73.162.10.99"` (IPv6 sources become a `/64`, e.g. `2a0e:b107:1:2::/64`) |
| `"issued_to":"<id>"`, `/api/honeytrap/flagged` output, flag file lines | same replacement |
| `{"msg":"request","sealed":"7-wjuG..."}` | `{"msg":"request","method":"GET","path":"/.env","status":200,"latency":"156ms","client_ip":"73.162.10.99","correlation_id":"..."}` |
| `LOG_FORMAT=text` lines with `sealed=...` | `method=GET path=/.env status=200 ...` |

A summary (`revealed N source id(s) and M sealed access log line(s)`) goes to standard error. The exit status is non-zero when a sealed line could not be decrypted, which means the key is wrong or the line was altered. A wrong key cannot be detected for source ids on their own: they are simply left as they are, and the summary reports `0 source id(s)`.

Limits: submitted passwords are not recoverable (only their length and a truncated hash were ever logged), and data written under a different secret needs that secret.

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
- **Rules**: Detection is by request path only; User-Agent and request body are not inspected. Rules match whole path segments or file names (`/login` matches, `/login-help` does not) and carry a weight: high (8) for things no normal user requests such as `.env`, `.git`, SSH keys and SQL dumps; medium (4) for admin panels, CMS logins, ops consoles and `.php`/`.asp`/`.jsp` scripts; low (1) for any other 404
- **Scoring**: Each source has a leaky bucket. A new path adds its rule's weight, a path already seen adds only 0.25, and the bucket leaks at `HONEYTRAP_BLOCK_THRESHOLD / HONEYTRAP_BLOCK_WINDOW_SEC` per second. IPv4 is scored per address, IPv6 per /64
- **Tiered Response**:
  - Any rule hit is delayed (the delay grows with the score) and answered with fake content generated for that path. Fake credentials are unique and stable per source
  - When a rule hit brings the score to the flag threshold the source is flagged for the flag duration (404s alone never flag). With `HONEYTRAP_AFFECTS_VERDICT=true`, `/api/v1/ip`, `/api/v2/*` and `/filter-proxies` report flagged sources as risky (source `honeytrap`); known CDN ranges are never reported this way
  - At the block threshold the source gets 429 on rule paths and unknown paths for the block duration; real API routes stay reachable
- **Multi-Step Deception**: The fake WordPress, phpMyAdmin, generic admin and Tomcat Manager (HTTP Basic) entry points accept credentials. Wrong credentials get the product's usual error page. Credentials that came from this service's own fake content (e.g. `DB_PASSWORD` or `ADMIN_PASSWORD` from the fake `.env`) "succeed": the client gets a fake session cookie and is shown a fake admin page
- **Credential Tracking**: Fake credentials are derived per source and registered when served (up to 50,000, oldest dropped first). On honeypot paths the query string, `Cookie`, `Authorization` and up to 8 KiB of the request body are searched for them. A match is recorded with both the source using the credential and the source it was originally issued to, and the using source is flagged immediately regardless of score. A source using fake credentials or a fake session is scored at the repeat rate, so the interaction is not cut short by the block threshold
- **Safety Limits**: Request content is only inspected on honeypot paths that will get a fake response, never on real API routes. It is searched, never executed or forwarded. Client input shown in fake pages is HTML-escaped and truncated, redirects only point to same-site paths, and fake sessions are meaningless outside the honeypot. Submitted passwords are never stored or logged in clear text: only their length and a truncated SHA-256
- **Events**: Every step (`bait`, `tarpit`, `login_attempt`, `credential_reuse`, `flagged`, `soft_block`, `block`) is written as one structured log line (`honeytrap <kind>`)
- **Obfuscated Sources**: Honeypot log lines and the flag file never contain client addresses. Each source (IPv4 address or IPv6 /64) appears as a 32-character id, produced by encrypting it with a key derived from `HONEYTRAP_SECRET`. The same source always gets the same id, so ids can be compared and joined across log lines and instances. With the secret the id can be turned back into the address: `GET /api/honeytrap/source/{id}` (admin token required).
- **Sealed Access Log Lines**: When a request hits a honeypot rule, its access log line (`msg=request`) is written as a single encrypted string, `sealed=<...>`, instead of the usual fields, so the address and path do not appear in clear text anywhere in the log. `POST /api/honeytrap/unseal` (admin token; one sealed value per line in the body) returns the original fields. Requests that do not hit a rule are logged as before. This hides addresses from someone reading the log; it does not hide which paths are traps, because the rule table is part of this public repository and the `honeytrap ...` event lines name the path and rule
- **Honeypot Risk List**: Flagged sources are kept in a list keyed by obfuscated id, which the verdict consults when `HONEYTRAP_AFFECTS_VERDICT` is on. It is not part of the public `/api/export`; admins can list it with `GET /api/honeytrap/flagged`. When `HONEYTRAP_FLAG_FILE` is set, each new flag is appended to that file and unexpired flags are read back at startup. With `CLUSTER_MODE=1` and `HONEYTRAP_SECRET` set, new flags are broadcast to all instances over Redis (an instance that starts later only sees flags raised after it started, or those in its flag file). Changing the secret makes existing entries unmatchable rather than wrong
- **Self-Protection**: The source table is bounded (least recently active evicted first, flagged sources last) and at most 1024 requests are delayed at once
- **State**: Flags survive restarts when the flag file is configured. Scores, soft blocks and the credential registry live in memory only; they are per instance and reset on restart

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

### Multi-replica deployment (k8s / k3s)
Replicas usually share one egress IP. If every replica fetches the 30+ risk feeds and calls ip.sb / Meituan on its own, upstream traffic multiplies and gets rate limited.
With `CLUSTER_MODE=1` and `REDIS_URL` set:
- **Risk feeds**: each cycle exactly one instance fetches (Redis lock) and publishes a gzip snapshot (~2–3 MB); the others check every 30s and load it. New pods load the existing snapshot on startup, so rolling updates no longer refetch everything.
- **`/api/v1/info`**: a shared Redis cache sits behind each instance's in-memory cache, so an IP is looked up externally once per cluster.
- **ip.sb rate limit**: all instances together stay under `IPSB_RATE_PER_SEC`.
- **Admin broadcast**: `/api/cache/flush/*` runs on the instance that handles the request, clears the shared cache, and notifies the other instances over Redis pub/sub to apply the same flush (`broadcast: true` in the response, `broadcast_error` on failure). Messages are not persisted; an instance disconnected at that moment misses them.

Redis is an optimisation, not a dependency: being unreachable at startup does not block startup; errors at runtime fall back to local state within 5s (local cache, local rate limit, per-instance fetching), and Redis is used again once it recovers.
For a single host (e.g. `compose.yaml`) simply leave `CLUSTER_MODE` unset; behaviour is unchanged.

```yaml
# Valkey only holds rebuildable cache and snapshots; no persistence needed
apiVersion: apps/v1
kind: Deployment
metadata:
  name: valkey
spec:
  replicas: 1
  selector:
    matchLabels: {app: valkey}
  template:
    metadata:
      labels: {app: valkey}
    spec:
      containers:
        - name: valkey
          image: valkey/valkey:8.1-alpine
          # volatile-lru: under memory pressure only TTL-bound info cache is evicted, never the risk list snapshot
          args: ["--save", "", "--appendonly", "no", "--maxmemory", "256mb", "--maxmemory-policy", "volatile-lru"]
          ports:
            - containerPort: 6379
          resources:
            limits: {memory: 320Mi}
---
apiVersion: v1
kind: Service
metadata:
  name: valkey
spec:
  selector: {app: valkey}
  ports:
    - port: 6379
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: riskapi
spec:
  replicas: 4
  selector:
    matchLabels: {app: riskapi}
  template:
    metadata:
      labels: {app: riskapi}
    spec:
      terminationGracePeriodSeconds: 20 # must exceed the 15s in-process graceful shutdown timeout
      containers:
        - name: riskapi
          image: <dockerhub-user>/risk-api:latest
          env:
            - name: CLUSTER_MODE
              value: "1"
            - name: REDIS_URL
              value: redis://valkey:6379/0
            - name: IPSB_FALLBACK_RATE_PER_SEC # 5 / replicas
              value: "1.25"
            - name: LOG_FORMAT
              value: json
          ports:
            - containerPort: 8080
          # /api/ready returns 503 until risk lists load; with a snapshot present new pods are ready in seconds
          readinessProbe:
            httpGet: {path: /api/ready, port: 8080}
            periodSeconds: 5
          livenessProbe:
            httpGet: {path: /api/status, port: 8080}
            periodSeconds: 30
          resources:
            limits: {memory: 1Gi}
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
│   ├── shared/          # Optional Redis/Valkey: shared snapshot, cache and rate limit across replicas
│   ├── honeytrap/       # Honeypot middleware, decoy routes, scoring and source flagging
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

See [CONTRIBUTING.md](CONTRIBUTING.md) for local setup and what CI runs on pull requests from forks.

## FAQ

**Q: Why are geolocation query results inconsistent?**  
A: Different data sources have varying update frequencies and data origins. We recommend considering multiple results for comprehensive judgment.

**Q: Will the honeypot system affect normal users?**  
A: Normal API calls are never delayed or blocked. A source is only scored when it requests a path in the rule table or a path that does not exist; a few stray 404s (e.g. `/favicon.ico`) stay far below the thresholds. Flags only affect the verdict with `HONEYTRAP_AFFECTS_VERDICT=true`; then a flagged source is reported as risky to everyone querying it, so users behind a shared IP are affected together.

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
