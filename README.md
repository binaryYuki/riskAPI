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
- **Language**: Go 1.21+
- **Framework**: Gin Web Framework
- **Cache**: Radix Tree (prefix-matching cache)
- **Databases**: MaxMind MMDB, QQWry IP Database
- **Deployment**: Docker, Docker Compose

## Quick Start

### Requirements
- Go 1.21+
- Docker (optional)
- 8GB+ RAM (recommended for large-scale IP list caching)

### Local Development
```bash
# 1. Clone the repository
git clone https://github.com/your-repo/riskAPI.git
cd riskAPI

# 2. Install dependencies
go mod tidy

# 3. Download geolocation databases (optional)
# MaxMind databases require account registration
# QQWry database downloads automatically

# 4. Configure environment variables (optional)
export ALLOWED_CORS="yourdomain.com,anotherdomain.com"
export HONEYTRAP_ENABLED=true
export HONEYTRAP_DECOYS=true

# 5. Start the service
go run .
```

### Docker Deployment
```bash
# Build image
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
  "ip": "1.2.3.4"
}
```

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

# Monitoring metrics
GET /api/metrics

# QQWry database status (New Feature)
GET /api/qqwry/stats

# Version information
GET /version
```

### 6. Cache Management (New Feature)
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
├── main.go              # Main program entry
├── handlers.go          # HTTP handlers
├── info_handler.go      # Geolocation query handler
├── middleware.go        # Middleware (logging, CORS, honeypot)
├── honeytrap.go         # Honeypot protection system
├── qqwry.go            # QQWry database parser
├── ip_checker.go        # IP checking logic
├── types.go            # Data structure definitions
├── config.go           # Configuration management
├── providers/          # Geolocation data sources
│   ├── maxmind/        # MaxMind database
│   ├── qqwry/          # QQWry database
│   ├── ipsb/           # IP.SB API
│   └── meituan/        # Meituan API
└── data/               # Static data files
    ├── cdn/            # CDN IP ranges
    └── idc/            # IDC IP ranges
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
