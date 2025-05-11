# Risky IP Filter

[中文文档](https://github.com/binaryYuki/riskAPI/blob/master/README_cn.md)

## Project Overview
**Risky IP Filter** is a Go-based service designed to detect and filter risky IP addresses. It regularly updates its risk IP list from multiple public blacklists and provides API endpoints for users to check and filter proxies.

## Features
- Periodically updates a list of risky IPs from multiple public blacklist sources
- Provides RESTful API endpoints:
    - Check whether a single IP is considered risky
    - Filter a list of proxies, removing risky IPs
    - Check service status
- CORS support
- Rate limiting support !!Deprecated --leave it to your rev proxy!

## Tech Stack
- **Language**: Go
- **Framework**: Gin
- **Dependencies**:
    - `github.com/gin-gonic/gin` - Web framework
    - `github.com/patrickmn/go-cache` - In-memory caching
    - `golang.org/x/time/rate` - Rate limiting
    - Other dependencies can be found in `go.mod`

## Getting Started

### Requirements
- Go 1.24.2 or later
- Docker (optional, for containerized deployment)

### Run Locally
1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/risky-ip-filter.git
   cd risky-ip-filter
   ```

2. Install dependencies:
   ```bash
   go mod tidy
   ```

3. Start the service:
   ```bash
   go run main.go
   ```

4. By default, the service will be available at `http://localhost:8080`.

### Deploy with Docker
1. Build the Docker image:
   ```bash
   docker build -t risky-ip-filter .
   ```

2. Run the container:
   ```bash
   docker run -d -p 8080:8080 --name risky-ip-filter risky-ip-filter
   ```

### Configuration
Configure the service using environment variables:
- `ALLOWED_CORS`: Comma-separated list of allowed CORS domains (default: `catyuki.com,tzpro.xyz`)

## API Documentation

### 1. Check IP Risk
**GET** `/api/v1/ip/:ip`  
**POST** `/api/v1/ip/:ip`

**Path Parameter**:
- `ip`: The IP address to check

**Response**:
```json
{
  "status": "ok/banned",
  "reason": "Optional reason for risk"
}
```

### 2. Filter Proxy List
**POST** `/filter-proxies`

**Request Body**:
```json
[
  {
    "name": "Proxy Name",
    "server": "Proxy Server Address"
  }
]
```

**Response**:
```json
{
  "filtered_count": 1,
  "proxies": [
    {
      "name": "Safe Proxy",
      "server": "Safe Proxy Address"
    }
  ]
}
```

### 3. Check Service Status
**GET** `/api/status`

**Response**:
```json
{
  "status": "running",
  "risky_ip_count": 12345
}
```

## Development & Contribution
1. Fork this repository
2. Create a new branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add your feature'`)
4. Push your branch (`git push origin feature/your-feature`)
5. Create a Pull Request

## License
This project is open-sourced under the MIT License. See the `LICENSE` file for details.
