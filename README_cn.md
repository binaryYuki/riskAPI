# 风险IP过滤与地理位置查询服务 (Risky IP Filter & Geolocation Service)

## 项目简介
这是一个基于 Go 的高性能服务，提供风险 IP 检测、地理位置查询、CDN/IDC 识别等功能。服务支持多数据源查询、智能缓存、蜜罐防护等企业级特性，适用于安全防护、代理过滤、IP 情报分析等场景。

## 核心功能

### 🔍 风险IP检测
- **多源黑名单**: 整合20+公开黑名单源，包括Tor出口节点、恶意IP、数据中心IP等
- **实时更新**: 定期自动更新风险IP列表，确保数据时效性
- **CIDR支持**: 支持单个IP和CIDR网段的快速查询
- **私网过滤**: 自动识别并跳过私网和bogon地址

### 🌍 地理位置查询 (`/api/v1/info`)
- **多数据源融合**: 集成7个地理位置数据库
  - MaxMind GeoLite2 (国家/ASN)
  - IPInfo (国家/ASN)
  - IPLocate (国家/ASN)  
  - 纯真IP数据库 (中国地区高精度)
  - 美团API (中国IP专用)
  - IP.SB API (海外IP专用)
- **智能路由**: 根据IP归属地智能选择最适合的查询源
- **结果聚合**: 多数据源结果统一格式输出

### 🛡️ 蜜罐防护系统
- **可疑路径检测**: 识别对敏感路径的访问尝试
- **自适应延迟**: 对可疑请求实施渐进式延迟惩罚
- **软封机制**: 基于频次的临时封禁策略
- **诱饵路由**: 可选的蜜罐路由部署

### 🚀 CDN/IDC识别
- **主流CDN**: 支持Cloudflare、Fastly、腾讯云EdgeOne等
- **云服务商**: AWS、Azure、GCP、阿里云等IDC IP识别
- **实时同步**: 定期更新各大服务商的IP范围

### ⚡ 性能优化
- **Radix树缓存**: 高效的前缀匹配缓存系统
- **并发处理**: 优化的协程池和连接复用
- **智能超时**: 分层超时控制，防止请求堆积
- **内存优化**: 针对大规模IP列表的内存使用优化

## 技术栈
- **语言**: Go 1.26+
- **框架**: Gin Web Framework
- **缓存**: Radix Tree (前缀匹配缓存)
- **数据库**: MaxMind MMDB、纯真IP数据库
- **部署**: Docker、Docker Compose

## 快速开始

### 环境要求
- Go 1.26+ 
- Docker (可选)
- 8GB+ RAM (推荐，用于大规模IP列表缓存)

### 本地运行
```bash
# 1. 克隆项目
git clone https://github.com/your-repo/riskAPI.git
cd riskAPI

# 2. 安装依赖
go mod tidy

# 3. 下载地理位置数据库（不入 git）
# 先从 GitHub Release `geo-data` 取最近一次成功版本（需 `gh auth login`），再从源头更新；
# MaxMind / IPinfo 仅在设置了对应 token 时更新
./scripts/fetch-geo-data.sh

# 4. 配置环境变量 (可选)
export ALLOWED_CORS="yourdomain.com,anotherdomain.com"
export HONEYTRAP_ENABLED=true
export HONEYTRAP_DECOYS=true

# 5. 启动服务
go run ./cmd/server
```

### Docker部署
```bash
# 构建镜像
./scripts/fetch-geo-data.sh   # 构建镜像前需准备好 providers/ 下的数据库
docker build -t riskapi .

# 运行容器
docker run -d \
  -p 8080:8080 \
  -e ALLOWED_CORS="yourdomain.com" \
  -e HONEYTRAP_ENABLED=true \
  --name riskapi \
  riskapi
```

### Docker Compose部署
```bash
# 使用项目提供的compose.yaml
docker-compose up -d
```

## 配置选项

### 环境变量
| 变量名 | 描述 | 默认值 |
|--------|------|--------|
| `ALLOWED_CORS` | 允许的CORS域名，逗号分隔 | `catyuki.com,tzpro.xyz` |
| `HONEYTRAP_ENABLED` | 是否启用蜜罐防护 | `false` |
| `HONEYTRAP_DECOYS` | 是否启用诱饵路由 | `false` |
| `HONEYTRAP_BASE_DELAY_MIN_MS` | 蜜罐最小延迟(毫秒) | `100` |
| `HONEYTRAP_BASE_DELAY_MAX_MS` | 蜜罐最大延迟(毫秒) | `500` |
| `HONEYTRAP_BLOCK_THRESHOLD` | 封禁阈值(次数) | `5` |
| `HONEYTRAP_BLOCK_DURATION` | 封禁时长(秒) | `300` |
| `HONEYTRAP_MAX_OFFENDERS` | 蜜罐最多跟踪的来源数 | `100000` |
| `ADMIN_TOKEN` | `/api/cache/flush*` 的 Bearer 令牌；未设置时管理接口禁用 | _(未设置)_ |
| `TRUSTED_PROXIES` | 允许读取转发头的可信代理 CIDR/IP，逗号分隔（已知 CDN 网段始终可信） | 回环 + 私网网段 |
| `PARSE_VV_SECRET` | `/api/v1/parse` 的 HMAC 签名密钥；未设置时接口返回 503 | _(未设置)_ |
| `PARSE_WORKER_BASE` | 上游解析 Worker 地址 | `https://xhs-proxy.tzpro.workers.dev` |
| `PARSE_RATE_LIMIT_PER_MIN` | `/api/v1/parse` 每个客户端 IP 每分钟请求上限（`0` 不限流） | `30` |
| `INFO_CACHE_MAX_ENTRIES` | `/api/v1/info` 缓存最大条目数（TTL 1 小时） | `20000` |
| `LISTEN_ADDR` | 监听地址 | `:8080` |
| `LOG_FORMAT` | 日志格式：`text` 或 `json` | `text` |
| `LOG_LEVEL` | 日志级别：`debug`、`info`、`warn`、`error` | `info` |
| `QQWRY_PATH` | 纯真库 `qqwry.dat` 路径 | `providers/qqwry/qqwry.dat` |

## API文档

### 1. 风险IP检测
```bash
# 检查单个IP
GET /api/v1/ip/{ip}
POST /api/v1/ip/{ip}

# 检查请求者IP
GET /api/v1/ip
```

**响应示例**:
```json
{
  "status": "risky",
  "message": "IP is in risky list: tor_exit_node",
  "ip": "1.2.3.4",
  "isRisky": true
}
```

### 2. 地理位置查询 (新功能)
```bash
# 查询指定IP地理信息
GET /api/v1/info/{ip}

# 查询请求者IP地理信息  
GET /api/v1/info
```

**响应示例**:
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
      "data": "美国",
      "area": "Google公司DNS服务器"
    }
  }
}
```

### 3. 代理过滤
```bash
POST /filter-proxies
```

**请求体**:
```json
[
  {
    "name": "安全代理",
    "server": "1.2.3.4:8080"
  },
  {
    "name": "风险代理", 
    "server": "5.6.7.8:8080"
  }
]
```

### 3.1 WebRTC 泄露检测
```bash
POST /api/v1/webrtc   # 检测
GET  /api/v1/webrtc   # 浏览器脚本
```
浏览器通过公共 STUN 服务器收集 ICE 候选后上报到此接口。服务将每个 WebRTC 地址与 HTTP 请求来源 IP 对比：存在与请求 IP 同地址族、但不相同的公网地址，说明 HTTP 走了代理/VPN 而 WebRTC 暴露了真实出口（`leak: true`）。私网 `host` 候选、mDNS（`*.local`）主机名及跨地址族（双栈）地址不计为泄露。单次最多处理 32 个地址，请求体上限 16KB。`requestInfo` 与每个候选的 `info` 为地理位置信息，内容同 `/api/v1/info` 的 `results`（共用缓存）；私网/bogon 地址不查询。

**请求体**（`candidates` 为原始 `RTCIceCandidate.candidate` 字符串，`ips` 为纯地址，二选一或同时提供）:
```json
{
  "candidates": ["candidate:842163049 1 udp 1677729535 45.10.10.10 54321 typ srflx raddr 0.0.0.0 rport 0"],
  "ips": []
}
```

**响应**:
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

**浏览器脚本**（推荐）：`GET /api/v1/webrtc` 下发混淆后的检测脚本（源码 `web/webrtc/src/index.ts`），加载后挂在 `window.RiskWebRTC`。脚本负责收集候选并上报，默认请求脚本自身来源域名下的接口；调用页面的域名需在 `ALLOWED_CORS` 白名单内。
```html
<script src="https://your-api/api/v1/webrtc"></script>
<script>
  RiskWebRTC.check({ timeoutMs: 5000 }).then((r) => {
    // r.status: "ok" | "leak" | "unsupported"（浏览器或扩展屏蔽了 WebRTC：不会泄露，也不会请求接口）
    console.log(r.status, r);
  });
</script>
```
可选参数：`endpoint`（覆盖接口地址）、`stunServers`、`timeoutMs`（默认 5000）、`ips`、`signal`。另导出 `isSupported()` 与 `gather()`。

脚本响应允许 CDN 缓存：`Cache-Control: public, max-age=600, s-maxage=3600, stale-while-revalidate=86400`、`CDN-Cache-Control: max-age=3600`，并带内容哈希 `ETag`（`If-None-Match` 命中返回 304）。URL 不带版本号，发布后 CDN 最多一小时内仍返回旧脚本，需要立即生效时请手动清除 CDN 缓存。修改源码后执行 `cd web/webrtc && npm ci && npm run build` 并提交 `internal/httpapi/assets/webrtc.js`；入库产物与源码不一致时 CI 会失败。

### 4. CDN/IDC查询 (新功能)
```bash
# 查询指定CDN的IP范围
GET /cdn/{provider}  # cloudflare, fastly, edgeone

# 查询所有CDN信息
GET /cdn/all
```

### 5. 服务监控
```bash
# 服务状态
GET /api/status

# 就绪检查：风险 IP 列表首轮加载完成前返回 503，之后返回 200。
# 建议配置为平台的 HTTP 健康检查路径，避免新实例在数据为空时接流量。
GET /api/ready

# 监控指标
GET /api/metrics

# Prometheus 文本格式
GET /metrics

# 纯真数据库状态 (新功能)
GET /api/qqwry/stats

# 版本信息
GET /version
```

### 6. 缓存管理 (新功能)
需设置 `ADMIN_TOKEN`，并携带请求头 `Authorization: Bearer <ADMIN_TOKEN>`。
```bash
# 刷新缓存索引
GET /api/cache/flush

# 刷新指定缓存
POST /api/cache/flush/{method}/{range}
```

## 性能特性

### 缓存策略
- **IP查询缓存**: 1小时TTL，减少重复查询
- **地理位置缓存**: 1小时TTL，多数据源结果缓存
- **CDN/IDC缓存**: 6小时更新周期
- **Radix树索引**: O(k)复杂度的前缀匹配

### 并发优化
- **连接池**: 最大1000个空闲连接
- **协程控制**: 智能协程池管理
- **超时控制**: 多层超时防护
- **内存复用**: 高效的内存分配策略

### 监控指标
- 请求统计 (总数、成功率、延迟分布)
- 缓存命中率
- 蜜罐触发统计
- 数据源健康状态

## 安全特性

### 蜜罐防护
- **路径检测**: 自动识别对管理后台的访问尝试
- **行为分析**: 基于User-Agent和访问模式的异常检测  
- **渐进惩罚**: 首次警告，重复访问逐步增加延迟
- **智能封禁**: 短期软封禁机制，避免误封正常用户

### 访问控制
- **CORS策略**: 严格的跨域访问控制
- **请求限制**: 基于IP的请求频率限制
- **Header安全**: 安全相关HTTP头部设置

## 数据源

### 风险IP来源 (20+)
- Tor项目官方出口节点列表
- X4BNet VPN/数据中心IP列表
- Project Honeypot恶意IP
- Dan.me.uk Tor列表
- 其他开源威胁情报源

### 地理位置数据源
- **MaxMind GeoLite2**: 全球覆盖，准确度较高
- **IPInfo**: 商业级精度
- **IPLocate**: 开源替代方案
- **纯真IP**: 中国地区高精度
- **美团API**: 中国IP专用服务
- **IP.SB**: 海外IP查询服务

## 部署建议

### 生产环境
- **资源配置**: 4C8G起步，推荐8C16G
- **存储**: SSD存储，预留20GB空间用于数据库文件
- **网络**: 建议配置CDN和负载均衡
- **监控**: 集成Prometheus/Grafana监控

### 高可用部署
```yaml
# docker-compose.yml 示例
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

## 开发指南

### 项目结构
```
├── cmd/server/          # 程序入口：组装依赖、启动、优雅停机
├── internal/
│   ├── config/          # 全部配置（从环境变量加载）
│   ├── httpapi/         # HTTP 服务：路由、处理函数、中间件、客户端 IP 解析
│   ├── feeds/           # 风险 IP 数据源：抓取、解析、失败沿用旧数据、就绪状态
│   ├── ipset/           # 最长前缀匹配 IP 表（bart）、bogon 判断
│   ├── netlists/        # CDN / IDC（云厂商）网段列表
│   ├── geo/             # 地理位置聚合（MMDB、纯真、美团、IP.SB）
│   ├── honeytrap/       # 蜜罐中间件与诱饵路由
│   └── cache/           # 带 TTL 与容量上限的缓存
├── providers/           # 地理位置数据库（MMDB、qqwry.dat，CI 每日更新）
└── data/                # 静态数据
    ├── cdn/             # CDN IP 范围
    ├── idc/             # IDC IP 范围
    └── pages/           # 403 页面
```

### 添加新数据源
1. 在`providers/`目录下创建新的provider
2. 实现标准查询接口
3. 在`info_handler.go`中集成
4. 添加相应的配置选项

### 贡献指南
1. Fork本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送分支 (`git push origin feature/amazing-feature`)  
5. 创建Pull Request

## FAQ

**Q: 为什么地理位置查询结果不一致？**  
A: 不同数据源的更新频率和数据来源不同，建议综合多个结果判断。

**Q: 蜜罐系统会影响正常用户吗？**  
A: 蜜罐只对访问敏感路径的请求生效，正常API调用不受影响。

**Q: 如何自定义风险IP列表？**  
A: 可以通过修改`config.go`中的`ipListAPIs`添加自定义数据源。

**Q: 服务的内存占用多少？**  
A: 典型场景下约2-4GB，主要用于IP列表和地理位置数据缓存。

## 许可证
本项目采用 MIT 许可证开源。详情请参阅 [LICENSE](LICENSE) 文件。

## 联系我们
- GitHub Issues: 报告问题或功能请求
- Email: [维护者邮箱]
- 文档: [项目Wiki]
