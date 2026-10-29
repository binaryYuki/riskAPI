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
  - MaxMind GeoLite2 (国家/城市/ASN)
  - IPInfo (国家/ASN)
  - IPLocate (国家/ASN)  
  - 纯真IP数据库 (中国地区高精度)
  - 美团API (中国IP专用)
  - IP.SB API (海外IP专用)
- **智能路由**: 根据IP归属地智能选择最适合的查询源
- **结果聚合**: 多数据源结果统一格式输出

### 🛡️ 蜜罐防护系统
- **带权重的规则表**: 一张常被扫描路径的规则表，每条规则有权重（凭据、版本库为高，后台、脚本为中，未知404为低）
- **按来源计分**: 每个来源一个带权重的漏桶，按不同路径去重；IPv4按单个地址，IPv6按/64
- **自适应延迟**: 随机基础延迟，并随来源分数追加指数增长的惩罚延迟
- **高仿假内容**: 命中规则的请求得到与真实内容相似的响应（`.env`、Git元数据、WordPress / phpMyAdmin登录页、SQL导出等）
- **多步欺骗**: 伪造的登录页接受提交；用假内容里的凭据登录会"成功"，并进入伪造的后台
- **假凭据回收**: 发出的每个假凭据都会登记，之后在任何蜜罐请求中再次出现时都能认出，并追溯到当初拿走它的来源
- **来源标记**: 分数达到标记阈值的来源会被IP检测接口判为风险
- **软封机制**: 分数达到封禁阈值后返回429

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
# MaxMind / IPinfo 仅在设置了对应 token 时更新。
# MaxMind 支持多个 key（逗号分隔），某个 key 被拒绝或达到下载上限时自动换下一个：
# MAXMIND_LICENSE_KEY=keyA,keyB，MAXMIND_ACCOUNT_ID=111,222（按位置对应；只给一个账号 ID 时所有 key 共用）
./scripts/fetch-geo-data.sh

# 4. 配置环境变量 (可选)
export ALLOWED_CORS="yourdomain.com,anotherdomain.com"
export HONEYTRAP_ENABLED=true
export HONEYTRAP_FLAG_THRESHOLD=8

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
| `HONEYTRAP_ENABLED` | 是否启用蜜罐防护 | `true` |
| `HONEYTRAP_BASE_DELAY_MIN_MS` | 命中规则的最小基础延迟(毫秒) | `40` |
| `HONEYTRAP_BASE_DELAY_MAX_MS` | 命中规则的最大基础延迟(毫秒) | `220` |
| `HONEYTRAP_MAX_PENALTY_MS` | 随来源分数追加的延迟上限(毫秒) | `1200` |
| `HONEYTRAP_FAKEOK` | 命中规则时返回假内容的概率(0-1)；按来源和路径确定，重复请求结果一致。设为 `0` 则返回真实的 403/404 | `1` |
| `HONEYTRAP_LOG` | 是否记录每次蜜罐命中（来源被标记时始终记录） | `true` |
| `HONEYTRAP_FLAG_THRESHOLD` | 来源被标记为风险的分数（高权重规则 8 分，中权重 4 分，未知 404 为 1 分） | `8` |
| `HONEYTRAP_FLAG_DURATION_SEC` | 最后一次达标命中后标记保留的时长(秒) | `3600` |
| `HONEYTRAP_BLOCK_THRESHOLD` | 触发软封的分数 | `16` |
| `HONEYTRAP_BLOCK_WINDOW_SEC` | 等于封禁阈值的分数完全漏空所需时间(秒) | `60` |
| `HONEYTRAP_BLOCK_DURATION_SEC` | 软封时长(秒) | `180` |
| `HONEYTRAP_MAX_OFFENDERS` | 蜜罐最多跟踪的来源数；表满时淘汰最久未活动的来源 | `100000` |
| `HONEYTRAP_SECRET` | 混淆蜜罐日志和标记文件中来源地址、以及封存命中蜜罐的访问日志行所用的密钥。未设置时使用随机密钥：来源标识和封存的日志行重启后无法还原，也不会写标记文件 | _(未设置)_ |
| `HONEYTRAP_FLAG_FILE` | 保存被标记来源的文件（JSON Lines），使标记在重启后保留；需要同时设置 `HONEYTRAP_SECRET`。使用相同密钥并共用该文件的实例共享标记 | _(未设置；`compose.yaml` 中设为卷内路径)_ |
| `ADMIN_TOKEN` | `/api/cache/flush*` 与 `/api/honeytrap/*` 的 Bearer 令牌；未设置时管理接口禁用 | _(未设置)_ |
| `TRUSTED_PROXIES` | 允许读取转发头的可信代理 CIDR/IP，逗号分隔（已知 CDN 网段始终可信） | 回环 + 私网网段 |
| `PARSE_VV_SECRET` | `/api/v1/parse` 的 HMAC 签名密钥；未设置时接口返回 503 | _(未设置)_ |
| `PARSE_WORKER_BASE` | 上游解析 Worker 地址 | `https://xhs-proxy.tzpro.workers.dev` |
| `PARSE_RATE_LIMIT_PER_MIN` | `/api/v1/parse` 每个客户端 IP 每分钟请求上限（`0` 不限流） | `30` |
| `INFO_CACHE_MAX_ENTRIES` | `/api/v1/info` 缓存最大条目数（TTL 1 小时） | `20000` |
| `CLUSTER_MODE` | 设为 `1` 开启多副本集群模式：通过 Redis/Valkey 共享风险数据快照（整个集群每小时只抓取一次数据源）、`/api/v1/info` 二级缓存与 ip.sb 限速，并广播管理操作到所有实例。未开启时各实例独立运行、不连接 Redis，见[多副本部署](#多副本部署k8s--k3s) | _(未设置)_ |
| `REDIS_URL` | Redis/Valkey 地址（`redis://` 或 `rediss://`）。`CLUSTER_MODE=1` 时必填，缺少或格式错误时启动失败；未开启集群模式时忽略 | _(未设置)_ |
| `REDIS_KEY_PREFIX` | Redis 键前缀，多个部署共用同一 Redis 时用于隔离 | `riskapi:` |
| `IPSB_RATE_PER_SEC` | ip.sb 请求速率上限（免费接口按出口 IP 限制 5 次/秒）；集群模式下为全部实例合计，否则为每个实例，`0` 不限速 | `5` |
| `IPSB_FALLBACK_RATE_PER_SEC` | 集群模式下 Redis 暂时不可用时每个实例的 ip.sb 速率（建议设为 `IPSB_RATE_PER_SEC / 副本数`） | 同 `IPSB_RATE_PER_SEC` |
| `RISK_SIGNING_KEY` | `/api/v2` 令牌的 Ed25519 私钥：PEM（PKCS#8）或 32 字节种子 / PKCS#8 DER 的 base64（`openssl genpkey -algorithm ed25519 -outform DER \| base64`）。格式错误时启动失败 | _(未设置：v2 不签发令牌)_ |
| `RISK_SIGNING_KID` | 写入令牌和 `/.well-known/risk-keys.json` 的密钥 ID | 公钥指纹 |
| `RISK_PUBLISHED_KEYS` | 轮换期间继续公布的旧公钥，`kid=base64` 逗号分隔 | _(未设置)_ |
| `RISK_TOKEN_TTL_SEC` | 令牌有效期（秒） | `120` |
| `RISK_TOKEN_AUDIENCES` | 允许的 `aud` 域名，逗号分隔；`*.example.com` 匹配任意层级子域名但不含 `example.com` 本身，主域名需另写（为空不限制） | _(未设置)_ |
| `LISTEN_ADDR` | 监听地址 | `:8080` |
| `LOG_FORMAT` | 日志格式：`text` 或 `json` | `text` |
| `LOG_LEVEL` | 日志级别：`debug`、`info`、`warn`、`error` | `info` |
| `OPENTELEMETRY` | 设为 `1` 时通过 OTLP/HTTP 上报日志与链路追踪；未设置时不创建任何 OpenTelemetry 组件 | _(未设置)_ |
| `OPENTELEMETRY_LOG_LEVEL` | 经 OTLP 上报日志的最低级别 | 同 `LOG_LEVEL` |
| `BETTERSTACK_SOURCE_TOKEN` | 设置后直接发往 Better Stack（优先于 `OTEL_EXPORTER_OTLP_*`）；未设置时按标准 `OTEL_*` 变量配置（`OTEL_EXPORTER_OTLP_ENDPOINT`、`OTEL_EXPORTER_OTLP_HEADERS`、`OTEL_TRACES_SAMPLER` 等） | _(未设置)_ |
| `BETTERSTACK_INGESTING_HOST` | Better Stack 接收地址（只填主机名） | `s2788200.us-west-2a.betterstackdata.com` |
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
  "isRisky": true,
  "isIdc": false,
  "isProxy": true
}
```

`isRisky` 在命中风险列表或被本服务蜜罐标记（来源名为 `honeytrap`）时为 true。`isIdc` / `isProxy` 是独立标记：`isIdc` 来自 data/idc 云厂商网段与数据中心类数据源；`isProxy` 来自 VPN/Tor/iCloud Private Relay 与公开代理列表（公开代理只打标记，不判定为风险）。

### 1.1 签名结果 (v2)
```bash
# 请求方 IP 风险判定，带签名
GET /api/v2/ip?aud={接入站点域名}&nonce={一次性随机串}

# 请求方 IP 地理位置 + 风险判定，带签名（只查请求方自身，没有 /{ip} 形式）
GET /api/v2/info?aud={接入站点域名}&nonce={一次性随机串}

# 验签公钥（JWK Set，OKP/Ed25519，按 kid 列出）
GET /.well-known/risk-keys.json
```

浏览器请求 v2，把 `token` 原样转交给接入站点的服务端，服务端用公布的公钥验签；任何字段被篡改签名都会失效。v2 响应为 v1 的内容加上 `token`（`/api/v2/info` 还带 `isRisky` / `isIdc` / `isProxy`）：

```json
{
  "status": "ok", "message": "IP is not listed as risky.", "ip": "2a00:…",
  "isRisky": false, "isIdc": false, "isProxy": false,
  "token": "<base64url(payload)>.<base64url(Ed25519 签名)>"
}
```

签名覆盖第一段的 ASCII 字节（两段均为不带填充的 base64url）。payload：

```json
{ "v": 1, "kid": "2026-10", "ip": "2a00:…", "status": "ok", "isRisky": false, "isIdc": false, "isProxy": false,
  "aud": "gdue-ca.paperee.guru", "nonce": "…", "iat": 1791979000, "exp": 1791979120 }
```

接入方需校验：签名（按 `kid` 选公钥）、`exp`、`aud` 等于本站域名、`nonce` 是本站下发且未使用过的、`ip` 与本站看到的访客 IP 一致（IPv6 按 /64 比较）。

- `aud` 与 `nonce` 要么都带、要么都不带：都不带时不签发令牌；只带其一返回 400。`aud` 必须是纯域名；`nonce` 为 8～128 位 `[A-Za-z0-9._~-]`。
- 未配置签名返回 503；`aud` 不在 `RISK_TOKEN_AUDIENCES` 中返回 403；以下情况返回 403：
  - 既没有 `Origin` 也没有 `Referer`（如 curl 或服务端直接调用）。
  - `Origin` 或 `Referer` 的主机名与 `aud` 不一致，两者都带时都要一致。
  - `Sec-Fetch-Mode: navigate`，即在浏览器地址栏直接打开、点链接跳转或用 iframe 加载。

  令牌只能由接入站点页面里的 `fetch`/XHR 申请。
- v2 与 `/.well-known/risk-keys.json` 返回 `Access-Control-Allow-Origin: *`，不带凭据；v1 的 CORS 不变。公钥集合可缓存 5 分钟。
- 轮换密钥：把 `RISK_SIGNING_KEY` / `RISK_SIGNING_KID` 换成新密钥，旧公钥写入 `RISK_PUBLISHED_KEYS`，至少保留令牌有效期 + 公钥缓存时间。

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

### 7. 蜜罐日志还原
蜜罐日志用混淆后的标识表示来源，命中蜜罐规则的请求的访问日志行是封存的。这两个接口用于还原。认证方式与缓存管理相同；只对当前 `HONEYTRAP_SECRET` 生成的内容有效。
```bash
# 混淆的来源标识 -> 地址（IPv4）或网段（IPv6 /64）
GET /api/honeytrap/source/{id}

# 封存的访问日志行 -> 原始字段（请求体每行一个 sealed 值）
POST /api/honeytrap/unseal
```

#### 离线还原：`scripts/honeytrap-reveal.py`
持有 `HONEYTRAP_SECRET` 的人不需要服务在运行、也不需要管理令牌，就能完成同样的事。这个脚本是一个文本过滤器：把输入原样写到标准输出，其中认得出的来源标识和封存的行替换成原文，其余内容不动。行数、顺序以及 JSON 日志的合法性都保持不变，所以输出可以直接接到你已有的工具上。

**依赖**：Python 3.8+ 和 `cryptography` 包（`pip install cryptography`）。

**密钥**：从环境变量 `HONEYTRAP_SECRET` 读取，或用 `--env-file` 指向部署所用的 `.env`；不接受从命令行参数传入。必须是这些数据写入时服务所用的密钥。

```bash
export HONEYTRAP_SECRET=...                  # 或在每条命令后加 --env-file .env

# 日志：蜜罐事件行换回真实来源，封存的访问日志行换回各字段
docker compose logs --no-log-prefix server | scripts/honeytrap-reveal.py > revealed.log

# 只看蜜罐相关的活动
docker compose logs --no-log-prefix server | scripts/honeytrap-reveal.py | grep -E 'honeytrap |/\.env'

# 被标记的来源列表：来自标记文件，或来自导出
docker compose exec server cat /var/lib/riskapi/honeytrap-flagged.jsonl | scripts/honeytrap-reveal.py
curl -s https://your-host/api/export | grep '^# honeytrap' | scripts/honeytrap-reveal.py

# 直接处理文件
scripts/honeytrap-reveal.py --env-file .env app.log.1 app.log.2
```

输出中发生变化的内容：

| 输入 | 输出 |
|---|---|
| `"source":"803c4091c04865c83877ddd1dbc1d70f"` | `"source":"73.162.10.99"`（IPv6 来源还原为 `/64`，如 `2a0e:b107:1:2::/64`） |
| `"issued_to":"<标识>"`、`# honeytrap <标识> until ...`、标记文件中的行 | 同样替换 |
| `{"msg":"request","sealed":"7-wjuG..."}` | `{"msg":"request","method":"GET","path":"/.env","status":200,"latency":"156ms","client_ip":"73.162.10.99","correlation_id":"..."}` |
| `LOG_FORMAT=text` 下带 `sealed=...` 的行 | `method=GET path=/.env status=200 ...` |

处理结果的汇总（`revealed N source id(s) and M sealed access log line(s)`）输出到标准错误。有封存的行无法解密时以非零状态退出，这说明密钥不对或该行被改动过。来源标识单独出现时无法判断密钥是否正确：它们会保持原样，汇总里显示 `0 source id(s)`。

限制：提交的密码无法还原（日志里从来只有长度和截断的哈希）；用另一个密钥写入的数据需要用那个密钥。

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
- **规则**: 仅按请求路径判定，不检查User-Agent和请求体。规则按完整的路径段或文件名匹配（`/login` 命中，`/login-help` 不命中），并带有权重：正常用户不会请求的内容为高权重(8)，如 `.env`、`.git`、SSH密钥、SQL导出；管理后台、CMS登录、运维面板和 `.php`/`.asp`/`.jsp` 脚本为中权重(4)；其余的404为低权重(1)
- **计分**: 每个来源一个漏桶。新路径按规则权重加分，桶内已出现过的路径只加0.25分，漏桶每秒漏掉 `HONEYTRAP_BLOCK_THRESHOLD / HONEYTRAP_BLOCK_WINDOW_SEC` 分。IPv4按单个地址计分，IPv6按/64计分
- **分级响应**:
  - 命中规则即延迟（延迟随分数增长），并返回针对该路径生成的假内容。假凭据按来源唯一且保持不变
  - 达到标记阈值后记下该来源：在标记时长内，`/api/v1/ip` 和 `/filter-proxies` 将其判为风险（来源名 `honeytrap`）。已知CDN网段不会因此被判为风险
  - 达到封禁阈值后，该来源在封禁时长内访问规则路径和不存在的路径一律返回429；真实API路由不受影响
- **多步欺骗**: 伪造的 WordPress、phpMyAdmin、通用后台和 Tomcat Manager（HTTP Basic）入口接受凭据提交。错误的凭据得到对应产品的常见错误页；提交的是本服务假内容里的凭据（如假 `.env` 中的 `DB_PASSWORD`、`ADMIN_PASSWORD`）时"登录成功"：发放假会话 Cookie，并展示伪造的后台页面
- **假凭据回收**: 假凭据按来源生成，返回时登记（最多 50,000 个，先淘汰最早登记的）。在蜜罐路径上会检查查询串、`Cookie`、`Authorization` 以及最多 8 KiB 的请求体。命中时同时记录使用该凭据的来源和当初拿到它的来源，并且不论分数多少立即标记使用方。正在使用假凭据或假会话的来源只按重复计分，交互不会被封禁阈值打断
- **安全边界**: 只在将要返回假内容的蜜罐路径上查看请求内容，真实API路由从不查看；内容只做查找，不执行、不转发。回显到假页面的客户端输入会做HTML转义并截断，重定向只指向本站路径，假会话在蜜罐之外没有任何作用。提交的密码不以明文保存或写入日志，只保留长度和截断的 SHA-256
- **事件**: 每一步（`bait`、`tarpit`、`login_attempt`、`credential_reuse`、`flagged`、`soft_block`、`block`）都输出为一行结构化日志（`honeytrap <类型>`）
- **来源混淆**: 蜜罐日志和标记文件里不出现客户端地址。每个来源（IPv4地址或IPv6 /64）显示为一个32位的标识，由 `HONEYTRAP_SECRET` 派生的密钥加密得到。同一来源的标识始终相同，可以跨日志行、跨实例比对和关联。持有密钥时可以把标识还原为地址：`GET /api/honeytrap/source/{id}`（需要管理令牌）。
- **访问日志封存**: 请求命中蜜罐规则时，它的访问日志行（`msg=request`）不再输出各个字段，而是整行加密成一个字符串 `sealed=<...>`，日志里任何地方都不再有这次请求的明文地址和路径。`POST /api/honeytrap/unseal`（需要管理令牌；请求体每行一个 sealed 值）返回原始字段。没有命中规则的请求照常记录。这能让读日志的人看不到地址；但它隐藏不了"哪些路径是陷阱"：规则表就在这个公开仓库里，而且 `honeytrap ...` 事件行本身写着路径和规则名
- **蜜罐风险列表**: 被标记的来源保存在一张以混淆标识为键的列表中，`/api/v1/ip` 和 `/filter-proxies` 查询的就是它。`/api/export` 会把这张列表以注释行的形式附在末尾（`# honeytrap <标识> until <时间>`），按 CIDR 解析的使用方不受影响；数量见响应头 `X-Honeytrap-Count`。设置了 `HONEYTRAP_FLAG_FILE` 时，每个新标记追加写入该文件，启动时读回未到期的标记；共用该文件的实例会在一个 `HONEYTRAP_BLOCK_WINDOW_SEC` 内看到彼此的标记。更换密钥后，已有条目只是无法再匹配，不会错标到别的地址
- **自我保护**: 来源表有上限（优先淘汰最久未活动的来源，被标记的来源最后淘汰），同时处于延迟中的请求最多1024个
- **状态**: 配置了标记文件时，标记在重启后保留。分数、软封和假凭据登记表只保存在内存中，各实例独立，重启后清空

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
- Spamhaus DROP（IPv4 + IPv6）、AbuseIPDB（置信度 100、30 天镜像）、Binary Defense、StopForumSpam 滥用网段
- 公开代理列表（monosans、TheSpeedX），仅标记 `isProxy`
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

### 多副本部署（k8s / k3s）
多个副本通常共用同一个出口 IP。如果每个副本都自己抓取 30 多个风险数据源、各自调用 ip.sb 和美团，请求量会成倍增加，很容易被上游限流。
设置 `CLUSTER_MODE=1` 与 `REDIS_URL` 后：
- **风险数据源**：每个周期只由一个实例抓取（Redis 锁），抓取结果以 gzip 快照形式发布到 Redis（约 2–3 MB），其它实例每 30 秒检查一次并加载。新 Pod 启动时直接加载已有快照，滚动更新不会再触发重新抓取。
- **`/api/v1/info`**：本实例内存缓存之外再加一层共享的 Redis 缓存，同一个 IP 在整个集群内只查询一次外部 API。
- **ip.sb 限速**：全部实例合计不超过 `IPSB_RATE_PER_SEC`。
- **管理接口广播**：`/api/cache/flush/*` 在处理请求的实例上执行，同时清理共享缓存，并通过 Redis pub/sub 通知其它实例执行同样的清理（响应中 `broadcast: true`；广播失败时返回 `broadcast_error`）。广播不持久化，当时断开连接的实例会收不到。

Redis 只是加速和去重用的，不影响服务可用性：启动时连不上不影响启动；运行中出错会在 5 秒内退回到本实例状态（本地缓存、本地限速、本实例自行抓取），恢复后自动重新使用 Redis。
不需要多副本时（如单机 `compose.yaml`）不设置 `CLUSTER_MODE` 即可，行为与之前完全一致。

```yaml
# Valkey 只保存可重建的缓存与快照，不需要持久化
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
          # volatile-lru：内存不足时只淘汰带 TTL 的 info 缓存，保留不过期的风险数据快照
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
      terminationGracePeriodSeconds: 20 # 需大于程序内 15s 的优雅停机超时
      containers:
        - name: riskapi
          image: <dockerhub-user>/risk-api:latest
          env:
            - name: CLUSTER_MODE
              value: "1"
            - name: REDIS_URL
              value: redis://valkey:6379/0
            - name: IPSB_FALLBACK_RATE_PER_SEC # 5 / 副本数
              value: "1.25"
            - name: LOG_FORMAT
              value: json
          ports:
            - containerPort: 8080
          # 风险 IP 列表加载完成前 /api/ready 返回 503；已有快照时新 Pod 几秒内就绪
          readinessProbe:
            httpGet: {path: /api/ready, port: 8080}
            periodSeconds: 5
          livenessProbe:
            httpGet: {path: /api/status, port: 8080}
            periodSeconds: 30
          resources:
            limits: {memory: 1Gi}
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
│   ├── shared/          # 可选 Redis/Valkey：多副本共享快照、缓存与限速
│   ├── honeytrap/       # 蜜罐中间件、诱饵路由、规则计分与来源标记
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

本地环境准备，以及来自 fork 的 PR 上 CI 会执行哪些步骤，见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## FAQ

**Q: 为什么地理位置查询结果不一致？**  
A: 不同数据源的更新频率和数据来源不同，建议综合多个结果判断。

**Q: 蜜罐系统会影响正常用户吗？**  
A: 正常API调用不会被延迟或封禁。只有请求规则表中的路径或不存在的路径才会计分，偶尔的几个404（如 `/favicon.ico`）远低于阈值。需要注意：被标记的来源对所有查询方都显示为风险，共享出口IP的用户会被一起影响。

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
