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
- **语言**: Go 1.21+
- **框架**: Gin Web Framework
- **缓存**: Radix Tree (前缀匹配缓存)
- **数据库**: MaxMind MMDB、纯真IP数据库
- **部署**: Docker、Docker Compose

## 快速开始

### 环境要求
- Go 1.21+ 
- Docker (可选)
- 8GB+ RAM (推荐，用于大规模IP列表缓存)

### 本地运行
```bash
# 1. 克隆项目
git clone https://github.com/your-repo/riskAPI.git
cd riskAPI

# 2. 安装依赖
go mod tidy

# 3. 下载地理位置数据库 (可选)
# MaxMind数据库需要注册账号下载
# 纯真数据库会自动下载

# 4. 配置环境变量 (可选)
export ALLOWED_CORS="yourdomain.com,anotherdomain.com"
export HONEYTRAP_ENABLED=true
export HONEYTRAP_DECOYS=true

# 5. 启动服务
go run .
```

### Docker部署
```bash
# 构建镜像
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
  "ip": "1.2.3.4"
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

# 监控指标
GET /api/metrics

# 纯真数据库状态 (新功能)
GET /api/qqwry/stats

# 版本信息
GET /version
```

### 6. 缓存管理 (新功能)
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
├── main.go              # 主程序入口
├── handlers.go          # HTTP处理程序
├── info_handler.go      # 地理位置查询处理
├── middleware.go        # 中间件 (日志、CORS、蜜罐)
├── honeytrap.go         # 蜜罐防护系统
├── qqwry.go            # 纯真数据库解析
├── ip_checker.go        # IP检查逻辑  
├── types.go            # 数据结构定义
├── config.go           # 配置管理
├── providers/          # 地理位置数据源
│   ├── maxmind/        # MaxMind数据库
│   ├── qqwry/          # 纯真数据库
│   ├── ipsb/           # IP.SB API
│   └── meituan/        # 美团API
└── data/               # 静态数据文件
    ├── cdn/            # CDN IP范围
    └── idc/            # IDC IP范围
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
