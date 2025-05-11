# Risky IP Filter

## 项目简介
Risky IP Filter 是一个基于 Go 的服务，用于检测和过滤风险 IP 地址。它通过多个公开的 IP 黑名单源更新风险 IP 列表，并提供 API 接口供用户查询和过滤代理。

## 功能
- 定期从多个公开的 IP 黑名单源更新风险 IP 列表
- 提供 RESTful API 接口：
    - 检查单个 IP 是否为风险 IP
    - 过滤代理列表，移除风险 IP
    - 查看服务状态
- 支持跨域请求 (CORS)

[//]: # (- 支持速率限制 &#40;Rate Limiting&#41;)

## 技术栈
- **语言**: Go
- **框架**: Gin
- **依赖**:
    - `github.com/gin-gonic/gin` - Web 框架
    - `github.com/patrickmn/go-cache` - 内存缓存
    - `golang.org/x/time/rate` - 速率限制
    - 其他依赖详见 `go.mod`

## 快速开始

### 环境要求
- Go 1.24.2 或更高版本
- Docker (可选，用于容器化部署)

### 本地运行
1. 克隆项目：
   ```bash
   git clone https://github.com/your-repo/risky-ip-filter.git
   cd risky-ip-filter
   ```

2. 安装依赖：
   ```bash
   go mod tidy
   ```

3. 运行服务：
   ```bash
   go run main.go
   ```

4. 服务启动后，默认监听 `http://localhost:8080`。

### 使用 Docker 部署
1. 构建 Docker 镜像：
   ```bash
   docker build -t risky-ip-filter .
   ```

2. 运行容器：
   ```bash
   docker run -d -p 8080:8080 --name risky-ip-filter risky-ip-filter
   ```

### 配置
通过环境变量进行配置：
- `ALLOWED_CORS`: 允许的跨域域名，多个域名用逗号分隔 (默认: `catyuki.com,tzpro.xyz`)

## API 文档

### 1. 检查 IP 风险
**GET** `/api/v1/ip/:ip`  
**POST** `/api/v1/ip/:ip`

**请求参数**:
- `ip`: 要检查的 IP 地址

**响应**:
```json
{
  "status": "ok/banned",
  "reason": "风险原因 (可选)"
}
```

### 2. 过滤代理列表
**POST** `/filter-proxies`

**请求体**:
```json
[
  {
    "name": "代理名称",
    "server": "代理服务器地址"
  }
]
```

**响应**:
```json
{
  "filtered_count": 1,
  "proxies": [
    {
      "name": "安全代理",
      "server": "安全代理地址"
    }
  ]
}
```

### 3. 查看服务状态
**GET** `/api/status`

**响应**:
```json
{
  "status": "running",
  "risky_ip_count": 12345
}
```

## 开发与贡献
1. Fork 本仓库
2. 创建分支 (`git checkout -b feature/your-feature`)
3. 提交更改 (`git commit -m 'Add your feature'`)
4. 推送分支 (`git push origin feature/your-feature`)
5. 创建 Pull Request

## 许可证
本项目基于 MIT 许可证开源，详情请参阅 `LICENSE` 文件。