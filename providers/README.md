# providers/

地理位置数据库目录（MMDB 与 `qqwry.dat`），**不入 git**。

运行 `./scripts/fetch-geo-data.sh` 下载：先从 GitHub Release [`geo-data`](https://github.com/binaryYuki/riskAPI/releases/tag/geo-data) 取最近一次成功版本，再从源头更新（MaxMind / IPinfo 需设置 `MAXMIND_ACCOUNT_ID`、`MAXMIND_LICENSE_KEY`、`IPINFO_TOKEN`，未设置时只用兜底版本）。

CI 每天 03:00 UTC 自动下载最新版本、构建镜像并重新部署。
