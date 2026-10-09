#!/usr/bin/env bash
# 下载地理位置数据库到 providers/（CI 构建镜像前执行；本地开发同样适用）。
#
# 每个文件的处理顺序：
#   1. 先取上游仓库 GitHub Release "geo-data" 中的最近一次成功版本作为兜底（需要 gh 已登录或 GH_TOKEN）
#   2. 再从源头下载最新版，校验数据库类型与大小通过后才替换
# 单个源失败不影响其它源；最终仍缺文件时以非零状态退出。
#
# 可选环境变量：MAXMIND_ACCOUNT_ID / MAXMIND_LICENSE_KEY、IPINFO_TOKEN（未设置则只用兜底版本）；
#   GEO_DATA_REPO 兜底 Release 所在仓库（默认上游；fork 仓库里没有该 Release，因此不跟随 GITHUB_REPOSITORY）
#
# MaxMind 支持多个 key（逗号分隔），某个 key 达到下载上限或失效时自动换下一个：
#   MAXMIND_LICENSE_KEY=keyA,keyB
#   MAXMIND_ACCOUNT_ID=111,222   # 按位置与 key 一一对应；只给一个时所有 key 共用
# 免费版下载上限按账号计算，同一账号下的多个 key 共享额度，要分散额度需用不同账号的 key。
set -euo pipefail

DEST="${DEST:-providers}"
REPO="${GEO_DATA_REPO:-binaryYuki/riskAPI}"
RELEASE_TAG="geo-data"
FILES="GeoLite2-ASN.mmdb GeoLite2-Country.mmdb ipinfo-asn.mmdb ipinfo-country.mmdb iplocate-asn.mmdb iplocate-country.mmdb qqwry.dat"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fresh=""

# 文件名 → providers 下的子目录
subdir() {
  case "$1" in
    GeoLite2-*) echo maxmind ;;
    ipinfo-*) echo ipinfo ;;
    iplocate-*) echo iplocate ;;
    qqwry.dat) echo qqwry ;;
    *) return 1 ;;
  esac
}

# 文件名 → MMDB 元数据中 database_type 应包含的字符串（防止把 A 源的文件当成 B 源）
expected_type() {
  case "$1" in
    GeoLite2-ASN.mmdb) echo "GeoLite2-ASN" ;;
    GeoLite2-Country.mmdb) echo "GeoLite2-Country" ;;
    ipinfo-asn.mmdb) echo "ipinfo" ;;
    ipinfo-country.mmdb) echo "ipinfo" ;;
    iplocate-asn.mmdb) echo "iplocate ip-to-asn" ;;
    iplocate-country.mmdb) echo "iplocate ip-to-country" ;;
  esac
}

valid() { # valid <name> <file>
  local name="$1" file="$2"
  [ -s "$file" ] || return 1
  if [ "$name" = "qqwry.dat" ]; then
    [ "$(wc -c <"$file")" -gt 10000000 ]
    return
  fi
  # MMDB 元数据位于文件末尾，以 "\xab\xcd\xefMaxMind.com" 标记开始
  tail -c 262144 "$file" | LC_ALL=C grep -aq "MaxMind.com" || return 1
  tail -c 262144 "$file" | LC_ALL=C grep -aqF "$(expected_type "$name")"
}

install() { # install <name> <file>：校验通过才放入 DEST
  local name="$1" file="$2"
  if valid "$name" "$file"; then
    mkdir -p "$DEST/$(subdir "$name")"
    cp -f "$file" "$DEST/$(subdir "$name")/$name"
    fresh="$fresh $name"
    echo "  ✓ $name 已更新"
  else
    echo "  ✗ $name 下载内容校验失败，保留兜底版本" >&2
  fi
}

echo "== 1/2 取最近一次成功版本（Release ${RELEASE_TAG}）"
if gh release download "$RELEASE_TAG" --repo "$REPO" --dir "$work/release" --pattern '*.mmdb' --pattern 'qqwry.dat' 2>"$work/gh.err"; then
  for name in $FILES; do
    if valid "$name" "$work/release/$name"; then
      mkdir -p "$DEST/$(subdir "$name")"
      cp -f "$work/release/$name" "$DEST/$(subdir "$name")/$name"
    fi
  done
  echo "  ✓ 兜底版本就绪"
else
  echo "  ! 无法下载兜底版本：$(cat "$work/gh.err")" >&2
fi

echo "== 2/2 从源头下载最新版"
dl() { curl -fsSL --retry 3 --retry-all-errors --connect-timeout 20 --max-time 600 "$@"; }

# split_csv <字符串>：按逗号拆分并去掉空白，结果放入数组 csv
split_csv() {
  local item
  csv=()
  IFS=',' read -ra items <<<"$1"
  for item in ${items[@]+"${items[@]}"}; do
    item="${item//[[:space:]]/}"
    [ -n "$item" ] && csv+=("$item")
  done
  return 0
}

mm_keys=() mm_ids=() mm_next=0
if [ -n "${MAXMIND_ACCOUNT_ID:-}" ] && [ -n "${MAXMIND_LICENSE_KEY:-}" ]; then
  # ${arr[@]+"${arr[@]}"}：bash 3.2（macOS）在 set -u 下展开空数组会报错
  split_csv "$MAXMIND_LICENSE_KEY"; mm_keys=(${csv[@]+"${csv[@]}"})
  split_csv "$MAXMIND_ACCOUNT_ID"; mm_ids=(${csv[@]+"${csv[@]}"})
  if [ "${#mm_ids[@]}" -eq 1 ]; then
    for ((i = 1; i < ${#mm_keys[@]}; i++)); do mm_ids+=("${mm_ids[0]}"); done
  fi
  if [ "${#mm_ids[@]}" -ne "${#mm_keys[@]}" ]; then
    echo "  ✗ MAXMIND_ACCOUNT_ID 数量（${#mm_ids[@]}）与 MAXMIND_LICENSE_KEY 数量（${#mm_keys[@]}）不一致，跳过 MaxMind" >&2
    mm_keys=()
  fi
  # GitHub Actions 只会遮蔽整个 secret；拆开后的单个 key 要单独遮蔽，以防出现在日志里
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    for k in ${mm_keys[@]+"${mm_keys[@]}"}; do echo "::add-mask::$k"; done
  fi
fi

# maxmind_download <edition> <输出文件>：从当前 key 开始依次尝试。
# 401/403（key 无效）与 429（达到下载上限）立即换下一个 key；其它错误（5xx、网络）同一 key 重试 3 次。
# 成功的 key 留给下一个 edition 继续用，已用尽的 key 不再重复请求。日志只显示 key 序号。
maxmind_download() {
  local edition="$1" out="$2" i attempt code
  for ((i = mm_next; i < ${#mm_keys[@]}; i++)); do
    for attempt in 1 2 3; do
      code="$(curl -sSL --connect-timeout 20 --max-time 600 -o "$out" -w '%{http_code}' \
        -u "${mm_ids[$i]}:${mm_keys[$i]}" \
        "${MAXMIND_DOWNLOAD_BASE:-https://download.maxmind.com}/geoip/databases/$edition/download?suffix=tar.gz")" || true
      case "$code" in
        200) mm_next=$i; return 0 ;;
        401 | 403 | 429) break ;;
      esac
      if [ "$attempt" -lt 3 ]; then sleep $((attempt * 3)); fi
    done
    echo "  ! MaxMind ${edition}：key #$((i + 1))/${#mm_keys[@]} 失败（HTTP ${code:-000}），换下一个" >&2
  done
  mm_next=${#mm_keys[@]}
  return 1
}

if [ "${#mm_keys[@]}" -gt 0 ]; then
  for edition in GeoLite2-ASN GeoLite2-Country; do
    d="$work/maxmind-$edition"; mkdir -p "$d"
    if maxmind_download "$edition" "$d/db.tar.gz" && tar -xzf "$d/db.tar.gz" -C "$d"; then
      install "$edition.mmdb" "$(find "$d" -name "$edition.mmdb" | head -n1)"
    else
      echo "  ✗ MaxMind $edition 下载或解压失败" >&2
    fi
  done
elif [ -z "${MAXMIND_ACCOUNT_ID:-}" ] || [ -z "${MAXMIND_LICENSE_KEY:-}" ]; then
  echo "  - 未设置 MAXMIND_ACCOUNT_ID / MAXMIND_LICENSE_KEY，跳过 MaxMind"
fi

if [ -n "${IPINFO_TOKEN:-}" ]; then
  for kind in asn country; do
    d="$work/ipinfo-$kind"; mkdir -p "$d"
    if dl -o "$d/db.mmdb" "https://ipinfo.io/data/free/$kind.mmdb?token=$IPINFO_TOKEN" ||
      dl -o "$d/db.mmdb" "https://ipinfo.io/data/$kind.mmdb?token=$IPINFO_TOKEN"; then
      install "ipinfo-$kind.mmdb" "$d/db.mmdb"
    else
      echo "  ✗ IPinfo $kind 下载失败" >&2
    fi
  done
else
  echo "  - 未设置 IPINFO_TOKEN，跳过 IPinfo"
fi

# IPLocate 官方免费数据库（Git LFS，每日更新，无需 token）
for kind in asn country; do
  d="$work/iplocate-$kind"; mkdir -p "$d"
  if dl -o "$d/db.mmdb" "https://media.githubusercontent.com/media/iplocate/ip-address-databases/main/ip-to-$kind/ip-to-$kind.mmdb"; then
    install "iplocate-$kind.mmdb" "$d/db.mmdb"
  else
    echo "  ✗ IPLocate $kind 下载失败" >&2
  fi
done

# 纯真库（metowolf/qqwry.dat 每日发布）
d="$work/qqwry"; mkdir -p "$d"
latest="$(dl https://raw.githubusercontent.com/metowolf/qqwry.dat/refs/heads/main/version.json 2>/dev/null | grep -o '"latest"[^,}]*' | grep -o '[0-9]\{8\}' || true)"
if [ -n "$latest" ] && dl -o "$d/qqwry.dat" "https://github.com/metowolf/qqwry.dat/releases/download/$latest/qqwry.dat"; then
  install qqwry.dat "$d/qqwry.dat"
else
  echo "  ✗ QQWry 下载失败" >&2
fi

echo "== 结果"
missing=0
for name in $FILES; do
  path="$DEST/$(subdir "$name")/$name"
  if [ -s "$path" ]; then
    case " $fresh " in *" $name "*) state="最新" ;; *) state="兜底" ;; esac
    printf "  %-24s %-6s %s\n" "$name" "$state" "$(wc -c <"$path" | tr -d ' ')B"
  else
    printf "  %-24s 缺失\n" "$name" >&2
    missing=1
  fi
done
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  { echo "## Geo databases"; echo; echo "Updated from source:${fresh:- (none, using last known good)}"; } >>"$GITHUB_STEP_SUMMARY"
fi
exit "$missing"
