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

if [ -n "${MAXMIND_ACCOUNT_ID:-}" ] && [ -n "${MAXMIND_LICENSE_KEY:-}" ]; then
  for edition in GeoLite2-ASN GeoLite2-Country; do
    d="$work/maxmind-$edition"; mkdir -p "$d"
    if dl -u "$MAXMIND_ACCOUNT_ID:$MAXMIND_LICENSE_KEY" -o "$d/db.tar.gz" \
      "https://download.maxmind.com/geoip/databases/$edition/download?suffix=tar.gz" &&
      tar -xzf "$d/db.tar.gz" -C "$d"; then
      install "$edition.mmdb" "$(find "$d" -name "$edition.mmdb" | head -n1)"
    else
      echo "  ✗ MaxMind $edition 下载失败" >&2
    fi
  done
else
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
