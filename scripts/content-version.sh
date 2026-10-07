#!/bin/sh
# 输出源码内容 hash（6 位十六进制），用作版本号的后半段：YYMMDDHHMM-<hash>。
#
# Portainer 拉取代码后会删除 .git，构建时拿不到 commit，因此改用内容 hash：
# 只由下面 PATHS 中的文件内容决定，同样的代码在任何地方构建都得到同样的 hash。
# Dockerfile 构建时调用本脚本；本地可用它找出线上版本对应的 commit：
#
#   scripts/content-version.sh            # 当前工作区
#   scripts/content-version.sh <commit>   # 某个 commit（不影响工作区）
#   for c in $(git rev-list -20 HEAD); do echo "$c $(scripts/content-version.sh "$c")"; done
#
# PATHS 中的文件必须都在构建上下文里（不能被 .dockerignore 排除）。
set -eu

PATHS="go.mod go.sum cmd internal data"

if command -v sha256sum >/dev/null 2>&1; then
  sha() { sha256sum "$@"; }
else
  sha() { shasum -a 256 "$@"; } # macOS
fi

# 文件按路径排序后逐个计算 sha256，再对整个列表取 sha256。路径中不含空格（见 git ls-files）。
# find 单独执行：放在管道中间时失败会被吞掉，静默得到空内容的 hash
content_hash() {
  (
    cd "$1"
    # shellcheck disable=SC2086
    files="$(find $PATHS -type f)"
    [ -n "$files" ] || { echo "content-version: no files under $PATHS" >&2; exit 1; }
    sums="$(printf '%s\n' "$files" | LC_ALL=C sort | while read -r f; do sha "$f" || exit 1; done)"
    printf '%s\n' "$sums" | sha | cut -c1-6
  )
}

if [ $# -eq 0 ]; then
  content_hash "$(dirname "$0")/.."
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
# shellcheck disable=SC2086
git archive "$1" -- $PATHS | tar -x -C "$tmp"
content_hash "$tmp"
