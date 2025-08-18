#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
统一入口: 生成各云厂商/服务商 IP 列表 -> 校验是否与现有 data/idc 下文件完全一致 -> 移动覆盖。

使用方式:
  基本执行 (仅在全部与 data/idc 基准完全一致时才会覆盖并删除 output 中对应文件):
  Basic usage (will only overwrite and delete output files if they match the baseline in data/idc):
    python3 run.py

  生成并校验, 不修改 data/idc (不会复制/覆盖/删除):
    Generate and verify without modifying data/idc (no copy/overwrite/delete):
    python3 run.py --verify-only

  强制更新基准 (忽略差异, 覆盖 data/idc, 并删除 output 源文件):
    Force update baseline (ignore differences, overwrite data/idc, and delete output source files):
    python3 run.py --force

  强制更新但保留 output 目录中的生成文件 (用于排查/比对):
    Force update but keep generated files in output directory (for debugging/diffing):
    python3 run.py --force --keep-output

  仅生成并校验, 同时保留 output 文件 (调试差异过程):
    Generate and verify only, keeping output files (for debugging differences):
    python3 run.py --verify-only --keep-output

参数说明:
  --verify-only   只生成与比较, 不写入 idc 目录 (不产生副作用)
                  Only generate and compare, do not write to idc directory (no side effects)
  --force         即便存在差异也覆盖 idc 目录 (与基准更新日常操作时使用, 需人工确认)
                  Force overwrite idc directory even if differences exist (used for baseline updates, requires manual confirmation)
  --keep-output   执行后保留 output 下所有生成文件 (默认会在移动后删除它们)
                  Keep all generated files in output directory after execution (default deletes them after moving)

处理逻辑概要:
  1. 运行子脚本拉取各云厂商最新 CIDR -> 写入 data/scripts/output/*.txt
  2. 直接下载并处理额外供应商 (akamai / apple / linode / zscaler)
  3. 与 data/idc 下同名文件逐一做内容(逐行)严格比较
  4. 默认若存在任何差异则终止并返回非 0 (满足“必须完全一致”的约束)
  5. 在满足一致或使用 --force 情况下复制至 data/idc (默认复制后删除 output 源文件; 传 --keep-output 则保留)

退出码:
Exit codes:
  0  成功 (全部一致 或 使用 --force 已覆盖)
     Success (all files match or --force has been used to overwrite)
  1  存在差异且未指定 --force
     Differences found and --force not specified
  2  子脚本或下载等过程发生异常
     Exception occurred in sub-scripts or downloads

建议工作流:
  # 查看是否有变化 (安全)
  python3 run.py --verify-only

  # 若确认需要更新基准 (有差异且评估无问题)
  python3 run.py --force

  # 若想保留中间文件作进一步 diff
  python3 run.py --force --keep-output

额外说明:
  为满足“生成的文件要与现在已经存在的完全一致”这一需求, 默认发现差异会直接报错退出 (code 1)。
"""
from __future__ import annotations
import subprocess
import hashlib
import filecmp
import shutil
import sys
import json
from pathlib import Path
import argparse
import difflib

SCRIPT_DIR = Path(__file__).parent
OUTPUT_DIR = SCRIPT_DIR / "output"
IDC_DIR = SCRIPT_DIR.parent / "idc"

# 需要运行的子脚本 (保持与原 bulk.py 一致)
PROVIDER_SCRIPTS = [
    "aws/aws.py",
    "azure/azure.py",
    "gcp/get_gcp.py",
    "digitalOcean/do.py",
    "oci/oci.py",
]

# 由 run.py 内部直接下载处理的供应商 (逻辑来自 bulk.py)
EXTRA_PROVIDERS = {
    "akamai": {
        "type": "multi-txt",
        "sources": [
            "https://raw.githubusercontent.com/femueller/cloud-ip-ranges/refs/heads/master/akamai-v4-ip-ranges.txt",
            "https://raw.githubusercontent.com/femueller/cloud-ip-ranges/refs/heads/master/akamai-v6-ip-ranges.txt",
        ],
    },
    "apple": {
        "type": "csv-first-column",
        "source": "https://raw.githubusercontent.com/femueller/cloud-ip-ranges/refs/heads/master/apple-icloud-private-relay-ip-ranges.csv",
    },
    "linode": {
        "type": "geofeed",
        "source": "https://raw.githubusercontent.com/femueller/cloud-ip-ranges/refs/heads/master/linode.txt",
    },
    "zscaler": {
        "type": "json-list",
        "source": "https://raw.githubusercontent.com/femueller/cloud-ip-ranges/refs/heads/master/zscaler-cloud-ip-ranges.json",
        "json_key": "hubPrefixes",
    },
}

# 所有最终应该存在的输出文件名 (与 data/idc 下保持一致)
EXPECTED_FILES = [
    "aws.txt",
    "azure.txt",
    "gcp.txt",
    "digitalocean.txt",
    "oracle.txt",
    "akamai.txt",
    "apple.txt",
    "linode.txt",
    "zscaler.txt",
]


def run_sub_script(rel_path: str) -> None:
    script = SCRIPT_DIR / rel_path
    if not script.exists():
        print(f"⚠️ 子脚本不存在, 跳过: {rel_path}")
        return
    print(f"🚀 运行子脚本: {rel_path}")
    subprocess.run([sys.executable, str(script)], check=True, cwd=script.parent)


def curl_download(url: str) -> str | None:
    try:
        result = subprocess.run(["curl", "-sL", url], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode("utf-8", errors="ignore")
    except subprocess.CalledProcessError as e:
        print(f"❌ 下载失败: {url} => {e.stderr.decode(errors='ignore')}")
        return None


def save_sorted_unique(lines: set[str], path: Path) -> None:
    with path.open("w", encoding="utf-8") as f:
        for line in sorted(lines):
            f.write(line.strip() + "\n")
    print(f"✅ 写入 {len(lines)} 条: {path.name}")


def process_extra_providers():
    for name, meta in EXTRA_PROVIDERS.items():
        out_file = OUTPUT_DIR / f"{name}.txt"
        t = meta["type"]
        print(f"🛠️ 处理 {name} ({t})")
        if t == "multi-txt":
            lines: set[str] = set()
            for u in meta["sources"]:
                content = curl_download(u)
                if not content:
                    continue
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'):
                        lines.add(line)
            save_sorted_unique(lines, out_file)
        elif t in ("csv-first-column", "geofeed"):
            content = curl_download(meta["source"])
            if not content:
                continue
            lines: set[str] = set()
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                cidr = line.split(',', 1)[0].strip()
                if cidr:
                    lines.add(cidr)
            save_sorted_unique(lines, out_file)
        elif t == "json-list":
            content = curl_download(meta["source"])
            if not content:
                continue
            try:
                data = json.loads(content)
                key = meta["json_key"]
                lines = set(data.get(key, []))
                save_sorted_unique(lines, out_file)
            except json.JSONDecodeError:
                print(f"❌ JSON 解析失败: {name}")
        else:
            print(f"⚠️ 未知类型: {t}")


def sha256sum(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def compare_and_report(output_file: Path, idc_file: Path) -> tuple[bool, str | None]:
    if not idc_file.exists():
        return False, f"❌ 缺失基准文件: {idc_file.name}"
    if filecmp.cmp(output_file, idc_file, shallow=False):
        return True, None
    # 生成差异文本 (截取前若干行)
    with output_file.open(encoding='utf-8') as f1, idc_file.open(encoding='utf-8') as f2:
        out_lines = f1.readlines()
        base_lines = f2.readlines()
    diff = difflib.unified_diff(base_lines, out_lines, fromfile=f"idc/{idc_file.name}", tofile=f"output/{output_file.name}")
    collected = []
    for i, line in enumerate(diff):
        if i > 200:  # 限制输出
            collected.append('... (diff 省略)')
            break
        collected.append(line.rstrip('\n'))
    return False, "\n".join(collected)


def move_files(force: bool, keep_output: bool) -> list[str]:
    messages = []
    for fname in EXPECTED_FILES:
        src = OUTPUT_DIR / fname
        if not src.exists():
            messages.append(f"⚠️ 未生成: {fname}")
            continue
        dst = IDC_DIR / fname
        if dst.exists() and not force:
            # 已验证一致时再移动; 这里假设上一步已做一致性检查
            pass
        if not keep_output:
            shutil.copy2(src, dst)
            try:
                src.unlink()  # 移动后删除源文件
                messages.append(f"📦 已移动并删除源文件: {dst.relative_to(SCRIPT_DIR.parent)}")
            except OSError as e:
                messages.append(f"⚠️ 已复制但删除源文件失败 {fname}: {e}")
        else:
            shutil.copy2(src, dst)
            messages.append(f"📦 已复制(保留源文件): {dst.relative_to(SCRIPT_DIR.parent)}")
    return messages


def main():
    parser = argparse.ArgumentParser(description="统一生成并校验云厂商 IP 列表")
    parser.add_argument('--verify-only', action='store_true', help='仅生成与校验, 不移动文件')
    parser.add_argument('--force', action='store_true', help='忽略差异强制覆盖 idc 文件')
    parser.add_argument('--keep-output', action='store_true', help='保留 output 下文件 (不移动)')
    args = parser.parse_args()

    OUTPUT_DIR.mkdir(exist_ok=True)
    IDC_DIR.mkdir(exist_ok=True)

    # 1. 运行子脚本 (这些脚本自己写入 OUTPUT_DIR)
    for rel in PROVIDER_SCRIPTS:
        try:
            run_sub_script(rel)
        except subprocess.CalledProcessError as e:
            print(f"❌ 子脚本执行失败: {rel} => {e}")
            sys.exit(2)

    # 2. 处理额外供应商
    process_extra_providers()

    # 3. 校验是否都生成
    missing = [f for f in EXPECTED_FILES if not (OUTPUT_DIR / f).exists()]
    if missing:
        print(f"⚠️ 缺失生成文件: {missing}")

    # 4. 一致性检查
    all_ok = True
    diff_reports: list[str] = []
    for fname in EXPECTED_FILES:
        out_file = OUTPUT_DIR / fname
        idc_file = IDC_DIR / fname
        if not out_file.exists() or not idc_file.exists():
            if not idc_file.exists():
                print(f"⚠️ 基准不存在(首次生成?): {fname}")
            continue
        same, diff_text = compare_and_report(out_file, idc_file)
        if same:
            print(f"✅ 一致: {fname} ({sha256sum(out_file)})")
        else:
            all_ok = False
            print(f"❌ 差异: {fname}")
            if diff_text:
                diff_reports.append(diff_text)

    if not all_ok and not args.force:
        print("\n================ 差异详情(截断) ================")
        for d in diff_reports:
            print(d)
            print('----------------------------------------')
        print("发现差异, 已按要求阻止覆盖 (使用 --force 可强制覆盖)。")
        sys.exit(1)

    # 5. 移动/复制到 idc 目录 (仅在非 verify-only 且未 keep-output 情况下)
    if not args.verify_only:
        msgs = move_files(force=args.force, keep_output=args.keep_output)
        for m in msgs:
            print(m)
    else:
        print("🔍 已完成校验 (--verify-only 模式, 未移动文件)")

    if all_ok or args.force:
        print("\n🎉 完成: 所有生成文件与现有完全一致" if all_ok else "⚠️ 已强制覆盖差异文件")
    sys.exit(0 if all_ok or args.force else 1)


if __name__ == '__main__':
    main()
