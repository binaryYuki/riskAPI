#!/usr/bin/env python3
"""离线还原蜜罐日志、标记文件和导出中被混淆的内容，不需要服务在运行。

它是一个文本过滤器：逐行读入，把认得出的内容换成明文后原样输出，其余内容不动。
  - 来源标识（32 位十六进制）      -> IPv4 地址，或 IPv6 的 /64 网段
    出现在：蜜罐事件日志的 source / issued_to、标记文件、/api/export 的 "# honeytrap" 行
  - 访问日志中封存的行（sealed）  -> 原始字段（method、path、status、latency、client_ip、correlation_id）

密钥从环境变量 HONEYTRAP_SECRET 读取，或用 --env-file 指向部署所用的 .env；
必须与写入这些内容时服务使用的密钥相同。密钥不对时内容保持原样：封存的行会被计数并以非零状态退出，
来源标识则无从判断（它与普通的 32 位十六进制串无法区分），只会体现在"还原了 0 个"上。
运行时的提示信息用英文输出，避免在非 UTF-8 终端上乱码。

用法：
  export HONEYTRAP_SECRET=...            # 或加 --env-file .env
  docker compose logs --no-log-prefix server | scripts/honeytrap-reveal.py
  scripts/honeytrap-reveal.py honeytrap-flagged.jsonl
  curl -s https://example.com/api/export | grep '^# honeytrap' | scripts/honeytrap-reveal.py

依赖：Python 3.8+ 和 cryptography 包（pip install cryptography）。
算法与 internal/honeytrap/obfuscate.go 一致，那边改动时这里要同步。
"""

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import sys

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("the cryptography package is required: pip install cryptography")

SOURCE_ID = re.compile(r"(?<![0-9A-Za-z_-])[0-9a-f]{32}(?![0-9A-Za-z_-])")
SEALED_JSON = re.compile(r'"sealed":"([A-Za-z0-9_-]+)"')
SEALED_TEXT = re.compile(r"\bsealed=([A-Za-z0-9_-]+)")
V4_MAPPED = bytes(10) + b"\xff\xff"


def derive_key(purpose, secret):
    """与服务端相同的密钥派生：SHA-256("riskapi/honeytrap/<用途>/v1" + 0x00 + 密钥)"""
    return hashlib.sha256(f"riskapi/honeytrap/{purpose}/v1\0".encode() + secret.encode()).digest()


class Revealer:
    def __init__(self, secret):
        self.source_cipher = Cipher(algorithms.AES(derive_key("source", secret)), modes.ECB())
        self.line_cipher = AESGCM(derive_key("line", secret))
        self.sources = self.lines = self.failed_lines = 0

    def source(self, source_id):
        """来源标识是对 16 字节地址做的一次 AES-256 单块加密。
        解密结果只有两种合法形态，都不是则说明它不是来源标识（如请求 ID），或密钥不对"""
        decryptor = self.source_cipher.decryptor()
        plain = decryptor.update(bytes.fromhex(source_id)) + decryptor.finalize()
        if plain[:12] == V4_MAPPED:
            return str(ipaddress.IPv4Address(plain[12:]))
        if plain[8:] == bytes(8):
            return f"{ipaddress.IPv6Address(plain)}/64"
        return None

    def line(self, sealed):
        """封存的行：URL 安全 Base64（无填充），前 12 字节是随机数，其余是 AES-256-GCM 密文"""
        try:
            raw = base64.urlsafe_b64decode(sealed + "=" * (-len(sealed) % 4))
            return self.line_cipher.decrypt(raw[:12], raw[12:], None).decode()
        except (InvalidTag, ValueError):
            return None

    def reveal(self, text):
        def sealed_json(match):
            plain = self.line(match.group(1))
            if plain is None:
                self.failed_lines += 1
                return match.group(0)
            self.lines += 1
            return plain.strip()[1:-1]  # 去掉外层花括号，字段并入原来的 JSON 对象

        def sealed_text(match):
            plain = self.line(match.group(1))
            if plain is None:
                self.failed_lines += 1
                return match.group(0)
            self.lines += 1
            return " ".join(f"{k}={v}" for k, v in json.loads(plain).items())

        def source_id(match):
            source = self.source(match.group(0))
            if source is None:
                return match.group(0)
            self.sources += 1
            return source

        text = SEALED_JSON.sub(sealed_json, text)
        text = SEALED_TEXT.sub(sealed_text, text)
        return SOURCE_ID.sub(source_id, text)


def read_secret(env_file):
    if env_file:
        with open(env_file, encoding="utf-8") as f:
            for line in f:
                key, sep, value = line.strip().partition("=")
                if sep and key == "HONEYTRAP_SECRET":
                    return value
        sys.exit(f"HONEYTRAP_SECRET not found in {env_file}")
    return os.environ.get("HONEYTRAP_SECRET", "")


def main():
    parser = argparse.ArgumentParser(description="Reveal obfuscated sources and sealed access log lines from honeypot logs, the flag file and /api/export, offline.")
    parser.add_argument("files", nargs="*", help="files to process; reads standard input when omitted")
    parser.add_argument("--env-file", help="read HONEYTRAP_SECRET from this .env file instead of the environment")
    args = parser.parse_args()

    secret = read_secret(args.env_file)
    if not secret:
        sys.exit("no key: set HONEYTRAP_SECRET in the environment or pass --env-file")
    revealer = Revealer(secret)

    out = open(sys.stdout.fileno(), "w", encoding="utf-8", newline="", closefd=False)
    streams = [open(p, "rb") for p in args.files] or [sys.stdin.buffer]
    for stream in streams:
        for raw in stream:
            out.write(revealer.reveal(raw.decode("utf-8", errors="replace")))
    out.flush()

    print(f"revealed {revealer.sources} source id(s) and {revealer.lines} sealed access log line(s)", file=sys.stderr)
    if revealer.failed_lines:
        print(f"{revealer.failed_lines} sealed line(s) could not be revealed: wrong key, or the content was altered", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
