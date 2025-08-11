import subprocess
import json
import os


scripts = [
    "aws/aws.py",
    "azure/azure.py",
    "gcp/get_gcp.py",
    "digitalOcean/do.py",
    "oci/oci.py",
]

def run_script(script_path):
    print(f"\n🚀 正在执行: {script_path}")
    try:
        subprocess.run(["python3", script_path], check=True)
        print(f"✅ 完成: {script_path}")
    except subprocess.CalledProcessError as e:
        print(f"❌ 失败: {script_path}\n错误信息: {e}")

def download(url):
    try:
        result = subprocess.run(["curl", "-sL", url], check=True, stdout=subprocess.PIPE)
        return result.stdout.decode()
    except subprocess.CalledProcessError as e:
        print(f"❌ 下载失败: {url}")
        return None

def save_lines_to_file(lines, filepath):
    with open(filepath, "w", encoding="utf-8") as f:
        for line in sorted(lines):
            f.write(line.strip() + "\n")
    print(f"✅ 写入 {len(lines)} 条记录到 {filepath}")

# 处理 Akamai IPv4 + IPv6 txt 合并
def process_akamai():
    urls = [
        "https://raw.githubusercontent.com/femueller/cloud-ip-ranges/refs/heads/master/akamai-v4-ip-ranges.txt",
        "https://raw.githubusercontent.com/femueller/cloud-ip-ranges/refs/heads/master/akamai-v6-ip-ranges.txt"
    ]
    all_lines = set()
    for url in urls:
        content = download(url)
        if content:
            for line in content.strip().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    all_lines.add(line)
    save_lines_to_file(all_lines, "akamai.txt")

# 处理 Apple iCloud Private Relay CSV
def process_apple():
    url = "https://raw.githubusercontent.com/femueller/cloud-ip-ranges/refs/heads/master/apple-icloud-private-relay-ip-ranges.csv"
    content = download(url)
    if not content:
        return
    lines = set()
    for line in content.strip().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            cidr = line.split(",", 1)[0]
            lines.add(cidr)
    save_lines_to_file(lines, "apple.txt")

# 处理 Linode geofeed 文件（RFC8805）
def process_linode():
    url = "https://raw.githubusercontent.com/femueller/cloud-ip-ranges/refs/heads/master/linode.txt"
    content = download(url)
    if not content:
        return
    lines = set()
    for line in content.strip().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            cidr = line.split(",", 1)[0]
            lines.add(cidr)
    save_lines_to_file(lines, "linode.txt")

# 处理 Zscaler JSON 文件
def process_zscaler():
    url = "https://raw.githubusercontent.com/femueller/cloud-ip-ranges/refs/heads/master/zscaler-cloud-ip-ranges.json"
    content = download(url)
    if not content:
        return
    try:
        data = json.loads(content)
        cidrs = set(data.get("hubPrefixes", []))
        save_lines_to_file(cidrs, "zscaler.txt")
    except json.JSONDecodeError as e:
        print("❌ 解析 Zscaler JSON 失败")

def main():
    for script in scripts:
        if os.path.exists(script):
            run_script(script)
        else:
            print(f"⚠️ 跳过: {script} 文件不存在")
    print("\n🎉 所有脚本执行完成！")

    os.makedirs("output", exist_ok=True)
    os.chdir("output")
    process_akamai()
    process_apple()
    process_linode()
    process_zscaler()
    print("\n🎉 所有数据同步完成！")

if __name__ == "__main__":
    main()
