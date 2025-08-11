import subprocess
import json

url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
output_file = "../output/aws.txt"

def fetch_json_with_curl(url):
    try:
        result = subprocess.run(["curl", "-s", url], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print("curl 命令失败:", e.stderr.decode())
        return None
    except json.JSONDecodeError as e:
        print("解析 JSON 失败:", str(e))
        return None

def extract_cidrs(data):
    cidrs = set()
    for prefix in data.get("prefixes", []):
        if "ip_prefix" in prefix:
            cidrs.add(prefix["ip_prefix"])
    for prefix in data.get("ipv6_prefixes", []):
        if "ipv6_prefix" in prefix:
            cidrs.add(prefix["ipv6_prefix"])
    return cidrs

def write_to_file(cidrs, path):
    with open(path, "w", encoding="utf-8") as f:
        for cidr in sorted(cidrs):
            f.write(cidr + "\n")
    print(f"成功写入 {len(cidrs)} 个 CIDR 到 {path}")

def main():
    data = fetch_json_with_curl(url)
    if data:
        cidrs = extract_cidrs(data)
        write_to_file(cidrs, output_file)

if __name__ == "__main__":
    main()
