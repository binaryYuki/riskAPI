import subprocess
import json

url = "https://www.gstatic.com/ipranges/cloud.json"
output_file = "../output/gcp.txt"

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
        if "ipv4Prefix" in prefix:
            cidrs.add(prefix["ipv4Prefix"])
        if "ipv6Prefix" in prefix:
            cidrs.add(prefix["ipv6Prefix"])
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
