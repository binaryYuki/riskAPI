import subprocess
import json

url = "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json"
output_file = "../output/oracle.txt"

def fetch_json_with_curl(url):
    try:
        result = subprocess.run(["curl", "-sL", url], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print("❌ curl 命令失败:", e.stderr.decode())
        return None
    except json.JSONDecodeError as e:
        print("❌ JSON 解析失败:", str(e))
        return None

def extract_cidrs(data):
    cidrs = set()
    for region in data.get("regions", []):
        for cidr_entry in region.get("cidrs", []):
            cidr = cidr_entry.get("cidr")
            if cidr:
                cidrs.add(cidr)
    return cidrs

def write_to_file(cidrs, path):
    with open(path, "w", encoding="utf-8") as f:
        for cidr in sorted(cidrs):
            f.write(cidr + "\n")
    print(f"✅ 成功写入 {len(cidrs)} 个 CIDR 到 {path}")

def main():
    data = fetch_json_with_curl(url)
    if data:
        cidrs = extract_cidrs(data)
        if cidrs:
            write_to_file(cidrs, output_file)
        else:
            print("⚠️ 没有提取到任何 CIDR")

if __name__ == "__main__":
    main()
