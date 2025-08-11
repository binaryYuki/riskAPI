import subprocess

url = "https://digitalocean.com/geo/google.csv"
output_file = "../output/digitalocean.txt"

def fetch_csv_with_curl(url):
    try:
        result = subprocess.run(["curl", "-sL", url], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        content = result.stdout.decode()
        if not content.strip():
            print("❌ 下载的 CSV 内容为空")
            return None
        return content
    except subprocess.CalledProcessError as e:
        print("❌ curl 命令失败:", e.stderr.decode())
        return None

def extract_cidrs(csv_text):
    cidrs = set()
    for line in csv_text.strip().splitlines():
        line = line.strip()
        if line and ',' in line:
            cidr = line.split(",", 1)[0].strip()
            if cidr:
                cidrs.add(cidr)
    return cidrs

def write_to_file(cidrs, path):
    with open(path, "w", encoding="utf-8") as f:
        for cidr in sorted(cidrs):
            f.write(cidr + "\n")
    print(f"✅ 成功写入 {len(cidrs)} 个 CIDR 到 {path}")

def main():
    csv_text = fetch_csv_with_curl(url)
    if csv_text:
        cidrs = extract_cidrs(csv_text)
        if cidrs:
            write_to_file(cidrs, output_file)
        else:
            print("⚠️ 没有提取到任何 CIDR")

if __name__ == "__main__":
    main()
