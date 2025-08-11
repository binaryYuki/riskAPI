import json
import os

# 文件路径（根据实际情况修改）
input_file = os.path.join(os.path.dirname(__file__), "azure.json")
output_file = "../output/azure.txt"

def extract_cidrs(input_file, output_file):
    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    cidr_set = set()

    for item in data.get("values", []):
        prefixes = item.get("properties", {}).get("addressPrefixes", [])
        cidr_set.update(prefixes)

    # 写入文件（按 IP 排序）
    with open(output_file, "w", encoding="utf-8") as f:
        for cidr in sorted(cidr_set):
            f.write(cidr + "\n")

    print(f"成功写入 {len(cidr_set)} 个 CIDR 到 {output_file}")

if __name__ == "__main__":
    extract_cidrs(input_file, output_file)
