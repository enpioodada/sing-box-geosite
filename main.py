import os
import re
import json
import yaml
import requests
import ipaddress
import subprocess
import pandas as pd
from io import StringIO
from concurrent.futures import ThreadPoolExecutor

# ========================
# 配置
# ========================
HEADERS = {'User-Agent': 'Mozilla/5.0'}
OUTPUT_DIR = "./rule"
MAX_WORKERS = 10

MAP_DICT = {
    'DOMAIN-SUFFIX': 'domain_suffix',
    'HOST-SUFFIX': 'domain_suffix',
    'DOMAIN': 'domain',
    'HOST': 'domain',
    'DOMAIN-KEYWORD': 'domain_keyword',
    'HOST-KEYWORD': 'domain_keyword',
    'IP-CIDR': 'ip_cidr',
    'IP-CIDR6': 'ip_cidr',
    'IP6-CIDR': 'ip_cidr',
    'SRC-IP-CIDR': 'source_ip_cidr',
    'GEOIP': 'geoip',
    'DST-PORT': 'port',
    'SRC-PORT': 'source_port',
    'URL-REGEX': 'domain_regex',
    'DOMAIN-REGEX': 'domain_regex'
}

# ========================
# 工具函数
# ========================
def safe_filename(url: str) -> str:
    name = os.path.basename(url).split('?')[0]
    return name.split('.')[0]


def is_ip(address: str):
    try:
        ipaddress.ip_network(address, strict=False)
        return True
    except ValueError:
        return False


def fetch(url: str) -> str:
    r = requests.get(url, headers=HEADERS, timeout=15)
    r.raise_for_status()
    return r.text


# ========================
# 解析 YAML / TXT
# ========================
def parse_yaml(text: str):
    try:
        data = yaml.safe_load(text)
    except Exception:
        return []

    if isinstance(data, dict):
        return data.get("payload", [])
    elif isinstance(data, list):
        return data
    return []


def parse_text(text: str):
    csv_data = StringIO(text)
    df = pd.read_csv(
        csv_data,
        header=None,
        names=['pattern', 'address', 'other'],
        on_bad_lines='skip'
    )
    return df


# ========================
# 核心解析逻辑
# ========================
def parse_link(url: str) -> pd.DataFrame:
    try:
        text = fetch(url)

        # YAML 优先
        items = parse_yaml(text)

        rows = []

        if items:
            for item in items:
                item = str(item).strip().strip("'")

                if ',' in item:
                    pattern, address = item.split(',', 1)
                else:
                    address = item
                    if is_ip(address):
                        pattern = 'IP-CIDR'
                    elif address.startswith('.') or address.startswith('+'):
                        pattern = 'DOMAIN-SUFFIX'
                        address = address.lstrip('.+')
                    else:
                        pattern = 'DOMAIN'

                rows.append((pattern.strip(), address.strip().lower()))

            return pd.DataFrame(rows, columns=['pattern', 'address'])

        # fallback 文本解析
        df = parse_text(text)
        df = df[['pattern', 'address']]
        df['address'] = df['address'].astype(str).str.lower()
        return df

    except Exception as e:
        print(f"❌ 解析失败: {url} | {e}")
        return pd.DataFrame(columns=['pattern', 'address'])


# ========================
# 转换为 sing-box 规则
# ========================
def build_rules(df: pd.DataFrame) -> dict:
    df = df.dropna()
    df = df[~df['pattern'].str.contains('#', na=False)]

    df['pattern'] = df['pattern'].str.strip()
    df = df[df['pattern'].isin(MAP_DICT.keys())]

    df['pattern'] = df['pattern'].map(MAP_DICT)
    df = df.drop_duplicates()

    result = {"version": 2, "rules": []}

    grouped = df.groupby('pattern')['address'].apply(list).to_dict()

    for pattern, values in grouped.items():
        result["rules"].append({
            pattern: sorted(set(values))
        })

    return result


# ========================
# 编译 srs
# ========================
def compile_srs(json_path: str):
    srs_path = json_path.replace(".json", ".srs")
    try:
        subprocess.run(
            ["sing-box", "rule-set", "compile", "--output", srs_path, json_path],
            check=True
        )
    except Exception as e:
        print(f"⚠️ 编译失败: {json_path} | {e}")


# ========================
# 主处理流程
# ========================
def process_link(url: str):
    name = safe_filename(url)
    json_path = os.path.join(OUTPUT_DIR, f"{name}.json")

    df = parse_link(url)

    if df.empty:
        return None

    rules = build_rules(df)

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(rules, f, ensure_ascii=False, indent=2, sort_keys=True)

    compile_srs(json_path)

    print(f"✅ 完成: {name}")
    return json_path


# ========================
# 主入口
# ========================
def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with open("../links.txt", "r") as f:
        links = [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(executor.map(process_link, links))

    print("\n🎉 全部完成！")


if __name__ == "__main__":
    main()
