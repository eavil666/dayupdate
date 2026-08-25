"""threat_check.py - 威胁分级检查模块（基于公开威胁源，无需 API Key）

对 IP 集合做"公开威胁源匹配 + 分级"：
  - 数据源：Emerging Threats / Abuse.ch Feodo Tracker / Blocklist.de（公开 IP 黑名单）
  - 下载一次后磁盘缓存 6 小时，避免每次生成都等网络
  - 分级：命中 2+ 源 -> Critical（实锤已知恶意）；命中 1 源 -> High；未命中 -> Clean
  - 全部降级：网络不可达/超时 -> 返回空名单（调用方显示"未查"），不阻塞主流程

用法：
    import threat_check
    bad, detail = threat_check.load_bad_ips(cache_file)   # 返回 (set, {ip: [源名]})
    level = threat_check.check_ip(ip, bad)                 # 单 IP 分级
"""

import json
import os
import time
import urllib.request

# 公开威胁源（IP 黑名单）
THREAT_FEEDS = {
    "EmergingThreats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "AbuseFeodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "BlocklistDE": "https://lists.blocklist.de/lists/all.txt",
}
# 缓存有效期（秒）：6 小时
CACHE_TTL = 6 * 3600
DOWNLOAD_TIMEOUT = 20


def _download_ips(url):
    """下载威胁源并解析为 IP 集合（支持 CIDR 前缀截断）。失败返回 None。"""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "daily-report-threat-check/1.0"})
        with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
        ips = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            token = line.split()[0]
            # 截断 CIDR（黑名单多为单 IP，CIDR 简化为网络地址也够用）
            if "/" in token:
                token = token.split("/")[0]
            # 只收合法 IPv4
            parts = token.split(".")
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                ips.add(token)
        return ips
    except Exception:
        return None


def load_bad_ips(cache_file=None):
    """加载威胁名单，返回 (bad_ips:set, sources:dict[ip->[源名]])。

    cache_file 提供时优先读缓存（6 小时内有效）；下载失败且无缓存时返回空。
    """
    # 1) 缓存命中
    if cache_file and os.path.exists(cache_file):
        try:
            with open(cache_file, encoding="utf-8") as f:
                cache = json.load(f)
            if time.time() - cache.get("ts", 0) < CACHE_TTL and "sources" in cache:
                sources = cache["sources"]
                bad = set(sources.keys())
                return bad, sources
        except Exception:
            pass

    # 2) 重新下载
    sources = {}
    for name, url in THREAT_FEEDS.items():
        ips = _download_ips(url)
        if ips:
            for ip in ips:
                sources.setdefault(ip, []).append(name)
            print(f"[threat] {name}: {len(ips)} 条")

    # 3) 写缓存（即使部分失败也缓存已有结果；全失败则不动旧缓存）
    if sources and cache_file:
        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump({"ts": time.time(), "sources": sources}, f, ensure_ascii=False)
        except Exception:
            pass
    return set(sources.keys()), sources


def check_ip(ip, bad_ips, sources=None):
    """单 IP 威胁分级。返回 (level, detail)。

    level: Critical(2+源) / High(1源) / Clean(无记录)
    detail: 命中源名列表（未命中为空）
    """
    if ip in bad_ips:
        hits = sources.get(ip, ["未知源"]) if sources else ["命中"]
        if len(hits) >= 2:
            return "Critical", hits
        return "High", hits
    return "Clean", []
