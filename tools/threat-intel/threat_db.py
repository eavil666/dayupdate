"""威胁情报离线库核心模块

数据源（全部权威、免费、可直接下载的 Feed，汇报时可引用来源名称）：
  - Spamhaus DROP                恶意IP段（僵尸网络 / 垃圾邮件控制服务器）
  - blocklist.de                 外部攻击源（SSH爆破 / Web攻击 / 端口扫描）
  - CINSscore                    恶意IP（经主动探测确认活跃）
  - Feodo Tracker                僵尸网络C2（Emotet / TrickBot / Dridex 等）
  - Proofpoint ET Open           失陷IP（ET Open 规则集附带，工作日每日更新）
  - FireHOL Level1               聚合恶意段（聚合400+黑名单中的低误报精选）
  - IPsum Level3                 聚合恶意IP（30+黑名单交叉命中≥3次，按阈值过滤降噪）

选型依据：《IP 威胁情报库分类指南》（自动化封禁优先"可直接下载的 Feed"类源）——
上述均属「可直接下载 Feed + 免费」类，适合直接拉取做封堵；API 查询型（AbuseIPDB /
VirusTotal / 微步等）用于告警富化与人工研判，不在此链路。

许可提示：免费≠可商用（Spamhaus 非商用、abuse.ch 系 CC0、ET Open 为 BSD 许可），
商用封堵前请核对各源许可证或采购企业版。

本地建库、离线秒查，避免在线 API 免 Key 通道不稳定问题。
解析时过滤私网/保留/回环/组播地址（部分聚合列表含 bogon 段，避免内网IP误报）。

已停用/不再收录的源（勿重复添加）：
  - Spamhaus EDROP：官方已并入 DROP（edrop.txt 仅剩注释，解析结果恒为 0 条）
  - abuse.ch SSLBL：最后更新 2025-01-02，文件仅剩注释，已停更
  - DShield block.txt：格式为 "起始 结束 掩码" 三列，且仅约 20 条 /24，价值有限
"""

import datetime
import ipaddress
import json
import os
import re
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
RAW_DIR = os.path.join(DATA_DIR, "raw")
DB_FILE = os.path.join(DATA_DIR, "db.json")

SOURCES = [
    # Spamhaus 官方直连在国内/受限网络下常间歇性读超时；FireHOL 的 blocklist-ipsets
    # 仓库同步了同一份列表（spamhaus_drop.netset），作为镜像回退（条数略少，可接受）。
    {
        "key": "spamhaus_drop",
        "urls": [
            "https://www.spamhaus.org/drop/drop.txt",
            "https://cdn.jsdelivr.net/gh/firehol/blocklist-ipsets@master/spamhaus_drop.netset",
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_drop.netset",
        ],
        "file": "spamhaus_drop.txt",
        "fmt": "cidr",
        "label": "Spamhaus DROP 恶意IP段",
    },
    {
        "key": "blocklist_de",
        "url": "https://lists.blocklist.de/lists/all.txt",
        "file": "blocklist_de_all.txt",
        "fmt": "ip",
        "label": "blocklist.de 外部攻击源",
    },
    {
        "key": "cins_score",
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "file": "cins_ci-badguys.txt",
        "fmt": "ip",
        "label": "CINSscore 恶意IP",
    },
    {
        "key": "feodo_tracker",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "file": "feodo_ipblocklist.txt",
        "fmt": "ip",
        "label": "Feodo Tracker 僵尸网络C2",
    },
    {
        "key": "et_open",
        "urls": ["https://rules.emergingthreats.net/blockrules/compromised-ips.txt"],
        "file": "et_compromised-ips.txt",
        "fmt": "ip",
        "label": "Proofpoint ET Open 失陷IP",
    },
    {
        "key": "firehol_level1",
        "urls": [
            "https://cdn.jsdelivr.net/gh/firehol/blocklist-ipsets@master/firehol_level1.netset",
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        ],
        "file": "firehol_level1.netset",
        "fmt": "cidr",
        "label": "FireHOL Level1 聚合恶意段(低误报)",
    },
    {
        "key": "ipsum_level3",
        "urls": [
            "https://cdn.jsdelivr.net/gh/stamparm/ipsum@master/levels/3.txt",
            "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
        ],
        "file": "ipsum_level3.txt",
        "fmt": "ip",
        "label": "IPsum 聚合恶意IP(多源交叉命中)",
    },
]

MAX_AGE_HOURS = 24  # 威胁库超过24小时未更新则提示刷新
DOWNLOAD_ATTEMPTS = 2  # 每个地址的尝试次数：境外源间歇性读超时，单次失败即放弃会造成整源缺失


def _ensure_dirs():
    os.makedirs(RAW_DIR, exist_ok=True)


def _clean_token(line):
    """去掉注释行/行内注释/空行，返回首个有效token"""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    line = re.split(r"[;#]", line)[0].strip()
    return line if line else None


def _http_get(url, timeout=30):
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) threat-intel-mcp/1.0"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _download_source(src):
    """下载单个源（支持 urls 多地址回退 + 每地址重试），返回 (解析后的记录列表, 原始行数)

    urls 多地址回退是必需的：jsdelivr CDN 与 raw.githubusercontent.com 在不同网络
    环境下可达性互补（实测本机 jsdelivr 超时而 raw 正常），单地址源一旦被墙即整源失效。
    重试同样必要：境外源（如 Spamhaus）会间歇性读超时，实测同一天内一次成功、一次失败。
    """
    urls = src.get("urls") or [src["url"]]
    raw, last_err = None, None
    for u in urls:
        for _ in range(DOWNLOAD_ATTEMPTS):
            try:
                raw = _http_get(u)
                break
            except Exception as e:
                last_err = e
        if raw is not None:
            break
    if raw is None:
        raise last_err if last_err else RuntimeError("无可用下载地址")
    text = raw.decode("utf-8", "replace")
    raw_path = os.path.join(RAW_DIR, src["file"])
    with open(raw_path, "wb") as f:
        f.write(raw)

    records = []
    seen = set()
    for line in text.splitlines():
        tok = _clean_token(line)
        if not tok:
            continue
        if src["fmt"] == "cidr":
            # 形如 "1.2.3.0/24" 或 "1.2.3.4"
            cidr = tok if "/" in tok else tok + "/32"
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            na = net.network_address  # 以首地址属性判定（网络级属性对 224.0.0.0/3 等聚合段不可靠）
            if not na.is_global or na.is_reserved or na.is_multicast or na.is_loopback or na.is_link_local:
                continue  # 跳过私网/保留/回环/组播段，避免内网IP误报
            key = str(net)
            if key in seen:
                continue
            seen.add(key)
            records.append({"net": key, "source": src["key"]})
        else:
            try:
                ip_obj = ipaddress.ip_address(tok)
            except ValueError:
                continue
            if (
                not ip_obj.is_global
                or ip_obj.is_reserved
                or ip_obj.is_multicast
                or ip_obj.is_loopback
                or ip_obj.is_link_local
            ):
                continue  # 同上，过滤非公网地址
            key = str(ip_obj)
            if key in seen:
                continue
            seen.add(key)
            records.append({"ip": key, "source": src["key"]})
    return records, text.count("\n")


def update_db(verbose=False):
    """下载全部源并重建本地库。单源失败不影响其他源。"""
    _ensure_dirs()
    result = {}
    ip_sets = {}  # source -> set(ip)
    cidr_list = []  # [{"net": <ip_network>, "net_str": "...", "source": ...}]

    for src in SOURCES:
        try:
            records, raw_lines = _download_source(src)
            cnt = len(records)
            if src["fmt"] == "cidr":
                for r in records:
                    cidr_list.append(
                        {
                            "net": ipaddress.ip_network(r["net"], strict=False),
                            "net_str": r["net"],
                            "source": r["source"],
                        }
                    )
            else:
                ip_sets[src["key"]] = {r["ip"] for r in records}
            result[src["key"]] = {"status": "ok", "count": cnt, "raw_lines": raw_lines}
            if verbose:
                print(f"[OK] {src['key']}: {cnt} 条", flush=True)
        except Exception as e:
            result[src["key"]] = {"status": "fail", "error": str(e)[:150]}
            if verbose:
                print(f"[FAIL] {src['key']}: {str(e)[:120]}", flush=True)

    # 序列化（cidr 转字符串；net 对象在加载时重建）
    db = {
        "updated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sources": {k: {"label": next(s["label"] for s in SOURCES if s["key"] == k), **v} for k, v in result.items()},
        "ip_sets": {k: sorted(v) for k, v in ip_sets.items()},
        "cidrs": [{"net_str": c["net_str"], "source": c["source"]} for c in cidr_list],
    }
    db["total_ips"] = sum(len(v) for v in ip_sets.values())
    db["total_cidrs"] = len(cidr_list)

    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=1)
    return db


def load_db():
    """加载本地库，cidr 字符串转为 ip_network 对象便于匹配"""
    if not os.path.exists(DB_FILE):
        return None
    with open(DB_FILE, encoding="utf-8") as f:
        db = json.load(f)
    db["_cidr_nets"] = []
    for c in db.get("cidrs", []):
        try:
            db["_cidr_nets"].append(
                {
                    "net": ipaddress.ip_network(c["net_str"], strict=False),
                    "net_str": c["net_str"],
                    "source": c["source"],
                }
            )
        except ValueError:
            pass
    return db


def _age_hours(db):
    try:
        t = datetime.datetime.strptime(db["updated_at"], "%Y-%m-%d %H:%M:%S")
        return (datetime.datetime.now() - t).total_seconds() / 3600
    except Exception:
        return None


def check_ip(ip_str):
    """查询单个IP是否命中威胁库。返回命中列表（可多条）。"""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return {"error": f"无效 IP 地址: {ip_str}", "hits": []}

    db = load_db()
    if db is None:
        return {"error": "威胁库尚未初始化，请先调用 threat_intel_update 建库", "hits": []}

    ip_s = str(ip)
    hits = []
    for src_key, lst in db.get("ip_sets", {}).items():
        if ip_s in lst:
            label = db["sources"].get(src_key, {}).get("label", src_key)
            hits.append({"source": src_key, "source_label": label, "type": "精确IP命中", "match": ip_s})
    for c in db.get("_cidr_nets", []):
        if ip in c["net"]:
            label = db["sources"].get(c["source"], {}).get("label", c["source"])
            hits.append({"source": c["source"], "source_label": label, "type": "IP段命中", "match": c["net_str"]})

    return {
        "ip": ip_s,
        "verdict": "malicious" if hits else "clean",
        "hits": hits,
        "db_age_hours": round(_age_hours(db), 1) if _age_hours(db) is not None else None,
        "stale": _age_hours(db) is not None and _age_hours(db) > MAX_AGE_HOURS,
    }


def db_status():
    db = load_db()
    if db is None:
        return {"initialized": False, "msg": "威胁库尚未初始化。请先运行 threat_intel_update 下载建库。"}
    srcs = {
        k: {
            "label": v.get("label"),
            "count": v.get("count"),
            "status": v.get("status"),
            "raw_lines": v.get("raw_lines"),
        }
        for k, v in db.get("sources", {}).items()
    }
    return {
        "initialized": True,
        "updated_at": db.get("updated_at"),
        "age_hours": round(_age_hours(db), 1) if _age_hours(db) is not None else None,
        "total_ips": db.get("total_ips"),
        "total_cidrs": db.get("total_cidrs"),
        "sources": srcs,
    }


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "update":
        r = update_db(verbose=True)
        print("\n更新完成:")
        print(json.dumps(r["sources"], ensure_ascii=False, indent=1))
    else:
        print(json.dumps(db_status(), ensure_ascii=False, indent=1))
