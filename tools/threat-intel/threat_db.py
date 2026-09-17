"""威胁情报离线库核心模块

数据源（全部权威、免费、可查证，汇报时可引用来源名称）：
  - Spamhaus DROP                恶意IP段（僵尸网络 / 垃圾邮件控制服务器）
  - blocklist.de                 外部攻击源（SSH爆破 / Web攻击 / 端口扫描）
  - CINSscore                    恶意IP（经主动探测确认活跃）
  - Proofpoint ET Open           失陷IP（ET Open 规则集附带，工作日每日更新）
  - FireHOL Level1               聚合恶意段（聚合400+黑名单中的低误报精选）
  - IPsum Level3                 聚合恶意IP（30+黑名单交叉命中≥3次，按阈值过滤降噪）
  - abuse.ch ThreatFox           C2 IOC（僵尸网络C2，需免费 Auth-Key）

选型依据：《IP 威胁情报库分类指南》（自动化封禁优先"可直接下载的 Feed"类源）——
前 6 个属「可直接下载 Feed + 免费」类，适合直接拉取做封堵；ThreatFox 虽有 API 形态，
但其 C2 IOC 质量最高、且是 abuse.ch 指定的 C2 情报入口（Feodo 已停更的继任者），
故通过免费 Auth-Key 接入。其余纯 API 查询型（AbuseIPDB / VirusTotal / 微步 / GreyNoise）
用于告警富化与人工研判，不进入本建库链路。

许可提示：免费≠可商用（Spamhaus 非商用、abuse.ch 系 CC0、ET Open 为 BSD 许可），
商用封堵前请核对各源许可证或采购企业版。

凭据：ThreatFox 需环境变量 THREATFOX_API_KEY（abuse.ch 免费注册后在 GitHub
仓库配为同名的 Actions Secret）。**未配置时该源标记为 skip 而非 fail**，
不阻塞建库——本地/MCP 无凭据照常工作，云端配好 Secret 后自动启用。

本地建库、离线秒查，避免在线 API 免 Key 通道不稳定问题。
解析时过滤私网/保留/回环/组播地址（部分聚合列表含 bogon 段，避免内网IP误报）。

已停用/不再收录的源（勿重复添加）：
  - Spamhaus EDROP：官方已并入 DROP（edrop.txt 仅剩注释，解析结果恒为 0 条）
  - Feodo Tracker：最后更新 2026-03-04、全网仅剩 5 条，已停更（ThreatFox 是其继任者）
  - abuse.ch SSLBL：最后更新 2025-01-02，文件仅剩注释，已停更
  - DShield block.txt：格式为 "起始 结束 掩码" 三列，且仅约 20 条 /24，价值有限
"""

import datetime
import ipaddress
import json
import os
import re
import urllib.error
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
RAW_DIR = os.path.join(DATA_DIR, "raw")
DB_FILE = os.path.join(DATA_DIR, "db.json")

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) threat-intel-mcp/1.0"

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
    # API 型源（需凭据），无 THREATFOX_API_KEY 时整源 skip
    {
        "key": "threatfox",
        "api": "threatfox",
        "file": "threatfox_c2_ips.txt",
        "fmt": "ip",
        "label": "abuse.ch ThreatFox C2 IOC",
    },
]

MAX_AGE_HOURS = 24  # 威胁库超过24小时未更新则提示刷新
DOWNLOAD_ATTEMPTS = 2  # 每个地址的尝试次数：境外源间歇性读超时，单次失败即放弃会造成整源缺失

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
THREATFOX_DAYS = 7  # 回看天数：C2 IOC 生命周期较长，取一周窗口而非仅最近 24h


class SourceSkipped(Exception):
    """源因缺少前置条件（如未配置凭据）被跳过——不算失败，不计入"全源失败"判定"""


def _ensure_dirs():
    os.makedirs(RAW_DIR, exist_ok=True)


def _clean_token(line):
    """去掉注释行/行内注释/空行，返回首个有效token"""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    line = re.split(r"[;#]", line)[0].strip()
    return line if line else None


def _is_bogon(obj):
    """非公网地址（私网/保留/组播/回环/link-local）——聚合列表常含 bogon 段，
    不过滤会把内网 IP 误判为威胁。"""
    return (
        not obj.is_global
        or obj.is_reserved
        or obj.is_multicast
        or obj.is_loopback
        or obj.is_link_local
    )


def _http_get(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _extract_ip(value):
    """从 ThreatFox 的 ioc 字段取 IP：形如 "1.2.3.4:443"（含端口）或纯 IP"""
    text = str(value).strip()
    for cand in (text, text.rsplit(":", 1)[0]):
        try:
            return ipaddress.ip_address(cand)
        except ValueError:
            continue
    return None


def _fetch_threatfox(src):
    """ThreatFox（abuse.ch）C2 IOC：POST get_ioc，需免费 Auth-Key。

    只取 ioc_type 以 ip 开头的条目（本库只索引 IP/网段，域名与哈希不入库）；
    落地为解析后的 IP 列表，便于排查当日实际抓到了什么。
    """
    key = (os.environ.get("THREATFOX_API_KEY") or "").strip()
    if not key:
        raise SourceSkipped("未配置 THREATFOX_API_KEY（abuse.ch 免费注册后配为 GitHub Secret）")

    payload = json.dumps({"query": "get_ioc", "days": THREATFOX_DAYS}).encode("utf-8")
    last_err, raw = None, None
    for _ in range(DOWNLOAD_ATTEMPTS):
        req = urllib.request.Request(
            THREATFOX_API,
            data=payload,
            method="POST",
            headers={"User-Agent": _UA, "Auth-Key": key, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                raw = r.read()
            break
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise SourceSkipped(f"THREATFOX_API_KEY 无效或未授权（HTTP {e.code}）")
            last_err = e
        except Exception as e:
            last_err = e
    if raw is None:
        raise last_err if last_err else RuntimeError("ThreatFox 请求失败")

    data = json.loads(raw.decode("utf-8", "replace"))
    if data.get("query_status") != "ok":
        raise RuntimeError(f"ThreatFox 返回 query_status={data.get('query_status')}")

    ips, seen = [], set()
    for item in data.get("data") or []:
        if not str(item.get("ioc_type", "")).startswith("ip"):
            continue
        obj = _extract_ip(item.get("ioc", ""))
        if obj is None or _is_bogon(obj):
            continue
        s = str(obj)
        if s in seen:
            continue
        seen.add(s)
        ips.append(s)

    body = "\n".join(ips) + ("\n" if ips else "")
    with open(os.path.join(RAW_DIR, src["file"]), "w", encoding="utf-8") as f:
        f.write(body)
    return [{"ip": ip, "source": src["key"]} for ip in ips], len(ips)


def _download_source(src):
    """下载单个源（支持 urls 多地址回退 + 每地址重试），返回 (解析后的记录列表, 原始行数)

    urls 多地址回退是必需的：jsdelivr CDN 与 raw.githubusercontent.com 在不同网络
    环境下可达性互补（实测本机 jsdelivr 超时而 raw 正常），单地址源一旦被墙即整源失效。
    重试同样必要：境外源（如 Spamhaus）会间歇性读超时，实测同一天内一次成功、一次失败。
    """
    if src.get("api") == "threatfox":
        return _fetch_threatfox(src)

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
            # 以首地址属性判定（网络级属性对 224.0.0.0/3 等聚合段不可靠）
            if _is_bogon(net.network_address):
                continue
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
            if _is_bogon(ip_obj):
                continue
            key = str(ip_obj)
            if key in seen:
                continue
            seen.add(key)
            records.append({"ip": key, "source": src["key"]})
    return records, text.count("\n")


def update_db(verbose=False):
    """下载全部源并重建本地库。单源失败/跳过不影响其他源。"""
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
        except SourceSkipped as e:
            result[src["key"]] = {"status": "skip", "note": str(e)[:150]}
            if verbose:
                print(f"[SKIP] {src['key']}: {str(e)[:120]}", flush=True)
        except Exception as e:
            result[src["key"]] = {"status": "fail", "error": str(e)[:150]}
            if verbose:
                print(f"[FAIL] {src['key']}: {str(e)[:120]}", flush=True)

    # 序列化（cidr 转字符串；net 对象在加载时重建）
    db = {
        "updated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sources": {
            k: {"label": next(s["label"] for s in SOURCES if s["key"] == k), **v}
            for k, v in result.items()
        },
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
