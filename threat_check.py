"""threat_check.py - 威胁分级检查模块（本地情报库优先 + 公开威胁源兜底）

数据链路（v1.8 起）：
  1) 优先：exe/脚本同目录 threat_db.json —— 本地 5 源情报库（每日由自动化任务刷新并
     发布到 GitHub Release，供多端分发）。含两类匹配：
       - 精确 IP 命中：blocklist.de / CINSscore / Feodo Tracker
       - CIDR 恶意段命中：Spamhaus DROP / EDROP（如 1.2.3.0/24 内的源 IP 也算命中）
  2) 兜底：threat_db.json 缺失/无效时，联网下载 3 个公开源（Emerging Threats /
     Abuse.ch Feodo Tracker / blocklist.de），磁盘缓存 6 小时，避免每次生成都等网络
  3) 全失败：返回空名单（调用方显示"未查"），不阻塞主流程

命中分级：命中 2+ 源 -> Critical（实锤已知恶意）；命中 1 源 -> High；未命中 -> Clean。
说明：3 源中的 blocklist.de / Feodo 与 5 源情报库同源，联网兜底仅覆盖"无情报库"场景，
     不做加法合并（Emerging Threats 实测无增量贡献）。

用法：
    from threat_check import load_bad_ips, match_ip, update_intel
    bad, detail = load_bad_ips(cache_file)   # 兼容旧接口：返回 (精确命中IP集合, {ip: [源]})
    labels = match_ip(ip)                    # 统一命中查询（精确+恶意段），空列表=未命中
    ok, msg = update_intel()                 # 官方 GitHub + 加速镜像并行测速择优下载最新情报库
"""

import concurrent.futures
import ipaddress
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from common import runtime_dir

# ---------------- 本地情报库（threat_db.json）配置 ----------------
INTEL_DB_FILENAME = "threat_db.json"
# 固定 tag Release 的 asset 下载地址（无需每次发布新正式版；由每日自动化覆盖上传）
GITHUB_INTEL_URL = "https://github.com/eavil666/dayupdate/releases/download/threat-intel-latest/threat_db.json"
# 国内加速镜像前缀（前缀代理：<镜像>/<完整官方URL>）。官方 GitHub 偶发不可达时，
# 下载更新会并行探测"官方+镜像"择优使用、失败自动轮换——写死的域名可能失效，探测自动剔除。
INTEL_MIRRORS = [
    "https://mirror.ghproxy.com/",
    "https://ghfast.top/",
    "https://gh-proxy.com/",
    "https://ghproxy.net/",
    "https://gh.llkk.cc/",
    "https://hub.gitmirror.com/",
]
# 择优探测参数：并行对每个候选发 Range 请求取前 PROBE_BYTES 字节计时，单源超时 PROBE_TIMEOUT 秒
PROBE_TIMEOUT = 5
PROBE_BYTES = 131072  # 128KB 测速窗口
# 远端版本比对：Range 只取文件头 REMOTE_HEAD_BYTES 字节即含首个键 updated_at（db.json 生成时排最前），
# 无需完整下载 1MB 即可判断"是否有新版"
REMOTE_HEAD_BYTES = 2048
# 情报库超过该时长未更新时，加载/更新提示"可刷新"（不自动联网，避免阻塞日报生成）
INTEL_MAX_AGE_HOURS = 30
DOWNLOAD_TIMEOUT = 30
DOWNLOAD_UA = "daily-report-threat-check/1.8"

# ---------------- 兜底公开威胁源（仅本地情报库缺失时使用） ----------------
THREAT_FEEDS = {
    "EmergingThreats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "AbuseFeodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "BlocklistDE": "https://lists.blocklist.de/lists/all.txt",
}
# 缓存有效期（秒）：6 小时
CACHE_TTL = 6 * 3600

# ---------------- 模块级加载状态 ----------------
_ACTIVE = None       # 当前生效的索引（惰性初始化：db.json 或 legacy 下载结果）
_CACHE_FILE = None   # load_bad_ips 传入的 legacy 缓存路径


class _IntelIndex:
    """统一命中索引：精确 IP -> 源标签列表 + CIDR 恶意段表。

    db.json 与 legacy 下载两种数据源都灌进本结构，上层只需调 match()。
    """

    def __init__(self, legacy=False):
        self.exact = {}        # ip -> [label, ...]（去重保序）
        self.cidrs = []        # [(ip_network, label), ...]（db.json 独有）
        self.updated_at = None  # db.json 的 updated_at 字符串
        self.age_hours = None   # 库龄（小时），db.json 独有
        self.legacy = legacy    # True=来自联网 3 源兜底

    # ---- 构建 ----
    def add_exact(self, ip, label):
        labels = self.exact.setdefault(ip, [])
        if label not in labels:
            labels.append(label)

    def add_cidr(self, net, label):
        self.cidrs.append((net, label))

    # ---- 查询 ----
    def match(self, ip):
        """统一命中查询：返回命中源标签列表（精确 + 恶意段），空列表=未命中。"""
        if not ip:
            return []
        ip_s = str(ip).strip()
        out = list(self.exact.get(ip_s, []))
        if self.cidrs:
            try:
                obj = ipaddress.ip_address(ip_s)
            except ValueError:
                return out
            for net, label in self.cidrs:
                if obj in net:
                    out.append(f"{label}({net})")
        return out

    def as_tuple(self):
        """兼容旧接口 load_bad_ips 的返回：((精确命中IP集合, {ip: [源]}))"""
        return set(self.exact.keys()), {ip: list(labels) for ip, labels in self.exact.items()}

    def __len__(self):
        return len(self.exact)


def _intel_db_path():
    """情报库默认路径：exe/脚本所在目录下的 threat_db.json"""
    return os.path.join(runtime_dir, INTEL_DB_FILENAME)


def _intel_url_from_config():
    """情报库下载地址：优先 config.ini [intel] db_url（内网部署可指向镜像/共享路径）。"""
    try:
        import configparser

        cfg = configparser.ConfigParser()
        cfg.read(os.path.join(runtime_dir, "config.ini"), encoding="utf-8")
        if cfg.has_option("intel", "db_url"):
            # 逐行取首个有效行（过滤空行/注释/多行示例残留）
            for ln in cfg.get("intel", "db_url").splitlines():
                ln = ln.strip()
                if ln and not ln.startswith(("#", ";")):
                    return ln
    except Exception:
        pass
    return GITHUB_INTEL_URL


def _http_read(url, timeout=DOWNLOAD_TIMEOUT):
    """下载 URL 内容。SSL/CA 校验失败时降级为不校验重试一次（内网 OCSP 封锁场景）。"""
    req = urllib.request.Request(url, headers={"User-Agent": DOWNLOAD_UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.URLError as exc:
        if isinstance(getattr(exc, "reason", None), ssl.SSLError):
            ctx = ssl._create_unverified_context()
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.read()
        raise


def _host_of(url):
    """取 URL 的 host（展示用，识别当前走的是官方还是哪个镜像）。"""
    try:
        return urllib.parse.urlsplit(url).netloc
    except Exception:
        return url


def _intel_candidates():
    """下载候选 URL 列表。

    config.ini [intel] db_url 自定义（如内网镜像/共享路径）→ 仅该单一地址；
    未配置 → 官方 GitHub + 各加速镜像前缀（拼接为 <镜像>/<官方URL>）。
    """
    base = _intel_url_from_config()
    if base != GITHUB_INTEL_URL:
        return [base]
    return [GITHUB_INTEL_URL] + [m + GITHUB_INTEL_URL for m in INTEL_MIRRORS]


def _read_head(url, n, timeout=PROBE_TIMEOUT):
    """Range 读取 URL 文件头 n 字节。失败/非 200-206/空响应返回 None。"""
    req = urllib.request.Request(
        url, headers={"User-Agent": DOWNLOAD_UA, "Range": f"bytes=0-{n - 1}"}
    )
    try:
        try:
            resp = urllib.request.urlopen(req, timeout=timeout)
        except urllib.error.URLError as exc:
            if isinstance(getattr(exc, "reason", None), ssl.SSLError):
                resp = urllib.request.urlopen(
                    req, timeout=timeout, context=ssl._create_unverified_context()
                )
            else:
                raise
        with resp:
            if resp.status not in (200, 206):
                return None
            return resp.read(n) or None
    except Exception:
        return None


def _probe_one(url, timeout=PROBE_TIMEOUT, need_bytes=PROBE_BYTES):
    """单候选测速：Range 读前 need_bytes 字节并计时。

    返回耗时秒数（float）；任何失败返回 None。
    """
    t0 = time.monotonic()
    if _read_head(url, need_bytes, timeout=timeout) is None:
        return None
    return time.monotonic() - t0


def _remote_meta_one(url, timeout=PROBE_TIMEOUT):
    """单候选远端版本探测：Range 读文件头并提取 updated_at（生成脚本首个键）。

    返回 "YYYY-MM-DD HH:MM:SS" 字符串；读不到/不含该键返回 None。
    """
    raw = _read_head(url, REMOTE_HEAD_BYTES, timeout=timeout)
    if not raw:
        return None
    m = re.search(rb'"updated_at"\s*:\s*"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"', raw)
    if not m:
        return None
    return m.group(1).decode("ascii")


def _probe_candidates(urls, timeout=PROBE_TIMEOUT):
    """并行测速全部候选，返回按耗时升序排列的可达 URL 列表（探测全挂时为空）。"""
    best = {}

    def work(u):
        el = _probe_one(u, timeout=timeout)
        if el is not None:
            best[u] = el

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(urls))) as ex:
        list(ex.map(work, urls))
    return [u for u, _ in sorted(best.items(), key=lambda kv: kv[1])]


def _probe_remote_candidates(urls, timeout=PROBE_TIMEOUT):
    """并行轻量读取各候选文件头并提取 updated_at。

    返回按耗时升序的 [(updated_at, url, elapsed), ...]；全部失败返回空列表。
    """
    out = []

    def work(u):
        t0 = time.monotonic()
        meta = _remote_meta_one(u, timeout=timeout)
        if meta is not None:
            out.append((meta, u, time.monotonic() - t0))

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(urls))) as ex:
        list(ex.map(work, urls))
    out.sort(key=lambda x: x[2])
    return out


def remote_intel_info():
    """轻量探测"官方+镜像"上最新库的版本日期（Range 头部 2KB，不完整下载）。

    返回 dict：
      updated_at: 最快可达源解析出的 "YYYY-MM-DD HH:MM:SS"（全部不可达为 None）
      host:       该源域名（识别走官方还是镜像）；reachable/total: 可达/候选总数
    """
    cands = _intel_candidates()
    found = _probe_remote_candidates(cands)
    if not found:
        return {"updated_at": None, "host": None, "reachable": 0, "total": len(cands)}
    meta, url, _el = found[0]
    return {"updated_at": meta, "host": _host_of(url), "reachable": len(found), "total": len(cands)}


def _download_install(url, dest_path, timeout=DOWNLOAD_TIMEOUT):
    """从 url 下载威胁情报库并原子替换 dest_path。

    下载到 .tmp → 校验结构（sources 非空、含精确/段条目）→ 通过才替换正式文件，
    失败保留旧库并清理临时文件。返回 (ok, msg)。
    """
    tmp_path = dest_path + ".tmp"
    try:
        raw = _http_read(url, timeout=timeout)
        data = json.loads(raw.decode("utf-8", errors="replace"))
        if not isinstance(data, dict) or not data.get("sources"):
            return False, "下载内容不是有效的威胁情报库（缺 sources 段）"
        n_ip = sum(len(v) for v in (data.get("ip_sets") or {}).values())
        n_cidr = len(data.get("cidrs") or [])
        if n_ip <= 0 and n_cidr <= 0:
            return False, "下载的威胁情报库为空（无精确 IP 且无恶意段）"
        os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
        with open(tmp_path, "wb") as f:
            f.write(raw)
        os.replace(tmp_path, dest_path)
    except Exception as exc:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        return False, f"更新失败: {exc}"
    return True, f"情报库已更新: {data.get('updated_at') or '?'}，精确IP {n_ip} 条 + 恶意段 {n_cidr} 条"


def _load_db_index(db_path=None):
    """读取本地 db.json 构建索引。文件缺失/结构非法返回 None。"""
    path = db_path or _intel_db_path()
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or not data.get("sources"):
            return None
        idx = _IntelIndex()
        src_labels = {k: v.get("label", k) for k, v in data.get("sources", {}).items()}
        for key, ips in (data.get("ip_sets") or {}).items():
            label = src_labels.get(key, key)
            for ip in ips:
                idx.add_exact(ip, label)
        for c in data.get("cidrs") or []:
            try:
                net = ipaddress.ip_network(c["net_str"], strict=False)
            except ValueError:
                continue
            idx.add_cidr(net, src_labels.get(c.get("source", ""), c.get("source", "")))
        idx.updated_at = data.get("updated_at")
        if idx.updated_at:
            try:
                t = time.mktime(time.strptime(idx.updated_at, "%Y-%m-%d %H:%M:%S"))
                idx.age_hours = (time.time() - t) / 3600
            except ValueError:
                idx.age_hours = None
        return idx
    except Exception:
        return None


def _download_ips(url):
    """下载兜底威胁源并解析为 IP 集合（支持 CIDR 前缀截断）。失败返回 None。"""
    try:
        text = _http_read(url).decode("utf-8", errors="ignore")
        ips = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            token = line.split()[0]
            # 截断 CIDR（兜底黑名单多为单 IP，CIDR 简化为网络地址也够用）
            if "/" in token:
                token = token.split("/")[0]
            # 只收合法 IPv4
            parts = token.split(".")
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                ips.add(token)
        return ips
    except Exception:
        return None


def _load_legacy_index(cache_file=None):
    """无本地情报库时的兜底：联网下载 3 源（6h 缓存）。返回 _IntelIndex（可能为空）。"""
    idx = _IntelIndex(legacy=True)
    # 1) 缓存命中
    if cache_file and os.path.exists(cache_file):
        try:
            with open(cache_file, encoding="utf-8") as f:
                cache = json.load(f)
            if time.time() - cache.get("ts", 0) < CACHE_TTL and "sources" in cache:
                sources = cache["sources"]
                for ip, names in sources.items():
                    for name in names:
                        idx.add_exact(ip, name)
                return idx
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
    for ip, names in sources.items():
        for name in names:
            idx.add_exact(ip, name)
    return idx


def _ensure_loaded(cache_file=None, allow_legacy=True):
    """确保 _ACTIVE 已初始化（db.json 优先）。非线程安全，供单次生成调用。

    allow_legacy=False（match_ip 路径）时不做任何联网：仅尝试本地 db.json，
    避免测试/外部直接调用 render 时触发兜底下载拖慢或失败。
    """
    global _ACTIVE
    if _ACTIVE is not None:
        return _ACTIVE
    idx = _load_db_index()
    if idx is None and allow_legacy:
        idx = _load_legacy_index(cache_file)
    if idx is not None:
        if not idx.legacy:
            age_txt = f"{idx.age_hours:.1f}h" if idx.age_hours is not None else "?"
            print(
                f"[threat] 本地情报库 {idx.updated_at} (库龄 {age_txt}): "
                f"精确 {len(idx)} 条 + 恶意段 {len(idx.cidrs)} 条"
            )
        elif not len(idx):
            print("[threat] 本地情报库缺失且联网兜底为空，威胁源分级显示 —")
    else:
        idx = _IntelIndex(legacy=True)  # 无 db 且不允许联网：空索引静默降级
    _ACTIVE = idx
    return idx


def load_bad_ips(cache_file=None):
    """加载威胁名单，返回 (bad_ips:set, sources:dict[ip->[源名]])。

    cache_file 为兜底源的磁盘缓存路径。优先读取 exe 同目录 threat_db.json
    （本地 5 源情报库，秒查、支持恶意段）；缺失/无效时退回联网 3 源。
    """
    global _CACHE_FILE
    _CACHE_FILE = cache_file
    idx = _ensure_loaded(cache_file)
    return idx.as_tuple()


def match_ip(ip):
    """统一威胁命中查询（精确 IP + CIDR 恶意段）。返回命中源标签列表，空=未命中。

    需先调用 load_bad_ips 完成加载；未加载时会以无缓存路径自动加载一次。
    """
    idx = _ensure_loaded(_CACHE_FILE, allow_legacy=False)
    return idx.match(ip) if idx is not None else []


def check_ip(ip, bad_ips, sources=None):
    """单 IP 威胁分级（旧接口，精确命中语义）。返回 (level, detail)。

    level: Critical(2+源) / High(1源) / Clean(无记录)
    detail: 命中源名列表（未命中为空）
    """
    if ip in bad_ips:
        hits = sources.get(ip, ["未知源"]) if sources else ["命中"]
        if len(hits) >= 2:
            return "Critical", hits
        return "High", hits
    return "Clean", []


def update_intel(dest=None, url=None, timeout=DOWNLOAD_TIMEOUT):
    """从发布源下载最新 threat_db.json 并原子替换本地库。返回 (ok, msg)。

    - dest 默认 runtime_dir/threat_db.json。
    - url 显式指定 → 仅该单一地址（不做择优）。
    - url 为空 → 候选列表 = config.ini [intel] db_url（若配置）否则 官方 GitHub + 加速镜像：
        1) 并行测速"官方 + 镜像"（Range 128KB 计时），可达源按耗时升序；
        2) 依次完整下载，成功即停（msg 标注实际所用下载源域名）；
        3) 探测全挂时只硬试官方一次（缩短超时），不逐镜像空等，快速给出失败结论。
    - 下载到 .tmp 后校验结构（sources 非空、含精确/段条目），通过才原子替换正式文件，
      失败保留旧库并清理临时文件；成功重置模块级索引，下次 load_bad_ips/match_ip 读新库。
    """
    global _ACTIVE
    dest_path = dest or _intel_db_path()
    if url:
        ok, msg = _download_install(url, dest_path, timeout=timeout)
        if ok:
            _ACTIVE = None
            return True, f"{msg}（下载源: {_host_of(url)}）"
        return ok, msg

    candidates = _intel_candidates()
    if len(candidates) == 1:  # config 自定义单一地址（内网镜像场景）：直连不择优
        ok, msg = _download_install(candidates[0], dest_path, timeout=timeout)
        if ok:
            _ACTIVE = None
            return True, f"{msg}（下载源: {_host_of(candidates[0])}）"
        return ok, msg

    ordered = _probe_candidates(candidates)  # 并行测速：可达源按耗时升序
    if ordered:
        queue, try_timeout = ordered, timeout
    else:  # 探测全挂（官方与镜像均 5s 内无响应）→ 只硬试官方一次、缩短超时，不逐镜像空等
        queue, try_timeout = candidates[:1], min(timeout, 15)
    last = "所有下载源均不可用"
    for u in queue:
        ok, msg = _download_install(u, dest_path, timeout=try_timeout)
        if ok:
            _ACTIVE = None
            return True, f"{msg}（下载源: {_host_of(u)}）"
        last = f"{_host_of(u)}: {msg}"
    return False, last


def intel_status():
    """当前情报库/兜底源的简要状态（供 GUI/CLI 展示）。返回 dict。

    仅查本地（不触发联网），未加载时按 db.json 是否存在如实描述。
    结构化字段：mode/detail/updated_at/total_ips/total_cidrs/age_hours（无库时后四者为 None/0/0/None）。
    """
    global _ACTIVE
    if _ACTIVE is None:
        idx = _load_db_index()
        if idx is None:
            return {
                "mode": "none",
                "detail": f"无本地情报库（{INTEL_DB_FILENAME}），生成日报时将联网兜底或分级显示 —",
                "updated_at": None,
                "total_ips": 0,
                "total_cidrs": 0,
                "age_hours": None,
            }
        _ACTIVE = idx
    idx = _ACTIVE
    if not idx.legacy:
        return {
            "mode": "db",
            "detail": f"本地情报库 {idx.updated_at}，精确 {len(idx)} + 段 {len(idx.cidrs)}"
            + (f"，库龄 {idx.age_hours:.1f}h" if idx.age_hours is not None else ""),
            "updated_at": idx.updated_at,
            "total_ips": len(idx),
            "total_cidrs": len(idx.cidrs),
            "age_hours": idx.age_hours,
        }
    return {
        "mode": "legacy",
        "detail": f"联网兜底 3 源 {len(idx)} 条",
        "updated_at": None,
        "total_ips": len(idx),
        "total_cidrs": 0,
        "age_hours": None,
    }


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--update-intel":
        ok, msg = update_intel()
        print(f"[{'OK' if ok else 'FAIL'}] {msg}")
        sys.exit(0 if ok else 1)
    else:
        print(json.dumps(intel_status(), ensure_ascii=False))
