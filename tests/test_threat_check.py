"""threat_check 单元测试：本地情报库(dbl.json)优先 + 恶意段命中 + 下载更新。

覆盖：
- _IntelIndex：精确命中 / CIDR 段命中 / 去重保序 / as_tuple 旧接口兼容
- _load_db_index：合法库加载、缺失/非法结构返回 None、updated_at 解析
- load_bad_ips / match_ip：本地库优先，legacy 兜底不联网路径
- check_ip：旧接口精确命中分级（Critical/High/Clean）
- update_intel：下载成功原子替换 + 校验失败保留旧库
"""
import json
import sys
import urllib.error

import pytest

sys.path.insert(0, ".")  # noqa: E402 保证以项目根可导入（与 conftest pythonpath 一致）

import threat_check  # noqa: E402


def _sample_db(updated_at="2026-09-02 08:00:00"):
    return {
        "updated_at": updated_at,
        "sources": {
            "spamhaus_drop": {"label": "SpamhausDROP"},
            "blocklist_de": {"label": "BlocklistDE"},
            "feodo": {"label": "FeodoTracker"},
        },
        "ip_sets": {
            "blocklist_de": ["1.2.3.4"],
            "feodo": ["5.6.7.8"],
        },
        "cidrs": [
            {"net_str": "185.242.3.0/24", "source": "spamhaus_drop"},
            {"net_str": "223.26.48.0/20", "source": "spamhaus_drop"},
        ],
    }


@pytest.fixture(autouse=True)
def _reset_state():
    """每个用例前重置模块级加载状态，避免用例间相互污染。"""
    threat_check._ACTIVE = None
    threat_check._CACHE_FILE = None
    yield
    threat_check._ACTIVE = None
    threat_check._CACHE_FILE = None


@pytest.fixture
def db_file(tmp_path):
    """把样本情报库写到临时目录，返回 (path, monkeypatch runtime_dir)。"""
    p = tmp_path / "threat_db.json"
    p.write_text(json.dumps(_sample_db()), encoding="utf-8")
    return p


def test_intel_index_exact_and_cidr_match():
    """精确 IP 与恶意段命中分别返回对应源标签；段命中带网段说明。"""
    idx = threat_check._IntelIndex()
    idx.add_exact("1.2.3.4", "BlocklistDE")
    idx.add_exact("1.2.3.4", "FeodoTracker")
    idx.add_cidr(threat_check.ipaddress.ip_network("185.242.3.0/24"), "SpamhausDROP")

    assert idx.match("1.2.3.4") == ["BlocklistDE", "FeodoTracker"]  # 去重保序
    assert idx.match("185.242.3.55") == ["SpamhausDROP(185.242.3.0/24)"]
    assert idx.match("8.8.8.8") == []
    assert idx.match("") == []  # 空值不炸
    assert idx.match("not-an-ip") == []  # 非法 IP 不炸
    # 段命中不覆盖精确结果（两者叠加）
    idx.add_cidr(threat_check.ipaddress.ip_network("1.2.3.0/24"), "段源")
    assert idx.match("1.2.3.4") == ["BlocklistDE", "FeodoTracker", "段源(1.2.3.0/24)"]


def test_intel_index_as_tuple_legacy_compat():
    """as_tuple 兼容旧 load_bad_ips 返回形态。"""
    idx = threat_check._IntelIndex()
    idx.add_exact("1.2.3.4", "A")
    idx.add_exact("1.2.3.4", "B")
    idx.add_exact("9.9.9.9", "C")
    bad, srcs = idx.as_tuple()
    assert bad == {"1.2.3.4", "9.9.9.9"}
    assert srcs["1.2.3.4"] == ["A", "B"]


def test_load_db_index_valid(db_file):
    """合法 db.json 加载：精确数 / 段数 / updated_at 解析。"""
    idx = threat_check._load_db_index(str(db_file))
    assert idx is not None
    assert not idx.legacy
    assert len(idx) == 2  # 精确 IP 2 条
    assert len(idx.cidrs) == 2
    assert idx.updated_at == "2026-09-02 08:00:00"
    assert idx.age_hours is not None and idx.age_hours >= 0
    # 段标签来自 sources.label
    assert idx.match("185.242.3.99") == ["SpamhausDROP(185.242.3.0/24)"]


def test_load_db_index_missing(tmp_path):
    """文件缺失返回 None（不抛异常）。"""
    assert threat_check._load_db_index(str(tmp_path / "nope.json")) is None


@pytest.mark.parametrize(
    "bad_content",
    [
        "{not json",
        json.dumps({"foo": 1}),            # 非 dict 结构缺 sources
        json.dumps({"sources": None}),     # sources 为空 → None
    ],
)
def test_load_db_index_invalid(tmp_path, bad_content):
    """结构非法的库返回 None，不抛异常。"""
    p = tmp_path / "threat_db.json"
    p.write_text(bad_content, encoding="utf-8")
    assert threat_check._load_db_index(str(p)) is None


def test_load_db_index_empty_sources_ok(tmp_path):
    """sources 为有效 dict 但无 ip_sets/cidrs：可构建空索引（调用方按 len=0 处理）。"""
    p = tmp_path / "threat_db.json"
    p.write_text(json.dumps({"sources": {"a": {}}}), encoding="utf-8")
    idx = threat_check._load_db_index(str(p))
    assert idx is not None and len(idx) == 0


def test_load_db_index_updated_at_invalid(tmp_path):
    """updated_at 无法解析时 age_hours=None 不报错。"""
    p = tmp_path / "threat_db.json"
    data = _sample_db(updated_at="昨天")
    p.write_text(json.dumps(data), encoding="utf-8")
    idx = threat_check._load_db_index(str(p))
    assert idx is not None
    assert idx.age_hours is None


def test_load_bad_ips_prefers_db(db_file, monkeypatch):
    """有本地库时 load_bad_ips 走 db（不触发 legacy 联网），返回兼容元组。"""
    monkeypatch.setattr(threat_check, "runtime_dir", str(db_file.parent))
    bad, srcs = threat_check.load_bad_ips(str(db_file.parent / "legacy_cache.json"))
    assert bad == {"1.2.3.4", "5.6.7.8"}
    assert srcs["1.2.3.4"] == ["BlocklistDE"]
    # match_ip 不联网也能段命中
    assert threat_check.match_ip("185.242.3.55") == ["SpamhausDROP(185.242.3.0/24)"]
    assert threat_check.match_ip("8.8.8.8") == []


def test_load_bad_ips_no_db_keeps_legacy_cache(tmp_path, monkeypatch, capsys):
    """无本地库时读 legacy 磁盘缓存（不联网）；空缓存可静默降级。"""
    monkeypatch.setattr(threat_check, "runtime_dir", str(tmp_path))
    cache = tmp_path / "legacy.json"
    cache.write_text(
        json.dumps({"ts": 10**12, "sources": {"6.6.6.6": ["BlocklistDE"]}}),
        encoding="utf-8",
    )
    bad, srcs = threat_check.load_bad_ips(str(cache))
    assert bad == {"6.6.6.6"}
    assert srcs["6.6.6.6"] == ["BlocklistDE"]


def test_match_ip_without_load_quiet(tmp_path, monkeypatch, capsys):
    """match_ip 无库且未 load 时静默降级（allow_legacy=False 不触发联网下载）。"""
    monkeypatch.setattr(threat_check, "runtime_dir", str(tmp_path))
    assert threat_check.match_ip("1.1.1.1") == []


def test_check_ip_legacy_grading():
    """check_ip 旧接口：2+源 Critical / 1 源 High / 无 Clean。"""
    bad = {"1.2.3.4", "5.6.7.8"}
    srcs = {"1.2.3.4": ["A", "B"], "5.6.7.8": ["A"]}
    assert threat_check.check_ip("1.2.3.4", bad, srcs)[0] == "Critical"
    assert threat_check.check_ip("5.6.7.8", bad, srcs)[0] == "High"
    assert threat_check.check_ip("9.9.9.9", bad, srcs)[0] == "Clean"


def test_update_intel_success(db_file, monkeypatch):
    """update_intel：下载合法库 → 原子替换 → 重置索引 → 下次读到新库。"""
    dest = db_file.parent / "threat_db.json"  # 复用样本位置
    dest.unlink()  # 模拟目标不存在
    monkeypatch.setattr(
        threat_check,
        "_http_read",
        lambda url, timeout=30: json.dumps(_sample_db(updated_at="2026-09-02 12:00:00")).encode(),
    )
    ok, msg = threat_check.update_intel(dest=str(dest), url="https://example.com/x.json")
    assert ok
    assert "情报库已更新" in msg
    assert dest.exists()
    # 索引已重置，下次加载读到新 updated_at
    idx = threat_check._load_db_index(str(dest))
    assert idx.updated_at == "2026-09-02 12:00:00"


def test_update_intel_invalid_keeps_old(db_file, monkeypatch):
    """下载内容非法：返回失败且不破坏既有库。"""
    old_content = db_file.read_text(encoding="utf-8")
    monkeypatch.setattr(threat_check, "_http_read", lambda url, timeout=30: b"{bad json")

    ok, msg = threat_check.update_intel(dest=str(db_file), url="https://example.com/x.json")
    assert not ok
    assert "更新失败" in msg
    assert db_file.read_text(encoding="utf-8") == old_content  # 旧库原样保留
    # 临时文件已清理
    assert not (db_file.parent / "threat_db.json.tmp").exists()


def test_update_intel_empty_db_rejected(db_file, monkeypatch):
    """下载内容有 sources 但无任何条目：判空拒绝。"""
    bad = {"updated_at": "x", "sources": {"a": {"label": "A"}}, "ip_sets": {}, "cidrs": []}
    monkeypatch.setattr(threat_check, "_http_read", lambda url, timeout=30: json.dumps(bad).encode())
    ok, msg = threat_check.update_intel(dest=str(db_file), url="https://example.com/x.json")
    assert not ok
    assert "为空" in msg


def test_intel_url_from_config_custom(tmp_path, monkeypatch):
    """config.ini [intel] db_url 覆盖内置 GitHub 地址（含注释行过滤）。"""
    monkeypatch.setattr(threat_check, "runtime_dir", str(tmp_path))
    (tmp_path / "config.ini").write_text(
        "[intel]\n# 注释\n\ndb_url =\n    http://mirror.local/threat_db.json\n",
        encoding="utf-8",
    )
    assert threat_check._intel_url_from_config() == "http://mirror.local/threat_db.json"


def test_intel_url_from_config_fallback(monkeypatch):
    """无配置文件时回落内置 GitHub 固定地址。"""
    assert threat_check._intel_url_from_config() == threat_check.GITHUB_INTEL_URL


def test_intel_status_modes(db_file, monkeypatch):
    """intel_status：有库显示 db 模式（含结构化版本字段）；无库显示 none（不触发联网）。"""
    monkeypatch.setattr(threat_check, "runtime_dir", str(db_file.parent))
    st = threat_check.intel_status()
    assert st["mode"] == "db"
    assert "本地情报库" in st["detail"]
    # 结构化字段：供 GUI 启动比对"本地 vs 远端版本日期"
    assert st["updated_at"] == "2026-09-02 08:00:00"
    assert st["total_ips"] == 2
    assert st["total_cidrs"] == 2
    assert st["age_hours"] is not None


# ---------------- 远端版本比对（Range 头部 2KB 轻量探测） ----------------

INTEL_HEAD = (
    b'{\n "updated_at": "2026-09-02 08:25:55",\n'
    b' "sources": {"spamhaus_drop": {"label": "SpamhausDROP", "count": 6}},\n'
    b' "ip_sets": {...'
)


def test_remote_meta_extract(monkeypatch):
    """头部字节解析 updated_at：正常提取 / 无该键 / 读不到均不炸。"""
    monkeypatch.setattr(threat_check, "_read_head", lambda url, n, timeout=5: INTEL_HEAD)
    assert threat_check._remote_meta_one("https://x/db.json") == "2026-09-02 08:25:55"

    monkeypatch.setattr(threat_check, "_read_head", lambda url, n, timeout=5: b'{"foo": 1}')
    assert threat_check._remote_meta_one("https://x/db.json") is None

    monkeypatch.setattr(threat_check, "_read_head", lambda url, n, timeout=5: None)
    assert threat_check._remote_meta_one("https://x/db.json") is None


def test_probe_remote_candidates_sorts_by_latency(monkeypatch):
    """并行读取候选头部：可达者按耗时升序返回（快的排前）。"""
    import time as _time

    def fake(url, timeout=5):
        _time.sleep(0.15 if "slow" in url else 0.02)
        return "2026-09-02 08:25:55"

    monkeypatch.setattr(threat_check, "_remote_meta_one", fake)
    res = threat_check._probe_remote_candidates(
        ["https://slow.example/db.json", "https://fast.example/db.json"]
    )
    assert len(res) == 2
    assert res[0][1] == "https://fast.example/db.json"  # 快源排第一
    assert all(r[0] == "2026-09-02 08:25:55" for r in res)


def test_remote_intel_info_reachable(monkeypatch):
    """远端可达：返回最快源版本日期与 host（识别官方/镜像）。"""
    monkeypatch.setattr(threat_check, "runtime_dir", "X:/nope")  # 无 config.ini → 官方+镜像候选
    url = (
        "https://ghfast.top/"
        "https://github.com/eavil666/dayupdate/releases/download/threat-intel-latest/threat_db.json"
    )
    monkeypatch.setattr(
        threat_check,
        "_probe_remote_candidates",
        lambda urls: [("2026-09-02 08:25:55", url, 0.3), ("2026-09-02 08:25:55", urls[0], 1.2)],
    )
    info = threat_check.remote_intel_info()
    assert info["updated_at"] == "2026-09-02 08:25:55"
    assert info["host"] == "ghfast.top"
    assert info["reachable"] == 2 and info["total"] >= 2


def test_remote_intel_info_unreachable(monkeypatch):
    """远端全部不可达：updated_at=None、host=None，不抛异常。"""
    monkeypatch.setattr(threat_check, "_probe_remote_candidates", lambda urls: [])
    info = threat_check.remote_intel_info()
    assert info["updated_at"] is None
    assert info["host"] is None
    assert info["reachable"] == 0


# ---------------- 多源择优下载（官方 + 加速镜像） ----------------

FAST_MIRROR = (
    "https://ghfast.top/"
    "https://github.com/eavil666/dayupdate/releases/download/threat-intel-latest/threat_db.json"
)


def test_update_intel_multi_source_picks_fastest(db_file, monkeypatch):
    """默认多源路径：测速择优结果优先 → 用最快源下载，msg 标注实际下载源域名。"""
    dest = db_file.parent / "threat_db.json"
    dest.unlink()  # 模拟目标不存在
    monkeypatch.setattr(threat_check, "runtime_dir", str(db_file.parent))  # 无 config.ini → 官方+镜像
    monkeypatch.setattr(threat_check, "_probe_candidates", lambda urls: [FAST_MIRROR])
    monkeypatch.setattr(
        threat_check,
        "_http_read",
        lambda url, timeout=30: json.dumps(
            _sample_db(updated_at="2026-09-02 12:00:00")
        ).encode(),
    )

    ok, msg = threat_check.update_intel(dest=str(dest))
    assert ok
    assert "情报库已更新" in msg
    assert "下载源: ghfast.top" in msg  # 用户可辨识当前走的源
    assert dest.exists()


def test_update_intel_all_sources_down(db_file, monkeypatch):
    """多源全部不可达（测速全挂 → 硬试官方+首个镜像也失败）：返回失败且旧库保留。"""
    old = db_file.read_text(encoding="utf-8")
    monkeypatch.setattr(threat_check, "runtime_dir", str(db_file.parent))
    monkeypatch.setattr(threat_check, "_probe_candidates", lambda urls: [])

    def boom(url, timeout=30):
        raise urllib.error.URLError(TimeoutError("timed out"))

    monkeypatch.setattr(threat_check, "_http_read", boom)
    ok, msg = threat_check.update_intel(dest=str(db_file))
    assert not ok
    assert db_file.read_text(encoding="utf-8") == old  # 旧库不受影响
    assert not (db_file.parent / "threat_db.json.tmp").exists()


def test_update_intel_candidates_include_mirrors(monkeypatch):
    """无 config 时候选 = 官方 + 全部镜像前缀拼接；自定义 db_url 只留单地址。"""
    monkeypatch.setattr(threat_check, "runtime_dir", "X:/nope")
    cands = threat_check._intel_candidates()
    assert cands[0] == threat_check.GITHUB_INTEL_URL
    assert len(cands) == 1 + len(threat_check.INTEL_MIRRORS)
    assert all(c.startswith(m) for c, m in zip(cands[1:], threat_check.INTEL_MIRRORS))
