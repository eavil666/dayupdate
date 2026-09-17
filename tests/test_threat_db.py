"""tools/threat-intel/threat_db.py 离线单元测试（不联网）。

覆盖 ThreatFox CSV 导出的解析口径——这块踩过的坑最多：
- CSV 前几行是 `#` 注释，会被 csv 解析成单列（列数不足需跳过）；
- 字段外面可能裹单/双引号，`startswith("ip")` 前必须剥引号；
- IP 型条目的 ioc_value 形如 `1.2.3.4:443`（带端口），需剥端口；
- 聚合数据里混有私网/保留段（bogon），必须过滤掉，否则内网 IP 被误判为 C2。
"""

import importlib.util
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_DB_PATH = os.path.join(_HERE, os.pardir, "tools", "threat-intel", "threat_db.py")


def _load():
    spec = importlib.util.spec_from_file_location("threat_db_under_test", _DB_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


td = _load()


# 真实 CSV 导出的头部（注释行 + 表头），后接数据行
_CSV_HEAD = """# ThreatFox IOCs for the last 48 hours (YYYY-MM-DD HH:MM:SS UTC)
#
# For more information on how to use this file please refer to
# https://threatfox.abuse.ch/faq/
#
"first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","last_seen_utc","confidence_level","anonymous","reporter","tags"
"""


def test_parse_csv_basic():
    """正常行：ip:port → 剥端口取 IP；非 ip 类型（domain/url）跳过。"""
    text = _CSV_HEAD + (
        '"2026-09-17 01:02:03","1","196.251.107.252:443","ip:port","botnet_cc",'
        '"win.cobalt_strike","","Cobalt Strike","","100","0","reporter",""\n'
        '"2026-09-17 01:02:03","2","evil.example.com","domain","botnet_cc",'
        '"win.cobalt_strike","","Cobalt Strike","","100","0","reporter",""\n'
        '"2026-09-17 01:02:03","3","103.67.163.201:80","ip:port","payload_delivery",'
        '"win.cobalt_strike","","Cobalt Strike","","100","0","reporter",""\n'
    )
    assert td._threatfox_parse_csv(text) == ["196.251.107.252", "103.67.163.201"]


def test_parse_csv_skips_comments_and_quotes():
    """注释行（单列/少列）不得被当成数据；带引号的字段要能正确判断类型。"""
    text = _CSV_HEAD + (
        "# a stray comment line\n"
        '"2026-09-17 01:02:03","4","85.137.252.40","ip:port","botnet_cc","","","","","100","0","r",""\n'
    )
    assert td._threatfox_parse_csv(text) == ["85.137.252.40"]


def test_parse_csv_filters_bogon_and_dedup():
    """bogon（私网/保留）必须过滤；同一 IP 多次出现只保留一条。"""
    text = _CSV_HEAD + (
        '"2026-09-17 01:02:03","5","192.168.1.10:443","ip:port","botnet_cc","","","","","100","0","r",""\n'
        '"2026-09-17 01:02:03","6","10.0.0.5:8080","ip:port","botnet_cc","","","","","100","0","r",""\n'
        '"2026-09-17 01:02:03","7","2.25.222.233:443","ip:port","botnet_cc","","","","","100","0","r",""\n'
        '"2026-09-17 01:02:03","8","2.25.222.233:8443","ip:port","botnet_cc","","","","","100","0","r",""\n'
    )
    assert td._threatfox_parse_csv(text) == ["2.25.222.233"]


def test_parse_csv_empty_and_header_only():
    """只有注释与表头时返回空列表，不得抛异常。"""
    assert td._threatfox_parse_csv(_CSV_HEAD) == []
    assert td._threatfox_parse_csv("") == []


def test_api_iocs_to_ips():
    """API 条目同口径：只取 ioc_type 以 ip 开头的行，剥端口 + 过滤 bogon + 去重。"""
    items = [
        {"ioc_type": "ip:port", "ioc": "47.98.124.244:443"},
        {"ioc_type": "domain", "ioc": "evil.example.com"},
        {"ioc_type": "ip:port", "ioc": "127.0.0.1:80"},
        {"ioc_type": "ip:port", "ioc": "47.98.124.244:8080"},
    ]
    assert td._threatfox_iocs_to_ips(items) == ["47.98.124.244"]


def test_sources_contain_threatfox_with_csv_api_flag():
    """source 清单必须把 ThreatFox 标记成 api 型源并落到独立落地文件。"""
    src = [s for s in td.SOURCES if s["key"] == "threatfox"]
    assert len(src) == 1
    assert src[0]["api"] == "threatfox"
    assert src[0]["file"] == "threatfox_c2_ips.txt"


def test_api_channel_without_key_returns_hint():
    """无 THREATFOX_API_KEY 时回退通道直接返回空 + 说明，不发起网络请求。"""
    old = os.environ.pop("THREATFOX_API_KEY", None)
    try:
        ips, err = td._threatfox_from_api()
    finally:
        if old is not None:
            os.environ["THREATFOX_API_KEY"] = old
    assert ips == []
    assert "THREATFOX_API_KEY" in err
