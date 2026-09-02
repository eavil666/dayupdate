"""日报域逻辑测试：analyze / load_single_file / pick_input_and_date / load_intel"""

import pandas as pd
import pytest

import report
from report import analyze, load_intel, load_single_file, pick_input_and_date


def _conf():
    return {
        "nets": [],
        "zones": {"集团四楼"},
        "geos": {"长春"},
        "crit_levels": {"严重", "高危"},
        "top": 5,
        "probes": [],
        "retention": 180,
        "ban_levels": {"高危", "严重"},
    }


def test_analyze_stats():
    """analyze：总量/内外网/等级/封禁统计"""
    df = pd.DataFrame(
        {
            "源IP": ["1.2.3.4", "10.0.0.1", "5.6.7.8", "9.9.9.9"],
            "目的IP": ["10.0.0.1", "10.0.0.2", "10.0.0.1", "10.0.0.1"],
            "攻击名称": ["端口扫描", "弱口令", "漏洞利用", "webshell"],
            "威胁等级": ["高危", "低危", "严重", "中危"],
            "网络类型": ["外网", "内网", "外网", "外网"],
        }
    )
    stats = analyze(df)
    assert stats["total"] == 4
    assert stats["int_count"] == 1
    assert stats["ext_count"] == 3
    assert stats["ext_level"]["高危"] == 1
    assert stats["ext_level"]["严重"] == 1
    assert stats["ban_count"] == 3  # 外网→内网 3 个源IP去重


def test_analyze_no_external():
    """全内网：封禁为 0，等级统计为空"""
    df = pd.DataFrame(
        {
            "源IP": ["10.0.0.1", "10.0.0.2"],
            "目的IP": ["10.0.0.3", "10.0.0.4"],
            "攻击名称": ["A", "B"],
            "威胁等级": ["高危", "中危"],
            "网络类型": ["内网", "内网"],
        }
    )
    stats = analyze(df)
    assert stats["ban_count"] == 0
    assert stats["ext_count"] == 0
    assert stats["int_level"]["高危"] == 1


def test_load_single_file_column_mapping(tmp_path):
    """load_single_file：列名映射（含前导空格）+ 网络类型判定"""
    alert = tmp_path / "alerts.xlsx"
    pd.DataFrame(
        {
            "最近发生时间": ["2026-07-19 20:00:00"],
            " 攻击名称": ["端口扫描"],  # 前导空格
            "源 IP": ["1.2.3.4"],
            "目的 IP": ["10.0.0.1"],
            "威胁等级": ["高危"],
            "源区域": ["集团四楼"],
            "源地理信息": ["吉林-长春"],
        }
    ).to_excel(alert, index=False)
    df = load_single_file(alert, _conf())
    assert "源IP" in df.columns and "目的IP" in df.columns
    assert "攻击名称" in df.columns and "威胁等级" in df.columns
    assert df.iloc[0]["攻击名称"] == "端口扫描"
    # 源区域命中 zones + 地理命中 geos → 内网
    assert df.iloc[0]["网络类型"] == "内网"


def test_load_single_file_zone_not_hit(tmp_path):
    """源区域未命中 zones → 走公网判定"""
    alert = tmp_path / "alerts2.xlsx"
    pd.DataFrame(
        {
            "攻击名称": ["扫描"],
            "源 IP": ["8.8.8.8"],
            "目的 IP": ["10.0.0.1"],
            "威胁等级": ["低危"],
            "源区域": ["默认区域"],
            "源地理信息": ["美国"],
        }
    ).to_excel(alert, index=False)
    df = load_single_file(alert, _conf())
    assert df.iloc[0]["网络类型"] == "外网"


def test_pick_input_and_date(tmp_path, monkeypatch):
    """pick_input_and_date：按 8 位日期识别 + 排除业务/日报文件"""

    monkeypatch.setattr(report, "runtime_dir", str(tmp_path))
    # 构造：当天告警 2 份 + 干扰文件（业务ip/日报/终端表 应被排除）
    for name in ("安全告警20260719_1.xlsx", "安全告警20260719_2.xlsx"):
        pd.DataFrame({"源 IP": ["1.1.1.1"], "目的 IP": ["10.0.0.1"]}).to_excel(tmp_path / name, index=False)
    pd.DataFrame({"ip": ["8.8.8.8"]}).to_excel(tmp_path / "业务ip.xlsx", index=False)
    pd.DataFrame({"x": [1]}).to_excel(tmp_path / "值守保障日报20260719.xlsx", index=False)

    files, date = pick_input_and_date("*.xlsx")
    names = [f.name for f in files]
    assert date == "20260719"
    assert "安全告警20260719_1.xlsx" in names
    assert not any("业务ip" in n or "日报" in n for n in names)


def test_pick_input_and_date_no_files(tmp_path, monkeypatch):
    """无告警文件 → FileNotFoundError"""

    monkeypatch.setattr(report, "runtime_dir", str(tmp_path))
    with pytest.raises(FileNotFoundError):
        pick_input_and_date("*.xlsx")


def test_load_intel(tmp_path, monkeypatch):
    """load_intel：intel.csv 读取；缺失返回空"""

    monkeypatch.setattr(report, "runtime_dir", str(tmp_path))
    conf = {"intel_file": "intel.csv"}
    # 无文件 → 空
    assert load_intel(conf) == []
    # 有文件 → 记录列表
    (tmp_path / "intel.csv").write_text("类型,编号,风险\nCVE,CVE-2024-1,高危\n", encoding="utf-8")
    rows = load_intel(conf)
    assert len(rows) == 1 and rows[0]["编号"] == "CVE-2024-1"


def test_render_generates_docx(tmp_path):
    """render：完整渲染生成 docx（冒烟，不断言内容）"""
    from report import LEVELS, render

    conf = {
        "title": "测试日报",
        "retention": 180,
        "top": 5,
        "crit_levels": {"严重", "高危"},
        "probes": [("探针A", "1.1.1.1")],
    }
    df = pd.DataFrame(
        {
            "攻击名称": ["端口扫描", "弱口令"],
            "源IP": ["1.2.3.4", "10.0.0.1"],
            "威胁等级": ["高危", "中危"],
            "网络类型": ["外网", "内网"],
            "目的IP": ["10.0.0.1", "10.0.0.2"],
        }
    )
    stats = {
        "total": 2,
        "int_count": 1,
        "ext_count": 1,
        "ban_count": 1,
        "int_level": {lv: 0 for lv in LEVELS},
        "ext_level": {lv: 0 for lv in LEVELS},
        "internal": df[df["网络类型"] == "内网"],
        "external": df[df["网络类型"] == "外网"],
    }
    out = tmp_path / "report.docx"
    render(
        conf,
        df,
        stats,
        conf["probes"],
        [],
        "20260719",
        str(out),
        work_summary="1. 完成整改\n2. 处置告警",
        intel_items="1. CVE-2024-1 高危",
    )
    assert out.exists() and out.stat().st_size > 1000


def test_parse_lines_drops_example_block():
    """示例占位块（示例：\n1. xx\n2. xx）应整块丢弃，后续条目行不得漏进日报。

    回归：此前只按行过滤"示例："前缀，示例块的 1./2. 条目行会泄漏到日报
    「重点工作总结」里（如"1. 完成防火墙规则优化"）。
    """
    from report import _parse_lines

    # GUI 占位示例原样传回 → 整块丢弃
    assert _parse_lines("示例：\n1. 完成防火墙规则优化\n2. 处置高危漏洞告警") == []
    assert _parse_lines("示例：\n1. CVE-2024-XXXX 高危漏洞，需尽快修复") == []
    # 半角冒号同样识别
    assert _parse_lines("示例:\n1. 完成防火墙规则优化") == []
    # 用户真实输入不受影响
    assert _parse_lines("1. 完成整改\n2. 处置告警") == ["完成整改", "处置告警"]
    # 空输入 → 空列表
    assert _parse_lines("") == []
    assert _parse_lines(None) == []


def test_render_example_placeholder_not_in_docx(tmp_path):
    """docx 成品不得出现 GUI 示例占位中的条目。

    回归：用户未填写「重点工作总结/情报动态」时，示例文本曾以
    "2. 完成防火墙规则优化""3. 处置高危漏洞告警"形式写进日报正文。
    """
    import docx as docxlib

    from report import LEVELS, render

    conf = {
        "title": "测试日报",
        "retention": 180,
        "top": 5,
        "crit_levels": {"严重", "高危"},
        "probes": [("探针A", "1.1.1.1")],
    }
    df = pd.DataFrame(
        {
            "攻击名称": ["端口扫描", "弱口令"],
            "源IP": ["1.2.3.4", "10.0.0.1"],
            "威胁等级": ["高危", "中危"],
            "网络类型": ["外网", "内网"],
            "目的IP": ["10.0.0.1", "10.0.0.2"],
        }
    )
    stats = {
        "total": 2,
        "int_count": 1,
        "ext_count": 1,
        "ban_count": 1,
        "int_level": {lv: 0 for lv in LEVELS},
        "ext_level": {lv: 0 for lv in LEVELS},
        "internal": df[df["网络类型"] == "内网"],
        "external": df[df["网络类型"] == "外网"],
    }
    out = tmp_path / "report.docx"
    render(
        conf,
        df,
        stats,
        conf["probes"],
        [],
        "20260719",
        str(out),
        work_summary="示例：\n1. 完成防火墙规则优化\n2. 处置高危漏洞告警",
        intel_items="示例：\n1. CVE-2024-XXXX 高危漏洞，需尽快修复",
        follow_items="示例：\n1. 内网高危告警溯源",
    )
    d = docxlib.Document(str(out))
    text = "\n".join(p.text for p in d.paragraphs)
    for leaked in ("完成防火墙规则优化", "处置高危漏洞告警", "CVE-2024-XXXX"):
        assert leaked not in text, f"示例内容泄漏进日报正文: {leaked}"
