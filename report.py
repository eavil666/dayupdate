#!/usr/bin/env python3
"""
值守日报业务域（方案一拆分）
功能：告警文件加载/分类、威胁等级统计、docx 值守日报渲染（八大板块）、情报/跟进/总结。
依赖：common（日志/路径）、ipdb（is_private_ip/is_excluded_ip/load_config/load_terminal_ip_table）。
注意：classify 等 IP 判定逻辑在 ipdb（IP 判定为 IP 域职责）；本模块只做业务统计与渲染。
"""

import ipaddress
import os
import re
from datetime import datetime
from pathlib import Path

from common import _log, runtime_dir
from ipdb import is_excluded_ip, is_private_ip, load_config


def classify(ip, zone, geo, conf):
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return "未知"
    for net in conf["nets"]:
        if addr in net:
            return "内网"
    # 使用None检查替代pd.isna
    zone = "" if zone is None or (hasattr(zone, "__class__") and zone.__class__.__name__ == "NaNType") else str(zone)
    geo = "" if geo is None or (hasattr(geo, "__class__") and geo.__class__.__name__ == "NaNType") else str(geo)
    if zone in conf["zones"] and any(g in geo for g in conf["geos"]):
        return "内网"
    return "外网" if addr.is_global else "待确认"


def load_single_file(path, conf):
    import pandas as pd

    df = pd.read_excel(path, sheet_name=0, dtype={"源 IP": str, "目的 IP": str})
    df.columns = df.columns.str.strip()
    cols = []
    seen = set()
    for c in df.columns:
        if c in seen:
            i = 1
            while f"{c}_{i}" in seen:
                i += 1
            cols.append(f"{c}_{i}")
            seen.add(f"{c}_{i}")
        else:
            cols.append(c)
            seen.add(c)
    df.columns = cols
    col_map = {}
    target_counts = {}
    for c in df.columns:
        base = c.split("_")[0] if "_" in c else c
        target = None
        if "源" in base and "IP" in base and "目的" not in base:
            target = "源IP"
        elif "目的" in base and "IP" in base:
            target = "目的IP"
        elif "攻击" in base and ("名称" in base or "类型" in base):
            target = "攻击名称"
        elif "威胁" in base and "等级" in base:
            target = "威胁等级"
        elif "源" in base and "区域" in base:
            target = "源区域"
        elif "源" in base and "地理" in base:
            target = "源地理信息"
        elif "情报" in base or "IOC" in base.upper():
            target = "情报IOC"
        elif "攻击" in base and "阶段" in base:
            target = "攻击阶段"
        elif "攻击" in base and "状态" in base:
            target = "攻击状态"
        if target:
            if target in target_counts:
                target_counts[target] += 1
                col_map[c] = f"{target}_{target_counts[target]}"
            else:
                target_counts[target] = 1
                col_map[c] = target
    df = df.rename(columns=col_map)
    for must in ["源IP", "目的IP", "攻击名称", "威胁等级"]:
        if must not in df.columns:
            df[must] = ""
    df["网络类型"] = df.apply(lambda r: classify(r["源IP"], r.get("源区域", ""), r.get("源地理信息", ""), conf), axis=1)
    return df


def load_and_classify(paths, conf):
    dfs = []
    import pandas as pd

    for path in paths:
        _log(f"[+] 读取文件: {path.name}")
        df = load_single_file(path, conf)
        dfs.append(df)
    if not dfs:
        raise ValueError("没有读取到任何数据")
    df = pd.concat(dfs, ignore_index=True)
    _log(f"[+] 合并后共 {len(df)} 条记录")
    return df


LEVELS = ["严重", "高危", "中危", "低危"]


def analyze(df):
    total = len(df)
    internal = df[df["网络类型"] == "内网"]
    external = df[df["网络类型"] == "外网"]

    def by_level(sub):
        return {lv: int((sub["威胁等级"] == lv).sum()) for lv in LEVELS}

    external_to_internal = external.copy()
    # 空 external 时跳过过滤：pandas 空 df 用空 bool 过滤会丢失全部列（KeyError）
    if "目的IP" in external.columns and len(external) > 0:
        external_to_internal = external[external["目的IP"].apply(is_private_ip)]
    external_to_internal = external_to_internal[~external_to_internal["源IP"].apply(is_excluded_ip)]
    ban_count = int(external_to_internal["源IP"].nunique()) if len(external_to_internal) > 0 else 0
    return {
        "total": total,
        "internal": internal,
        "external": external,
        "int_count": len(internal),
        "ext_count": len(external),
        "int_level": by_level(internal),
        "ext_level": by_level(external),
        "ban_count": ban_count,
    }


def _set_run_font(run, size=None, bold=None):
    """统一设置 run 字体：英文 Times New Roman，中文宋体"""
    from docx.oxml.ns import qn
    from docx.shared import Pt

    run.font.name = "Times New Roman"
    rPr = run._element.get_or_add_rPr()
    rFonts = rPr.find(qn("w:rFonts"))
    if rFonts is None:
        rFonts = run._element.makeelement(qn("w:rFonts"), {})
        rPr.insert(0, rFonts)
    rFonts.set(qn("w:ascii"), "Times New Roman")
    rFonts.set(qn("w:hAnsi"), "Times New Roman")
    rFonts.set(qn("w:eastAsia"), "宋体")
    rFonts.set(qn("w:cs"), "Times New Roman")
    if size is not None:
        run.font.size = Pt(size)
    if bold is not None:
        run.bold = bold


def _parse_lines(text, skip_example=True):
    """解析多行文本：按换行分割，去除空行和序号前缀"""
    if not text or not text.strip():
        return []
    items = []
    for line in text.split("\n"):
        line = line.strip()
        if line and (not skip_example or not line.startswith("示例：")):
            line = re.sub(r"^\d+\.\s*", "", line)
            items.append(line)
    return items


def _add_para(doc, text, bold=False, size=None):
    """添加段落并统一字体"""
    p = doc.add_paragraph()
    r = p.add_run(str(text))
    _set_run_font(r, size=size, bold=bold)
    return p


def _add_heading(doc, text, level=1):
    """添加标题并统一字体"""
    h = doc.add_heading(text, level)
    for run in h.runs:
        _set_run_font(run)
    return h


def _add_numbered_list(doc, items, start=1):
    """添加编号列表段落"""
    for i, item in enumerate(items, start):
        _add_para(doc, f"{i}. {item}")


def _add_table(doc, headers, widths, rows):
    """创建表格并填充数据，统一设置样式和列宽"""
    from docx.shared import Pt

    tbl = doc.add_table(rows=1, cols=len(headers))
    tbl.style = "Table Grid"
    _hdr(tbl, headers)
    for row_data in rows:
        cells = tbl.add_row().cells
        for i, val in enumerate(row_data):
            _set_cell(cells[i], val)
    _fit_table(tbl, [Pt(w) for w in widths])
    return tbl


def _hdr(table, headers):
    from docx.enum.table import WD_ALIGN_VERTICAL
    from docx.enum.text import WD_ALIGN_PARAGRAPH

    for i, h in enumerate(headers):
        c = table.rows[0].cells[i]
        c.text = ""
        p = c.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        _set_run_font(p.add_run(h), size=9, bold=True)
        c.vertical_alignment = WD_ALIGN_VERTICAL.CENTER


def _set_cell(cell, text, bold=False, size=9, padding=None):
    from docx.enum.table import WD_ALIGN_VERTICAL
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Pt

    cell.text = ""
    p = cell.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(0)
    p.paragraph_format.space_before = Pt(0)
    _set_run_font(p.add_run(str(text)), size=size, bold=bold)
    cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
    # 仅当指定 padding 时才设置，否则使用 Word 默认值
    if padding is not None:
        tc = cell._tc
        tcPr = tc.get_or_add_tcPr()
        tcMar = tcPr.find(qn("w:tcMar"))
        if tcMar is None:
            tcMar = OxmlElement("w:tcMar")
            tcPr.append(tcMar)
        for child in list(tcMar):
            tcMar.remove(child)
        for side, val in padding.items():
            elem = OxmlElement(f"w:{side}")
            elem.set(qn("w:w"), val)
            elem.set(qn("w:type"), "dxa")
            tcMar.append(elem)


def _fit_table(table, widths=None):
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    if widths is None:
        widths = []
    # 在所有行上设置单元格宽度
    for row in table.rows:
        for i, cell in enumerate(row.cells):
            if i < len(widths):
                cell.width = widths[i]
    # 设置表格固定布局（与用户调整的文档一致）
    tbl = table._tbl
    tblPr = tbl.tblPr if tbl.tblPr is not None else OxmlElement("w:tblPr")
    tblLayout = tblPr.find(qn("w:tblLayout"))
    if tblLayout is None:
        tblLayout = OxmlElement("w:tblLayout")
        tblPr.append(tblLayout)
    tblLayout.set(qn("w:type"), "fixed")
    # 允许跨页断行
    for row in table.rows:
        trPr = row._tr.find(qn("w:trPr"))
        if trPr is None:
            trPr = OxmlElement("w:trPr")
            row._tr.insert(0, trPr)
        cant_split = trPr.find(qn("w:cantSplit"))
        if cant_split is None:
            cant_split = OxmlElement("w:cantSplit")
            trPr.append(cant_split)


def render(
    conf, df, stats, health_rows, intel_list, date, out_path, work_summary=None, follow_items=None, intel_items=None
):
    import docx
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Pt

    doc = docx.Document()

    # 统一设置样式字体
    def _apply_style_font(style):
        f = style.font
        f.name = "Times New Roman"
        rPr = style.element.get_or_add_rPr()
        rFonts = rPr.find(qn("w:rFonts"))
        if rFonts is None:
            rFonts = OxmlElement("w:rFonts")
            rPr.insert(0, rFonts)
        for attr in ("w:ascii", "w:hAnsi", "w:cs"):
            rFonts.set(qn(attr), "Times New Roman")
        rFonts.set(qn("w:eastAsia"), "宋体")

    _apply_style_font(doc.styles["Normal"])
    doc.styles["Normal"].font.size = Pt(10.5)
    for name in ("Heading 1", "Heading 2", "Title"):
        try:
            _apply_style_font(doc.styles[name])
        except KeyError:
            pass
    h = _add_heading(doc, conf["title"], 0)
    h.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sub = doc.add_paragraph()
    r = sub.add_run(f"日期：{date[:4]}-{date[4:6]}-{date[6:]}    编制：网络安全值守组    密级：内部")
    _set_run_font(r, bold=True)
    sub.alignment = WD_ALIGN_PARAGRAPH.RIGHT

    # 一、当日态势概览与重点工作总结
    _add_heading(doc, "一、当日态势概览与重点工作总结", 1)
    total = max(stats["total"], 1)
    auto_summary = (
        f"今日共捕获告警 {stats['total']} 起，其中内网 {stats['int_count']} 起"
        f"（{stats['int_count'] / total * 100:.1f}%），外网 {stats['ext_count']} 起"
        f"（{stats['ext_count'] / total * 100:.1f}%），累计处置 IP {stats['ban_count']} 个。"
    )
    _add_para(doc, f"1. {auto_summary}")
    work_items = _parse_lines(work_summary)
    _add_numbered_list(doc, work_items, start=2)

    # 二、关键指标
    _add_heading(doc, "二、关键指标", 1)
    _add_table(
        doc,
        ["内网告警", "次数", "外网告警", "次数"],
        [110, 111, 110, 111],
        [(lv, stats["int_level"].get(lv, 0), lv, stats["ext_level"].get(lv, 0)) for lv in LEVELS],
    )
    for idx, (title, body) in enumerate(
        [
            ("可疑域名解析请求分析", "通过定期对应用进行安全事件监测，暂未发现可疑域名解析请求事件。"),
            ("敏感文件分析", "通过定期对应用进行安全事件监测，暂未发现敏感文件。"),
            ("黑链挂马分析", "通过定期对应用进行安全事件监测，暂未发现黑链/挂马事件。"),
            ("可用性分析", "通过定期对应用进行安全事件监测，暂未发现存在可用性事件。"),
            ("篡改分析", "通过定期对应用进行安全事件监测，暂未发现网页篡改事件。"),
            ("域名劫持分析", "通过定期对应用进行安全事件监测,暂未发现域名劫持事件。"),
        ],
        start=1,
    ):
        _add_heading(doc, f"{idx}. {title}", 2)
        _add_para(doc, body)

    # 三、研判与处置流程
    _add_heading(doc, "三、研判与处置流程", 1)
    for s in [
        "流量采集：安全设备日志导出 + NDR 探针 + 防火墙 IPS",
        "情报比对：威胁情报平台 IOC 命中 / ASN 与归属地归类",
        "内外网判定：源 IP 静态段 + 资产归属 + 流量方向三重校验",
        "分级处置：P0 即时处置 / P1 当日处置 / P2 观察 / P3 沉淀",
    ]:
        p = doc.add_paragraph(style="List Number")
        _set_run_font(p.add_run(s))

    # 四、资产健康检查
    _add_heading(doc, "四、资产健康检查", 1)
    _add_para(doc, "值守期间持续监控安全设备运行状态，确保监测能力不降级。")
    _add_table(
        doc,
        ["探针名称", "IP", "状态", "备注"],
        [120, 100, 111, 111],
        [(name, ip, "正常", "") for name, ip, *_ in health_rows],
    )
    _add_para(doc, f"日志留存：{conf['retention']} 天。")

    # 五、外网攻击研判与处置
    _add_heading(doc, "五、外网攻击研判与处置", 1)
    ext = stats["external"]
    if len(ext) > 0:
        grp = ext.groupby("攻击名称", sort=False).agg({"威胁等级": "first", "源IP": "count"}).reset_index()
        ext_rows = [
            (idx, row["攻击名称"], f"{int(row['源IP'])} 起", "流量特征+情报比对", "已处置")
            for idx, (_, row) in enumerate(grp.iterrows(), start=1)
        ]
    else:
        ext_rows = [("（无外网告警）", "", "", "", "")]
    _add_table(doc, ["序号", "威胁类型", "命中次数", "研判依据", "状态"], [41, 203, 51, 106, 41], ext_rows)

    # 六、内网异常研判与处置
    _add_heading(doc, "六、内网异常研判与处置", 1)
    intdf = stats["internal"]
    if len(intdf) > 0:
        agg_map = {"源IP": "count"}
        if "威胁等级" in intdf.columns:
            agg_map["威胁等级"] = "first"
        grp = intdf.groupby("攻击名称", sort=False).agg(agg_map).reset_index()
        int_rows = []
        for idx, (_, row) in enumerate(grp.iterrows(), start=1):
            lvl = row.get("威胁等级", "") if "威胁等级" in row else ""
            status = "取证/核查" if lvl in conf["crit_levels"] else "观察"
            int_rows.append((idx, row["攻击名称"], f"{int(row['源IP'])} 起", "流量特征+情报比对", status))
    else:
        int_rows = [("（无内网告警）", "", "", "", "")]
    _add_table(doc, ["序号", "威胁类型", "命中次数", "研判依据", "状态"], [41, 203, 51, 106, 41], int_rows)

    # 七、重点事件研判
    _add_heading(doc, "七、重点事件研判", 1)
    key = df[df["威胁等级"].isin(conf["crit_levels"])].copy()
    if len(key) > 0:
        key["_p"] = key["威胁等级"].map({lv: i for i, lv in enumerate(LEVELS)})
        key = key.sort_values("_p")
        grp = key.groupby(["攻击名称", "源IP"], sort=False).size().reset_index(name="count")
        grp = grp.sort_values("count", ascending=False).head(conf["top"])
        evt_name_map = {}
        for idx, row in enumerate(grp[["攻击名称"]].drop_duplicates().values, 1):
            evt_name_map[row[0]] = idx
        key_rows = [
            (evt_name_map[row["攻击名称"]], row["攻击名称"], row["源IP"], row["count"]) for _, row in grp.iterrows()
        ]
        _add_table(doc, ["序号", "事件名称", "源地址", "攻击次数"], [41, 145, 135, 121], key_rows)
    else:
        _add_para(doc, "今日无严重/高危级事件。")

    # 八、情报动态
    _add_heading(doc, "八、情报动态", 1)
    _add_para(doc, "当日需关注的新增 CVE / 行业预警：")
    intel_parsed = _parse_lines(intel_items, skip_example=False)
    if intel_parsed:
        _add_numbered_list(doc, intel_parsed)
    elif intel_list:
        _add_table(
            doc,
            ["类型", "编号", "风险", "关联资产", "应对/时限"],
            [60, 85, 65, 115, 117],
            [
                (
                    item.get("类型", ""),
                    item.get("编号", ""),
                    item.get("风险", ""),
                    item.get("关联资产", ""),
                    f"{item.get('应对', '')} / {item.get('时限', '')}",
                )
                for item in intel_list
            ],
        )
    else:
        _add_para(doc, "（暂无新增情报，详见威胁情报平台）")

    # 九、待跟进事项
    _add_heading(doc, "九、待跟进事项", 1)
    default_items = [
        "内网高危告警溯源与处置闭环",
        "外网封禁 IP 清单同步至边界防火墙",
        "失陷终端取证与隔离",
        "资产健康检查异常处理",
    ]
    follow_parsed = _parse_lines(follow_items, skip_example=False)
    _add_numbered_list(doc, follow_parsed if follow_parsed else default_items)

    doc.save(out_path)


def load_intel(conf):
    p = Path(os.path.join(runtime_dir, conf["intel_file"]))
    if not p.exists():
        return []
    try:
        import pandas as pd

        return pd.read_csv(p).fillna("").to_dict("records")
    except Exception as e:
        _log(f"[!] 加载情报文件失败: {e}")
        return []


def pick_input_and_date(pattern):
    # 文件名排除关键词（不区分大小写）：非安全告警类的辅助/输出/配置文件
    _EXCLUDE_KEYS = (
        "终端ip地址表",
        "终端ip",
        "业务ip",
        "业务IP",
        "biz_ip",
        "ip归属分析",
        "IP归属分析",
        "ip分析",
        "IP分析",
        "值守保障日报",
        "值守日报",
        "日报",
        "日报汇总",
        "config",
        "配置",
        "config.ini",
        "version",
        "情报",
        "intel",
    )

    def _is_excluded(fpath):
        s = fpath.stem
        for k in _EXCLUDE_KEYS:
            if k.lower() in s.lower():
                return k
        return None

    files = sorted(Path(runtime_dir).glob(pattern), key=os.path.getmtime, reverse=True)
    if not files:
        files = sorted(Path(runtime_dir).glob("*.xls*"), key=os.path.getmtime, reverse=True)

    # 先输出候选与排除情况，便于定位
    excluded_info = []
    filtered = []
    for f in files:
        reason = _is_excluded(f)
        if reason:
            excluded_info.append(f"  ! {f.name}  已排除(命中关键词: {reason})")
        else:
            filtered.append(f)
    files = filtered
    if excluded_info:
        _log("[*] 自动识别排除文件:")
        _log("\n".join(excluded_info))

    if not files:
        raise FileNotFoundError(
            "未找到安全告警类 Excel，请把安全设备导出的日志放到脚本目录，"
            "并确保文件名不含「业务IP/终端IP/值守日报/IP归属分析」等排除关键词"
        )

    # 锚点优先选择: stem 中包含 8 位日期 的最新 mtime 文件（真实告警导出一般带时间戳）
    dated_files = [f for f in files if re.search(r"(\d{8})", f.stem)]
    if dated_files:
        anchor = sorted(dated_files, key=os.path.getmtime, reverse=True)[0]
    else:
        anchor = files[0]  # 退化: 所有文件都没带日期，取 mtime 最新

    stem = anchor.stem
    m = re.search(r"(\d{8})", stem)
    if m:
        date = m.group(1)
        _log(f"[*] 自动识别锚点文件: {anchor.name} (日期: {date})")
    else:
        date = datetime.now().strftime("%Y%m%d")
        _log(f"[*] 自动识别锚点文件: {anchor.name} (文件名无日期，使用今日: {date})")

    target_files = []
    for f in files:
        fm = re.search(r"(\d{8})", f.stem)
        if fm and fm.group(1) == date:
            target_files.append(f)
    if not target_files:
        target_files = [anchor]
    _log(f"[*] 自动识别结果: 共 {len(target_files)} 个文件 (日期: {date})")
    return target_files, date


def generate_daily_report(files, date, work_summary=None, follow_items=None, intel_items=None, local_geos=None):
    conf = load_config(files, local_geos=local_geos)  # files：自动提取区域/归属地；local_geos：GUI 自定义
    df = load_and_classify(files, conf)
    stats = analyze(df)
    _log(
        f"[+] 总告警 {stats['total']} | 内网 {stats['int_count']} | 外网 {stats['ext_count']} | 处置 {stats['ban_count']}"
    )
    health_rows = conf["probes"]
    intel_list = load_intel(conf)
    # 使用 runtime_dir（脚本/exe所在目录）作为输出基础目录
    out_dir = Path(runtime_dir) / conf["out_dir"]
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / f"值守保障日报{date}.docx"
    render(conf, df, stats, health_rows, intel_list, date, str(out_path), work_summary, follow_items, intel_items)
    _log(f"[✓] 值守日报已生成: {out_path}")
    return out_path
