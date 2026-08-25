#!/usr/bin/env python3
"""
网络安全值守保障日报整合脚本（纯入口，方案一拆分后）
功能：1. IP归属分析（ipdb.py） 2. 值守日报生成（report.py） 3. GUI（gui.py）
依赖：pip install pandas openpyxl python-docx requests py-ip2region
"""

import os
import subprocess
import sys
import warnings
from datetime import datetime

# B档：通用工具与自动更新逻辑已拆分至 common.py / updater.py
# 方案一：IP 归属域 → ipdb.py；日报域 → report.py；GUI → gui.py；本文件仅保留入口与版本
# 以下 re-export 为兼容层（cli_main 使用 + tests 以 main.xxx 访问），# noqa: F401 防 ruff 误删
from gui import gui_main
from ipdb import (  # noqa: F401
    EXCLUDED_IP_LABELS,
    EXCLUDED_IP_NETWORKS,
    _parse_ip_range,
    extract_geos_from_alerts,
    extract_zones_from_alerts,
    format_online_result,
    generate_ip_report,
    is_excluded_ip,
    is_private_ip,
    is_valid_public_ip,
    load_config,
    load_external_excluded_ips,
    load_probes_from_excel,
    load_terminal_ip_table,
    local_ip_label,
    parse_region,
    query_all_ips,
    set_terminal_ip_table_path,
)
from report import (  # noqa: F401
    analyze,
    classify,
    generate_daily_report,
    load_and_classify,
    load_intel,
    load_single_file,
    pick_input_and_date,
    render,
)
from updater import update_worker_main


# 修复 numpy 2.x 在打包后 DLL 加载问题
def _setup_dll_paths():
    """在打包模式下设置 numpy/pandas 的 DLL 路径"""
    if not getattr(sys, "frozen", False):
        return

    # 获取基础目录
    if hasattr(sys, "_MEIPASS"):
        base_dir = sys._MEIPASS
    else:
        base_dir = os.path.dirname(sys.executable)

    # 添加 numpy.libs 目录
    numpy_libs = os.path.join(base_dir, "numpy.libs")
    if os.path.isdir(numpy_libs):
        try:
            os.add_dll_directory(numpy_libs)
        except (OSError, AttributeError):
            if hasattr(os, "environ"):
                os.environ["PATH"] = numpy_libs + os.pathsep + os.environ.get("PATH", "")

    # 添加 pandas.libs 目录
    pandas_libs = os.path.join(base_dir, "pandas.libs")
    if os.path.isdir(pandas_libs):
        try:
            os.add_dll_directory(pandas_libs)
        except (OSError, AttributeError):
            if hasattr(os, "environ"):
                os.environ["PATH"] = pandas_libs + os.pathsep + os.environ.get("PATH", "")

    # 调试信息（可选）
    if os.environ.get("DEBUG_NUMPY", "0") == "1":
        print(f"[DEBUG] frozen={getattr(sys, 'frozen', False)}")
        print(f"[DEBUG] base_dir={base_dir}")
        print(f"[DEBUG] numpy.libs exists={os.path.isdir(numpy_libs)}")
        print(f"[DEBUG] pandas.libs exists={os.path.isdir(pandas_libs)}")
        if os.path.isdir(numpy_libs):
            print(f"[DEBUG] numpy.libs contents: {os.listdir(numpy_libs)}")
        if os.path.isdir(pandas_libs):
            print(f"[DEBUG] pandas.libs contents: {os.listdir(pandas_libs)}")


_setup_dll_paths()

warnings.filterwarnings("ignore", category=UserWarning, module="openpyxl")

REQUIRED = {
    "pandas": "pandas",
    "openpyxl": "openpyxl",
    "python-docx": "docx",
    "requests": "requests",
    "py-ip2region": "ip2region",
}


def ensure_deps():
    # 打包后禁用自动安装（sys.executable会指向exe本身，导致无限递归）
    # 同时检查 frozen 和 _MEIPASS，确保在各种打包场景下都能正确检测
    if getattr(sys, "frozen", False) or hasattr(sys, "_MEIPASS"):
        return
    if os.environ.get("NO_AUTO_INSTALL") == "1":
        return
    miss = [p for p, i in REQUIRED.items() if _import_failed(i)]
    if not miss:
        return
    print(f"[!] 自动安装缺失依赖: {miss}")
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", *miss, "-i", "https://pypi.tuna.tsinghua.edu.cn/simple"]
    )


def _import_failed(name):
    try:
        __import__(name)
        return False
    except ImportError:
        return True


ensure_deps()

# ================ 版本 ================
APP_VERSION = "1.7.0"
# 自动更新逻辑已拆分至 updater.py；GUI 版本号经 gui_main(app_version) 注入


def cli_main():
    """命令行模式入口"""
    print("=" * 60)
    print("网络安全值守保障日报整合脚本")
    print("功能：1. IP归属分析  2. 值守日报生成")
    print("=" * 60)
    input_files, date = pick_input_and_date("*.xlsx")
    print(f"\n[+] 日期: {date}")
    print(f"[+] 发现 {len(input_files)} 个待处理文件:")
    for f in input_files:
        print(f"    - {f.name}")
    print("\n" + "=" * 60)
    print("步骤1: IP归属分析")
    print("=" * 60)
    ip_report_path = generate_ip_report(input_files, date)
    print("\n" + "=" * 60)
    print("步骤2: 生成值守日报")
    print("=" * 60)
    daily_report_path = generate_daily_report(input_files, date)
    print("\n" + "=" * 60)
    print("全部完成！")
    print(f"IP归属分析结果: {ip_report_path}")
    print(f"值守日报: {daily_report_path}")
    print("=" * 60)


def main():
    """
    主入口（按优先级判断模式）:
      1) --update-worker=<jsonPath>   纯后台覆盖模式（优先级最高，绝不加载GUI）
      2) -c / --cli                   命令行模式
      3) 默认                          GUI 模式
    """
    for arg in sys.argv[1:]:
        if arg.startswith("--update-worker="):
            _path = arg.split("=", 1)[1].strip('"')
            try:
                _rc = update_worker_main(_path)
            except Exception as _e:
                try:
                    import tempfile as _tf

                    _log = os.path.join(_tf.gettempdir(), "update_last.log")
                    with open(_log, "a", encoding="utf-8") as _f:
                        import traceback as _tb

                        _f.write(f"[{datetime.now():%H:%M:%S}] worker崩溃: {_e}\n{_tb.format_exc()}\n")
                except Exception:
                    pass
                _rc = 99
            sys.exit(_rc)
    if "-c" in sys.argv or "--cli" in sys.argv:
        cli_main()
    else:
        gui_main(APP_VERSION)


if __name__ == "__main__":
    main()
