#!/usr/bin/env python3
"""通用共享模块（B档拆分自 main.py）

职责：
- 运行路径（script_dir / runtime_dir / meipass_dir）
- 日志 / 进度回调注册（_log / _set_progress / set_gui_callbacks）
- 文件查找（_find_file）

零业务依赖，仅标准库。被 updater.py / main.py 等模块复用。
"""

import os
import sys
from datetime import datetime

script_dir = os.path.dirname(os.path.abspath(__file__))
# 运行时基础目录（打包后优先使用exe所在目录）
if getattr(sys, "frozen", False):
    # 单文件模式：优先使用exe所在目录，用户的数据文件放在这里
    exe_dir = os.path.dirname(sys.executable)
    runtime_dir = exe_dir
    # 记录临时解压目录，用于读取内置资源
    if hasattr(sys, "_MEIPASS"):
        meipass_dir = sys._MEIPASS
    else:
        meipass_dir = None
else:
    runtime_dir = script_dir
    meipass_dir = None


# GUI 日志回调，由 App 实例注册
_gui_log_callback = None
_gui_progress_callback = None

# ---- 日志级别 ----
INFO = "INFO"

# 文件日志路径（追加；*.log 已在 .gitignore，不入库）
_log_file_path = os.path.join(runtime_dir, "app.log")


def set_gui_callbacks(log_cb=None, progress_cb=None):
    """注册 GUI 日志/进度回调（GUI 初始化时调用；传 None 则保留原值）。

    - log_cb(msg)：日志文本回调（收到原始 msg，GUI 自带时间戳显示）
    - progress_cb(value, maximum)：进度回调（maximum=None 不确定模式，0 表示完成）
    """
    global _gui_log_callback, _gui_progress_callback
    if log_cb is not None:
        _gui_log_callback = log_cb
    if progress_cb is not None:
        _gui_progress_callback = progress_cb


def _append_log_file(msg, level=INFO):
    """追加写文件日志（带日期时间戳），失败不影响主流程"""
    try:
        with open(_log_file_path, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] [{level}] {msg}\n")
    except Exception:
        pass


def _log(msg, level=INFO):
    """统一日志：时间戳 + 级别 + 文件（app.log）+ GUI/控制台。

    - GUI 模式：回调收到【原始 msg】（GUI 自带时间戳，避免双时间戳）
    - CLI 模式：print 带时间戳与级别（flush 保证 CI/管道及时输出）
    - 文件：追加到 runtime_dir/app.log（含日期，便于跨天排障）
    """
    _append_log_file(msg, level)
    if _gui_log_callback:
        _gui_log_callback(msg)
    else:
        print(f"[{datetime.now():%H:%M:%S}] [{level}] {msg}", flush=True)


def _set_progress(value, maximum=None):
    """设置进度条：value 为当前值，maximum 为最大值（None 表示不确定模式）"""
    if _gui_progress_callback:
        _gui_progress_callback(value, maximum)


def _find_file(filename):
    """查找文件，优先从exe目录，其次从临时解压目录"""
    # 先从exe目录查找
    exe_path = os.path.join(runtime_dir, filename)
    if os.path.exists(exe_path):
        return exe_path
    # 如果有临时解压目录，从那里查找
    if meipass_dir:
        meipass_path = os.path.join(meipass_dir, filename)
        if os.path.exists(meipass_path):
            return meipass_path
    return exe_path  # 返回exe目录路径（可能不存在）
