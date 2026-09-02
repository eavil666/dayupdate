"""pytest 公共配置：
- 打桩 tkinter（main.py 顶层 import，测试环境无显示）
- 关闭自动安装依赖（NO_AUTO_INSTALL=1）
"""

import os
import sys
import types

os.environ.setdefault("NO_AUTO_INSTALL", "1")

_tk = types.ModuleType("tkinter")
for _n in (
    "Tk",
    "Frame",
    "Label",
    "Button",
    "Listbox",
    "Entry",
    "Text",
    "Scrollbar",
    "filedialog",
    "messagebox",
    "StringVar",
    "END",
    "NONE",
    "DISABLED",
    "NORMAL",
):
    setattr(_tk, _n, type(_n, (), {}))
sys.modules.setdefault("tkinter", _tk)
