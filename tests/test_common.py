"""common.py 单元测试：路径、日志/进度回调、文件查找"""

import os

import common


def test_paths_defined():
    assert os.path.isdir(common.script_dir)
    assert common.runtime_dir == common.script_dir  # 非 frozen 模式
    assert common.meipass_dir is None


def test_log_routes_to_callback():
    msgs = []
    common.set_gui_callbacks(log_cb=msgs.append, progress_cb=lambda v, m: None)
    common._log("hello")
    assert msgs == ["hello"]
    common._log("world")
    assert msgs == ["hello", "world"]
    # 不传 log_cb 时保留原回调
    common.set_gui_callbacks(progress_cb=lambda v, m: None)
    common._log("still")
    assert msgs == ["hello", "world", "still"]


def test_progress_routes_to_callback():
    events = []
    common.set_gui_callbacks(log_cb=lambda m: None, progress_cb=lambda v, m: events.append((v, m)))
    common._set_progress(10, 100)
    common._set_progress(0, 0)
    assert events == [(10, 100), (0, 0)]


def test_find_file(tmp_path, monkeypatch):
    monkeypatch.setattr(common, "runtime_dir", str(tmp_path))
    (tmp_path / "config.ini").write_text("x", encoding="utf-8")
    assert common._find_file("config.ini") == str(tmp_path / "config.ini")
    # 不存在时返回 exe 目录路径（不抛异常）
    missing = common._find_file("not_exist.ini")
    assert missing == str(tmp_path / "not_exist.ini")
