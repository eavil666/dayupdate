"""更新链路端到端测试：本地 file:// 更新源（不触网，CI Linux/Windows 均可跑）

覆盖：检查更新（发现/已最新/失败）→ 下载 + MD5 校验 → 安装参数契约。
"""

import hashlib
import json
import json as _json
import os
import sys

import pytest

import updater


def _make_update_source(tmp_path, version="9.9.9", exe_data=b"fake-exe-content"):
    """构造本地更新源：version.json + exe 副本，返回 (version_json路径, exe路径, md5)"""
    exe_path = tmp_path / "daily-report.exe"
    exe_path.write_bytes(exe_data)
    md5 = hashlib.md5(exe_data).hexdigest().upper()
    (tmp_path / "version.json").write_text(
        json.dumps(
            {
                "version": version,
                "exe_urls": [str(exe_path)],
                "md5": md5,
                "release_note": "test",
                "force_update": False,
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return str(tmp_path / "version.json"), str(exe_path), md5


def test_update_flow_local_source(tmp_path):
    """端到端：本地源 检查更新 → 下载 → MD5 校验"""
    vj, exe_src, md5 = _make_update_source(tmp_path)
    au = updater.AutoUpdater(current_version="1.6.1", version_urls=[vj], exe_urls=[], log_cb=lambda m: None)
    info = au.check_update()
    assert info is not None
    assert info["version"] == "9.9.9"
    assert au.last_status == "发现新版本"

    tmp_exe = au.download_update(info)
    assert tmp_exe and os.path.exists(tmp_exe)
    with open(tmp_exe, "rb") as f:
        assert hashlib.md5(f.read()).hexdigest().upper() == md5
    os.remove(tmp_exe)


def test_update_no_new_version(tmp_path):
    """当前版本 >= 最新 → 已是最新（不触发下载）"""
    vj, _, _ = _make_update_source(tmp_path, version="1.0.0")
    au = updater.AutoUpdater(current_version="1.6.1", version_urls=[vj], log_cb=lambda m: None)
    assert au.check_update() is None
    assert au.last_status == "已是最新"


def test_update_source_unreachable(tmp_path):
    """本地源缺失 → 检查失败并记录原因"""
    au = updater.AutoUpdater(current_version="1.6.1", version_urls=[str(tmp_path / "nope.json")], log_cb=lambda m: None)
    assert au.check_update() is None
    assert au.last_status == "检查失败"
    assert au.last_check_error


def test_install_params_contract(tmp_path, monkeypatch):
    """install_and_restart 的 params.json 键名契约（mock 进程/复制，不真正执行）"""
    import shutil
    import subprocess
    import tempfile

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "app.exe"))
    new_exe = tmp_path / "new.exe"
    new_exe.write_bytes(b"new-binary")

    monkeypatch.setattr(shutil, "copy2", lambda src, dst: None)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: None)
    monkeypatch.setattr(os, "_exit", lambda code: (_ for _ in ()).throw(SystemExit(code)))
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))

    au = updater.AutoUpdater(current_version="1.6.1", log_cb=lambda m: None)
    with pytest.raises(SystemExit):
        au.install_and_restart(str(new_exe))

    params = list(tmp_path.glob("update_*_params.json"))
    assert params, "params.json 未生成"
    data = _json.loads(params[0].read_text(encoding="utf-8"))
    for key in ("parentPid", "oldExe", "newExe", "bakExe", "workDir", "jsonPath", "workerExe"):
        assert key in data, f"params.json 缺少键: {key}"
    assert data["newExe"] == str(new_exe)
    assert data["oldExe"] == str(tmp_path / "app.exe")
    # worker 副本应生成（copy2 目标在 temp 目录）
    str_values = [v for v in data.values() if isinstance(v, str)]
    assert any(str(tmp_path) in v for v in str_values)
