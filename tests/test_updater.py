# -*- coding: utf-8 -*-
"""updater.py 单元测试：版本比较、SSL 降级、配置解析、AutoUpdater 状态机"""
import sys
import types
from types import SimpleNamespace

import pytest

import updater


class _Resp:
    status = 200
    headers = {}

    def __init__(self, payload=None):
        self._payload = payload or {}

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class _FakeRequests:
    """可编程 requests 桩：verify=True 时抛 SSL 错（可关），否则返回响应。"""
    exceptions = SimpleNamespace(SSLError=Exception)

    def __init__(self, ssl_break=True, payload=None, fail_always=None):
        self.ssl_break = ssl_break
        self.payload = payload or {'version': '9.9.9'}
        self.fail_always = fail_always
        self.calls = []

    def get(self, url, **kw):
        self.calls.append((url, kw))
        if self.fail_always:
            raise self.fail_always
        if self.ssl_break and kw.get('verify') is not False:
            raise Exception('CERTIFICATE_VERIFY_FAILED test')
        return _Resp(self.payload)


@pytest.fixture
def fake_requests(monkeypatch):
    def _install(fake):
        monkeypatch.setitem(sys.modules, 'requests', fake)
        return fake
    return _install


# ---------- parse_version ----------

def test_parse_version():
    assert updater.parse_version('1.5.0') > updater.parse_version('1.4.1')
    assert updater.parse_version('1.4.1') == updater.parse_version('1.4.1')
    assert updater.parse_version('1.10.0') > updater.parse_version('1.9.9')
    assert updater.parse_version('v1.2.3') == (1, 2, 3)
    assert updater.parse_version(None) == ()


# ---------- is_ssl_or_ca_error ----------

def test_is_ssl_or_ca_error_keywords():
    assert updater.is_ssl_or_ca_error(Exception('CERTIFICATE_VERIFY_FAILED')) is True
    assert updater.is_ssl_or_ca_error(Exception('SSL handshake failed')) is True
    assert updater.is_ssl_or_ca_error(Exception('Could not find suitable TLS CA bundle')) is True
    assert updater.is_ssl_or_ca_error(Exception('HTTP 500 server error')) is False
    assert updater.is_ssl_or_ca_error(OSError('CERTIFICATE bundle problem')) is True


# ---------- safe_get ----------

def test_safe_get_ssl_fallback(fake_requests):
    fake = _FakeRequests(ssl_break=True)
    fake_requests(fake)
    r = updater.safe_get('http://a', ssl_fallback_msg='msg', timeout=10)
    assert r.status == 200
    assert len(fake.calls) == 2
    assert fake.calls[0][1]['verify'] is not False
    assert fake.calls[1][1]['verify'] is False


def test_safe_get_normal_single_call(fake_requests):
    fake = _FakeRequests(ssl_break=False)
    fake_requests(fake)
    updater.safe_get('http://b')
    assert len(fake.calls) == 1


def test_safe_get_non_ssl_raises(fake_requests):
    fake = _FakeRequests(fail_always=Exception('HTTP 500 server error'))
    fake_requests(fake)
    with pytest.raises(Exception, match='HTTP 500'):
        updater.safe_get('http://c')


def test_safe_get_ssl_fallback_silent(fake_requests, monkeypatch):
    """降级重试成功后不应打印 ssl_fallback_msg（成功路径对用户透明）。

    用户反馈：之前每次启动都会看到 "SSL验证失败，跳过证书验证重试"，
    即使重试成功也显示，造成误报。修复后只有真正失败时才有提示。
    """
    import common
    logs = []
    monkeypatch.setattr(common, '_log', logs.append)
    monkeypatch.setattr(common, 'set_gui_callbacks', lambda *a, **k: None)
    fake = _FakeRequests(ssl_break=True)
    fake_requests(fake)
    r = updater.safe_get('http://a', ssl_fallback_msg='不应打印', timeout=10)
    assert r.status == 200
    assert len(fake.calls) == 2  # 确认走了降级路径
    assert logs == []  # 但用户日志完全无干扰


# ---------- load_update_config ----------

def test_load_update_config_reads_section(tmp_path, monkeypatch):
    monkeypatch.setattr(updater, 'runtime_dir', str(tmp_path))
    (tmp_path / 'config.ini').write_text(
        '[update]\n'
        'version_urls = http://192.168.1.10/report/version.json\n'
        '# comment line\n'
        'exe_urls = http://192.168.1.10/report/daily-report-{version}.exe\n',
        encoding='utf-8')
    vu, eu = updater.load_update_config()
    assert vu == ['http://192.168.1.10/report/version.json']
    assert eu == ['http://192.168.1.10/report/daily-report-{version}.exe']


def test_load_update_config_no_section(tmp_path, monkeypatch):
    monkeypatch.setattr(updater, 'runtime_dir', str(tmp_path))
    (tmp_path / 'config.ini').write_text('[network]\nx = 1\n', encoding='utf-8')
    assert updater.load_update_config() == ([], [])


def test_load_update_config_no_file(tmp_path, monkeypatch):
    monkeypatch.setattr(updater, 'runtime_dir', str(tmp_path))
    assert updater.load_update_config() == ([], [])


# ---------- AutoUpdater ----------

def test_autoupdater_eval_and_return():
    au = updater.AutoUpdater(current_version='1.0.0')
    info = au._eval_and_return({'version': '1.1.0'})
    assert info is not None and au.last_status == '发现新版本'
    au2 = updater.AutoUpdater(current_version='1.5.0')
    assert au2._eval_and_return({'version': '1.1.0'}) is None
    assert au2.last_status == '已是最新'


def test_autoupdater_resolve_exe_urls():
    au = updater.AutoUpdater(exe_urls=['http://x/v{version}/a.exe'])
    urls = au._resolve_exe_urls({'version': '1.2.0'})
    assert urls == ['http://x/v1.2.0/a.exe']
    # info 自带 exe_urls 优先
    assert au._resolve_exe_urls({'version': '1.2.0', 'exe_urls': ['u1', 'u2']}) == ['u1', 'u2']


def test_autoupdater_custom_source_fail():
    """配置自定义源（本地不存在的文件）→ 检查失败并记录原因，不触网"""
    au = updater.AutoUpdater(current_version='1.0.0',
                             version_urls=[r'E:/nonexistent/version.json'])
    assert au.custom_source is True
    info = au.check_update()
    assert info is None
    assert au.last_status == '检查失败'
    assert '获取失败' in au.last_check_error


def test_autoupdater_default_not_custom():
    au = updater.AutoUpdater(current_version='1.0.0')
    assert au.custom_source is False
