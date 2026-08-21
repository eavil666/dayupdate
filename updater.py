#!/usr/bin/env python3
"""自动更新模块（B档拆分自 main.py）

职责：
- 更新源配置与版本检查（GitHub API / version.json 镜像 / 内网自定义源）
- EXE 下载（多镜像回退 + MD5 校验 + 进度回调）
- 安装与重启（--update-worker 自更新模式，无外部依赖）
- 网络/SSL 基础设施（get_requests_verify / is_ssl_or_ca_error / safe_get，
  供 IP 库下载等业务模块复用）

依赖：仅 stdlib + requests + common（日志/路径）。**不依赖任何业务模块**。
"""

import configparser
import os
import re
import subprocess
import sys
import time
from datetime import datetime

from common import runtime_dir

# ================ 版本 & 自动更新 ================

# 版本信息来源：按优先级依次尝试
# 在 GitHub / 内网HTTP / 共享目录 放置 version.json，例如：
# {
#   "version": "1.1.0",
#   "exe_urls": [
#     "https://github.com/eavil666/dayupdate/releases/download/v1.1.0/daily-report.exe",
#     "https://ghfast.top/https://github.com/eavil666/dayupdate/releases/download/v1.1.0/daily-report.exe",
#     "https://ghproxy.net/https://github.com/eavil666/dayupdate/releases/download/v1.1.0/daily-report.exe"
#   ],
#   "md5": "abc123...",
#   "release_note": "修复IP归属显示问题",
#   "force_update": false
# }
# exe_urls 为数组时按顺序回退；也兼容 exe_url 单字符串格式
# GitHub API：始终返回真实最新 release（无 CDN 缓存），作为首选版本源
# 注意：未鉴权时 60 次/小时限频，桌面应用每次启动查一次足够
GITHUB_API_LATEST = "https://api.github.com/repos/eavil666/dayupdate/releases/latest"

# EXE 下载 CDN 镜像前缀（应用到 GitHub 直链前，按顺序回退）
CDN_MIRROR_PREFIXES = [
    "",  # GitHub 直链
    "https://ghfast.top/",
    "https://ghproxy.net/",
    "https://gh-proxy.com/",
    "https://mirror.ghproxy.com/",
]

# version.json 兜底源（GitHub API 失败时使用）
# 分支开发模式：兜底源指向当前开发分支（refactor/b-module-split），
# 保证分支发布的 version.json 能被客户端兜底读到。
# 注意：raw.githubusercontent.com 对含斜杠的分支名须用【非编码】路径（斜杠直接放），
# URL 编码 %2F 会 404。若日后合并回 main，把下面三处分支名改回 main 即可。
# 不要用 jsDelivr（cdn.jsdelivr.net）——它对 version.json 长缓存且忽略 ?t= 参数，
# 会返回远古旧版本（实测缓存到 1.0.0），导致"一版一版升"或检测错乱
UPDATE_VERSION_URLS = [
    # raw 优先：缓存仅 5 分钟（分支名斜杠不编码）
    "https://raw.githubusercontent.com/eavil666/dayupdate/refactor/b-module-split/version.json",
    # ghproxy/ghfast 镜像 raw：国内可达，无长缓存问题
    "https://ghproxy.net/https://raw.githubusercontent.com/eavil666/dayupdate/refactor/b-module-split/version.json",
    "https://ghfast.top/https://raw.githubusercontent.com/eavil666/dayupdate/refactor/b-module-split/version.json",
    # "http://intranet-server/apps/report/version.json",
    # r"\\file-server\share\report\version.json",
]

# 备选EXE下载源（如果version.json内未提供exe_urls/exe_url）
UPDATE_EXE_URLS = [
    "https://github.com/eavil666/dayupdate/releases/download/v{version}/daily-report.exe",
    "https://ghfast.top/https://github.com/eavil666/dayupdate/releases/download/v{version}/daily-report.exe",
    # "http://intranet-server/apps/report/daily-report-{version}.exe",
    # r"\\file-server\share\report\daily-report-{version}.exe",
]


def parse_version(v):
    """把版本号字符串解析为可比较的整数元组（如 '1.10.0' -> (1,10,0)）"""
    parts = []
    for x in re.findall(r"\d+", str(v)):
        try:
            parts.append(int(x))
        except (ValueError, TypeError):
            parts.append(0)
    return tuple(parts)


# ---------------- 网络 / SSL 基础设施 ----------------


def get_requests_verify():
    """返回 requests 可用的 verify 参数。
    - 若 certifi 的 CA bundle 实际可用（路径存在且能被 ssl 创建 context）则用该路径；
    - 否则返回 True，让 requests 走默认/环境变量；
    - 最终 SSL 若仍失败，调用方的降级逻辑会再降到 verify=False。"""
    try:
        if getattr(sys, "frozen", False):
            try:
                import ssl

                import certifi

                ca_path = certifi.where()
                # PyInstaller certifi hook 有时把 cacert.pem 放到多个目录，
                # certifi.where() 返回的路径虽 os.path.exists 为 True，
                # 但 requests/urllib3 ssl.create_default_context(cafile=ca_path) 会报
                # "Could not find a suitable TLS CA certificate bundle, invalid path"。
                # 所以除了文件存在，还要用 ssl 模块实际验证一下该 PEM 能被加载。
                if ca_path and os.path.isfile(ca_path) and os.path.getsize(ca_path) > 0:
                    try:
                        ssl.create_default_context(cafile=ca_path)  # 仅验证 PEM 可加载（无异常即合法）
                        # 没异常说明 cafile 合法
                        # 但仍需要避免重复覆盖 REQUESTS_CA_BUNDLE（运行时 hook 已经设置过）
                        if "REQUESTS_CA_BUNDLE" not in os.environ:
                            os.environ["REQUESTS_CA_BUNDLE"] = ca_path
                        if "SSL_CERT_FILE" not in os.environ:
                            os.environ["SSL_CERT_FILE"] = ca_path
                        return ca_path
                    except Exception:
                        # cafile 虽存在但不可用，直接返回 True（用系统默认），
                        # 不设置环境变量避免干扰默认逻辑
                        pass
            except Exception:
                pass
        return True
    except Exception:
        return True


def is_ssl_or_ca_error(exc):
    """判断异常是否属于 SSL/TLS/CA bundle 相关，意味着 verify=False 大概率可绕过。"""
    import requests

    _s = str(exc) + type(exc).__name__
    _u = _s.upper()
    if isinstance(exc, requests.exceptions.SSLError):
        return True
    for kw in (
        "SSL",
        "TLS",
        "CERTIFICATE",
        "CERTIFICATE_VERIFY_FAILED",
        "CERTIFICATE BUNDLE",
        "INVALID PATH",
        "CERT",
        "HANDSHAKE",
        "UNABLE TO GET LOCAL ISSUER CERTIFICATE",
    ):
        if kw in _u:
            return True
    if isinstance(exc, OSError) and ("CERTIFICATE" in _u or "BUNDLE" in _u or "INVALID PATH" in _u):
        return True
    return False


def safe_get(url, ssl_fallback_msg=None, log_cb=None, **kwargs):
    """requests.get 的 SSL 降级封装。

    先按正常证书校验（verify=get_requests_verify()）发起请求；
    若遇 SSL/CA 相关错误，则降级为 verify=False 重试一次（绕过本机
    内网对证书吊销 OCSP/CRL 的封锁）。其余异常原样上抛。
    kwargs 透传给 requests.get（如 timeout / headers / stream）。

    设计原则：降级重试对调用方完全透明——SSL 降级只在网络层生效，
    不污染用户日志；只在降级**也失败**时由调用方 catch 后打印原因，
    避免成功路径被 "SSL验证失败" 这种误报信息打扰。
    """
    import requests

    verify = get_requests_verify()
    try:
        resp = requests.get(url, verify=verify, **kwargs)
        resp.raise_for_status()
        return resp
    except Exception as exc:
        if is_ssl_or_ca_error(exc) and verify is not False:
            resp = requests.get(url, verify=False, **kwargs)
            resp.raise_for_status()
            return resp
        raise


# ---------------- 更新源配置 ----------------


def load_update_config():
    """从 config.ini [update] 段读取自定义更新源（内网部署用）。

    返回 (version_urls, exe_urls) 两个 list；未配置该段或值为空/仅注释时返回 ([], [])，
    调用方据此回退到内置 GitHub 源。支持 http/https 与本地/共享路径
    （如 //server/share/version.json）；exe_urls 模板支持 {version} 占位符。
    """
    if not os.path.exists(os.path.join(runtime_dir, "config.ini")):
        return [], []
    try:
        _cfg = configparser.ConfigParser()
        _cfg.read(os.path.join(runtime_dir, "config.ini"), encoding="utf-8")
        if not _cfg.has_section("update"):
            return [], []

        def _split(val):
            out = []
            for line in (val or "").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                out.append(line)
            return out

        vu = _split(_cfg.get("update", "version_urls", fallback=""))
        eu = _split(_cfg.get("update", "exe_urls", fallback=""))
        return vu, eu
    except Exception:
        return [], []


# ---------------- 自动更新核心 ----------------


class AutoUpdater:
    def __init__(
        self,
        current_version="0.0.0",
        version_urls=None,
        exe_urls=None,
        progress_cb=None,
        log_cb=None,
        ask_confirm_cb=None,
    ):
        # 当前版本号由调用方注入（通常是 main.APP_VERSION），updater 不反向依赖业务模块
        self.current_version = current_version
        self.version_urls = version_urls or UPDATE_VERSION_URLS
        self.exe_urls = exe_urls or UPDATE_EXE_URLS
        self.progress_cb = progress_cb or (lambda v, m: None)
        self.log_cb = log_cb or (lambda m: print(m))
        self.ask_confirm_cb = ask_confirm_cb or (lambda msg: True)
        self._latest_info = None
        self.custom_source = bool(version_urls)  # 是否使用了 config 自定义源（通常是内网）
        self.last_check_error = None  # 版本信息获取失败原因（用于区分"已是最新"）
        self.last_status = None  # 更新流程终态：发现新版本/已是最新/检查失败/下载失败/安装失败/用户取消

    def _fetch_latest_release_api(self):
        """通过 GitHub API 获取最新 release（无 CDN 缓存，始终返回真实最新版）。

        解决 jsDelivr 等对 version.json 长缓存导致的"一版一版升"问题：
        国内 raw.githubusercontent.com 常不通，程序会降级到 jsDelivr，而 jsDelivr
        缓存可能停留在远古版本（实测缓存到 1.0.0），导致检测到的"最新版"是旧版。
        GitHub API 无此问题——每次请求都返回真实最新 release。

        返回与 version.json 同结构的 dict；API 不提供 md5，下载时不做 MD5 校验
        （requests 流式下载 + raise_for_status 已能捕获传输错误，足够可靠）。
        """
        try:
            import importlib.util

            if importlib.util.find_spec("requests") is None:
                raise ImportError
        except ImportError:
            self.log_cb("[版本] 缺少 requests 库，跳过 GitHub API 检查")
            return None
        try:
            r = safe_get(
                GITHUB_API_LATEST,
                timeout=10,
                headers={"User-Agent": "daily-report-updater"},
                ssl_fallback_msg="[版本] GitHub API SSL验证失败，跳过证书验证重试",
                log_cb=self.log_cb,
            )
            data = r.json()
            tag = data.get("tag_name", "") or ""
            version = tag.lstrip("vV").strip()
            # 找到 .exe 资产
            asset_url = None
            for a in data.get("assets", []) or []:
                if (a.get("name") or "").lower().endswith(".exe"):
                    asset_url = a.get("browser_download_url")
                    break
            if not version or not asset_url:
                return None
            # 用 CDN 镜像前缀构造回退下载列表（直链在前，镜像兜底）
            exe_urls = [p + asset_url for p in CDN_MIRROR_PREFIXES]
            self.log_cb(f"[版本] GitHub API 获取最新版本成功 (version={version}, tag={tag})")
            return {
                "version": version,
                "exe_urls": exe_urls,
                "md5": None,  # API 不提供 md5，下载时跳过 MD5 校验
                "release_note": data.get("body", "") or "",
                "force_update": False,
            }
        except Exception as exc:
            self.log_cb(f"[版本] GitHub API 获取失败: {exc}")
            return None

    def _fetch_version_json(self):
        if not self.version_urls:
            return None
        for url in self.version_urls:
            try:
                if url.startswith("http://") or url.startswith("https://"):
                    # CDN 防缓存：加 ?t=时间戳（raw 本身不缓存；ghproxy 镜像也不长缓存）
                    if "?" in url:
                        fetch_url = f"{url}&t={int(time.time())}"
                    else:
                        fetch_url = f"{url}?t={int(time.time())}"
                    r = safe_get(fetch_url, timeout=10)
                    data = r.json()
                else:
                    # 共享目录 / 本地文件
                    import json

                    with open(url, encoding="utf-8") as f:
                        data = json.load(f)
                if isinstance(data, dict) and "version" in data:
                    self.log_cb(f"[版本] 从 {url} 获取版本信息成功 (version={data.get('version')})")
                    return data
            except Exception as exc:
                self.log_cb(f"[版本] {url} 获取失败: {exc}")
        return None

    def _eval_and_return(self, data):
        """根据版本号判断是否有新版本，并记录状态后返回 info 或 None。"""
        latest_ver = data.get("version", "0.0.0")
        self.log_cb(f"[版本] 当前版本 v{self.current_version} | 最新版本 v{latest_ver}")
        if parse_version(latest_ver) > parse_version(self.current_version):
            self.log_cb(f"[版本] 发现新版本 v{latest_ver}，准备更新")
            self.last_check_error = None
            self.last_status = "发现新版本"
            self._latest_info = data
            return data
        self.log_cb(f"[版本] 当前版本 v{self.current_version} 已是最新")
        self.last_check_error = None
        self.last_status = "已是最新"
        return None

    def check_update(self):
        # 配置了自定义（通常是内网）更新源时，跳过 GitHub API 探测，直接走自定义源
        if self.custom_source:
            data = self._fetch_version_json()
            if data:
                return self._eval_and_return(data)
            self.last_check_error = "配置的更新源均获取失败（网络不可达或源无响应）"
            self.last_status = "检查失败"
            self.log_cb("[版本] 自定义更新源获取失败，跳过")
            return None
        # 默认链路：GitHub API 首选（无 CDN 缓存），失败降级 version.json 镜像源
        data = self._fetch_latest_release_api()
        if not data:
            data = self._fetch_version_json()
        if not data:
            self.last_check_error = "所有更新源（GitHub API / 镜像）均获取失败，可能为网络不可达"
            self.last_status = "检查失败"
            self.log_cb("[版本] 未配置更新源或获取失败，跳过")
            return None
        return self._eval_and_return(data)

    def _download(self, url, dest_path, expected_md5=None):
        file_size = 0
        if url.startswith("http://") or url.startswith("https://"):
            resp = safe_get(
                url,
                timeout=(30, 600),
                stream=True,
                ssl_fallback_msg="[更新] 下载SSL验证失败，跳过证书验证重试",
                log_cb=self.log_cb,
            )
            total = int(resp.headers.get("content-length", 0))
            if total > 0:
                self.progress_cb(0, total)
            downloaded = 0
            with open(dest_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total > 0:
                            self.progress_cb(downloaded, total)
            file_size = downloaded
        else:
            # 共享目录 / 本地文件
            total = os.path.getsize(url)
            if total > 0:
                self.progress_cb(0, total)
            import shutil

            shutil.copy2(url, dest_path)
            self.progress_cb(total, total)
            file_size = total

        # MD5 校验
        if expected_md5:
            import hashlib

            h = hashlib.md5()
            with open(dest_path, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            actual = h.hexdigest().lower()
            if actual != expected_md5.lower():
                raise RuntimeError(f"MD5校验失败: 期望 {expected_md5}, 实际 {actual}")
            self.log_cb(f"[更新] MD5校验通过: {actual}")
        self.progress_cb(0, 0)
        return file_size

    def _resolve_exe_urls(self, info):
        """解析 EXE 下载地址列表，支持 exe_urls(数组/CDN回退) 和 exe_url(单字符串/兼容)"""
        if info:
            if info.get("exe_urls"):
                return info["exe_urls"]
            if info.get("exe_url"):
                return [info["exe_url"]]
        version = info.get("version", "") if info else ""
        urls = []
        for url in self.exe_urls:
            try:
                urls.append(url.format(version=version))
            except (KeyError, IndexError):
                continue
        return urls

    def download_update(self, info=None):
        if info is None:
            info = self._latest_info or self.check_update()
        if not info:
            return None

        exe_urls = self._resolve_exe_urls(info)
        if not exe_urls:
            self.log_cb("[更新] 未配置EXE下载地址")
            return None

        import tempfile

        tmp_dir = tempfile.gettempdir()
        tmp_exe = os.path.join(tmp_dir, f"report_update_{int(time.time())}.exe")

        for idx, exe_url in enumerate(exe_urls):
            try:
                self.log_cb(f"[更新] 下载新版本 v{info.get('version')}: {exe_url}")
                size = self._download(exe_url, tmp_exe, info.get("md5"))
                self.log_cb(f"[更新] 下载完成: {size // 1024 // 1024} MB")
                return tmp_exe
            except Exception as exc:
                self.log_cb(f"[更新] 下载失败: {exc}")
                try:
                    if os.path.exists(tmp_exe):
                        os.remove(tmp_exe)
                except OSError as e:
                    self.log_cb(f"[!] 清理临时文件失败: {e}")
                if idx < len(exe_urls) - 1:
                    self.log_cb("[更新] 尝试下一个镜像源...")
                else:
                    self.log_cb("[!] 所有镜像源均下载失败")
                    return None

    def install_and_restart(self, new_exe_path):
        if not new_exe_path or not os.path.exists(new_exe_path):
            return False
        if not getattr(sys, "frozen", False):
            self.log_cb("[更新] 源码模式跳过安装（仅EXE模式支持自动替换）")
            return False

        old_exe = os.path.abspath(sys.executable)
        old_dir = os.path.dirname(old_exe)
        backup_exe = old_exe + ".bak"
        parent_pid = os.getpid()

        # === 用当前 exe 自身作为 Worker 模式更新 ===
        # 历史踩坑：
        #   - .bat：中文路径在 GBK/UTF-8 codepage 间乱码 → 不替换/生成乱码文件
        #   - PowerShell：5.1 对 PyInstaller frozen 父进程触发安全校验弹窗
        #   - 外部 updater.exe：循环依赖（旧版本不含 updater.exe 无法更新到新版本）
        # 结论：用自身 --update-worker 模式，任何版本都能自更新，无外部依赖。
        # worker 模式入口在 main() 顶部，检测到 --update-worker=<jsonPath> 即
        # 跳到 update_worker_main()，不加载任何 GUI/Tkinter。
        import hashlib
        import json
        import shutil as _shu
        import tempfile

        tag = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        json_params_path = os.path.join(tempfile.gettempdir(), f"update_{tag}_params.json")

        # === 先准备 Worker 副本 ===
        # 关键：不能直接用 sys.executable 启动 Worker！
        #   - PyInstaller frozen exe 运行时会锁住自身文件，
        #     Worker = 原 exe 副本 -> 自己锁住了要覆盖的目标文件 -> [WinError 32]
        #   - 也不能用 new_exe_path：若新 exe 不含 --update-worker（如 v1.2.1），
        #     Worker 会直接进入 GUI 模式
        # 方案：复制原 exe 到 %TEMP%，用副本启动 Worker。
        #   - Worker 的 sys.executable = 临时副本，不锁住原 exe
        #   - Worker 代码来自原 exe，一定包含 --update-worker 支持
        worker_exe = os.path.join(tempfile.gettempdir(), f"update_worker_{tag}.exe")
        try:
            _shu.copy2(sys.executable, worker_exe)
            self.log_cb(f"[更新] 已复制 Worker 副本: {os.path.basename(worker_exe)}")
        except Exception as exc:
            self.log_cb(f"[更新] 复制 Worker 副本失败: {exc}")
            return False

        params_json = json.dumps(
            {
                "parentPid": parent_pid,
                "oldExe": old_exe,
                "newExe": new_exe_path,
                "bakExe": backup_exe,
                "workDir": old_dir,
                "jsonPath": json_params_path,
                "workerExe": worker_exe,
            },
            ensure_ascii=False,
            indent=2,
        )

        try:
            with open(json_params_path, "w", encoding="utf-8") as f:
                f.write(params_json)
        except Exception as exc:
            self.log_cb(f"[更新] 写入参数文件失败: {exc}")
            return False

        # 启动 Worker（DETACHED，独立于父进程；os._exit 后 worker 继续运行）
        CREATE_NO_WINDOW = 0x08000000
        DETACHED_PROCESS = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        flags = CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP

        worker_arg = f"--update-worker={json_params_path}"
        try:
            # 用 STARTUPINFO + stdio 重定向确保更新 Worker 完全不弹控制台窗口，
            # 避免中文标题/路径在错误代码页下出现乱码（旧版 find /I 命令的坑）。
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            subprocess.Popen(
                [worker_exe, worker_arg],
                cwd=old_dir,
                creationflags=flags,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                startupinfo=startupinfo,
            )
            self.log_cb(f"[更新] 启动更新 Worker (pid={parent_pid} -> worker={os.path.basename(worker_exe)})")
        except OSError as e:
            self.log_cb(f"[!] 启动更新 Worker 失败: {e}")
            return False

        self.log_cb(f"[更新] 日志将写入: %TEMP%\\update_last.log 和 {os.path.join(old_dir, 'update_last.log')}")
        self.log_cb("[更新] 正在重启应用完成更新...")
        os._exit(0)

    def run_update_flow(self, force_dialog=False):
        info = self.check_update()
        if not info:
            if force_dialog:
                self.log_cb(
                    "[更新] 当前已是最新版本"
                    if self.last_status == "已是最新"
                    else f"[更新] 检查失败: {self.last_check_error}"
                )
            return False
        ver = info.get("version", "?")
        note = info.get("release_note", "")
        force = bool(info.get("force_update", False))

        prompt = f"发现新版本 v{ver}\n\n当前版本: v{self.current_version}\n新版本: v{ver}"
        if note:
            prompt += f"\n\n更新说明:\n{note}"
        prompt += "\n\n是否立即更新？"

        if force or self.ask_confirm_cb(prompt):
            tmp = self.download_update(info)
            if tmp:
                ok = self.install_and_restart(tmp)
                if ok:
                    self.last_status = "已触发安装"
                    return True
                self.last_status = "安装失败"
                return False
            self.last_status = "下载失败"
            return False
        self.last_status = "用户取消"
        return False


# ---------------- 更新 Worker（安装/覆盖/重启） ----------------


def update_worker_main(json_path):
    """
    更新 Worker 模式：不加载 GUI，纯文件操作。
    由 install_and_restart() 触发：主进程 os._exit 后，worker 副本负责
    备份旧 exe → 覆盖新 exe → 启动新程序。

    设计目的：
    - 避免 PowerShell 5.1 的安全校验（Security validation failure:
      parent process has different executable! / failed to obtain executable path...）
    - 避免 cmd/.bat 的中文路径 GBK/UTF-8 乱码
    - 100% 走 Python 文件 API（Copy-Item 级），中文路径零问题
    """
    import hashlib
    import json

    # ===== 解析参数 =====
    try:
        with open(json_path, encoding="utf-8") as f:
            params = json.load(f)
        parent_pid = int(params["parentPid"])
        old_exe = str(params["oldExe"])
        new_exe = str(params["newExe"])
        bak_exe = str(params["bakExe"])
        work_dir = str(params["workDir"])
        cleanups = [str(params["jsonPath"])]
        if "ps1Path" in params and params["ps1Path"]:
            cleanups.append(str(params["ps1Path"]))
        worker_exe = str(params.get("workerExe", ""))
    except Exception as e:
        # 尽量写日志（优先临时目录，避免 exe 目录无写权限）
        try:
            import tempfile as _tf

            log = os.path.join(_tf.gettempdir(), "update_last.log")
            with open(log, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.now():%H:%M:%S}] 参数解析失败: {e}\n")
        except Exception:
            pass
        return 2

    # 日志双写：优先临时目录（保证有写权限），同时尝试 exe 同目录（方便用户找）
    import tempfile as _tf

    _tmp_log = os.path.join(_tf.gettempdir(), "update_last.log")
    _exe_log = os.path.join(work_dir, "update_last.log")

    def wlog(msg):
        ts = datetime.now().strftime("%H:%M:%S")
        # 双写：优先临时目录（一定有权限），同时尝试 exe 同目录（方便用户找）
        for _p in (_tmp_log, _exe_log):
            try:
                with open(_p, "a", encoding="utf-8") as f:
                    f.write(f"[{ts}] {msg}\n")
            except Exception:
                pass

    wlog("=" * 40)
    wlog(f"开始更新 (pid={os.getpid()}) parentPid={parent_pid}")
    wlog(f"oldExe={old_exe}")
    wlog(f"newExe={new_exe}")
    wlog(f"exe大小={os.path.getsize(new_exe)}" if os.path.exists(new_exe) else "新exe不存在！")

    # ===== 检测父进程是否仍在（用 OpenProcess Win32，不触发任何安全校验） =====
    try:
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        SYNCHRONIZE = 0x00100000

        def _is_alive(pid):
            h = k32.OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, False, wintypes.DWORD(pid))
            if not h:
                return False
            # WaitForSingleObject 0 毫秒：若已退出立刻返回 WAIT_OBJECT_0
            WAIT_TIMEOUT = 0x00000102
            r = k32.WaitForSingleObject(h, 0)
            k32.CloseHandle(h)
            return r == WAIT_TIMEOUT
    except Exception as e:
        wlog(f"OpenProcess 不可用 ({e})，降级用 psutil/tasklist")

        def _is_alive(pid):
            # 兜底：tasklist /FO CSV 数字匹配（隐藏窗口，防止闪现乱码）
            try:
                import subprocess as _sp

                startupinfo = _sp.STARTUPINFO()
                startupinfo.dwFlags |= _sp.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = _sp.SW_HIDE
                out = _sp.check_output(
                    ["tasklist", "/FI", f"PID eq {pid}", "/NH", "/FO", "CSV"],
                    stderr=_sp.DEVNULL,
                    startupinfo=startupinfo,
                ).decode("gbk", errors="replace")
                return f'"{pid}"' in out
            except Exception:
                return False

    waited = 0
    while waited < 10:
        if not _is_alive(parent_pid):
            wlog(f"父进程已退出 (等待 {waited}s)")
            break
        time.sleep(1)
        waited += 1
    if waited >= 10:
        wlog(f"等待父进程超时 ({waited}s)，继续覆盖（有重试兜底）")
    time.sleep(0.3)

    # ===== 备份 =====
    if os.path.exists(old_exe):
        try:
            import shutil as _su

            _su.copy2(old_exe, bak_exe)
            wlog(f"已备份 -> {os.path.basename(bak_exe)}")
        except Exception as e:
            wlog(f"备份失败: {e}")

    # ===== 覆盖（重试 5 次，间隔 2s） =====
    ok = False
    last_err = None
    import shutil as _su

    for i in range(1, 6):
        try:
            _su.copy2(new_exe, old_exe)

            # 验证 MD5 一致
            def md5(p):
                h = hashlib.md5()
                with open(p, "rb") as f:
                    for c in iter(lambda: f.read(1024 * 1024), b""):
                        h.update(c)
                return h.hexdigest().lower()

            if md5(old_exe) != md5(new_exe):
                raise RuntimeError("覆盖后 MD5 不一致")
            wlog(f"覆盖成功 ({i}/5)，MD5 校验通过")
            ok = True
            break
        except Exception as e:
            last_err = e
            wlog(f"覆盖失败 {i}/5: {e}")
            time.sleep(2)

    if not ok:
        wlog(f"覆盖失败，尝试回滚：{last_err}")
        if os.path.exists(bak_exe):
            try:
                _su.copy2(bak_exe, old_exe)
                wlog("回滚成功")
            except Exception as e:
                wlog(f"回滚失败: {e}")
        # 回滚后依旧失败，留日志返回
        return 1

    # ===== 启动新程序 =====
    started_ok = False
    try:
        DETACHED_PROCESS = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        CREATE_NO_WINDOW = 0x08000000
        flags = CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        # 注意：不使用 close_fds=True 与 creationflags 同时传时在老 Python 有兼容
        # 直接用 subprocess.Popen(executable, cwd=work_dir)，且不指定 stdio
        import subprocess as _sp

        startupinfo = _sp.STARTUPINFO()
        startupinfo.dwFlags |= _sp.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = _sp.SW_HIDE
        _sp.Popen(
            [old_exe],
            cwd=work_dir,
            creationflags=flags,
            stdin=_sp.DEVNULL,
            stdout=_sp.DEVNULL,
            stderr=_sp.DEVNULL,
            startupinfo=startupinfo,
        )
        wlog("已启动新程序 (Popen+DETACHED)")
        started_ok = True
    except Exception as e:
        wlog(f"Popen 启动失败: {e}")
        try:
            # 兜底：os.startfile
            if hasattr(os, "startfile"):
                os.startfile(old_exe)
                wlog("已启动新程序 (os.startfile 兜底)")
                started_ok = True
        except Exception as e2:
            wlog(f"startfile 启动也失败: {e2}")

    # ===== 清理临时文件 =====
    # Worker 自身（sys.executable）正在运行，不能删除；其余可清理
    _worker_self = os.path.abspath(sys.executable) if getattr(sys, "frozen", False) else None
    for p in [new_exe, bak_exe] + cleanups + ([worker_exe] if worker_exe else []):
        if _worker_self and os.path.abspath(p) == _worker_self:
            wlog(f"跳过清理（Worker自身）: {os.path.basename(p)}")
            continue
        try:
            if os.path.exists(p):
                os.remove(p)
                wlog(f"清理: {os.path.basename(p)}")
        except Exception as e:
            wlog(f"清理 {os.path.basename(p)} 失败: {e}")

    wlog(f"更新完成，新程序启动状态: {'OK' if started_ok else '失败(请手动启动)'}")
    return 0
