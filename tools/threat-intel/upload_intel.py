"""upload_intel.py - 威胁情报库每日发布到 GitHub Release（供日报 exe 多端下载）

将本地 data/db.json 覆盖上传为固定 tag Release 的 asset：
  https://github.com/eavil666/dayupdate/releases/download/threat-intel-latest/threat_db.json
exe 端（threat_check.py 的 --update-intel / GUI 按钮）从该固定地址拉取最新库。

用法：
  python upload_intel.py            # 发布当前 data/db.json（已存在即上传/覆盖 asset）

说明：
  - Tag 固定为 threat-intel-latest（prerelease），每日覆盖 asset，不污染 git 历史、
    不占用正式版发布；仅依赖 uploads.github.com 上传接口
  - Token：环境变量 GH_TOKEN / GITHUB_TOKEN，或项目 .env（GH_TOKEN=xxx）
  - db.json 缺失时报错退出（不发布空库）；源下载部分失败仍发布现有库，
    便于 exe 端至少拿到上一份数据
"""
import json
import os
import sys
import urllib.error
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "data", "db.json")

REPO_OWNER = "eavil666"
REPO_NAME = "dayupdate"
TAG = "threat-intel-latest"      # 固定 tag：每日覆盖 asset
ASSET_NAME = "threat_db.json"    # 与日报 threat_check.GITHUB_INTEL_URL 末尾文件名一致
# 发布用日报项目的 .env（若该文件存在），避免重复维护 token
PROJECT_ENV = r"E:\script\python\日报update\.env"


def _utf8_stdio():
    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:
            pass
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def load_env_file(path):
    if not path or not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def get_token():
    load_env_file(PROJECT_ENV)
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("[!] 未找到 GH_TOKEN/GITHUB_TOKEN（环境变量或项目 .env）")
        sys.exit(2)
    return token


def github_api(method, path, token, data=None, content_type="application/json", timeout=60):
    """调用 GitHub REST API。返回 (status, data_or_text)。"""
    url = f"https://api.github.com{path}"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "threat-intel-uploader/1.0",
    }
    if data is not None:
        body = json.dumps(data).encode("utf-8") if content_type == "application/json" else data
        headers["Content-Type"] = content_type
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
    else:
        req = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw.decode("utf-8")) if raw else {}
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, str(e)


def ensure_release(token):
    """获取固定 tag 的 Release，不存在则创建（prerelease，避免影响正式版 latest）。"""
    status, data = github_api("GET", f"/repos/{REPO_OWNER}/{REPO_NAME}/releases/tags/{TAG}", token)
    if status == 200:
        return data
    if status != 404:
        print(f"[!] 查询 Release {TAG} 异常: {status} {str(data)[:200]}")
    body = {
        "tag_name": TAG,
        "name": "威胁情报库（每日更新）",
        "body": "每日 8:30 自动更新的威胁情报库快照（Spamhaus DROP/EDROP + blocklist.de + CINSscore + Feodo）。\n\n供网络安全值守保障日报 exe 的\"威胁源更新\"功能下载。",
        "draft": False,
        "prerelease": True,
    }
    status, data = github_api("POST", f"/repos/{REPO_OWNER}/{REPO_NAME}/releases", token, body)
    if status not in (200, 201):
        print(f"[!] 创建 Release 失败: {status} {str(data)[:200]}")
        return None
    print(f"[OK] 已创建 Release: {TAG}")
    return data


def upload_asset(token, release, db_path):
    """删除同名 asset 后重新上传 db.json。返回 (ok, size)。"""
    upload_url = release["upload_url"].split("{")[0]
    # 删除已存在同名 asset
    for asset in release.get("assets", []):
        if asset["name"] == ASSET_NAME:
            st, _ = github_api(
                "DELETE", f"/repos/{REPO_OWNER}/{REPO_NAME}/releases/assets/{asset['id']}", token
            )
            print(f"[*] 删除旧 asset {asset['id']}: HTTP {st}")
    size = os.path.getsize(db_path)
    with open(db_path, "rb") as f:
        data = f.read()
    url = f"{upload_url}?name={ASSET_NAME}".replace("api.github.com", "uploads.github.com")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "threat-intel-uploader/1.0",
            "Content-Type": "application/octet-stream",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            resp.read()
        print(f"[OK] 上传完成: {ASSET_NAME} ({size / 1024 / 1024:.2f} MB)")
        return True, size
    except urllib.error.HTTPError as e:
        print(f"[!] 上传失败: HTTP {e.code} {e.read().decode('utf-8', errors='replace')[:300]}")
        return False, 0


def main():
    _utf8_stdio()
    if not os.path.exists(DB_FILE):
        print(f"[!] 本地情报库不存在: {DB_FILE}")
        sys.exit(1)
    token = get_token()

    # 打印待发布库摘要
    ok_n = 0
    try:
        db = json.load(open(DB_FILE, encoding="utf-8"))
        srcs = db.get("sources", {})
        ok_n = sum(1 for s in srcs.values() if s.get("status") == "ok")
        print(
            f"[*] 待发布库: {db.get('updated_at')} | 源 ok {ok_n}/{len(srcs)} | "
            f"精确 {db.get('total_ips', 0)} + 段 {db.get('total_cidrs', 0)}"
        )
        for k, v in srcs.items():
            mark = "OK " if v.get("status") == "ok" else "FAIL"
            print(f"    [{mark}] {v.get('label', k)}: {v.get('count', '-')} 条")
    except Exception as e:
        print(f"[!] 读取 db.json 摘要失败（仍将尝试发布）: {e}")

    # 护栏：全部源失败（CI 干净环境重建出空库）时拒绝发布，避免覆盖线上 asset
    if ok_n == 0:
        print("[!] 所有数据源均失败，拒绝发布空库（保留线上上一份可用库）")
        sys.exit(1)

    release = ensure_release(token)
    if not release:
        sys.exit(1)
    ok, _ = upload_asset(token, release, DB_FILE)
    # 回读校验 asset 落地
    status, data = github_api("GET", f"/repos/{REPO_OWNER}/{REPO_NAME}/releases/tags/{TAG}", token)
    if status == 200:
        for asset in data.get("assets", []):
            if asset["name"] == ASSET_NAME:
                print(f"[*] 校验: asset id={asset['id']} size={asset['size']} url={asset.get('browser_download_url')}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
