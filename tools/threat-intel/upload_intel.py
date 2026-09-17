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
  - db.json 缺失时报错退出（不发布空库）

发布护栏（三层，任一不过即拒绝发布，避免降级库覆盖线上唯一 asset）：
  1. 库不完整：total_ips 或 total_cidrs 为 0
  2. 成功源不足半数（skip 不计入 ok，既不算成功也不算失败）
  3. 与线上现有库比对：精确 IP 或恶意段跌幅超过 30%（MIN_KEEP_RATIO）
  紧急放行：设置环境变量 INTEL_FORCE_PUBLISH=1 可跳过护栏（仅用于确认降级可接受时）

asset 覆盖采用「临时名先上传，成功后再删旧库并改名」的安全替换——直接「先删后传」
一旦上传失败（曾实测遇 502），线上库会在两个动作之间消失，exe 端全体断供。
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "data", "db.json")

REPO_OWNER = "eavil666"
REPO_NAME = "dayupdate"
TAG = "threat-intel-latest"  # 固定 tag：每日覆盖 asset
ASSET_NAME = "threat_db.json"  # 与日报 threat_check.GITHUB_INTEL_URL 末尾文件名一致
# 发布用日报项目的 .env（若该文件存在），避免重复维护 token
PROJECT_ENV = r"E:\script\python\日报update\.env"

MIN_KEEP_RATIO = 0.7  # 与线上库比，精确IP/恶意段跌幅上限 30%
_UA = "threat-intel-uploader/1.0"


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
        "User-Agent": _UA,
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


def download_asset(asset_url, token, timeout=180):
    """按 asset API 地址取原始文件内容（needs Accept: application/octet-stream）"""
    req = urllib.request.Request(
        asset_url,
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/octet-stream",
            "User-Agent": _UA,
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_published_counts(token):
    """取线上现有库的 (精确IP数, 段数)，用于降级比对。取不到返回 None。"""
    status, rel = github_api("GET", f"/repos/{REPO_OWNER}/{REPO_NAME}/releases/tags/{TAG}", token)
    if status != 200:
        return None
    asset = next((a for a in rel.get("assets", []) if a["name"] == ASSET_NAME), None)
    if not asset:
        return None
    try:
        prev = json.loads(download_asset(asset["url"], token).decode("utf-8", errors="replace"))
    except Exception as e:
        print(f"[*] 线上旧库下载/解析失败，跳过降级比对: {str(e)[:120]}")
        return None
    return int(prev.get("total_ips") or 0), int(prev.get("total_cidrs") or 0)


def check_guardrails(db, srcs, token):
    """三层护栏。返回 (ok, reason)。"""
    total_ips = int(db.get("total_ips") or 0)
    total_cidrs = int(db.get("total_cidrs") or 0)
    if total_ips <= 0 or total_cidrs <= 0:
        return False, f"库不完整（精确 {total_ips} / 段 {total_cidrs} 含 0 值）"

    ok_n = sum(1 for s in srcs.values() if s.get("status") == "ok")
    if ok_n * 2 < len(srcs):
        return False, f"成功源仅 {ok_n}/{len(srcs)}，不足半数"

    prev = fetch_published_counts(token)
    if prev is None:
        print("[*] 线上暂无可用旧库，跳过降级比对（首次发布或网络异常）")
        return True, ""
    p_ips, p_cidrs = prev
    if p_ips and total_ips < p_ips * MIN_KEEP_RATIO:
        drop = 100 * (1 - total_ips / p_ips)
        return False, f"精确IP {total_ips} 较线上 {p_ips} 下降 {drop:.0f}%，超过 {100 * (1 - MIN_KEEP_RATIO):.0f}% 阈值"
    if p_cidrs and total_cidrs < p_cidrs * MIN_KEEP_RATIO:
        drop = 100 * (1 - total_cidrs / p_cidrs)
        return False, f"恶意段 {total_cidrs} 较线上 {p_cidrs} 下降 {drop:.0f}%，超过 {100 * (1 - MIN_KEEP_RATIO):.0f}% 阈值"
    print(f"[*] 降级比对通过: 精确IP {total_ips} vs 线上 {p_ips} | 段 {total_cidrs} vs 线上 {p_cidrs}")
    return True, ""


def release_body(labels):
    src_list = "\n".join(f"- {s}" for s in labels)
    return (
        "每日 8:30 自动更新的威胁情报库快照（多源聚合，含精确 IP 与恶意网段）。\n\n"
        f"数据源：\n{src_list}\n\n"
        '供网络安全值守保障日报 exe 的"威胁源更新"功能下载。'
    )


def ensure_release(token, labels):
    """获取固定 tag 的 Release，不存在则创建（prerelease，避免影响正式版 latest）；
    已存在但发布说明过期时同步更新，保证公开页面与实际源清单一致。"""
    body = release_body(labels)
    status, data = github_api("GET", f"/repos/{REPO_OWNER}/{REPO_NAME}/releases/tags/{TAG}", token)
    if status == 200:
        if (data.get("body") or "").strip() != body.strip():
            st, _ = github_api(
                "PATCH",
                f"/repos/{REPO_OWNER}/{REPO_NAME}/releases/{data['id']}",
                token,
                {"body": body},
            )
            print(f"[*] 同步 Release 说明: HTTP {st}")
        return data
    if status != 404:
        print(f"[!] 查询 Release {TAG} 异常: {status} {str(data)[:200]}")
    payload = {
        "tag_name": TAG,
        "name": "威胁情报库（每日更新）",
        "body": body,
        "draft": False,
        "prerelease": True,
    }
    status, data = github_api("POST", f"/repos/{REPO_OWNER}/{REPO_NAME}/releases", token, payload)
    if status not in (200, 201):
        print(f"[!] 创建 Release 失败: {status} {str(data)[:200]}")
        return None
    print(f"[OK] 已创建 Release: {TAG}")
    return data


def upload_asset(token, release, db_path):
    """临时名上传成功后再顶替正式 asset。返回 (ok, size)。

    不能"先删后传"：删除成功而上传失败时（曾实测遇 502），线上库会在两个动作之间
    消失，而 exe 端全靠这一个 asset。
    """
    upload_url = release["upload_url"].split("{")[0].replace("api.github.com", "uploads.github.com")
    size = os.path.getsize(db_path)
    with open(db_path, "rb") as f:
        data = f.read()

    tmp_name = f"{ASSET_NAME}.tmp-{int(time.time())}"
    req = urllib.request.Request(
        f"{upload_url}?name={tmp_name}",
        data=data,
        method="POST",
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": _UA,
            "Content-Type": "application/octet-stream",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            new_asset = json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        print(f"[!] 上传失败: HTTP {e.code} {e.read().decode('utf-8', errors='replace')[:300]}")
        print("[*] 线上旧库未受影响，下载地址仍可用")
        return False, 0
    except Exception as e:
        print(f"[!] 上传失败: {type(e).__name__}: {str(e)[:200]}")
        print("[*] 线上旧库未受影响，下载地址仍可用")
        return False, 0
    print(f"[OK] 已上传临时 asset {tmp_name} ({size / 1024 / 1024:.2f} MB)")

    # 上传成功后才删旧 asset
    for asset in release.get("assets", []):
        if asset["name"] == ASSET_NAME:
            st, _ = github_api(
                "DELETE", f"/repos/{REPO_OWNER}/{REPO_NAME}/releases/assets/{asset['id']}", token
            )
            print(f"[*] 删除旧 asset {asset['id']}: HTTP {st}")

    # 改名回正式名（若仍有重名残留则再删一轮后重试）
    new_id = new_asset.get("id")
    for attempt in (1, 2):
        st, _ = github_api(
            "PATCH",
            f"/repos/{REPO_OWNER}/{REPO_NAME}/releases/assets/{new_id}",
            token,
            {"name": ASSET_NAME},
        )
        if st == 200:
            print(f"[OK] asset 已顶替: {ASSET_NAME}")
            return True, size
        print(f"[!] 临时 asset 改名失败（第 {attempt} 次）: HTTP {st}")
        if attempt == 1:
            status, rel = github_api(
                "GET", f"/repos/{REPO_OWNER}/{REPO_NAME}/releases/tags/{TAG}", token
            )
            for asset in (rel.get("assets", []) if status == 200 else []):
                if asset["name"] == ASSET_NAME and asset["id"] != new_id:
                    github_api(
                        "DELETE",
                        f"/repos/{REPO_OWNER}/{REPO_NAME}/releases/assets/{asset['id']}",
                        token,
                    )
    print("[!] 改名未成功，线上暂时没有正式名 asset，请重跑本脚本")
    return False, size


def main():
    _utf8_stdio()
    if not os.path.exists(DB_FILE):
        print(f"[!] 本地情报库不存在: {DB_FILE}")
        sys.exit(1)
    token = get_token()

    # 打印待发布库摘要
    try:
        db = json.load(open(DB_FILE, encoding="utf-8"))
        srcs = db.get("sources", {})
        ok_n = sum(1 for s in srcs.values() if s.get("status") == "ok")
        print(
            f"[*] 待发布库: {db.get('updated_at')} | 源 ok {ok_n}/{len(srcs)} | "
            f"精确 {db.get('total_ips', 0)} + 段 {db.get('total_cidrs', 0)}"
        )
        for k, v in srcs.items():
            st = v.get("status")
            mark = {"ok": "OK  ", "skip": "SKIP", "fail": "FAIL"}.get(st, "?   ")
            detail = v.get("count", v.get("note", v.get("error", "-")))
            print(f"    [{mark}] {v.get('label', k)}: {detail}")
    except Exception as e:
        print(f"[!] 读取 db.json 失败，拒绝发布: {e}")
        sys.exit(1)

    labels = [v.get("label", k) for k, v in srcs.items()]

    ok, reason = check_guardrails(db, srcs, token)
    if not ok:
        if os.environ.get("INTEL_FORCE_PUBLISH") == "1":
            print(f"[!] 护栏未通过但已设置 INTEL_FORCE_PUBLISH=1，强制发布: {reason}")
        else:
            print(f"[!] 护栏拦截，拒绝发布: {reason}")
            print("[*] 线上库保持上一份可用数据；确认降级可接受时可设 INTEL_FORCE_PUBLISH=1 放行")
            sys.exit(1)

    release = ensure_release(token, labels)
    if not release:
        sys.exit(1)
    ok, _ = upload_asset(token, release, DB_FILE)
    # 回读校验 asset 落地
    status, data = github_api("GET", f"/repos/{REPO_OWNER}/{REPO_NAME}/releases/tags/{TAG}", token)
    if status == 200:
        for asset in data.get("assets", []):
            if asset["name"] == ASSET_NAME:
                print(
                    f"[*] 校验: asset id={asset['id']} size={asset['size']} "
                    f"url={asset.get('browser_download_url')}"
                )
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
