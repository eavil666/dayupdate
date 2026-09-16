#!/usr/bin/env python3
"""发布收尾脚本（REST 版）—— 把「tag -> Release -> 上传 asset -> 验证」全走 API。

为什么需要它
------------
根目录 release.py 是正常终端环境的一键发布入口，但它依赖两件在受限环境下
不成立的事：
  1. `git tag -a` 必须把 tag 写进本地 git 库（沙箱/受限写盘下 refs 不落盘，
     会卡在 tag 或报 `Failed to resolve 'HEAD'`）；
  2. `git push -u origin <branch>` 走本地分支名（本地 ref 丢失时推不出去）。
此外它的 REST 调用没有重试与幂等，遇到 GitHub 偶发 502 或重复发布会中断。

本脚本只替换这两块：tag/Release/asset 全部走 REST，推送改用
`git push origin <full-sha>:refs/heads/<branch>`，并对 5xx/429 重试、
对已存在的 tag ref/Release/asset 做幂等处理。版本读取、version.json 同步、
token 加载等仍复用 release.py，避免两份实现漂移。

用法
----
  # 预演：只做预检并打印发布计划，不写任何东西
  python tools/release_rest.py --dry-run

  # 常规发布：打包 -> 同步 version.json -> 提交推送 -> REST 发布 -> 验证
  python tools/release_rest.py --build --commit-push

  # 只重发已打好的 exe（不打包、不碰 git），适合补传 asset
  python tools/release_rest.py

  # 换分支 / 换 exe / 临时改发布说明
  python tools/release_rest.py --branch main --note "紧急修复 XX"

参数默认值都来自仓库内的单一真源（pyproject.toml 版本、version.json 说明、
release.py 的仓库与 asset 名），正常情况下无需传参。

退出码：0 成功；非 0 表示预检失败或某个步骤失败，具体原因打印在最后一行。
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

# --- 以仓库根目录为基准，复用 release.py 的公共逻辑 ---
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import release as rel  # noqa: E402

# === Windows 控制台 UTF-8（中文 exe 名、发布说明不能把流程打断）===
if sys.platform == "win32":
    try:
        import ctypes

        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        ctypes.windll.kernel32.SetConsoleCP(65001)
    except Exception:
        pass
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

OWNER = rel.REPO_OWNER
REPO = rel.REPO_NAME
ASSET_NAME = rel.EXE_NAME_GH  # GitHub asset 用英文名，不支持中文
API = f"https://api.github.com/repos/{OWNER}/{REPO}"
DEFAULT_BRANCH = "refactor/b-module-split"
TAGGER_NAME = "eavil666"
TAGGER_EMAIL = "eavil666@users.noreply.github.com"

TOKEN = ""


# --------------------------------------------------------------------------
# 输出
# --------------------------------------------------------------------------
def step(msg):
    print(f"\n=== {msg} ===", flush=True)


def ok(msg):
    print(f"[+] {msg}", flush=True)


def warn(msg):
    print(f"[*] {msg}", flush=True)


def fail(msg):
    print(f"[!] {msg}", flush=True)


# --------------------------------------------------------------------------
# REST
# --------------------------------------------------------------------------
def call(method, url, payload=None, raw=None, ctype=None, retries=4, timeout=300):
    """带重试的 REST 调用。

    只对 5xx / 429 / 网络异常重试（退避 3/6/9s），4xx 是确定性错误直接返回，
    不浪费重试次数——这一点在排错时很重要，避免把 401/404 拖成超时。
    """
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "dayupdate-release-rest",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    body = None
    if raw is not None:
        body = raw
        headers["Content-Type"] = ctype or "application/octet-stream"
    elif payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    last = None
    for attempt in range(1, retries + 1):
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = r.read()
                return r.status, (json.loads(data) if data else {})
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")
            if e.code < 500 and e.code != 429:
                return e.code, detail
            last = f"HTTP {e.code}: {detail[:200]}"
        except Exception as e:  # noqa: BLE001
            last = repr(e)
        if attempt < retries:
            time.sleep(3 * attempt)
    return 0, last


def utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# --------------------------------------------------------------------------
# 本地准备
# --------------------------------------------------------------------------
def sync_version_json(version, md5, note=None):
    """同步 version.json：版本 / md5 / exe_urls 的版本段复用 release.py 实现，
    发布说明由 --note / --note-file 覆盖（不传则沿用文件里已有的）。

    最后统一重写一次并补结尾换行：release.py 的 json.dump 不写尾随换行，
    否则每次发布都会多出一个「仅换行差异」的提交噪音。
    """
    rel.update_version_json(version, md5)
    path = os.path.join(ROOT, rel.VERSION_JSON)
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if note:
        data["release_note"] = note
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    if note:
        ok(f"已写入发布说明（{len(note.splitlines())} 行）")


def git_run(args, env=None, check=False, timeout=600):
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, env=env, timeout=timeout, check=check
    )


def commit_and_push(version, branch):
    """提交版本相关文件并推送。用 full-sha 推送，绕开本地分支 ref 不落盘的问题。"""
    env = os.environ.copy()
    env.setdefault("GIT_AUTHOR_NAME", TAGGER_NAME)
    env.setdefault("GIT_AUTHOR_EMAIL", TAGGER_EMAIL)
    env.setdefault("GIT_COMMITTER_NAME", TAGGER_NAME)
    env.setdefault("GIT_COMMITTER_EMAIL", TAGGER_EMAIL)
    # 内网封锁 OCSP/CRL 会让 Schannel 吊销检查 fail-closed；仅对本次子进程关闭
    env["GIT_SSL_NO_VERIFY"] = "true"
    # token 鉴权同样只注入子进程环境，不写任何 git 配置
    env["GIT_CONFIG_COUNT"] = "1"
    env["GIT_CONFIG_KEY_0"] = f"url.https://x-access-token:{TOKEN}@github.com/.insteadOf"
    env["GIT_CONFIG_VALUE_0"] = "https://github.com/"

    files = [rel.MAIN_PY, rel.PYPROJECT, rel.VERSION_JSON]
    r = git_run(["add", *files], env=env)
    if r.returncode != 0:
        fail(f"git add 失败: {r.stderr.strip()}")
        return None

    if git_run(["diff", "--cached", "--quiet"], env=env).returncode == 0:
        warn("无待提交改动，跳过 commit")
    else:
        msg = f"release: v{version}"
        r = git_run(["commit", "-m", msg], env=env)
        if r.returncode != 0:
            fail(f"git commit 失败: {r.stderr.strip()}")
            return None
        w = r.stdout.strip().splitlines()
        ok(w[0] if w else "已提交")

    r = git_run(["rev-parse", "HEAD"], env=env)
    if r.returncode != 0:
        fail(f"无法解析 HEAD（本地 git ref 可能已损坏）: {r.stderr.strip()}")
        fail("修复办法：用 Write 手写 .git/refs/heads/<branch> = <完整 sha>，或重新 checkout")
        return None
    sha = r.stdout.strip()

    # 安全校验：确认这个 sha 就是刚打的提交。沙箱里 commit 后 refs 可能不落盘，
    # 此时 rev-parse HEAD 会拿到旧提交，直接推过去就会静默漏掉本次改动。
    subject = git_run(["log", "-1", "--format=%s", sha], env=env).stdout.strip()
    if subject != f"release: v{version}":
        fail(f"HEAD 指向的提交不是本次发布（subject={subject!r}），已中止推送以免漏提交")
        fail("通常是本地 refs/heads 未落盘：请手写 .git/refs/heads/<branch> 为本次 commit 的 sha 后重试")
        return None
    ok(f"本地提交 {sha[:7]} ({subject})")

    r = git_run(["push", "origin", f"{sha}:refs/heads/{branch}"], env=env, timeout=900)
    out = r.stdout + r.stderr
    if r.returncode != 0:
        # 输出里可能带 token，统一打码后再展示
        fail("推送失败: " + out.replace(TOKEN, "***").strip()[:400])
        return None
    line = [ln for ln in out.splitlines() if "->" in ln or "up-to-date" in ln]
    ok("推送完成: " + (line[0].strip() if line else f"{sha[:7]} -> {branch}"))
    return sha


# --------------------------------------------------------------------------
# REST 发布
# --------------------------------------------------------------------------
def get_remote_sha(branch):
    st, ref = call("GET", f"{API}/git/ref/heads/{branch}")
    if st != 200:
        fail(f"读取远端分支 {branch} 失败: {st} {str(ref)[:200]}")
        return None
    return ref["object"]["sha"]


def ensure_tag(tag, commit_sha):
    """创建 annotated tag 并让 refs/tags/<tag> 指向它。

    每次都新建 tag 对象再 force 更新 ref：重复发布同一版本时，tag 会被拉到
    最新提交上，而不是默默指向上一版（GitHub 不校验 tag 对象名唯一，旧对象
    成为孤儿，无副作用）。
    """
    st, obj = call(
        "POST",
        f"{API}/git/tags",
        {
            "tag": tag,
            "message": f"release {tag}",
            "object": commit_sha,
            "type": "commit",
            "tagger": {"name": TAGGER_NAME, "email": TAGGER_EMAIL, "date": utc_now()},
        },
    )
    if st not in (200, 201):
        fail(f"创建 tag 对象失败: {st} {str(obj)[:200]}")
        return None
    tag_sha = obj["sha"]

    st, res = call("POST", f"{API}/git/refs", {"ref": f"refs/tags/{tag}", "sha": tag_sha})
    if st in (200, 201):
        ok(f"refs/tags/{tag} -> {tag_sha[:7]}")
        return tag_sha
    if st == 422:  # 已存在：强制改指向，保证幂等重发可用
        st, res = call("PATCH", f"{API}/git/refs/tags/{tag}", {"sha": tag_sha, "force": True})
        if st in (200, 201):
            ok(f"refs/tags/{tag} 已更新 -> {tag_sha[:7]}")
            return tag_sha
    fail(f"创建 tag ref 失败: {st} {str(res)[:200]}")
    return None


def ensure_release(tag, note):
    st, data = call("GET", f"{API}/releases/tags/{tag}")
    if st == 200:
        rel_id = data["id"]
        if note and data.get("body") != note:
            call("PATCH", f"{API}/releases/{rel_id}", {"body": note, "name": tag})
            warn(f"Release {tag} 已存在，已更新发布说明")
        else:
            warn(f"Release {tag} 已存在，复用 id={rel_id}")
        return rel_id, data.get("html_url")

    st, data = call(
        "POST",
        f"{API}/releases",
        {
            "tag_name": tag,
            "name": tag,
            "body": note or f"v{tag.lstrip('v')}",
            "draft": False,
            "prerelease": False,
        },
    )
    if st not in (200, 201):
        fail(f"创建 Release 失败: {st} {str(data)[:200]}")
        return None, None
    ok(f"已创建 Release id={data['id']}")
    return data["id"], data.get("html_url")


def upload_asset(rel_id, exe_path):
    """上传 exe，采用「临时名先落地，再顶替旧 asset」的安全替换。

    不能直接「先删同名旧 asset 再上传」：一旦上传阶段遇到 502（已实际发生过
    一次），Release 就会在删除与上传之间失去 exe，下载链接直接断供。
    这里改成先以 `daily-report.exe.tmp-<ts>` 上传，确认成功后删旧 asset 并把
    临时 asset 改回正式名——任何一步失败都不会影响正在提供下载的旧文件。
    """
    with open(exe_path, "rb") as f:
        data = f.read()

    tmp_name = f"{ASSET_NAME}.tmp-{int(time.time())}"
    ok(f"上传 {os.path.basename(exe_path)}（{len(data) / 1024 / 1024:.2f} MB，临时名 {tmp_name}）")
    st, up = call(
        "POST",
        f"https://uploads.github.com/repos/{OWNER}/{REPO}/releases/{rel_id}/assets?name={tmp_name}",
        raw=data,
        ctype="application/octet-stream",
        retries=6,
        timeout=900,
    )
    if st not in (200, 201):
        fail(f"上传失败: {st} {str(up)[:200]}")
        fail("旧 asset 未动，Release 下载不受影响；确认网络后重跑本脚本即可")
        return None
    new_id = up["id"]
    ok(f"临时 asset 上传成功 id={new_id} ({up.get('size')} bytes)")

    # 新内容已落地，此时才删除旧 asset
    st, assets = call("GET", f"{API}/releases/{rel_id}/assets")
    if st == 200:
        for a in assets:
            if a["name"] == ASSET_NAME and a["id"] != new_id:
                st_d, _ = call("DELETE", f"{API}/releases/assets/{a['id']}")
                warn(f"删除旧 asset id={a['id']} ({st_d})")

    # 改回正式名（GitHub 的下载 URL 由 asset 名决定）
    st, renamed = call("PATCH", f"{API}/releases/assets/{new_id}", {"name": ASSET_NAME})
    if st not in (200, 201):
        fail(f"临时 asset 改名失败: {st} {str(renamed)[:200]}")
        fail(f"请手工把 asset {tmp_name} 重命名为 {ASSET_NAME}")
        return None
    ok(f"asset 已就位: {ASSET_NAME} {renamed.get('size')} bytes")
    return renamed


# --------------------------------------------------------------------------
# 发布后验证
# --------------------------------------------------------------------------
def verify(version, md5, branch):
    """发布后复核远端状态。优先用 API 而非 raw. CDN——后者常 502。"""
    tag = f"v{version}"
    problems = []

    st, r = call("GET", f"{API}/releases/tags/{tag}")
    if st != 200:
        problems.append(f"取不到 Release {tag}（{st}）")
    else:
        if r.get("draft") or r.get("prerelease"):
            problems.append("Release 是 draft/prerelease")
        sizes = [a["size"] for a in r.get("assets", []) if a["name"] == ASSET_NAME]
        if not sizes:
            problems.append(f"Release 上没有 {ASSET_NAME}")
        else:
            ok(f"Release {tag}: {ASSET_NAME} {sizes[0]} bytes")

    st, c = call("GET", f"{API}/contents/{rel.VERSION_JSON}?ref={branch}")
    if st != 200:
        problems.append(f"取不到远端 {rel.VERSION_JSON}（{st}）")
    else:
        v = json.loads(base64.b64decode(c["content"]).decode("utf-8"))
        if v.get("version") != version:
            problems.append(f"version.json 版本为 {v.get('version')}，应为 {version}")
        if v.get("md5") != md5:
            problems.append(f"version.json md5 为 {v.get('md5')}，应为 {md5}")
        urls = v.get("exe_urls") or ([v["exe_url"]] if v.get("exe_url") else [])
        if not urls:
            problems.append("version.json 没有 exe_urls")
        elif not all(f"/v{version}/" in u for u in urls):
            problems.append(f"exe_urls 未全部指向 v{version}")
        else:
            ok(f"version.json: version={version}, md5 一致, {len(urls)} 条镜像全指向 v{version}")

    return problems


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="发布收尾（REST 版）：tag/Release/asset 全走 API，绕开本地 git tag 与分支 ref",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", "-V", default=None, help="版本号，默认取 pyproject.toml（单一真源）")
    p.add_argument("--exe", default=None, help="exe 路径，默认 dist/网络安全值守日报.exe")
    p.add_argument("--branch", "-b", default=DEFAULT_BRANCH, help=f"目标分支（默认 {DEFAULT_BRANCH}）")
    p.add_argument("--note", default=None, help="发布说明；也可用 --note @文件路径")
    p.add_argument("--note-file", default=None, help="从文件读取发布说明（与 --note 二选一）")
    p.add_argument("--build", action="store_true", help="发布前先调用 build_exe.py 打包")
    p.add_argument(
        "--commit-push", action="store_true", help="提交 pyproject/main/version.json 并推送（full-sha 方式）"
    )
    p.add_argument("--no-sync", action="store_true", help="不改写 version.json，只做校验与发布")
    p.add_argument("--no-verify", action="store_true", help="跳过发布后验证")
    p.add_argument("--dry-run", action="store_true", help="只做预检并打印发布计划，不写任何东西")
    return p.parse_args()


def resolve_note(args):
    if args.note and args.note_file:
        fail("--note 与 --note-file 只能二选一")
        sys.exit(2)
    if args.note_file:
        with open(args.note_file, encoding="utf-8") as f:
            return f.read().rstrip("\n")
    if args.note and args.note.startswith("@"):
        with open(args.note[1:], encoding="utf-8") as f:
            return f.read().rstrip("\n")
    return args.note


def main():
    global TOKEN
    args = parse_args()
    print("=" * 60)
    print("发布收尾（REST 版）- 网络安全值守日报")
    print("=" * 60)

    step("1/7 读取发布参数")
    version = (args.version or rel.read_app_version() or "").strip()
    if not version:
        fail("无法读取版本号（pyproject.toml / main.py 都没有）")
        sys.exit(1)
    tag = f"v{version}"
    exe_path = os.path.abspath(args.exe) if args.exe else rel.EXE_PATH
    note = resolve_note(args)
    branch = args.branch
    ok(f"版本 {tag} | 分支 {branch}")
    ok(f"exe  {exe_path}")

    step("2/7 获取凭据")
    TOKEN = rel.get_github_token()
    if not TOKEN:
        sys.exit(1)
    ok("已加载 GitHub Token")

    # 打包前先把 pyproject 版本落定（build_exe.py 会据此写 main.py APP_VERSION）
    if args.version:
        rel.set_pyproject_version(version)
    if not args.dry_run and not args.build:
        # 不打包时也要保证 exe 内嵌版本与发布版本一致，否则升级后会重复触发更新
        rel.set_app_version(version)

    if args.build:
        step("3/7 打包 exe")
        if args.dry_run:
            warn("[dry-run] 将执行 build_exe.py")
        elif not rel.run_build(version):
            sys.exit(1)
    else:
        step("3/7 打包 exe（跳过，用现有 dist 产物）")

    step("4/7 计算指纹")
    if not os.path.exists(exe_path):
        fail(f"exe 不存在: {exe_path}（可加 --build 先打包）")
        sys.exit(1)
    md5 = rel.calc_md5(exe_path)
    size = os.path.getsize(exe_path)
    ok(f"{os.path.basename(exe_path)} | {size} bytes | md5 {md5}")

    step("5/7 同步 version.json")
    if args.no_sync or args.dry_run:
        warn("[跳过] 不改写 version.json")
    else:
        sync_version_json(version, md5, note)

    if args.dry_run:
        step("发布计划（dry-run）")
        print(f"  tag        : {tag}")
        print(f"  branch     : {branch}")
        print(f"  exe        : {exe_path}")
        print(f"  md5        : {md5}")
        print(f"  asset 名   : {ASSET_NAME}")
        print(f"  commit/push: {'是' if args.commit_push else '否'}")
        print(f"  发布说明   : {(note or '(沿用 version.json)').splitlines()[0]}")
        print("\n[dry-run] 未做任何改动，去掉 --dry-run 即执行。")
        return

    if args.commit_push:
        step("6/7 提交并推送")
        if commit_and_push(version, branch) is None:
            sys.exit(1)
    else:
        step("6/7 提交并推送（跳过）")

    step("7/7 REST 发布")
    remote_sha = get_remote_sha(branch)
    if not remote_sha:
        sys.exit(1)
    ok(f"远端 {branch} = {remote_sha[:7]}")
    if not ensure_tag(tag, remote_sha):
        sys.exit(1)
    rel_id, html_url = ensure_release(tag, note)
    if not rel_id:
        sys.exit(1)
    if not upload_asset(rel_id, exe_path):
        sys.exit(1)

    if not args.no_verify:
        step("发布后验证")
        problems = verify(version, md5, branch)
        if problems:
            fail("验证未通过：")
            for x in problems:
                print(f"    - {x}")
            sys.exit(1)
        ok("验证通过")

    print("\n" + "=" * 60)
    print(f"[OK] 发布完成 {tag}")
    print(f"    Release: {html_url or f'https://github.com/{OWNER}/{REPO}/releases/tag/{tag}'}")
    print(f"    MD5    : {md5}")
    print("=" * 60)


if __name__ == "__main__":
    main()
