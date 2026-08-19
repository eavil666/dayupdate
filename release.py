#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
一键发布脚本 - 本地打包并上传到 GitHub Release

使用方法:
  1. 配置 GitHub Token（任选一种）:
     方式A: 复制 .env.example 为 .env，填入 Token
        copy .env.example .env
        notepad .env

     方式B: 设置环境变量（重启终端生效）
        setx GH_TOKEN "ghp_xxxxxxxxxxxxxxxxxxxx"

  2. 运行:
     python release.py                    # 自动从 main.py 读取版本号
     python release.py --version 1.1.0    # 指定新版本号
     python release.py --skip-build       # 跳过打包，仅上传已有 exe

注意:
  - .env 文件不会被提交（已在 .gitignore 中），Token 安全
  - config.ini 不会被提交（已在 .gitignore 中）
  - exe 文件不会被提交到 git，只上传到 Release
  - 需要网络可访问 github.com
"""

import os
import sys
import json
import re
import hashlib
import argparse
import subprocess
import urllib.request
import urllib.error
import shutil

# === Windows 控制台 UTF-8（避免中文乱码/UnicodeEncodeError）===
if sys.platform == 'win32':
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        ctypes.windll.kernel32.SetConsoleCP(65001)
    except Exception:
        pass
# 强制标准流使用 UTF-8，避免 print 中文（如 exe 名）时崩溃/卡住
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

script_dir = os.path.dirname(os.path.abspath(__file__))
REPO_OWNER = 'eavil666'
REPO_NAME = 'dayupdate'
EXE_NAME = '网络安全值守日报.exe'              # 本地打包生成的 exe 名（中文，用户体验）
EXE_NAME_GH = 'daily-report.exe'              # GitHub Release asset 名（英文，GitHub 不支持中文名）
VERSION_JSON = 'version.json'
MAIN_PY = 'main.py'
EXE_PATH = os.path.join(script_dir, 'dist', EXE_NAME)


def log(msg, prefix='[+]'):
    print(f'{prefix} {msg}')


def log_err(msg):
    print(f'[!] {msg}')


def log_warn(msg):
    print(f'[*] {msg}')


def load_env_file():
    """从 .env 文件加载环境变量（不覆盖已存在的）"""
    env_path = os.path.join(script_dir, '.env')
    if not os.path.exists(env_path):
        return
    with open(env_path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' not in line:
                continue
            key, _, value = line.partition('=')
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def get_github_token():
    """从环境变量或 .env 文件获取 GitHub Token"""
    load_env_file()
    token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
    if not token:
        log_err('未找到 GitHub Token，请按以下步骤配置:')
        print('    方式1: 复制 .env.example 为 .env，填入 Token')
        print('           copy .env.example .env')
        print('           notepad .env')
        print('    方式2: 设置环境变量（重启终端生效）')
        print('           setx GH_TOKEN "ghp_xxxxxxxxxxxxxxxxxxxx"')
        print('    方式3: 临时使用（仅当前终端）')
        print('           $env:GH_TOKEN="ghp_xxx"')
        print()
        print('    Token 生成地址: https://github.com/settings/tokens')
        print('    权限要求: 勾选 repo（完整仓库访问）')
        return None
    return token


def read_app_version():
    """从 main.py 读取 APP_VERSION"""
    with open(os.path.join(script_dir, MAIN_PY), encoding='utf-8') as f:
        content = f.read()
    m = re.search(r'APP_VERSION\s*=\s*["\']([^"\']+)["\']', content)
    if m:
        return m.group(1)
    return None


def set_app_version(version):
    """修改 main.py 中的 APP_VERSION"""
    path = os.path.join(script_dir, MAIN_PY)
    with open(path, encoding='utf-8') as f:
        content = f.read()
    new_content, n = re.subn(
        r'(APP_VERSION\s*=\s*["\'])([^"\']+)(["\'])',
        rf'\g<1>{version}\g<3>',
        content,
        count=1
    )
    if n == 0:
        log_err(f'未在 {MAIN_PY} 中找到 APP_VERSION 常量')
        return False
    with open(path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    log(f'已更新 {MAIN_PY}: APP_VERSION = "{version}"')
    return True


def run_build(version=None):
    """运行 build_exe.py 打包。

    必须传入 version（--version），否则 build_exe.py 会用 `git describe --tags`
    推导版本号；当本地缺少最新 tag 时会取到旧 tag（如 v1.2.1），把 APP_VERSION
    覆写成旧版本，导致打出的 exe 实际版本 < version.json 声明版本，
    升级后程序仍认为自己是旧版 → 重复升级（"一版一版升"）。
    """
    log('开始打包...')
    # 强制子进程（build_exe.py -> PyInstaller）使用 UTF-8，避免中文输出乱码
    env = os.environ.copy()
    env['PYTHONUTF8'] = '1'
    env['PYTHONIOENCODING'] = 'utf-8'
    cmd = [sys.executable, 'build_exe.py']
    if version:
        cmd += ['--version', version]
    result = subprocess.run(
        cmd,
        cwd=script_dir,
        capture_output=False,
        env=env,
    )
    if result.returncode != 0:
        log_err('打包失败')
        return False
    if not os.path.exists(EXE_PATH):
        log_err(f'打包后未找到 exe: {EXE_PATH}')
        return False
    size_mb = os.path.getsize(EXE_PATH) / (1024 * 1024)
    log(f'打包完成: {EXE_PATH} ({size_mb:.2f} MB)')
    return True


def calc_md5(path):
    """计算文件 MD5"""
    h = hashlib.md5()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest().upper()


def update_version_json(version, md5):
    """更新 version.json 的版本号、MD5、exe_urls 中的版本号"""
    path = os.path.join(script_dir, VERSION_JSON)
    with open(path, encoding='utf-8') as f:
        data = json.load(f)

    data['version'] = version
    data['md5'] = md5
    # 更新 exe_urls 中的版本号（GitHub asset 用英文名 daily-report.exe）
    old_version_pattern = re.compile(r'/releases/download/v[^/]+/')
    new_segment = f'/releases/download/v{version}/'
    if 'exe_urls' in data:
        data['exe_urls'] = [old_version_pattern.sub(new_segment, u) for u in data['exe_urls']]
    elif 'exe_url' in data:
        data['exe_url'] = old_version_pattern.sub(new_segment, data['exe_url'])

    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    log(f'已更新 {VERSION_JSON}: version={version}, md5={md5}')


def git_commit_tag_push(version):
    """git add/commit/tag/push"""
    # 注入 git 提交身份（避免 "Author identity unknown" 导致 commit 失败）；
    # 用 setdefault：若用户已自行配置则尊重已有配置
    os.environ.setdefault('GIT_AUTHOR_NAME', 'eavil666')
    os.environ.setdefault('GIT_AUTHOR_EMAIL', 'eavil666@users.noreply.github.com')
    os.environ.setdefault('GIT_COMMITTER_NAME', 'eavil666')
    os.environ.setdefault('GIT_COMMITTER_EMAIL', 'eavil666@users.noreply.github.com')
    log('提交代码到 git...')
    subprocess.run(['git', 'add', MAIN_PY, VERSION_JSON, 'config.ini.example',
                    'release.py', 'build_exe.py'],
                   cwd=script_dir, check=True)
    # 检查是否有改动
    result = subprocess.run(['git', 'diff', '--cached', '--quiet'], cwd=script_dir)
    if result.returncode == 0:
        log_warn('无代码改动，跳过 commit')
    else:
        subprocess.run(
            ['git', 'commit', '-m', f'release: v{version}'],
            cwd=script_dir, check=True
        )

    # 删除已存在的 tag（如果重复发布）
    subprocess.run(['git', 'tag', '-d', f'v{version}'],
                   cwd=script_dir, capture_output=True)
    subprocess.run(['git', 'push', 'origin', f':refs/tags/v{version}'],
                   cwd=script_dir, capture_output=True)

    # 创建新 tag
    subprocess.run(
        ['git', 'tag', '-a', f'v{version}', '-m', f'Release v{version}'],
        cwd=script_dir, check=True
    )
    log(f'已创建 tag: v{version}')

    # push 代码和 tag
    log('推送到 GitHub...')
    subprocess.run(['git', 'push', '-u', 'origin', 'main'],
                   cwd=script_dir, check=True)
    subprocess.run(['git', 'push', 'origin', f'v{version}'],
                   cwd=script_dir, check=True)
    log('代码和 tag 推送完成')


def github_api(method, path, token, data=None, content_type='application/json'):
    """调用 GitHub REST API"""
    url = f'https://api.github.com{path}'
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github+json',
    }
    if data is not None:
        body = json.dumps(data).encode('utf-8') if content_type == 'application/json' else data
        headers['Content-Type'] = content_type
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
    else:
        req = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, json.loads(resp.read().decode('utf-8')) if resp.status != 204 else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')
        return e.code, body
    except Exception as e:
        return 0, str(e)


def create_release(token, version):
    """创建 GitHub Release（如果已存在则获取）"""
    tag = f'v{version}'
    # 先尝试获取已存在的 Release
    status, data = github_api('GET', f'/repos/{REPO_OWNER}/{REPO_NAME}/releases/tags/{tag}', token)
    if status == 200:
        log(f'Release {tag} 已存在，将更新 asset')
        return data

    # 创建新 Release
    body = {
        'tag_name': tag,
        'name': f'{tag} - 发布',
        'body': f'## v{version}\n\n详见 version.json',
        'draft': False,
        'prerelease': False,
    }
    status, data = github_api('POST', f'/repos/{REPO_OWNER}/{REPO_NAME}/releases', token, body)
    if status not in (200, 201):
        log_err(f'创建 Release 失败: {status} {data}')
        return None
    log(f'已创建 Release: {tag}')
    return data


def upload_asset(token, release, exe_path):
    """上传 exe 到 Release（GitHub asset 名用英文，不支持中文）"""
    upload_url = release['upload_url'].split('{')[0]  # 去掉 {?name,label}
    asset_url = f'{upload_url}?name={EXE_NAME_GH}'

    size = os.path.getsize(exe_path)
    log(f'上传 exe ({size / 1024 / 1024:.2f} MB), asset 名: {EXE_NAME_GH}')

    # 删除已存在的同名 asset
    for asset in release.get('assets', []):
        if asset['name'] == EXE_NAME_GH:
            log_warn(f'删除旧 asset: {asset["id"]}')
            github_api('DELETE', f'/repos/{REPO_OWNER}/{REPO_NAME}/releases/assets/{asset["id"]}', token)

    # 上传
    with open(exe_path, 'rb') as f:
        exe_data = f.read()
    url = asset_url.replace('api.github.com', 'uploads.github.com')
    req = urllib.request.Request(
        url,
        data=exe_data,
        headers={
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github+json',
            'Content-Type': 'application/octet-stream',
        },
        method='POST'
    )
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            result = json.loads(resp.read().decode('utf-8'))
            log(f'上传成功: {result.get("browser_download_url")}')
            return True
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')
        log_err(f'上传失败: {e.code} {body}')
        return False
    except Exception as e:
        log_err(f'上传异常: {e}')
        return False


def main():
    parser = argparse.ArgumentParser(description='本地打包并发布到 GitHub Release')
    parser.add_argument('--version', '-V', type=str, default=None,
                        help='指定版本号（如 1.1.0），默认从 main.py 读取')
    parser.add_argument('--skip-build', action='store_true',
                        help='跳过打包步骤，直接上传已有 exe')
    args = parser.parse_args()

    print('=' * 60)
    print('一键发布 - 网络安全值守日报')
    print('=' * 60)

    # 1. 获取 Token
    token = get_github_token()
    if not token:
        sys.exit(1)

    # 2. 确定版本号
    if args.version:
        version = args.version.strip()
        if not set_app_version(version):
            sys.exit(1)
    else:
        version = read_app_version()
        if not version:
            log_err('无法从 main.py 读取 APP_VERSION')
            sys.exit(1)
        log(f'当前版本: v{version}')

    # 3. 打包（传入版本号，防止 build_exe.py 从 git 标签覆写成旧版本）
    if not args.skip_build:
        if not run_build(version):
            sys.exit(1)
    else:
        log_warn('跳过打包步骤')
        if not os.path.exists(EXE_PATH):
            log_err(f'exe 不存在: {EXE_PATH}，请先打包')
            sys.exit(1)

    # 4. 计算 MD5 并更新 version.json
    md5 = calc_md5(EXE_PATH)
    log(f'exe MD5: {md5}')
    update_version_json(version, md5)

    # 5. git commit/tag/push
    try:
        git_commit_tag_push(version)
    except subprocess.CalledProcessError as e:
        log_err(f'git 操作失败: {e}')
        sys.exit(1)

    # 6. 创建 Release
    release = create_release(token, version)
    if not release:
        sys.exit(1)

    # 7. 上传 exe
    if not upload_asset(token, release, EXE_PATH):
        sys.exit(1)

    print('=' * 60)
    print('[OK] 发布完成! v{}'.format(version))
    print(f'    Release: https://github.com/{REPO_OWNER}/{REPO_NAME}/releases/tag/v{version}')
    print(f'    version.json: https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/main/version.json')
    print('=' * 60)


if __name__ == '__main__':
    main()
