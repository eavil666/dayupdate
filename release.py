#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
一键发布脚本 - 本地打包并上传到 GitHub Release

使用方法:
  1. 配置 GitHub Token：复制 .env.example 为 .env 并填入 Token
     （也支持环境变量 GH_TOKEN / GITHUB_TOKEN，脚本自动读取，无需手动 export）
        copy .env.example .env
        notepad .env

  2. 运行:
     python release.py                    # 自动从 main.py 读取版本号
     python release.py --version 1.1.0    # 指定新版本号
     python release.py --skip-build       # 跳过打包，仅上传已有 exe

说明:
  - .env / config.ini / exe 均不入库（已在 .gitignore），Token 与产物安全
  - 无需手动配置 git 或 insteadOf：git 推送的 token 鉴权与 Windows Schannel
    证书吊销检查绕过，均由脚本通过子进程环境变量自动注入（不写任何 git 配置）
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

# 匹配 main.py 中的 APP_VERSION 常量（read / set 共用，避免两处正则不一致）
APP_VERSION_RE = re.compile(r'(APP_VERSION\s*=\s*["\'])([^"\']+)(["\'])')
PYPROJECT = 'pyproject.toml'


def get_pyproject_version():
    """从 pyproject.toml [project].version 读取版本号（单一真源，失败返回 None）"""
    try:
        import tomllib  # py3.11+
    except ImportError:
        import tomli as tomllib  # py3.10 兜底（若已安装）
    try:
        with open(os.path.join(script_dir, PYPROJECT), 'rb') as f:
            return str(tomllib.load(f)['project']['version']).strip()
    except Exception:
        return None


def set_pyproject_version(version):
    """同步 pyproject.toml [project].version（单一真源）"""
    path = os.path.join(script_dir, PYPROJECT)
    if not os.path.exists(path):
        return False
    try:
        src = open(path, encoding='utf-8').read()
        new_src, n = re.subn(r'(?m)^version\s*=\s*["\']([^"\']+)["\']',
                             f'version = "{version}"', src, count=1)
        if n == 0:
            return False
        with open(path, 'w', encoding='utf-8') as f:
            f.write(new_src)
        return True
    except Exception:
        return False


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
    """读取版本号：优先 pyproject.toml（单一真源），回退 main.py APP_VERSION"""
    v = get_pyproject_version()
    if v:
        return v
    with open(os.path.join(script_dir, MAIN_PY), encoding='utf-8') as f:
        content = f.read()
    m = APP_VERSION_RE.search(content)
    if m:
        return m.group(2)
    return None


def set_app_version(version):
    """修改 main.py 中的 APP_VERSION"""
    path = os.path.join(script_dir, MAIN_PY)
    with open(path, encoding='utf-8') as f:
        content = f.read()
    new_content, n = APP_VERSION_RE.subn(
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


def git_commit_tag_push(version, token=None):
    """git add/commit/tag/push。

    SSL 吊销检查绕过 + GitHub token 鉴权，均通过环境变量局部注入给 git 子进程，
    不写任何 git 配置（不污染全局配置，也不写 .git/config），子进程结束即失效。
      - GIT_SSL_NO_VERIFY=true：绕过 Windows Schannel 的证书吊销检查
        （内网封锁 OCSP/CRL 导致 fail-closed，根因见项目记忆）。
      - GIT_CONFIG_KEY_0/VALUE_0：等价于
        `git config url."https://x-access-token:TOKEN@github.com/".insteadOf https://github.com/`
        仅对本次子进程生效，把 https 远端地址重写为带 token 的地址完成鉴权。
    """
    env = os.environ.copy()
    # 提交身份：仅注入本次子命令，尊重用户已有配置
    env.setdefault('GIT_AUTHOR_NAME', 'eavil666')
    env.setdefault('GIT_AUTHOR_EMAIL', 'eavil666@users.noreply.github.com')
    env.setdefault('GIT_COMMITTER_NAME', 'eavil666')
    env.setdefault('GIT_COMMITTER_EMAIL', 'eavil666@users.noreply.github.com')

    # 局部绕过证书吊销检查（不影响全局/仓库配置）
    env['GIT_SSL_NO_VERIFY'] = 'true'

    # 局部注入 token 鉴权（仅当前子进程，零写盘）
    if token:
        env['GIT_CONFIG_COUNT'] = '1'
        env['GIT_CONFIG_KEY_0'] = f'url.https://x-access-token:{token}@github.com/.insteadOf'
        env['GIT_CONFIG_VALUE_0'] = 'https://github.com/'
    log('提交代码到 git...')
    subprocess.run(['git', 'add', MAIN_PY, VERSION_JSON, 'config.ini.example',
                    'release.py', 'build_exe.py'],
                   cwd=script_dir, check=True, env=env)
    # 检查是否有改动
    result = subprocess.run(['git', 'diff', '--cached', '--quiet'], cwd=script_dir, env=env)
    if result.returncode == 0:
        log_warn('无代码改动，跳过 commit')
    else:
        subprocess.run(
            ['git', 'commit', '-m', f'release: v{version}'],
            cwd=script_dir, check=True, env=env
        )

    # 删除已存在的 tag（如果重复发布）
    subprocess.run(['git', 'tag', '-d', f'v{version}'],
                   cwd=script_dir, capture_output=True, env=env)
    subprocess.run(['git', 'push', 'origin', f':refs/tags/v{version}'],
                   cwd=script_dir, capture_output=True, env=env)

    # 创建新 tag
    subprocess.run(
        ['git', 'tag', '-a', f'v{version}', '-m', f'Release v{version}'],
        cwd=script_dir, check=True, env=env
    )
    log(f'已创建 tag: v{version}')

    # push 代码和 tag
    log('推送到 GitHub...')
    subprocess.run(['git', 'push', '-u', 'origin', 'main'],
                   cwd=script_dir, check=True, env=env)
    subprocess.run(['git', 'push', 'origin', f'v{version}'],
                   cwd=script_dir, check=True, env=env)
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
        # 同步单一真源 pyproject.toml（release 流程只改这一处版本声明）
        if not set_pyproject_version(version):
            log_warn('pyproject.toml 未找到 version 行，跳过同步')
    else:
        version = read_app_version()
        if not version:
            log_err('无法读取版本号（pyproject.toml / main.py）')
            sys.exit(1)
        log(f'当前版本: v{version}')

    # 同步 main.py APP_VERSION（exe 内嵌版本以 main.py 为准，必须与发布版本一致）
    if not set_app_version(version):
        sys.exit(1)

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
        git_commit_tag_push(version, token)
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
