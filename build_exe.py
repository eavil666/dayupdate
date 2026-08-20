#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
打包脚本 - 将项目打包成exe可执行文件（单文件模式，带体积优化）
使用方法: python build_exe.py
"""

import os
import sys
import subprocess
import shutil
import re
import argparse

script_dir = os.path.dirname(os.path.abspath(__file__))


def get_git_version():
    """从 Git 标签获取版本号（去除 v 前缀，失败返回 None）"""
    try:
        # 最近一个 tag（去掉 v 前缀）
        tag = subprocess.check_output(
            ['git', 'describe', '--tags', '--abbrev=0'],
            cwd=script_dir, stderr=subprocess.DEVNULL
        ).decode('utf-8').strip()
        version = tag.lstrip('vV').strip()
        if version and re.match(r'^\d+(\.\d+)*$', version):
            return version
    except Exception:
        pass
    return None


def set_app_version(version):
    """将 main.py 中的 APP_VERSION 常量修改为指定版本号"""
    main_file = os.path.join(script_dir, 'main.py')
    if not os.path.exists(main_file):
        print(f'[-] 未找到 main.py，无法写入版本号')
        return False
    with open(main_file, 'r', encoding='utf-8') as f:
        content = f.read()
    pattern = r'(APP_VERSION\s*=\s*["\'])([^"\']+)(["\'])'
    if not re.search(pattern, content):
        print('[-] main.py 中未找到 APP_VERSION 常量')
        return False
    new_content, n = re.subn(pattern, rf'\g<1>{version}\g<3>', content, count=1)
    if n == 0:
        return False
    with open(main_file, 'w', encoding='utf-8') as f:
        f.write(new_content)
    print(f'[+] 版本号已写入 main.py: APP_VERSION = "{version}"')
    return True


def install_pyinstaller():
    """安装PyInstaller"""
    try:
        import PyInstaller
        print('[+] PyInstaller 已安装')
        return True
    except ImportError:
        print('[!] 正在安装 PyInstaller...')
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pyinstaller',
                              '-i', 'https://pypi.tuna.tsinghua.edu.cn/simple'])
        return True


def create_runtime_hook():
    """创建运行时 hook 文件，用于设置 DLL 路径和 certifi CA 证书路径"""
    runtime_hook_content = '''import os
import sys

# Set numpy/pandas DLL paths in frozen mode
if getattr(sys, 'frozen', False):
    base_dir = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
    for lib_dir in ('numpy.libs', 'pandas.libs'):
        full_path = os.path.join(base_dir, lib_dir)
        if os.path.isdir(full_path):
            try:
                os.add_dll_directory(full_path)
            except (OSError, AttributeError):
                pass
    # certifi.where() 补丁：PyInstaller 单文件模式下 cacert.pem 被放到
    # _MEIPASS/certifi/cacert.pem，但 certifi.where() 默认指向错误路径。
    # 提前设置 REQUESTS_CA_BUNDLE / SSL_CERT_FILE，requests 和 ssl 默认都会用。
    _cacert = os.path.join(base_dir, 'certifi', 'cacert.pem')
    if os.path.exists(_cacert):
        os.environ['REQUESTS_CA_BUNDLE'] = _cacert
        os.environ['SSL_CERT_FILE'] = _cacert
        # 同时 monkey-patch certifi.where()，确保任何显式调用都返回正确路径
        try:
            import certifi as _certifi
            _certifi.where = lambda _p=_cacert: _p
        except Exception:
            pass
'''
    runtime_hook_file = os.path.join(script_dir, '_runtime_hook.py')
    with open(runtime_hook_file, 'w', encoding='utf-8') as f:
        f.write(runtime_hook_content)
    return runtime_hook_file


def build_exe():
    """执行打包（单文件模式，带体积优化）"""
    dist_dir = os.path.join(script_dir, 'dist')
    build_dir = os.path.join(script_dir, 'build')

    # 清理旧产物
    if os.path.exists(dist_dir):
        for f in os.listdir(dist_dir):
            if f.endswith('.exe'):
                try:
                    os.remove(os.path.join(dist_dir, f))
                except PermissionError:
                    pass
    if os.path.exists(build_dir):
        try:
            shutil.rmtree(build_dir)
        except PermissionError:
            pass

    # 创建运行时 hook
    runtime_hook_file = create_runtime_hook()
    print(f'[+] 运行时 hook: {runtime_hook_file}')

    # UPX 路径
    upx_path = 'upx'
    for path in [
        os.path.join(script_dir, 'upx.exe'),
        os.path.join(os.path.dirname(sys.executable), 'upx.exe'),
    ]:
        if os.path.exists(path):
            upx_path = path
            break
    upx_dir = os.path.dirname(upx_path) if upx_path != 'upx' else ''
    print(f'[+] UPX: {upx_path}')

    # 使用正斜杠避免 SyntaxWarning
    sd = script_dir.replace('\\', '/')
    rth = runtime_hook_file.replace('\\', '/')
    upx_d = upx_dir.replace('\\', '/') if upx_dir else ''

    # 收集需要打包的数据文件（终端IP地址表改为运行时外部导入，不打包）
    datas = []
    for fname in ('config.ini', 'office.ico'):
        if os.path.exists(os.path.join(script_dir, fname)):
            datas.append(f"('{fname}', '.')")
    # 把 certifi 的 cacert.pem 作为 data 打包到 certifi/ 目录，避免 frozen 模式 certifi.where() 找不到
    try:
        import certifi
        _cacert = certifi.where()
        if os.path.exists(_cacert):
            _src = _cacert.replace('\\', '/')
            datas.append(f"(r'{_src}', 'certifi')")
            print(f'[+] 打包 CA 证书: {_cacert}')
    except Exception as _e:
        print(f'[!] 未找到 certifi cacert.pem ({_e})，跳过')
    datas_str = ',\n        '.join(datas) if datas else ''

    spec_content = f'''# -*- mode: python ; coding: utf-8 -*-
block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=[r'{sd}'],
    binaries=[],
    datas=[
        {datas_str}
    ],
    hiddenimports=[
        'pandas', 'numpy', 'openpyxl', 'docx', 'requests',
        'certifi',
        'ip2region', 'ipaddress', 'configparser',
        'tkinter', 'tkinter.ttk', 'tkinter.messagebox', 'tkinter.filedialog',
        'tkinter.font',
    ],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[r'{rth}'],
    excludes=[
        'matplotlib', 'scipy', 'PIL', 'Pillow',
        'PyQt5', 'PyQt6', 'PySide2', 'PySide6',
        'IPython', 'jupyter', 'notebook', 'pytest', 'nose', 'tox',
        'sklearn', 'statsmodels', 'seaborn', 'plotly', 'bokeh', 'altair',
        'pytorch', 'tensorflow', 'keras', 'mxnet',
        'flask', 'django', 'fastapi', 'aiohttp',
        'beautifulsoup4', 'html5lib', 'scrapy',
        'cv2', 'pywin32', 'win32com', 'pythoncom', 'docx2txt',
        'tqdm', 'pandas_market_calendars',
        'openpyxl.tests', 'pandas.tests', 'numpy.tests',
        'tkinter.tix', 'tkinter.dnd', 'tkinter.scrolledtext',
        'unittest', 'doctest', 'pydoc', 'difflib',
        'telnetlib', 'py_compile', 'compileall',
        'lib2to3', 'ensurepip', 'venv',
        'turtle', 'turtledemo', 'cmd', 'pdb', 'profile', 'pstats', 'timeit',
        'pipes', 'resource', 'pty', 'fcntl', 'grp', 'pwd', 'readline', 'rlcompleter',
        'audioop', 'colorsys', 'imghdr', 'sndhdr', 'sunau', 'wave',
        'shelve', 'mailbox', 'xmlrpc',
        'aiohappyeyeballs', 'aiosignal', 'frozenlist', 'multidict', 'yarl', 'propcache',
        'packaging', 'setuptools', 'pip',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='网络安全值守日报',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    # UPX=False：避免压缩后的 exe 被覆盖/重启时被杀软（Defender/火绒/360）误报为可疑
    # 体积会增大，但自动更新更稳定
    upx=False,
    upx_dir=r'{upx_d}',
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='office.ico',
)
'''

    spec_file = os.path.join(script_dir, 'build_exe.spec')
    with open(spec_file, 'w', encoding='utf-8') as f:
        f.write(spec_content)

    # 设置缓存目录
    env = os.environ.copy()
    env['PYINSTALLER_CONFIG_DIR'] = os.path.join(script_dir, 'build', 'pyinstaller_cache')

    cmd = [
        sys.executable, '-m', 'PyInstaller',
        spec_file,
        '--distpath=dist',
        '--workpath=build',
    ]
    print(f'[+] 执行打包: {" ".join(cmd)}')
    subprocess.check_call(cmd, env=env)

    # 清理临时 spec
    if os.path.exists(spec_file):
        os.remove(spec_file)

    # 检查结果
    exe_path = os.path.join(dist_dir, '网络安全值守日报.exe')
    if os.path.exists(exe_path):
        exe_size = os.path.getsize(exe_path) / (1024 * 1024)
        print('[OK] 打包完成！')
        print(f'    文件: {exe_path}')
        print(f'    大小: {exe_size:.2f} MB')
    else:
        print('[-] 打包失败，exe文件未生成')


def main():
    parser = argparse.ArgumentParser(description='网络安全值守日报 - 打包工具')
    parser.add_argument('--version', '-V', type=str, default=None,
                        help='手动指定版本号（如 1.1.0），优先于 Git 标签')
    args = parser.parse_args()

    print('=' * 60)
    print('网络安全值守日报 - 打包工具（单文件模式）')
    print('=' * 60)

    # 版本号解析：--version > git tag > 保持不变
    target_version = None
    if args.version:
        target_version = args.version.strip()
        print(f'[+] 使用命令行指定版本号: {target_version}')
    else:
        git_ver = get_git_version()
        if git_ver:
            target_version = git_ver
            print(f'[+] 使用 Git 标签版本号: {target_version}')
        else:
            print('[!] 未指定版本号且无 Git 标签，将使用 main.py 中现有版本')

    if target_version:
        set_app_version(target_version)
    print('[!] ip2region数据库不打包，运行时自动下载')
    print('=' * 60)

    install_pyinstaller()
    # 当前更新方案：沿用 --update-worker 模式（由 main.py 自身完成自更新，无外部依赖）
    build_exe()


if __name__ == '__main__':
    main()
