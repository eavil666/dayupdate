# 网络安全值守保障日报工具

面向轨道集团网络安全值守场景的日报生成工具：读取安全告警 Excel → 生成「外网攻击 IP 归属分析」xlsx + 「网络安全值守保障日报」docx（公文体排版，含统计图表与威胁情报分级），并提供 GUI、CLI、自动更新、威胁情报库一键更新等能力。

> 当前工作分支：`refactor/b-module-split`；正式发布版本号以 `main.py` 的 `APP_VERSION` 为准（当前 `1.8.3`，历次版本见文末「版本记录」）。

---

## 一、功能总览

| 能力 | 说明 |
|---|---|
| IP 归属分析 | 告警外网源 IP 归属：本地缓存 → ip2region 离线库 → 在线补全（pconline / 百度 / ipwho.is 多源容错），输出带归属与威胁分级的 xlsx |
| 值守日报生成 | 按公文规范输出 docx：态势概览、重点工作、攻击统计表（等级/类型/趋势）、威胁源明细、待跟进事项，嵌入原生统计图表 |
| 威胁情报匹配 | 三层匹配：本地 `threat_db.json`（精确 IP + CIDR 恶意段）→ 联网 3 源兜底 → 归属表与日报**同口径**（同一 `match_ip` 索引） |
| GUI 一键操作 | 自动探测告警文件、业务配置 Excel 导入、进度条与日志回显、一键生成两类产物 |
| 威胁源更新 | GUI 按钮/CLI 参数下载最新情报库；官方 GitHub + 国内加速镜像**并行测速择优**，失败自动轮换 |
| 版本自检 | 启动后标题栏显示威胁源版本/库龄；后台轻量探测远端版本，有新版本时弹窗询问是否更新 |
| 程序自动更新 | 从 GitHub Release 拉取新 exe（多 CDN 镜像 + MD5 校验），后台 worker 原子替换并自重启 |
| 威胁情报云端发布 | GitHub Actions 每日 08:30 重建多源情报库（7 源，全部免费免凭据下载）并发布到固定 tag 的 Release asset，供各端下载；发布前有三层降级护栏 |

---

## 二、运行逻辑

### 2.1 入口判断（`main.py: main()`）

按命令行参数优先级分派：

| 参数 | 模式 | 说明 |
|---|---|---|
| `--update-worker=<json路径>` | 纯后台覆盖更新 | 由 updater 拉起的隐藏 worker，绝不加载 GUI；异常退出码 99 |
| `--update-intel` | 更新威胁情报库 | 多源择优下载 `threat_db.json` 覆盖本地后退出（退出码 0/1） |
| `-c` / `--cli` | 命令行 | 交互选择告警文件 → 归属分析 → 日报生成 |
| （无参数） | **GUI 模式**（默认） | 图形界面全流程 |

### 2.2 GUI 主流程（`gui.py` DailyReportGUI）

```
启动
 ├─ _setup 初始化：业务ip.xlsx（探针ip段）→ load_probes_from_excel
 │    └ 终端ip地址表.xlsx → set_terminal_ip_table_path
 ├─ 后台静默线程（不打扰用户）：
 │    ├─ _check_update_startup   exe 新版本探测（有新版弹窗询问）
 │    └─ _check_intel_startup    威胁源远端版本比对（头部2KB 轻量探测，
 │                                │   远端新 → 弹窗"检测到新的威胁源库"，
 │                                │   已最新 → 仅写日志；无本地库 → 提示更新）
 ├─ 用户点【自动探测】/手动选文件（安全告警*.xlsx）
 └─ 点【生成日报】
      ├─ 收集输入：重点工作总结 / 威胁源动态 / 待跟进事项
      │    （示例占位文本 == 未填写；report._parse_lines 再兜底整块过滤）
      └─ 后台线程执行 → _on_complete 完成弹窗
           ├─ 步骤1  generate_ip_report()  → 外网攻击IP归属.xlsx
           └─ 步骤2  generate_daily_report() → 网络安全值守保障日报_YYYYMMDD.docx
```

### 2.3 归属分析链路（`ipdb.py`）

```
extract_source_ips(告警xlsx)         提取外网源 IP（排除内网/终端/业务探针等）
   ↓
query_all_ips(ips)                   归属查询公共链路：
   ① geo_cache.json 命中直接返回
   ② ip2region 离线库（xdb，可自动下载）
   ③ 在线补全：pconline → 百度 → ipwho.is 多源容错（单条，非批量）
   ↓
威胁分级（外网攻击IP归属 sheet）
   match_ip(ip)  ← 与日报同一函数/同一索引
   ├─ 命中 ≥2 源     → Critical
   ├─ 命中 1 源      → High（段命中标 `源名(网段)`）
   ├─ 名单可用未命中 → Clean
   └─ 名单加载失败   → 未查
   ↓
openpyxl 写 xlsx（红=威胁/绿=Clean 配色，嵌入图表）
```

### 2.4 日报生成链路（`report.py`）

```
generate_daily_report(files, date, work_summary, follow_items, intel_items)
 ├─ pick_input_and_date  定位告警文件与业务日期
 ├─ load_and_classify    读取 + 等级/类型/区域分类
 ├─ load_intel           读取威胁情报（与归属分析共享）
 ├─ analyze              统计聚合（等级/攻击类型/时段趋势）
 └─ render               生成 docx：
      一级标题（公文体）→ 态势概览（自动生成）→ 重点工作总结（用户输入）
      → 攻击统计表 + 图表（等级柱状/类型条形/趋势折线，openpyxl 渲染为图片）
      → 威胁源明细（威胁情报命中 IP）→ 待跟进事项
```

### 2.5 威胁情报匹配（`threat_check.py`，三层）

| 层 | 触发 | 口径 |
|---|---|---|
| 本地库 `threat_db.json` | 库存在 | `match_ip`：精确 IP + CIDR 恶意段（多源聚合，段数与 IP 数随每日重建变化） |
| Legacy 3 源缓存 | 无库且本地缓存有效 | `load_bad_ips`（6h TTL，精确匹配） |
| 联网兜底 | 无库无缓存 | 运行期下载 3 源（慢、慎用） |

统一入口 `match_ip(ip)` / `_IntelIndex.match`；`intel_status()` 供 GUI/CLI 展示（mode/detail/updated_at/库龄）。

---

## 三、目录结构与模块职责

| 文件 | 行数 | 职责 |
|---|---|---|
| `main.py` | 208 | 纯入口：参数分派 + 版本号 + DLL/依赖兜底；**顶部 re-export 为兼容层**（CLI 与 tests 以 `main.xxx` 访问，勿精简） |
| `gui.py` | 658 | Tkinter GUI：界面构建、文件探测、后台线程编排、威胁源更新/版本比对、exe 更新 |
| `ipdb.py` | 1080 | IP 归属域：排除表、告警提取、离线/在线归属、IP 归属 xlsx 生成 |
| `report.py` | 994 | 日报域：数据读取分类、统计、docx 公文体渲染、示例过滤 |
| `threat_check.py` | 552 | 威胁情报：索引/匹配/版本探测/多源择优下载 |
| `updater.py` | 801 | 自动更新：Release API、version.json、多 CDN 镜像、MD5、worker 覆盖 |
| `release.py` | 494 | 发布编排：升版本 → 构建 → MD5/version.json → git → Release + asset |
| `build_exe.py` | 351 | PyInstaller 打包配置（hiddenimports、runtime hook、图标） |
| `common.py` | 108 | 路径/日志/进度回调（GUI 与 CLI 双通道） |
| `demo_chart.py` | 163 | 图表 demo（独立脚本，不入正式链路） |
| `threat_demo.py` | 115 | 威胁分级 demo（独立脚本；**引用旧 API `check_ip` 与旧缓存名，已过时**） |
| `_runtime_hook.py` | 26 | PyInstaller 运行时 hook（numpy/pandas DLL 路径 + certifi CA） |
| `tools/threat-intel/threat_db.py` | 430 | 云端建库：7 源重建 db.json（`updated_at` 为首个键；多地址回退 + 重试 + bogon 过滤；ThreatFox 走免凭据 CSV 导出、API 仅作回退） |
| `tools/threat-intel/upload_intel.py` | 333 | 云端发布：上传固定 tag `threat-intel-latest` asset（三层降级护栏 + 临时名安全替换，不断供） |
| `tools/release_rest.py` | 400 | 受限环境发布：tag/Release/asset 全走 REST，full-sha 推送，幂等 + 重试 + 发布后验证 |
| `tests/` | 1294 | pytest：threat_check / business / report / updater / update_e2e / common |

---

## 四、配置与数据文件

| 文件 | 作用 |
|---|---|
| `config.ini` | 运行时配置（更新源、情报库 URL 等） |
| `业务ip.xlsx`（`业务ip段` sheet） | 单位公网/业务地址 → 告警过滤排除 |
| `业务ip.xlsx`（`探针ip段` sheet） | 业务/探针 IP 段 → 资产健康检查探针清单 |
| `业务ip.xlsx`（`转发地址` sheet） | **防火墙地址转发（NAT）地址** → 不计入外网攻击源（见下） |
| `终端ip地址表.xlsx` | 终端 IP 归属表（GUI 可手动导入） |
| `安全告警*.xlsx` | 输入告警数据（自动探测） |
| `data/db.json` 或 `threat_db.json` | 本地威胁情报库（运行时生成/下载，不入库） |
| `.env` | `GH_TOKEN`（发布用 GitHub token，不入库） |
| GitHub Actions Secret `THREATFOX_API_KEY` | abuse.ch 免费 Auth-Key（**可选**，非必需）；CSV 主通道免凭据，该 Key 仅在 CSV 不可达时供 API 回退，未配不影响建库 |
| `.github/workflows/threat-intel.yml` | 云端每日建库+发布（cron `30 0 * * *` = 北京 08:30） |

> 项目约定：业务配置走 Excel、规避 `config.ini`；单数据源生成脚本（改一处全篇生效）；生成物/中间产物不入 git；`tools/threat-intel/` 为源，本地 MCP 副本（`~/.workbuddy/mcp-servers/threat-intel-mcp/`）须同步改动，两份保持一致避免行为分叉。

### 转发地址（NAT）口径说明

防火墙上做地址转发（NAT）且链路未启用 `X-Forwarded-For` 时，安全设备日志里的"源 IP"记录的是 **NAT 转换后的转发地址**，真实攻击源被掩盖。这类地址若计入攻击源统计，会把"多源扫描"误判为"单源猛攻"，研判方向失真。

- **配置**：`业务ip.xlsx` → `转发地址` sheet（列：`IP` / `说明`），支持单 IP、CIDR（`11.11.11.0/24`）、范围（`11.11.11.2-9`）；`config.ini [network] forward_ips` 可作兜底。
- **效果**：命中清单的源 IP 判为"转发"，单列统计，**不计入外网攻击源、不参与封禁建议、不进入重点事件**；日报概览、第五节说明、研判结论、待跟进事项均给出"真实源被 NAT 掩盖、需从防火墙会话表回溯"的正确口径；IP 归属表新增 `转发地址(NAT)` sheet 单独列示。


---

## 五、发布与更新链路

```
发布（本机用 release.py；受限环境用 tools/release_rest.py，两者步骤一致）
  读版本 → 升版(main.py APP_VERSION + pyproject) → PyInstaller 构建 exe
  → calc_md5 → 更新 version.json → git commit/tag/push
  → GitHub REST API 建 Release + 上传 asset（EXE_NAME_GH 英文名）
情报库发布（云端，GitHub Actions 每日 08:30）
  threat_db.py（7 源）→ db.json → 三层护栏 → upload_intel.py → threat-intel-latest asset
消费端
  exe【威胁源更新】按钮 / --update-intel → 多源择优下载覆盖本地
  exe 自动更新 → GitHub Release latest + version.json（MD5 校验 → worker 覆盖重启）
```

**双链路解耦**（2026-09-02 起）：本地 8:30 自动化=纯本地建库+在线源健康检查（喂 MCP）；云端 Actions=建库+发布（喂 exe 下载端）。

**威胁库数据源（7 源，全部「可直接下载 Feed + 免费」）**：Spamhaus DROP、blocklist.de、CINSscore、Proofpoint ET Open、FireHOL Level1、IPsum Level3，另接入 abuse.ch **ThreatFox**（C2 IOC 质量最高）。选型依据《IP 威胁情报库分类指南》——**自动化封堵优先选可直接下载的 Feed**，纯 API 查询型（AbuseIPDB / VirusTotal / 微步在线等）用于告警富化与人工研判，不进入本链路。三个工程要点：① FireHOL / IPsum 走 jsDelivr 与 raw.githubusercontent **双地址回退**（两者可达性互补，实测本机 jsDelivr 超时而 raw 正常，单地址源一旦不可达即整源失效），Spamhaus 另有 FireHOL 镜像通道，且每地址重试 2 次（实测 Spamhaus 同一会话内先超时后成功）；② 解析时过滤私网/保留/回环/组播，避免聚合列表内置的 bogon 段把内网 IP 误判为威胁；③ 已停更的源不再收录——Spamhaus EDROP（并入 DROP）、Feodo Tracker（2026-03 起停更）、abuse.ch SSLBL（2025-01 起停更）。

**ThreatFox 取数通道（2026-09-17 定稿）**：**主通道 = 官方 CSV 导出**（`threatfox.abuse.ch/export/csv/recent/`，48h 窗口），**不需要任何凭据**；`THREATFOX_API_KEY`（免费 Auth-Key）降为 **CSV 不可达时的回退通道**。实测对比：CSV 2399 个去重 C2 IP（耗时 40s~640s，波动大）vs API 1 天窗口 124~183 个 IP（26s），覆盖差 13 倍以上，且 API 多日窗口会被服务端截断（days=2 约 200s 断连、days=3/7 直接超时），`date` 参数被服务端忽略。两个通道都失败才记 fail，**无 Secret 的环境该源照常可用**。另有一个隐蔽坑：API 取列表的操作名是 `get_iocs`（复数），写成 `get_ioc`（单 IOC 反查）会返回 `query_status=unknown_operation` 但 **HTTP 仍是 200**，极易被当成正常响应而让整源静默为空。

**威胁库发布护栏（三层，2026-09-17 起）**：`upload_intel.py` 在发布前逐层校验，任一不过即拒绝并保留线上旧库——① 库不完整（`total_ips` 或 `total_cidrs` 为 0）；② 成功源不足半数（`skip` 既不算成功也不算失败）；③ 与线上现有库比对，精确 IP 或恶意段跌幅超过 30%。紧急放行用 `INTEL_FORCE_PUBLISH=1`。覆盖 asset 采用**临时名先上传、成功后再删旧库并改名**的安全替换：直接「先删后传」一旦上传遇 502，线上库会在两个动作之间消失、exe 端全体断供（2026-09-16 在正式版 Release 上实际踩过一次）。

**两套发布入口的分工**：`release.py` 面向正常终端环境（可直接 `git tag -a` 与按分支推送）；`tools/release_rest.py` 面向受限环境（沙箱/写盘受限，本地 tag 与分支 ref 不落盘），把 tag → Release → asset 全部改走 GitHub REST，推送改用 `git push origin <full-sha>:refs/heads/<branch>`，并对 5xx/429 重试、对已存在的 tag ref / Release / asset 做幂等处理。版本读取、version.json 同步、token 加载复用 `release.py`，避免两份实现漂移。

```bash
python tools/release_rest.py --dry-run                # 预检 + 打印发布计划，不写任何东西
python tools/release_rest.py --build --commit-push    # 全流程：打包 → 同步 version.json → 提交推送 → 发布 → 验证
python tools/release_rest.py                          # 只重发现有 dist 产物（适合补传 asset）
```

asset 上传采用「**临时名先上传，成功后再删旧 asset 并改名**」的安全替换：直接「先删后传」一旦上传遇到 502，Release 会在两个动作之间失去 exe、下载链接直接断供（2026-09-16 实际踩过一次）。

---

## 六、质量与测试

```bash
./.venv/Scripts/python.exe -m ruff check .          # lint（0 问题）
./.venv/Scripts/python.exe -m pytest -q             # 全量测试（约 58% 覆盖）
```

约定：调试信息仅在真实失败时输出；面向用户的可视化修复优先；发布前必须 ruff + pytest 双绿。

---

## 七、代码审查发现（2026-09-02，冗余/遗留清单）

> **清理状态（2026-09-02）：第 1-6 项已按建议处理完毕**（1-2 删代码、3-5 删残留文件、6 归档至 `tools/legacy/`）；第 7 项 `check_ip` 保留（兼容既有测试）；第 8 项 re-export 兼容层保留勿精简。清理后 ruff 0 问题、全量测试绿（59% 覆盖）。

| # | 位置 | 问题 | 处理 |
|---|---|---|---|
| 1 | `common.py` `_log_warn` / `_log_err`（原 81,86 行） | 定义后全项目 **0 调用**（统一走 `_log(msg, WARN/ERROR)`） | ✅ 已删除（连带仅被其引用的 `WARN`/`ERROR` 常量） |
| 2 | `ipdb.py` `query_online_batch` + `BATCH_SIZE`/`BATCH_INTERVAL`（原 538,406-407 行） | 旧「ip-api.com/batch 在线批量查询」实现，已被 缓存→ip2region→pconline 单条补全 链路取代，**全项目无调用方** | ✅ 已删除（`safe_get`/`requests` 仍被在线链路使用，未动） |
| 3 | `_patch_ssl.py` | **0 字节空文件**，SSL 补丁方案早已废弃 | ✅ 已删除 |
| 4 | `_probe_root.txt` | 遗留 marker（内容 `probe2-1787228976`） | ✅ 已删除 |
| 5 | `q`（143 KB 二进制） | 2026-08-20 产生的来源不明二进制残留（非文本/压缩流） | ✅ 已删除（删除前备份至 `%TEMP%\dayupdate_q_backup_20260902\q`） |
| 6 | `threat_demo.py`（及同类 `demo_chart.py`） | 独立演示脚本，不入正式链路；`threat_demo.py` 引用旧 API `check_ip` 与旧缓存文件名 | ✅ 已归档至 `tools/legacy/`（不入库） |
| 7 | `threat_check.py:446` `check_ip` | 旧 API，正式链路（ipdb/report）已切 `match_ip`，仅 tests/demo 引用 | ⏸ 保留（兼容既有测试 `test_check_ip_legacy_grading`） |
| 8 | `main.py:18-47` re-export 兼容层 | 30 个符号中绝大多数被 ipdb/report/gui 内部或 tests 以 `main.xxx` 访问 | ⏸ **保留勿精简**（已逐一核实） |

**运行逻辑检查结论**：两条入口（GUI/CLI）链路自洽；`_runtime_hook.py`（PyInstaller runtime hook）、`updater.update_worker_main`（`--update-worker=`）、`release.py:main`（手工执行）入口均可达；威胁判定已全仓统一到 `match_ip` 单一口径（归属表与日报同索引），无第二套判定逻辑。

---

## 八、版本记录

> 版本号三处必须同步：`main.py` 的 `APP_VERSION`、`pyproject.toml`、`version.json`；发布产物为 GitHub Release 的 asset `daily-report.exe`。

| 版本 | 日期 | 提交 | 主要变更 | exe（大小 / MD5） |
|---|---|---|---|---|
| **v1.8.3** | 2026-09-16 | `1b6a616` | 修复日报「威胁等级分布」图表**数值标签被图例遮挡**（最高柱只显示前两位，695 显示成 69）：顶部留 12% 余量、图例移至右上角、标签 y 夹在绘图区内、新增 `MIN_BAR_H` 保证极矮柱可见 | 47,639,069 B / `2167C5AACC54B40044E88DE8C7200ED7` |
| v1.8.2 | 2026-09-14 | `efc94e5` | 修复**升级后 NAT 转发地址判定失效**：转发地址清单新增内置默认值 `ipdb.BUILTIN_FORWARD_NETWORKS`（`11.11.11.0/24`），不再依赖用户目录里会被旧配置覆盖的 `业务ip.xlsx` / `config.ini`；`config.ini` 增 `forward_ips`（追加）与 `ignore_builtin_forward`（禁用内置） | 47,637,878 B / `137624999A6AF3D1ADED654DAB498A85` |
| v1.8.1 | 2026-09-14 | `3d69c6b` | NAT 转发地址研判口径修正；修三处 exe 缺陷：PIL 被误列入 `excludes` 导致图表缺失、GBK 控制台日志字符中断流程、打包清理加固 | 47,635,962 B / `CE340CC7DFDFCDF0B00CFAB01CBF4FB7` |
| v1.8.0 | 2026-09-02 | `b6cc718` | v1.8 积压改动合集（明细见下）。⚠️ **已知缺陷：exe 版日报无图表**（PIL 打包问题，v1.8.1 才修复），该版 exe 不可再分发 | — |
| v1.7.3 | 2026-08-27 | `1d38d06` | 上一基线：情报 IOC 优化——威胁源分级列 ×2 表 + 已处置、内网外联威胁表（目的归属三级补全）、PIL 三图（等级分布/外网类型/内网类型）、攻击面聚焦板块（网段/目标 Top/情报 IOC）、归属 failover（pconline/百度/ipwho.is）、出口分析 | — |

### v1.8.0 积压改动明细（`47286a0`，2026-09-02）

> 原 README「未发布改动（工作区，待提交 → v1.8）」一节——写于 v1.8.0 发布**之前**，该批改动已由 `47286a0` 落盘、随 v1.8.0 发布。此处保留明细供追溯。

1. GUI 按钮定名「威胁源更新」（统一用户可见文案；`gui.py`）
2. 威胁源下载多源加速择优（官方地址 + 6 个加速镜像，先测速用最快，失败自动轮换；`threat_check.py:INTEL_MIRRORS`）
3. 启动显示威胁源版本/日期 + 远端版本自动比对（远端更新才弹窗询问；`gui.py:_check_intel_startup`）
4. IP 归属表威胁分级与日报同口径（统一 `match_ip` 段命中，修复两处"对不上"）
5. 示例占位文本过滤（修复「1. 完成防火墙规则优化」等示例文案泄漏进日报；`report.py:_is_example_line`）
6. 死代码清理与运行逻辑检查（结论见第七节）

