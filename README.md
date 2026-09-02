# 网络安全值守保障日报工具

面向轨道集团网络安全值守场景的日报生成工具：读取安全告警 Excel → 生成「外网攻击 IP 归属分析」xlsx + 「网络安全值守保障日报」docx（公文体排版，含统计图表与威胁情报分级），并提供 GUI、CLI、自动更新、威胁情报库一键更新等能力。

> 当前工作分支：`refactor/b-module-split`（含一批**未发布**改动，见文末「未发布改动」）；正式发布版本号以 `main.py` 的 `APP_VERSION` 为准（当前 `1.7.3`）。

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
| 威胁情报云端发布 | GitHub Actions 每日 08:30 重建 5 源情报库并发布到固定 tag 的 Release asset，供各端下载 |

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
| 本地库 `threat_db.json` | 库存在 | `match_ip`：精确 IP + CIDR 恶意段（1,709 段） |
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
| `tools/threat-intel/threat_db.py` | 237 | 云端建库：5 源下载重建 db.json（`updated_at` 为首个键） |
| `tools/threat-intel/upload_intel.py` | 197 | 云端发布：上传固定 tag `threat-intel-latest` asset（全源失败拒绝发布护栏） |
| `tests/` | 1294 | pytest：threat_check / business / report / updater / update_e2e / common |

---

## 四、配置与数据文件

| 文件 | 作用 |
|---|---|
| `config.ini` | 运行时配置（更新源、情报库 URL 等） |
| `业务ip.xlsx`（`探针ip段` sheet） | 业务/探针 IP 段 → 告警过滤排除 |
| `终端ip地址表.xlsx` | 终端 IP 归属表（GUI 可手动导入） |
| `安全告警*.xlsx` | 输入告警数据（自动探测） |
| `data/db.json` 或 `threat_db.json` | 本地威胁情报库（运行时生成/下载，不入库） |
| `.env` | `GH_TOKEN`（发布用 GitHub token，不入库） |
| `.github/workflows/threat-intel.yml` | 云端每日建库+发布（cron `30 0 * * *` = 北京 08:30） |

> 项目约定：业务配置走 Excel、规避 `config.ini`；单数据源生成脚本（改一处全篇生效）；生成物/中间产物不入 git。

---

## 五、发布与更新链路

```
发布（本机，release.py main）
  读版本 → 升版(main.py APP_VERSION + pyproject) → PyInstaller 构建 exe
  → calc_md5 → 更新 version.json → git commit/tag/push
  → GitHub REST API 建 Release + 上传 asset（EXE_NAME_GH 英文名）
情报库发布（云端，GitHub Actions 每日 08:30）
  threat_db.py（5 源）→ db.json → upload_intel.py → threat-intel-latest asset
消费端
  exe【威胁源更新】按钮 / --update-intel → 多源择优下载覆盖本地
  exe 自动更新 → GitHub Release latest + version.json（MD5 校验 → worker 覆盖重启）
```

**双链路解耦**（2026-09-02 起）：本地 8:30 自动化=纯本地建库+在线源健康检查（喂 MCP）；云端 Actions=建库+发布（喂 exe 下载端）。

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

## 八、未发布改动（工作区，待提交 → v1.8）

1. GUI 按钮定名「威胁源更新」（统一用户可见文案）
2. 威胁源下载多源加速择优（官方 + 6 加速镜像，先测速用最快，失败自动轮换）
3. 启动显示威胁源版本/日期 + 远端版本自动比对（新则弹窗询问）
4. IP 归属表威胁分级与日报同口径（`match_ip` 段命中，修复"对不上"问题）
5. 示例占位文本过滤（修复"1. 完成防火墙规则优化"等示例泄漏进日报）
6. `tools/threat-intel/` 与本地 MCP 副本需保持同步（改动双份）
