# Skill 接口契约

本文定义 `literature-and-patents-search` 的稳定控制面。脚本自己的 `--help` 和 `--channel-inventory` 是当前版本的命令与渠道真值。

## 导航

- [入口与环境](#入口)
- [稳定输入](#稳定输入)
- [批次输出](#批次输出)
- [状态与续跑](#状态与续跑)
- [完成证据](#完成证据)
- [配置与敏感数据](#配置与敏感数据)

## 入口

| 入口 | 用途 |
|---|---|
| `scripts/literature_and_patents_search_scripts.py` | 元数据检索、状态、checkpoint 物化、检索后下载 |
| `scripts/literature_and_patents_download_scripts.py` | 下载状态、dry-run、渠道 probe、认证检查、PDF 下载 |
| `tools/check_environment.py` | 统一环境检查与准备 |

所有路径都从包含 `SKILL.md` 的目录解析，不依赖调用者工作目录。

## 环境接口

```text
python tools/check_environment.py --check [--json]
python tools/check_environment.py --prepare [--json]
```

- 报告 schema：`laps_environment_report_v1`。
- 状态：`ready`、`degraded`、`blocked`。
- `ready` / `degraded` 返回 0，缺少必需环境返回 2，检查或安装异常返回 1。
- `--check` 只读；`--prepare` 才允许在 `tools/.venv` 与 `tools/ms-playwright` 中补齐环境。
- Chrome、Node.js、Codex Chrome 插件、current-task connection 和 full CDP 属于可选的完整能力。缺失时是 `degraded`，不阻断公开/API 路径。

`--help`、`--status`、`--channel-inventory` 和 `--materialize-checkpoint` 不强制准备环境。搜索、下载、下载 dry-run、认证检查和渠道 probe 在业务 I/O 前通过统一门禁。

## 稳定输入

```text
keywords: list[str]
batch_name: str | optional
mode: all | literature | patents
operation: search | materialize_checkpoint | download | search_download | status
request_batching: page_size
limits: download_limit
input_contract: auto | v2 | legacy
disabled_channels: list[exact_channel_name]
download_on_partial: bool
external_hooks: challenge_hook, auth_hook, timeouts
```

- 关键词可通过 `--keywords`、`--keywords-file` 或位置参数传入；逗号分隔后的每项作为独立短语。
- `--page-size` 是单次 API/页面请求数量，不是总结果上限。
- `--batch-name` 使用默认 metadata/PDF 根目录；高级编排可传精确 `--metadata-root` 和 `--pdf-root`。
- 下载精确根目录必须成对出现，且不能与 `--batch-name` 混用。
- 正常下载保持完整渠道顺序；`--exact-channel` 仅用于有意的单渠道诊断。

## 批次输出

```text
literature_and_patents_metadata_list/<batch>/
  search_state.sqlite3
  canonical_records.v2.sqlite3
  literature_records.v2.jsonl
  patent_records.v2.jsonl
  handoff_manifest.v2.json
  search_run_report.json
  literature_metadata_list/literature_metadata_list.csv
  patents_metadata_list/patents_metadata_list.csv

literature_and_patents_pdf/<batch>/
  literature_pdf/
  patents_pdf/
  outputs/
    download_run_report.json
    download_state.sqlite3
    input_migration_report.v2.json
    download_attempts.csv
    literature_download_success_list.csv
    literature_download_failure_list.csv
    patents_download_success_list.csv
    patents_download_failure_list.csv
```

`search_state.sqlite3` 是检索 checkpoint 与请求范围的事务真值。`canonical_records.v2.sqlite3`、两份 v2 JSONL 和最后替换的 handoff manifest 共同构成发布 handoff。兼容 CSV 不是完整 canonical 数据源。

`download_state.sqlite3` 是下载 logical run、plan、candidate、attempt、artifact 和 cooldown 的事务真值。CSV 是可读兼容视图。

## 状态与续跑

- 先运行两个 CLI 各自的 `--status`；该入口只读，不初始化 Git、不访问网络。
- 检索默认复用兼容 checkpoint。`--refresh` 重置所选来源完成状态但保留 metadata；`--force` 忽略所选记录类型已有 metadata 并重新检索。
- `--materialize-checkpoint` 只从本地 SQLite 重建输出，不加载凭证、不启动浏览器、不访问网络，也不改变已存来源状态。
- 下载默认只恢复相同 fingerprint 的未 finalized logical run。`--no-resume` 新建 run 但可复用通过校验的 artifact；`--force` 隐含 no-resume 并重新获取，但不绕过 cooldown、安全或认证边界。
- 检索 partial 默认不启动下载。显式 `--download-on-partial` 可处理已有记录，但组合操作仍为 partial。

## 状态与退出码

工作流状态只能是：

- `complete`：请求范围全部满足契约，且 `ok=true`。
- `partial`：部分来源、路径或记录未完成，`ok=false`。
- `failed`：程序、状态、I/O 或契约发生致命失败，`ok=false`。

CLI 退出码：0=complete/成功只读命令，3=partial，1=致命失败，2=参数或配置错误。环境检查器另用 2 表示缺少必需环境。

## 完成证据

- **Search**：每个请求来源/路径均到达 complete，canonical SQLite、JSONL、manifest 一致，所需兼容投影存在。
- **Materialize**：输出由本地 checkpoint 重建，报告模式为 checkpoint materialize，已存 source-run 状态不变。
- **Download**：ledger 的 run/record/attempt/artifact 终态一致；每个提交下载的记录成功，或复用当前仍有效且可审计的 artifact。明确排除的 metadata-only 记录不计入下载分母。
- **Search-download**：search partial 即使获准下载已有记录，总结果仍为 partial。
- **Status**：打印当前本地计数、不修改文件并返回 0。

登录、候选 URL、HTTP 200 HTML、dry-run 或 probe 都不是 PDF 完成证据。PDF 成功要求精确 adapter/resolver 产生文件并通过 artifact 校验。

## 配置与敏感数据

登录配置优先级为 `LAPS_RUNTIME_CONFIG`、`LAPS_AUTH_CONFIG`、用户配置目录默认文件。API 配置由 `LAPS_API_CONFIG` 单独指定。两类配置都必须位于 Skill/项目目录之外。

允许读取脱敏的配置状态；禁止读取、打印、总结、复制或打包账号、密码、API key、cookie、token 和 storage state 内容。
