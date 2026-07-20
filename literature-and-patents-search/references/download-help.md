# PDF 下载帮助

## 基本语法

```text
python scripts/literature_and_patents_download_scripts.py [options]
```

下载器消费已有 metadata handoff。Skill 正常工作流只下载公开或用户有权访问的 PDF，并显式传入 `--disable-channel "Sci-Hub"`。

## 核心参数

| 参数 | 含义 |
|---|---|
| `--dry-run` | 检查环境、配置、输入和 map，不保存 PDF |
| `--probe-channel-plan` | 无网络地输出所选渠道计划 |
| `--literature-only` / `--patents-only` | 限制记录类型，二者互斥 |
| `--batch-name NAME` | 默认 metadata/PDF 根目录下的批次 |
| `--metadata-root PATH` / `--pdf-root PATH` | 成对指定精确批次根目录 |
| `--status` | 只读下载状态 |
| `--channel-inventory` | 只读渠道顺序、parser、method tags |
| `--limit N` | 每种记录类型最多处理 N 条 |
| `--channel TEXT` | 子串渠道诊断，可重复 |
| `--exact-channel NAME` | 精确渠道诊断，可重复，优先使用 |
| `--disable-channel NAME` | 精确禁用渠道，可重复；不重排其它渠道 |
| `--input-contract auto|v2|legacy` | 选择 metadata 输入契约 |
| `--doi DOI` | 只处理匹配 DOI 的文献，可重复 |
| `--publication-number ID` | 只处理匹配公开号的专利，可重复 |
| `--patent-id ID` | `--publication-number` 的别名 |
| `--no-resume` | 新 logical run，可复用有效 artifact |
| `--force` | 新 logical run 且重新获取，不绕过安全边界 |
| `--headful` | 使用可见浏览器调试认证页 |
| `--auth-check` | 检查认证 flow 并写 auth check 报告 |
| `--exact-auth-channel NAME` | 精确认证渠道诊断，可重复 |
| `--auth-no-state-reuse` | 不复用已有 state，执行新认证检查 |

脚本还支持各 hook、手工窗口、Chromium、Chrome、Codex extension 以及环境命令/锁的显式 timeout。用脚本 `--help` 查看当前名称。

## 输入契约

`--input-contract auto` 默认优先使用 generation-bound v2 JSONL/handoff；缺失时只读尝试旧 SQLite occurrence，再回退 legacy CSV。`v2` 明确要求 v2 输入；`legacy` 仅使用兼容输入。

文献若有 DOI，按完整文献渠道 map 遍历，之后才处理 metadata 暴露的稳定 URL。URL-only 记录可直接验证 URL。专利可用公开号或真实观察到的 landing/native locator；不得从 DOI、公开号、题名或 raw ID 合成 PDF URL。

## 状态、恢复与筛选

- 默认只恢复同 fingerprint 的未 finalized logical run。
- `--no-resume` 建立新 run，但仍可复用当前有效且可审计的 artifact。
- `--force` 隐含 no-resume，不复用 target/alias/ledger artifact；重新获取失败时不应破坏旧有效 PDF。
- DOI/公开号过滤发生在 `--limit` 之前。
- 渠道过滤只用于诊断；正常下载不应破坏完整 fallback traversal。
- `--force`、no-resume、精确渠道都不能绕过 persistent cooldown、outbound safety 或认证边界。

## 输出与结果解释

以 `outputs/download_run_report.json` 为主要机器可读摘要，结合：

- `download_state.sqlite3`：logical run、计划、候选、attempt、artifact、cooldown 真值。
- `download_attempts.csv`：planned/discovery/resolver/delivery provenance 和结构化原因。
- success/failure CSV：兼容的人类可读记录级视图。
- `literature_pdf/` 与 `patents_pdf/`：实际保存并通过校验的文件。

`complete|partial|failed` 是唯一工作流状态。0=complete，3=partial，1=致命失败，2=参数/配置错误。

## 常见结构化边界

| 原因族 | 解释与处理 |
|---|---|
| `environment_bootstrap_*` | 本机运行环境失败，不归因于来源 |
| `missing_required_doi_and_pdf_url` | 文献输入缺少可执行 locator；回到 metadata 层修复 |
| `missing_publication_number_or_url` | 专利输入缺少可执行 locator；回到 metadata 层修复 |
| `missing_api_key_or_required_parameter` | 当前渠道 prerequisite 缺失；记录并继续 |
| `skipped_auth_required` / `auth_check_*` | 认证前提或认证诊断结果，不是 PDF 成功 |
| `rate_limited` / `service_unavailable` | 冷却或切换，不重复刷新 |
| `security_challenge_required` | 进入有界验证流程；未解决则冷却/切换 |
| `domain_cooldown:*` / `channel_cooldown:*` | 遵守持久化 cooldown |
| `no_candidate_url` | 当前 adapter 没有观察到合法候选；不得合成 URL |

## 成功标准

只有精确 executed adapter/resolver 返回 PDF，文件通过结构/内容校验，并在 ledger、attempt、run report 与 success view 中一致，才能报告下载成功。登录成功、候选发现、200 HTML、dry-run、probe 或已有未校验文件都不够。
