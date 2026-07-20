# 元数据检索帮助

## 导航

- [基本语法与常用命令](#基本语法)
- [参数分组](#参数分组)
- [增量物化](#增量物化)
- [关键词与来源语义](#关键词与来源语义)
- [输出字段与身份](#输出字段与身份)
- [配置](#配置)

## 基本语法

```text
python scripts/literature_and_patents_search_scripts.py [keywords ...] [options]
```

先用 `tools/check_environment.py --check` 检查环境；必需组件缺失时显式运行 `--prepare`。`--help`、`--status`、`--channel-inventory`、`--materialize-checkpoint` 可直接只读执行。

## 常用命令

检索文献与专利：

```powershell
python scripts\literature_and_patents_search_scripts.py --keywords "Orbitrap, C-trap" --batch-name Orbitrap
```

只检索一种记录：

```powershell
python scripts\literature_and_patents_search_scripts.py --keywords "Orbitrap" --batch-name Orbitrap --literature-only
python scripts\literature_and_patents_search_scripts.py --keywords "Orbitrap" --batch-name Orbitrap --patents-only
```

查看状态、渠道与本地物化：

```powershell
python scripts\literature_and_patents_search_scripts.py --batch-name Orbitrap --status
python scripts\literature_and_patents_search_scripts.py --channel-inventory
python scripts\literature_and_patents_search_scripts.py --batch-name Orbitrap --materialize-checkpoint
```

检索完成后运行授权下载：

```powershell
python scripts\literature_and_patents_search_scripts.py --keywords "Orbitrap" --batch-name Orbitrap --download-after-search --download-extra-arg=--disable-channel --download-extra-arg=Sci-Hub
```

也可在检索后单独调用下载 CLI；这种方式更容易先核对 search status 和 download dry-run。

## 参数分组

| 参数 | 含义 |
|---|---|
| `--keywords TEXT` | 逗号分隔关键词列表 |
| `--keywords-file PATH` | UTF-8 关键词文件 |
| `--batch-name NAME` | 默认根目录下的批次名 |
| `--flat-output` | 兼容旧平铺 metadata 根目录 |
| `--metadata-root PATH` | 精确 metadata 批次根目录 |
| `--pdf-root PATH` | `--download-after-search` 使用的精确 PDF 根目录 |
| `--page-size N` | 单次来源请求/page 数量，不是总结果上限 |
| `--literature-only` | 只检索文献 |
| `--patents-only` | 只检索专利 |
| `--literature-source NAME` | 精确文献来源过滤，可重复 |
| `--patent-source NAME` | 精确专利来源过滤，可重复 |
| `--allow-cost-source NAME` | 明确允许一个计费来源，可重复 |
| `--refresh` | 重置所选来源 checkpoint，保留 metadata |
| `--force` | 忽略所选类型已有 metadata 并重新检索 |
| `--status` | 只读状态 |
| `--materialize-checkpoint` | 只从本地 checkpoint 重建输出 |
| `--channel-inventory` | 只读来源/adapter/path inventory |
| `--download-after-search` | search complete 后调用下载脚本 |
| `--download-on-partial` | 明确允许 search partial 时下载已有记录 |
| `--download-limit N` | 转发给下载脚本的记录上限 |
| `--download-dry-run` | 转发下载 dry-run |
| `--download-force` | 转发下载 force |
| `--download-headful` | 转发下载 headful |
| `--download-extra-arg VALUE` | 转发其它原始下载参数，可重复 |

`--literature-only` 与 `--patents-only` 互斥。精确 source 过滤用于诊断或明确的用户范围，默认运行共享 registry 的完整 map。

## 增量物化

正常检索以 SQLite 为真值，默认每 10 个已提交页面或有新页面后的 60 秒增量更新 CSV 与进度报告：

```text
--materialize-every-pages N
--materialize-every-seconds N
--no-incremental-materialize
```

关闭增量物化不会取消退出前的最终 flush。文件占用导致 CSV 物化失败只能形成 warning；不能据此否定已经提交到 SQLite 的 occurrence。

## 关键词与来源语义

- 对输入只做 Unicode NFKC 和来源语法转换，不自动生成同义词、词干或虚构扩展词。
- 每个来源声明自己的字段范围和 query variant；EPO、USPTO、BigQuery 等来源可在一次来源任务内覆盖多个字段。
- 页面或 API 的 page size 受各来源上限约束。
- Google BigQuery 等计费来源在明确批准前不运行。
- 当前来源名称与 adapter 标签用 `--channel-inventory` 读取，不依赖静态记忆。

## 输出字段与身份

文献 canonical 记录优先使用规范化 DOI 作为强身份，并保留 PMID、PMCID、arXiv ID、raw ID、landing/direct-PDF locator 和 provenance。专利 canonical 记录优先使用规范化公开号，并保留真实观察到的 URL 与来源证据。

不得从题名、DOI、公开号或 raw ID 推测不存在的 URL。缺 DOI/PDF 的 metadata-only 文献和仅有公开号的专利仍可留在 canonical；兼容 CSV 的投影范围可能更窄。

## 配置

- 登录配置：`LAPS_RUNTIME_CONFIG` 或 `LAPS_AUTH_CONFIG`。
- API 配置：`LAPS_API_CONFIG`。
- 配置必须在 Skill/项目外部；只能查看脱敏状态，不能读取或输出秘密值。
- 缺少某来源 key 或认证只影响相应来源，不能被概括成整个检索失败。

运行前可执行脚本自身 `--help` 获取当前完整参数说明。
