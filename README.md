# Literature and Patents Search Skills

`literature_and_patents_search_skills` 是面向 Codex、终端用户与自动化脚本的综合 Skill 发布包。它通过两个可复现的 Python CLI 检索科学文献与专利元数据，维护可续跑 checkpoint，物化规范化 handoff，并下载用户有权访问且通过文件校验的 PDF。

本项目坚持证据边界：元数据命中不等于全文可用，登录成功不等于订阅覆盖，候选 URL、HTTP 200 HTML、dry-run 或渠道 probe 都不等于 PDF 下载成功。缺少凭证、费用授权、订阅、限流或验证时，程序保留结构化边界，不将其包装成成功。

**运行时：** Python 3.10+ · Windows 与 POSIX 路径（Linux / macOS）  
**发布形式：** Codex Skill + Python CLI  
**开源协议：** [BSD-3-Clause](LICENSE)

## 目录

- [核心功能](#核心功能)
- [架构说明](#架构说明)
- [快速开始](#快速开始)
  - [Agent 自然语言安装](#agent-自然语言安装)
- [支持平台](#支持平台)
- [能力矩阵](#能力矩阵)
- [配置和环境要求](#配置和环境要求)
- [API Key 分级](#api-key-分级)
- [Agent Skill](#agent-skill)
- [命令](#命令)
- [使用范例](#使用范例)
- [输出](#输出)
- [排障](#排障)
- [使用边界](#使用边界)
- [开源协议](#开源协议)

## 核心功能

| 功能 | 入口 | 返回或完成证据 |
|---|---|---|
| 文献元数据检索 | 搜索 CLI | 文献 canonical SQLite、v2 JSONL、handoff manifest、兼容 CSV 与逐来源状态 |
| 专利元数据检索 | 搜索 CLI | 规范化公开号、真实 locator、provenance、canonical handoff 与逐来源状态 |
| 状态与断点续跑 | 两个 CLI 的 `--status` 及默认 resume | SQLite 事务状态、请求范围、未完成来源、logical run 与 ledger |
| Checkpoint 物化 | 搜索 CLI 的 `--materialize-checkpoint` | 从本地 SQLite 重建 canonical/兼容输出，不访问网络 |
| 授权 PDF 下载 | 下载 CLI | 已校验 PDF、attempt/ledger、success/failure CSV 与 run report |
| 认证与验证 | 下载 CLI + bundled hook | event-bound 响应、受控 auth state、脱敏 attestation 与结构化边界 |
| 渠道诊断 | 两个 CLI 的 `--channel-inventory`、下载 CLI 的 `--probe-channel-plan` | 当前 registry 顺序、adapter/parser、locator 前提与本地计划 |

本项目不提供引文扩展、期刊指标或正文片段检索，也不是 MCP Server。

## 架构说明

| 层 | 作用 |
|---|---|
| Codex Skill | 识别文献/专利任务，选择安全工作流，解释完成证据与失败边界 |
| 搜索 CLI | 检索元数据，维护 SQLite checkpoint，发布 canonical v2 与兼容 CSV |
| 下载 CLI | 消费 metadata handoff；全部渠道默认启用并严格按 registry 优先级尝试授权 PDF，维护 ledger 与报告 |
| 环境门禁 | 检查或准备 Skill 自有 Python/Playwright 环境；可选 Chrome/CDP 缺失只降级 |
| 浏览器交接 | 按 bundled Chromium、Playwright Chrome、普通 Chrome/CDP、Windows 可见控制逐层升级 |

数据流固定为：

```text
用户请求
  → Codex Skill
  → 环境门禁
  → 搜索 CLI / search_state.sqlite3
  → canonical handoff
  → 下载 CLI / download_state.sqlite3
  → 已校验 PDF + attempts + run report
```

安装器只把 `literature-and-patents-search` 目录复制到 Codex skills 目录。发布包不保存 API key、账号、cookie、浏览器 profile、认证状态或运行结果。

## 快速开始

要求系统已安装 Python 3.10 或更高版本，并能创建 venv、运行 pip。

先在发布包根目录预览安装，不写文件：

```powershell
python install.py --dry-run
```

安装到默认 Codex skills 目录：

```powershell
python install.py
```

默认目标为 `%CODEX_HOME%\skills`；未设置 `CODEX_HOME` 时为用户目录下的 `.codex\skills`。也可指定 skills 根目录：

```powershell
python install.py --target D:\path\to\skills
```

`--target` 指向 skills 根目录，安装器会在其下追加 `literature-and-patents-search`。若目标已存在，安装器以退出码 2 安全退出，不覆盖任何文件。安装成功后只运行一次只读环境检测，不自动下载依赖或修改 Chrome；即使检测显示运行时尚未就绪，复制成功的安装过程仍返回 0，并提示后续准备环境。

解析 Skill 路径并先检查环境。只有 `--check` 返回 2 时才运行 `--prepare`；返回 1 时应停止并报告环境异常：

```powershell
$skillsRoot = if ($env:CODEX_HOME) { Join-Path $env:CODEX_HOME "skills" } else { Join-Path $HOME ".codex\skills" }
$skillRoot = Join-Path $skillsRoot "literature-and-patents-search"
python "$skillRoot\tools\check_environment.py" --check --json
$gateExit = $LASTEXITCODE
if ($gateExit -eq 2) {
    python "$skillRoot\tools\check_environment.py" --prepare --json
    if ($LASTEXITCODE -eq 0) {
        python "$skillRoot\tools\check_environment.py" --check --json
    }
} elseif ($gateExit -eq 1) {
    throw "环境检查异常，停止运行。"
}
```

POSIX shell：

```bash
skills_root="${CODEX_HOME:-$HOME/.codex}/skills"
skill_root="$skills_root/literature-and-patents-search"
python3 "$skill_root/tools/check_environment.py" --check --json
gate_exit=$?
if [ "$gate_exit" -eq 2 ]; then
  python3 "$skill_root/tools/check_environment.py" --prepare --json &&
    python3 "$skill_root/tools/check_environment.py" --check --json
elif [ "$gate_exit" -eq 1 ]; then
  exit 1
fi
```

### Agent 自然语言安装

在 Codex 或其它具备终端能力的 Agent 中，可以直接发送以下提示词。Agent 应把 GitHub 仓库下载到临时目录，完成校验和安装后再删除临时副本；不得覆盖现有 Skill：

```text
请从 https://github.com/ZhongGuanbin/literature_and_patents_search_skills
安装 literature-and-patents-search Skill。

1. 只使用该 GitHub 仓库作为安装源，并先核对 MANIFEST.json 中的路径、大小和 SHA-256。
2. 在发布包根目录先运行 `python install.py --dry-run`。
3. 只有 dry-run 成功且目标 Skill 不存在时才运行 `python install.py`；若我指定了
   Codex skills 根目录，则使用 `python install.py --target "<skills-root>"`。
4. 不得覆盖、删除、合并或迁移已有 Skill、用户状态或配置。
5. 安装后定位包含 SKILL.md 的目录，运行
   `python tools/check_environment.py --check --json`。
6. 只有环境检查退出码为 2 时，才运行
   `python tools/check_environment.py --prepare --json` 并再次检查；退出码为 1 时停止并报告异常。
7. 向我报告安装路径、退出码及 ready/degraded/blocked 状态，但不要读取或显示
   API key、账号、密码、cookie、token、storage state 或浏览器 profile。
8. 不要自动安装 Chrome 插件、开启 CDP 或修改 Chrome/profile。
```

只希望预览自定义目标时，可补充一句：“仅运行 `python install.py --target "<skills-root>" --dry-run`，不要执行正式安装。”目标已存在时，正确结果是安全退出并请求用户决定，不是覆盖。

准备完成后，在 Codex 中调用：

```text
Use $literature-and-patents-search to search literature and patents about Orbitrap ion optics.
```

## 支持平台

| 平台 | CLI / API | Playwright | 普通 Chrome/CDP | 可见控制边界 |
|---|---|---|---|---|
| Windows | 支持；托管 Python 位于 `tools\.venv\Scripts\python.exe` | 支持 bundled Chromium 与 Playwright Chrome | 取决于 Chrome、插件、当前任务连接和 full CDP | 仅 Windows 层可用；每个已绑定验证节点最多一个动作 |
| Linux | POSIX 路径兼容；托管 Python 位于 `tools/.venv/bin/python` | 支持当前 Playwright 安装布局 | 仅在宿主提供相应插件/CDP 能力时可用 | 不宣称支持 Windows 可见控制 |
| macOS | POSIX 路径兼容；托管 Python 位于 `tools/.venv/bin/python` | 支持当前 Playwright 安装布局 | 仅在宿主提供相应插件/CDP 能力时可用 | 不宣称支持 Windows 可见控制 |

Python CLI、公开 API 和前两层浏览器能力不要求普通 Chrome 插件或 full CDP。不同系统仍应以本机 `tools/check_environment.py --check --json` 报告为准；本表不是对每个操作系统版本、CPU 架构或第三方站点的实网认证。

## 能力矩阵

当前 registry 版本声明：文献检索 32 个来源、专利检索 10 个来源、文献 PDF 35 个渠道、专利 PDF 11 个渠道。下表按精确名称合并为 43 行；同名渠道只合并展示，不同名称或 alias/resolver 保持独立。

图例：✅ 直接支持；🟡 条件支持（依赖 Key、机构权限、真实 locator、alias/fallback 或显式策略）；❌ 没有该工作流路径。图标表示静态能力，不代表当前环境、凭证或真实网络结果已经就绪。

静态表是发布快照。每次运行前使用两个 CLI 的 `--channel-inventory` 读取当前顺序、adapter、parser 与能力标签。

| 渠道 | 文献检索 | 专利检索 | 文献 PDF | 专利 PDF | 配置/认证 | 限制与降级 |
|---|---|---|---|---|---|---|
| ACM metadata | ✅ 公共网页→受限网页 | ❌ | 🟡 受限网页/观察直链 | ❌ | 机构 scope `acm_metadata` | metadata 来源名不等于全文成功；PDF 必须实际校验 |
| ACS Publications | ✅ 公共网页→受限网页 | ❌ | 🟡 受限网页/观察直链 | ❌ | 机构 scope `acs_publications` | CAPTCHA、403 或认证通过都不证明结果完整或 PDF 成功 |
| Annual Reviews | ❌ | ❌ | 🟡 受限网页/直链模式 | ❌ | 机构 scope `annual_reviews` | `/doi/pdf/` 可能返回 HTML 订阅页 |
| arXiv API | ✅ 公共 API | ❌ | ✅ 公共 API/直接 PDF | ❌ | 无 Key | 仅覆盖真实 arXiv/DOI/landing locator 与预印本范围 |
| bioRxiv / medRxiv | 🟡 Europe PMC resolver | ❌ | 🟡 landing/API→Europe PMC | ❌ | 无 Key | resolver 成功不能记成 bioRxiv/medRxiv 原生 API 能力 |
| ChemRxiv | ✅ ChemRxiv API + enrichment | ❌ | 🟡 OpenAlex fallback→landing | ❌ | 可选 `OPENALEX_API_KEY`、`CONTACT_EMAIL` | OpenAlex enrichment/PDF 不归因于 ChemRxiv 原生能力 |
| CNKI (中国知网) | ✅ 公共/IP session→受限网页 | ✅ 公共/IP session→受限网页 | 🟡 观察型详情/PDF | 🟡 观察型详情/PDF | 机构 scope `cnki` | 仅处理 source 精确匹配和真实观察 locator；文献/专利状态隔离 |
| CORE | ✅ API | ❌ | ✅ API/download URL | ❌ | 可选 `CORE_API_KEY` | 无 Key 可匿名降级；额度与限流单独记录 |
| Crossref API | ✅ API | ❌ | ✅ API metadata PDF link | ❌ | 可选 `CONTACT_EMAIL`、`CROSSREF_MAILTO` | 只消费 API 明确链接；原始命中数不等于最终记录数 |
| Crossref Metadata Search (search.crossref.org) | ✅ 公共网页 | ❌ | 🟡 OpenAlex→Crossref API | ❌ | 可选 OpenAlex/Crossref 联系配置 | PDF 路径是 API alias，不归因于网页下载能力 |
| DataCite Search (search.datacite.org) | ✅ 公共 API | ❌ | 🟡 API→repository/landing | ❌ | 无 Key | 数据集记录可能只有 metadata；非 PDF 不能记为成功 |
| DBLP | ✅ API | ❌ | 🟡 metadata→arXiv/landing | ❌ | 无 Key | PDF 通常来自实际 resolver，不是 DBLP 原生全文 |
| DOAJ (Directory of Open Access Journals) | ✅ 公共 API | ❌ | 🟡 API→landing | ❌ | 无 Key | OA metadata 或 landing 不保证 PDF |
| doi_resolver | ❌ | ❌ | 🟡 DOI HTTP landing | ❌ | 无 Key | 无浏览器 fallback；paywall 或无候选形成边界 |
| Elsevier | 🟡 ScienceDirect API→受限网页 | ❌ | 🟡 publisher API→ScienceDirect/机构网页 | ❌ | 必需 `ELSEVIER_API_KEY`；可选 `ELSEVIER_INSTTOKEN`；机构 scope `elsevier` | API metadata、机构登录与订阅/PDF 是独立证据 |
| EPO Open Patent Services (OPS) API | ❌ | 🟡 API | ❌ | 🟡 metadata-origin locator | 检索必需 `EPO_OPS_KEY`、`EPO_OPS_SECRET`；下载阶段无 Key | PDF 阶段不调用 OPS API，只消费 EPO-owned locator |
| Europe PMC | ✅ 公共 REST API | ❌ | ✅ API/full-text URL | ❌ | 无 Key | full-text URL 仍需下载与 artifact 校验 |
| Google BigQuery | ❌ | 🟡 计费 API | ❌ | 🟡 metadata-origin locator | 检索必需 `GOOGLE_APPLICATION_CREDENTIALS` 和显式费用授权；下载阶段无 Key | PDF 阶段不查询 BigQuery、不产生费用，只消费已有 locator |
| Google Patents | ❌ | ✅ XHR→公共网页 | ❌ | 🟡 公共 landing/storage PDF | 无 Key | `?download=1` 可能返回 HTML；必须解析并校验真实 PDF |
| Google Scholar | ✅ 公共浏览器 + enrichment | ❌ | 🟡 公共浏览器 | ❌ | 无 Key | 高验证/限流风险；只证明可见范围，不代表穷尽 |
| IACR ePrint | ✅ RSS/API + 公共网页 | ❌ | ✅ 公开 direct-PDF 模式 | ❌ | 无 Key | 403、验证或 archive 结构变化需冷却，不能无限重试 |
| IEEE Xplore API | 🟡 API→受限网页 | ❌ | 🟡 metadata API→受限网页 | ❌ | 必需 `IEEE_API_KEY`；机构 scope `ieee_xplore` | API Key 与机构订阅是两层独立前提 |
| input_url | ❌ | ❌ | ❌ | 🟡 metadata 已有 locator | 取决于目标站点；scope `unknown` | landing URL 不自动等于 PDF；不得推测或合成 |
| Nature | ✅ 公共网页→受限网页 | ❌ | 🟡 受限网页/直链模式 | ❌ | 机构 scope `nature` | 单页 full-access 标记不能外推到其它文章 |
| OpenAIRE | ✅ Graph API | ❌ | 🟡 API/access URL | ❌ | 可选 `OPENAIRE_API_KEY` | 无 Key 可降级；access URL 仍需验证 |
| OpenAlex API | ✅ API | ❌ | ✅ OA API | ❌ | 可选 `OPENALEX_API_KEY`、`CONTACT_EMAIL` | 匿名可运行；只认明确 OA PDF |
| OpenReview | ✅ notes API + enrichment | ❌ | ✅ 公开平台/直接模式 | ❌ | 无 Key | 只接受真实 raw ID、landing 或高置信 DOI |
| PMC (PubMed Central) | ✅ NCBI API | ❌ | ✅ 公共 repository | ❌ | 可选 `NCBI_API_KEY`、`PUBMED_API_KEY`、`CONTACT_EMAIL`、`NCBI_EMAIL`、`NCBI_TOOL` | 无 Key 可降级；安全中转页不是 PDF |
| PQAI API (Patent Quality AI) | ❌ | 🟡 API | ❌ | 🟡 metadata-origin locator | 检索必需 `PQAI_API_KEY`；下载阶段无 Key | PDF 阶段不调用 PQAI API，也不由公开号合成 URL |
| PubMed | ✅ NCBI API | ❌ | 🟡 API→Europe PMC→PMC | ❌ | 同 NCBI 可选配置 | 下载成功归因于实际 resolver，不宣称 PubMed 原生 PDF |
| RSC Publishing | ✅ 公共网页→受限网页 | ❌ | 🟡 受限网页/landing discovery | ❌ | 机构 scope `rsc_publishing` | 登录或 landing 都不是 PDF 完成证据 |
| Sci-Hub | ❌ | ❌ | 🟡 DOI form/browser | ❌ | 无 Key | 已注册且默认启用；仅处理公开或用户有权访问的内容，不得绕过授权边界 |
| Semantic Scholar | ✅ 公共网页 | ❌ | 🟡 OpenAlex→Semantic Scholar API | ❌ | 可选 `SEMANTIC_SCHOLAR_API_KEY` | 与 API 来源键独立；报告实际 resolver |
| Semantic Scholar API | ✅ Graph API | ❌ | ✅ OA API | ❌ | 可选 `SEMANTIC_SCHOLAR_API_KEY` | 无 Key 可匿名降级；无明确 OA URL 即无候选 |
| Springer | 🟡 SpringerLink API→受限网页 | ❌ | 🟡 同 SpringerLink | ❌ | 必需 `SPRINGER_API_KEY`；机构 scope `springerlink` | legacy alias；不重复计算原生能力 |
| SpringerLink | 🟡 meta/v2 API→受限网页 | ❌ | 🟡 API/直链模式→受限网页 | ❌ | 必需 `SPRINGER_API_KEY`；机构 scope `springerlink` | 与 Springer 共享 scope；cookie、订阅或验证可能阻断 |
| The Lens (lens.org) | 🟡 Scholarly API | 🟡 Patent API | 🟡 metadata API→OA URL | 🟡 metadata API/native locator | 必需 `LENS_Scholarly_API_KEY` 和/或 `LENS_Patents_API_KEY` | 缺相应 Key 只阻塞对应路径；必须保留真实 identifier/locator |
| USENIX | ✅ 公共网页 | ❌ | ✅ landing/system-files PDF | ❌ | 无 Key | 仅接受真实 landing 或 system-files PDF |
| USPTO Open Data Portal | ❌ | 🟡 API | ❌ | 🟡 metadata-origin locator | 检索必需 `USPTO_ODP_API_KEY`；下载阶段无 Key | PDF 阶段不调用 ODP API，只消费 USPTO-owned locator |
| Web of Science Starter API (Clarivate) | 🟡 API→受限网页 | ❌ | 🟡 metadata API→受限网页 | ❌ | 必需 `CLARIVATE_API_KEY`；机构 scope `web_of_science` | Key、API metadata、订阅、额度和 PDF 是独立证据 |
| WIPO PATENTSCOPE API | ❌ | 🟡 公共网页；可选 SOAP probe | ❌ | 🟡 公共网页/landing | 可选 `PATENTSCOPE_WEBSERVICE_USERNAME`、`PATENTSCOPE_WEBSERVICE_PASSWORD`、`PATENTSCOPE_WSDL_URL` | 当前不是完整下载 API；SOAP 仅在 WSDL 暴露搜索操作时启用 |
| 度衍 | ❌ | 🟡 公共网页→站点登录 | ❌ | 🟡 观察型详情/PDF | 可选 `uyanip_account`、`uyanip_password`；隔离 scope `uyanip` | 仅登录 gate 出现时使用；不得提交学校、CARSI 或通用凭据 |
| 万方数据 | ✅ 公共/IP session→受限网页 | ✅ 公共/IP session→受限网页 | 🟡 观察型详情/PDF | 🟡 观察型详情/PDF | 机构 scope `wanfang_data` | 只接受 source 精确匹配与实际跳转 locator；不能泛化合成 URL |

统一解释：

- API、公开网页、受限浏览器、alias 与实际 PDF resolver 是不同证据路径。
- 缺 Key、订阅、费用批准或认证只阻塞对应路径；其它允许来源与后续渠道继续。
- planner 只能跳过结构上不适用或被精确禁用的渠道，不能重排剩余 map。
- DOI、公开号、landing/PDF URL 必须来自真实 API、页面或网络事件，不得按模式猜测。
- 零结果不能直接解释为“没有相关内容”或“已经穷尽”。
- PDF 成功只成立于精确 adapter/resolver 保存了文件，且 artifact、ledger、attempt 和 run report 一致。

## 配置和环境要求

### 必需环境

| 项目 | 要求 |
|---|---|
| Python | 3.10 或更高版本 |
| Python 标准组件 | venv、pip |
| Python 依赖 | `tools/requirements.txt` 中的全部发行包、最低版本与 import 均通过 |
| PDF 与浏览器 API | `pypdf`、Playwright sync/async API |
| 浏览器运行时 | `tools/ms-playwright` 中的 bundled Chromium 可执行文件 |
| 一致性检查 | `pip check`、Python hook/helper 语法与可加载性 |

新安装只使用：

```text
tools/.venv
tools/ms-playwright
```

`tools/python_packages` 和 `tools/playwright-browsers` 仅用于读取旧环境，不作为新安装目标。

### 环境门禁

```text
python tools/check_environment.py --check [--json]
python tools/check_environment.py --prepare [--json]
```

报告 schema 为 `laps_environment_report_v1`：

| 状态 | 含义 | 退出码 |
|---|---|---:|
| `ready` | 必需环境完整，可选完整能力也已证明 | 0 |
| `degraded` | 必需环境完整，但普通 Chrome/Node/插件/CDP 等可选能力未证明 | 0 |
| `blocked` | 缺少必需环境 | 2 |
| 检查/安装异常 | 环境检测、安装、锁或命令发生异常 | 1 |

`--check` 只读；`--prepare` 才在 Skill 自有目录补齐环境。`--help`、`--status`、`--channel-inventory`、`--materialize-checkpoint` 不强制准备环境；搜索、下载、dry-run、认证检查和渠道 probe 在业务 I/O 前通过统一门禁。

### 完整浏览器能力

> 若想开启 Skill 的全部能力，需要完成这两件事情：  
> 1. 在普通 Chrome 中安装、启用并连接 Codex Chrome 插件；  
> 2. 为当前任务开启 full CDP 访问权限。

浏览器固定升级顺序：

1. Bundled Chromium。
2. Playwright Chrome。
3. 普通 Chrome + Codex Chrome 插件 + current-task full CDP。
4. Windows 可见控制。

只有前两层无法收敛且当前页仍是可操作验证节点，才进入普通 Chrome 层。依次确认 Chrome、插件安装/启用、当前任务连接和 full CDP；只有当前任务的只读 `Page.getFrameTree` 成功才标记 ready。每个确认阶段最多 5 分钟、每 5 分钟扫描一次、总流程最多 30 分钟。拒绝、策略阻止或超时只跳过该层。

不得自动安装插件、开启 CDP、修改 Chrome 设置/profile 或伪造 attestation。Windows 可见控制必须先证明目标 URL、当前事件绑定和单动作预算，执行一次后立即重新观察。

### 配置文件

登录配置按以下优先级读取：

1. `LAPS_RUNTIME_CONFIG`
2. `LAPS_AUTH_CONFIG`
3. 用户配置目录中的 `literature-and-patents-search-skills/literature_and_patents_search_scripts.json`

API 配置由 `LAPS_API_CONFIG` 指向，建议放在同一用户配置目录的独立 `config.json`。登录配置与 API 配置必须位于 Skill 和项目目录之外，不得合并或复制进发布包。

Codex 只能查看脱敏配置状态，不得读取、打印、总结或复制密码、API key、cookie、token、storage state、浏览器 profile 或 hook event 明文。运行时程序仅可在当前来源和认证 scope 内按最小权限读取完成请求所需的凭证，并且不得打印、复制、写入报告、打包或持久化这些明文。认证型低负载运行使用 `thread_num=1`。

## API Key 分级

| 等级 | 配置 | 适用渠道 | 缺失时行为 |
|---|---|---|---|
| 无 Key | 无 | arXiv、Europe PMC、DOAJ、DataCite、DBLP、OpenReview、Google Scholar/Patents 等公共路径 | 仍可能受限流、验证、服务或页面结构影响 |
| 可选增强 | `OPENALEX_API_KEY`、`SEMANTIC_SCHOLAR_API_KEY`、`CONTACT_EMAIL`、`CROSSREF_MAILTO`、`NCBI_API_KEY`、`PUBMED_API_KEY`、`NCBI_EMAIL`、`NCBI_TOOL`、`CORE_API_KEY`、`OPENAIRE_API_KEY` | OpenAlex、Semantic Scholar、Crossref、PMC/PubMed、CORE、OpenAIRE | 允许匿名/公共额度降级；记录缺失项与限流边界 |
| API 必需、可退合法网页 | `CLARIVATE_API_KEY`、`IEEE_API_KEY`、`ELSEVIER_API_KEY`、`SPRINGER_API_KEY` | Web of Science、IEEE、Elsevier、SpringerLink/Springer | API 路径受阻；只有渠道声明且用户有权访问时才尝试受限网页 |
| 渠道必需 | `LENS_Scholarly_API_KEY`、`LENS_Patents_API_KEY`、`EPO_OPS_KEY`、`EPO_OPS_SECRET`、`USPTO_ODP_API_KEY`、`PQAI_API_KEY` | Lens、EPO OPS、USPTO ODP、PQAI 检索 | 只阻塞相应来源，继续其它允许来源 |
| 可选专项 | `ELSEVIER_INSTTOKEN`、`PATENTSCOPE_WEBSERVICE_USERNAME`、`PATENTSCOPE_WEBSERVICE_PASSWORD`、`PATENTSCOPE_WSDL_URL` | Elsevier 机构 token、WIPO SOAP probe | 不配置时保留其它已声明路径；不宣称专项能力已就绪 |
| 计费级 | `GOOGLE_APPLICATION_CREDENTIALS` + `--allow-cost-source "Google BigQuery"` | Google BigQuery 专利检索 | 缺凭证或缺显式费用批准都不运行；普通检索授权不能代替费用授权 |

机构登录和站点个人登录不是 API Key：

- CNKI 与万方使用各自机构 scope，并只提交到经过验证的对应认证节点。
- SpringerLink/Springer 可共享已验证 publisher scope。
- 度衍只使用隔离的 `uyanip_account` / `uyanip_password`，不得接收学校、CARSI、通用账号或 IdP 凭据。

兼容配置名可由运行时解析，但新配置应优先使用矩阵和当前 `--channel-inventory` 显示的规范名称。

## Agent Skill

Skill 位于 `literature-and-patents-search/SKILL.md`。安装后可以显式使用 `$literature-and-patents-search`，也允许 Codex 在文献检索、专利检索、状态/续跑、物化和授权 PDF 任务中隐式触发。

一层参考文档：

- `references/interface.md`：稳定输入、输出、状态、退出码与完成契约。
- `references/channels.md`：当前渠道快照、顺序、认证 scope 与证据标签。
- `references/search-help.md` / `search-limitations.md`：检索命令、语义与边界。
- `references/download-help.md` / `download-usage.md` / `download-limitations.md`：下载接口、流程、成功标准与限制。
- `references/authentication.md`：机构登录、验证与 Chrome/CDP 分层边界。

## 命令

以下命令在 Skill 根目录执行；环境准备后优先使用托管 Python。

```powershell
$py = if (Test-Path "tools\.venv\Scripts\python.exe") { "tools\.venv\Scripts\python.exe" } else { "python" }
```

| 操作 | 命令 |
|---|---|
| 环境只读检查 | `python tools\check_environment.py --check --json` |
| 环境准备 | `python tools\check_environment.py --prepare --json` |
| 查看完整参数 | `& $py scripts\literature_and_patents_search_scripts.py --help` / `& $py scripts\literature_and_patents_download_scripts.py --help` |
| 检索状态 | `& $py scripts\literature_and_patents_search_scripts.py --batch-name Orbitrap --status` |
| 下载状态 | `& $py scripts\literature_and_patents_download_scripts.py --batch-name Orbitrap --status` |
| 渠道 inventory | `& $py scripts\literature_and_patents_search_scripts.py --channel-inventory` / `& $py scripts\literature_and_patents_download_scripts.py --channel-inventory` |
| 文献与专利检索 | `& $py scripts\literature_and_patents_search_scripts.py --keywords "Orbitrap, C-trap" --batch-name Orbitrap` |
| 仅文献 / 仅专利 | 追加 `--literature-only` 或 `--patents-only` |
| Checkpoint 物化 | `& $py scripts\literature_and_patents_search_scripts.py --batch-name Orbitrap --materialize-checkpoint` |
| 下载 dry-run | `& $py scripts\literature_and_patents_download_scripts.py --batch-name Orbitrap --dry-run` |
| 无网络渠道计划 | `& $py scripts\literature_and_patents_download_scripts.py --batch-name Orbitrap --probe-channel-plan --literature-only --exact-channel "PubMed" --limit 1` |
| 精确认证检查 | `& $py scripts\literature_and_patents_download_scripts.py --auth-check --headful --auth-no-state-reuse --exact-auth-channel "<CHANNEL>"` |
| 小批量授权下载 | `& $py scripts\literature_and_patents_download_scripts.py --batch-name Orbitrap --limit 5` |

正常下载不要使用 `--channel` / `--exact-channel` 破坏完整 fallback traversal；这两个参数只用于有界诊断。`--dry-run` 与 `--probe-channel-plan` 不进入真实下载闭环，也不证明 parser、候选或 PDF 成功。

`--probe-channel-plan` 不是只读命令：它可能创建输出目录、ledger、attempt/report/log，并可能初始化批次 Git。`--auth-check` 也会写 `outputs/auth_check_report.csv`，并可能产生受控 auth state/hook 产物；`--auth-no-state-reuse` 只表示强制新登录检查，不表示清除全部状态。认证检查返回 0 也不能替代报告行、订阅和 PDF 证据。

工作流退出码：0=complete/成功只读命令，3=partial，1=致命失败，2=参数或配置错误。环境检查器单独使用 2 表示缺少必需环境。

## 使用范例

以下命令均在 Skill 根目录执行，并沿用“命令”章节定义的 `$py`。将 `<...>` 替换为本机值；API 与登录配置必须放在 Skill 和项目目录之外。Agent 可以确认某个字段是否已配置，但不得读取、回显或复制秘密值。

### 1. 无 API Key：公开文献与专利检索

适用于只允许公开 API、公开网页且不允许账号登录的环境。可以这样告诉 Agent：

```text
使用 $literature-and-patents-search 检索“Orbitrap ion optics”。
只使用无 Key 的公开来源，不登录机构账号，不运行计费渠道；分别建立 Public-Literature
和 Public-Patents 批次。保留每个来源的真实状态，零结果不能解释为已经穷尽。
```

对应 CLI：

```powershell
& $py scripts\literature_and_patents_search_scripts.py `
  --keywords "Orbitrap ion optics" `
  --batch-name Public-Literature `
  --literature-only `
  --literature-source "arXiv API" `
  --literature-source "Europe PMC" `
  --literature-source "DOAJ (Directory of Open Access Journals)" `
  --literature-source "DataCite Search (search.datacite.org)" `
  --literature-source "DBLP" `
  --literature-source "OpenReview"

& $py scripts\literature_and_patents_search_scripts.py `
  --keywords "Orbitrap ion optics" `
  --batch-name Public-Patents `
  --patents-only `
  --patent-source "Google Patents" `
  --patent-source "WIPO PATENTSCOPE API"
```

公开来源仍可能出现限流、验证、服务不可用或页面结构变化；这些结果应记录为边界，而不是伪装成完整覆盖。

### 2. 可选 API Key：提高额度并保留匿名降级

适用于已经在外部配置文件中准备 OpenAlex、Semantic Scholar、CORE、OpenAIRE 或联系邮箱，但允许缺失字段匿名降级的环境：

```text
使用外部 API 配置检索 Orbitrap 离子光学文献。只确认可选 Key 是否已配置，
不要显示 Key 值。优先运行 OpenAlex、Semantic Scholar、CORE 和 OpenAIRE；
缺少可选 Key 时继续匿名路径，并报告限流或降级状态。
```

```powershell
$env:LAPS_API_CONFIG = "C:\secure\laps-api.json"

& $py scripts\literature_and_patents_search_scripts.py `
  --keywords "Orbitrap ion optics" `
  --batch-name Optional-APIs `
  --literature-only `
  --literature-source "OpenAlex API" `
  --literature-source "Semantic Scholar API" `
  --literature-source "CORE" `
  --literature-source "OpenAIRE"
```

配置文件可包含“API Key 分级”列出的可选键，但不得提交到 Git、复制进 Skill 或写入运行报告。匿名路径成功也不代表检索已经穷尽。

### 3. 必需 API Key：运行单个受控渠道

适用于 Lens、EPO OPS、USPTO ODP 或 PQAI 等缺少 Key 就阻塞相应 API 渠道的场景。以下示例要求外部配置已经包含 `EPO_OPS_KEY` 与 `EPO_OPS_SECRET`：

```text
使用 $literature-and-patents-search 只运行 EPO OPS 专利检索。
先以脱敏方式确认两个必需字段均已配置；任一缺失就停止该渠道，不能猜测凭据，
但也不要把该渠道的配置失败扩展成其它来源失败。
```

```powershell
$env:LAPS_API_CONFIG = "C:\secure\laps-api.json"

& $py scripts\literature_and_patents_search_scripts.py `
  --keywords "Orbitrap ion optics" `
  --batch-name EPO-Orbitrap `
  --patents-only `
  --patent-source "EPO Open Patent Services (OPS) API"
```

Clarivate、IEEE、Elsevier、Springer 的 API 分支同样需要相应 Key，但只有 registry 声明了合法受限网页 fallback 且用户有访问权时，才可继续网页路径。

### 4. 机构订阅：按当前渠道进行认证与下载

适用于用户明确拥有机构订阅，且登录配置已由 `LAPS_RUNTIME_CONFIG` 或 `LAPS_AUTH_CONFIG` 指向 Skill 外部文件的场景：

```text
检查 Nature 渠道的机构认证。只在经过验证的 Nature/机构 IdP 节点使用当前 scope 的凭据，
不要预登录其它站点，不要显示账号、密码或 cookie。认证成功后继续 MS-Batch 的授权下载，
并以实际 PDF 校验、attempt、ledger 和 run report 共同判断结果。
```

```powershell
$env:LAPS_RUNTIME_CONFIG = "C:\secure\laps-runtime.json"

& $py scripts\literature_and_patents_download_scripts.py `
  --auth-check `
  --headful `
  --auth-no-state-reuse `
  --exact-auth-channel "Nature"

& $py scripts\literature_and_patents_download_scripts.py `
  --batch-name MS-Batch `
  --literature-only `
  --limit 5
```

`--auth-check` 会写认证报告和受控状态，不是只读操作。登录成功只证明当前认证步骤，不证明订阅覆盖，更不等于 PDF 下载成功。

### 5. Google BigQuery：显式费用授权

适用于已配置 Google 服务凭证，而且用户明确批准本次计费查询的专利检索：

```text
使用 Google BigQuery 检索 Orbitrap 相关专利。先确认外部配置中的
GOOGLE_APPLICATION_CREDENTIALS 已设置，并再次确认我明确批准本次计费来源。
只授权精确来源“Google BigQuery”；不要把这次批准复用于其它批次或费用操作。
```

```powershell
$env:LAPS_API_CONFIG = "C:\secure\laps-api.json"

& $py scripts\literature_and_patents_search_scripts.py `
  --keywords "Orbitrap ion optics" `
  --batch-name BigQuery-Orbitrap `
  --patents-only `
  --patent-source "Google BigQuery" `
  --allow-cost-source "Google BigQuery"
```

服务凭证与精确的 `--allow-cost-source` 缺一不可。普通检索授权、已有凭证或历史运行都不能代替本次费用批准。

### 6. 批量关键词、断点续跑与 checkpoint 物化

适用于长时间、多来源批次。关键词文件使用 UTF-8；每行可以包含一个或多个逗号分隔短语：

```powershell
$keywordsFile = "D:\work\keywords.txt"

& $py scripts\literature_and_patents_search_scripts.py `
  --keywords-file $keywordsFile `
  --batch-name MS-Batch `
  --page-size 50

& $py scripts\literature_and_patents_search_scripts.py `
  --batch-name MS-Batch `
  --status

& $py scripts\literature_and_patents_search_scripts.py `
  --keywords-file $keywordsFile `
  --batch-name MS-Batch `
  --page-size 50

& $py scripts\literature_and_patents_search_scripts.py `
  --batch-name MS-Batch `
  --materialize-checkpoint
```

同一批次和兼容请求范围再次运行就是正常续跑，不存在 `--resume` 参数。`--page-size` 是每个 API/page 的请求量，不是总结果上限；`--refresh` 会重置选定来源完成状态，`--force` 会重新检索，二者都不能代替普通续跑。

### 7. 授权 PDF：dry-run、小批量下载和完成证据

适用于 metadata handoff 已生成，准备按固定渠道优先级下载用户有权访问的 PDF：

```text
继续 MS-Batch 的文献 PDF 下载。先检查 search status，再运行 download dry-run；
dry-run 没有致命错误后按 registry 原始顺序处理最多 5 条记录。
不要用 exact-channel 改写正常 fallback 顺序。完成后重新查看状态，并核对实际 PDF、
attempt、ledger、success/failure 视图和 download_run_report.json。
```

```powershell
& $py scripts\literature_and_patents_search_scripts.py `
  --batch-name MS-Batch `
  --status

& $py scripts\literature_and_patents_download_scripts.py `
  --batch-name MS-Batch `
  --literature-only `
  --dry-run

& $py scripts\literature_and_patents_download_scripts.py `
  --batch-name MS-Batch `
  --literature-only `
  --limit 5

& $py scripts\literature_and_patents_download_scripts.py `
  --batch-name MS-Batch `
  --status
```

所有下载渠道初始化为默认启用，并严格以 registry 顺序定义优先级。`--dry-run` 只检查环境、输入、配置和 map，不证明 parser、候选或 PDF 成功。

### 8. 单条记录或单渠道诊断

适用于排查某个 DOI、公开号或 adapter，不用于替代正常完整 traversal：

```powershell
& $py scripts\literature_and_patents_download_scripts.py `
  --batch-name MS-Batch `
  --probe-channel-plan `
  --literature-only `
  --doi "10.xxxx/example" `
  --exact-channel "PubMed" `
  --limit 1

& $py scripts\literature_and_patents_download_scripts.py `
  --batch-name MS-Batch `
  --probe-channel-plan `
  --patents-only `
  --publication-number "US1234567A" `
  --exact-channel "Google Patents" `
  --limit 1
```

`--probe-channel-plan` 不调用 API、浏览器、网页或 PDF 下载，但可能写入 plan、ledger、attempt、report 和日志。它只证明本地选择与 prerequisite 分类。

### 9. 普通 Chrome 插件与 current-task full CDP

适用于前两层浏览器无法收敛、当前页面仍是可操作验证节点的情况。不存在自动安装插件或自动开启 CDP 的 CLI 参数：

```text
当前授权页面在 bundled Chromium 和 Playwright Chrome 中都未收敛。
请先告诉我需要人工完成的步骤，不要修改 Chrome/profile：确认普通 Chrome，确认 Codex Chrome
插件已安装并启用，确认插件连接当前任务，再由我为当前任务开启 full CDP。
只有当前任务的只读 Page.getFrameTree 成功后才标记该层 ready；拒绝、策略阻止或超时就跳过该层。
```

人工权限完成后，仍使用现有认证诊断入口：

```powershell
& $py scripts\literature_and_patents_download_scripts.py `
  --auth-check `
  --headful `
  --auth-no-state-reuse `
  --exact-auth-channel "Nature"
```

该命令不会强制进入普通 Chrome 层；只有前两层失败且当前节点仍可操作时才升级。Windows 可见控制仍要求已证明目标 URL、当前事件绑定和单动作预算。

## 输出

使用 `--batch-name <name>` 时，默认维护：

```text
literature_and_patents_metadata_list/<name>/
  search_state.sqlite3
  canonical_records.v2.sqlite3
  literature_records.v2.jsonl
  patent_records.v2.jsonl
  handoff_manifest.v2.json
  search_run_report.json
  literature_metadata_list/literature_metadata_list.csv
  patents_metadata_list/patents_metadata_list.csv

literature_and_patents_pdf/<name>/
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

`search_state.sqlite3` 是检索 checkpoint 与请求范围的事务真值；canonical SQLite、两份 v2 JSONL 和最后替换的 handoff manifest 构成发布 handoff。兼容 CSV 是有损的人类可读视图。

`download_state.sqlite3` 是 logical run、计划、候选、attempt、artifact 与 cooldown 的事务真值。下载完成必须由 ledger、attempt、run report、success view 和实际 PDF 校验共同证明。

发布根目录的 `MANIFEST.json` 记录正式文件的相对路径、字节大小和 SHA-256。其中 `git_head` 与 `git_dirty` 均表示生成该发布包时的**外层源码仓库**提交及工作树状态，不表示当前发布仓库自身的 HEAD 或工作树。发布仓库根目录的 `.git/**` 属于版本控制元数据，不进入 Manifest 或正式发布内容；Skill 目录内部出现任何 `.git` 均视为发布边界失败。

唯一工作流状态为：

- `complete`：请求范围全部满足契约。
- `partial`：部分来源、路径或记录未完成。
- `failed`：程序、状态、I/O 或契约出现致命失败。

## 排障

| 现象 | 首先检查 |
|---|---|
| 环境检查 `blocked` | 运行 `tools/check_environment.py --prepare`，然后重新 `--check --json` |
| 环境检查 `degraded` | 查看 optional/full-capability 项；公开/API 与前两层浏览器能力通常仍可运行 |
| `environment_bootstrap_*` | 这是本机环境准备问题，不得归因于某个文献/专利来源 |
| 批次没有继续 | 分别运行搜索和下载 `--status`，核对 batch、root、checkpoint 与 logical run |
| 零结果 | 查看逐来源 path/query variant 状态；不能仅凭 CSV 或零计数下结论 |
| 缺 API Key | 对照 API Key 分级和 `--channel-inventory`；只报告并跳过相应路径 |
| Google BigQuery 未运行 | 同时确认服务凭证与显式费用授权，不能从普通搜索授权推断 |
| dry-run/probe 通过但真实失败 | 查看 `download_run_report.json`、attempts、候选与 artifact 校验 |
| 401/403/429、验证或 cooldown | 保留结构化原因并切换/等待，不高频刷新 |
| 找不到普通 Chrome | 跳过后两层能力；不要自动安装 Chrome 或修改 profile |
| 插件/CDP 未就绪 | 按 5 分钟确认、5 分钟扫描、最多 30 分钟的流程处理；只读 CDP probe 成功才算 ready |
| 认证成功但无 PDF | 核对订阅、locator、实际 resolver 与文件校验；认证不等于全文授权 |
| 目标 Skill 已存在 | 安装器不会覆盖；人工确认后另行备份或移除旧目标 |

## 使用边界

- 仅访问公开内容或用户依法、依合同和机构订阅有权访问的资源。
- 遵守平台条款、robots、限流、费用审批、机构政策与适用法律。
- 不绕过 paywall、订阅、访问控制、CAPTCHA、MFA、验证或宿主安全提示。
- 不伪造题名、作者、年份、摘要、DOI、公开号、URL、来源、认证、下载成功或穷尽性结论。
- 不从 DOI、题名、公开号、raw ID 或 URL pattern 合成未观察到的详情/PDF URL。
- 不把登录、候选、HTTP 200 HTML、dry-run、probe 或未校验文件称为 PDF 成功。
- 不自动安装 Chrome 插件、开启 CDP、修改 Chrome 设置/profile，或扩大 Windows 单动作可见控制。
- 不读取、输出或打包账号、密码、API key、cookie、token、storage state、浏览器 profile 或 hook event。
- 不把缓存、测试、PDF、metadata、SQLite、日志、事件、截图、认证状态、运行时 JSON 或用户配置加入正式发布包。

## 开源协议

本项目采用 [BSD-3-Clause](LICENSE) 开源协议。
