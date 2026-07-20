---
name: literature-and-patents-search
description: Search and resume scientific literature or patent metadata, materialize checkpoints, inspect status and channel inventories, and download authorized PDFs with truthful boundary reporting. Use when users ask for literature search, patent search, 文献检索, 专利检索, batch status or resume, checkpoint materialization, authorized full-text/PDF acquisition, publisher or institution authentication, or bounded browser/Chrome handoff.
---

# Literature and Patents Search

Use the bundled command-line programs for reproducible literature and patent work. Preserve source evidence, checkpoints, and structured failure reasons; never turn an unavailable path into a claimed result.

## Resolve the skill root

Resolve the directory containing this `SKILL.md` as `SKILL_ROOT`. Build every script, tool, and reference path from `SKILL_ROOT`; do not depend on the caller's working directory.

Use these entry points:

- `scripts/literature_and_patents_search_scripts.py` for metadata search, search status, checkpoint materialization, and optional search-then-download.
- `scripts/literature_and_patents_download_scripts.py` for download status, dry-run, channel probes, authentication checks, and authorized PDF download.
- `tools/check_environment.py` for the shared runtime gate.

## Apply the first-run gate

Display this reminder on first use:

> 若想开启 Skill 的全部能力，需要完成这两件事情：  
> 1. 在普通 Chrome 中安装、启用并连接 Codex Chrome 插件；  
> 2. 为当前任务开启 full CDP 访问权限。

Treat Chrome, Node.js, the plugin, the current-task connection, and full CDP as optional full-capability checks. Their absence is `degraded`, not a blocker for public/API or earlier browser paths.

Before search, download, download dry-run, authentication check, or channel probe:

1. Run `python <SKILL_ROOT>/tools/check_environment.py --check --json`.
2. If it exits 2, run `python <SKILL_ROOT>/tools/check_environment.py --prepare --json`, then check again.
3. If checking or preparation exits 1, stop and report a local environment failure without attributing it to a literature or patent source.
4. Use `<SKILL_ROOT>/tools/.venv/Scripts/python.exe` on Windows or `<SKILL_ROOT>/tools/.venv/bin/python` on POSIX after preparation.

Do not force environment preparation for `--help`, `--status`, `--channel-inventory`, or `--materialize-checkpoint`. `--prepare-runtime` remains a compatible script-level alias for the unified preparation path.

## Choose the operation

Read [interface.md](references/interface.md) for the stable I/O and completion contract. Read the task-specific reference before constructing arguments:

- Search or materialize: [search-help.md](references/search-help.md) and [search-limitations.md](references/search-limitations.md).
- Download or dry-run: [download-usage.md](references/download-usage.md), [download-help.md](references/download-help.md), and [download-limitations.md](references/download-limitations.md).
- Source selection or path interpretation: [channels.md](references/channels.md).
- Login, verification, ordinary Chrome/CDP, or visible control: [authentication.md](references/authentication.md).

Prefer these forms, replacing `<PY>` and `<SKILL_ROOT>` with resolved absolute paths:

```text
<PY> <SKILL_ROOT>/scripts/literature_and_patents_search_scripts.py --batch-name <BATCH> --status
<PY> <SKILL_ROOT>/scripts/literature_and_patents_search_scripts.py --keywords <KEYWORDS> --batch-name <BATCH>
<PY> <SKILL_ROOT>/scripts/literature_and_patents_search_scripts.py --batch-name <BATCH> --materialize-checkpoint
<PY> <SKILL_ROOT>/scripts/literature_and_patents_download_scripts.py --batch-name <BATCH> --status
<PY> <SKILL_ROOT>/scripts/literature_and_patents_download_scripts.py --batch-name <BATCH> --dry-run
<PY> <SKILL_ROOT>/scripts/literature_and_patents_download_scripts.py --batch-name <BATCH>
```

Download only material the user is authorized to access. Do not bypass subscriptions, access controls, robots, CAPTCHA, or platform terms.

## Run the workflow

1. Inspect status for an existing batch before starting work.
2. Run metadata search when the requested scope is missing or incomplete. Use exact source filters only for deliberate diagnostics; otherwise preserve the registry order.
3. Let SQLite checkpoints resume interrupted work. Use `--refresh` to rescan selected completed sources while preserving metadata; use `--force` only when the user explicitly wants a new metadata search.
4. Materialize canonical and compatibility outputs. Treat SQLite plus the v2 JSONL/manifest agreement as the handoff evidence, not CSV row count alone.
5. Run download status and then an authorized download. Keep the full channel traversal for normal work; use `--exact-channel` only for a bounded diagnostic.
6. Re-run status and inspect the structured run report, attempts, ledger, and actual PDF validation together.

Search `partial` does not start download by default. Use `--download-on-partial` only when the user accepts processing available records; keep the overall result `partial`.

## Report results truthfully

Use only `complete`, `partial`, or `failed` for workflow status. Treat exit codes as:

- `0`: complete, or a successful read-only command.
- `3`: partial, including exhausted record-level download paths.
- `1`: fatal program, state, I/O, or contract failure.
- `2`: invalid arguments/configuration; the environment checker also uses 2 for missing required runtime components.

Do not call a source successful because a dry-run, probe, parser fixture, login, 200 HTML response, or candidate URL succeeded. Claim PDF success only when the exact adapter/resolver produced a saved file that passed artifact validation. Record missing keys, subscriptions, cost approval, rate limits, cooldowns, verification, and no-candidate results as their observed boundaries.

Do not infer exhaustive coverage from source count or zero results. Preserve all returned metadata and provenance. Never invent DOI values, publication numbers, URLs, source evidence, credentials, or conclusions.

## Escalate browser control in order

Use this fixed order only when a page path actually requires it:

1. Bundled Chromium.
2. Playwright Chrome.
3. Ordinary Chrome through the Codex plugin and current-task full CDP.
4. Windows visible control for one verified action at the unresolved node.

Enter layer 3 only after the first two layers cannot converge. Then confirm, in order, that ordinary Chrome exists, the Codex Chrome plugin is installed and enabled, the plugin is connected to the current task, and full CDP is enabled. Mark the CDP layer ready only after a read-only `Page.getFrameTree` succeeds for the current task.

For plugin/current-task and full-CDP setup, allow up to 5 minutes for each confirmation, scan at 5-minute intervals, and stop the bounded setup flow after 30 minutes. On refusal, policy denial, or timeout, skip this layer and continue only with allowed channels or cooldown behavior. Never install the plugin, enable CDP, change Chrome settings/profile, or widen permissions automatically.

Use Windows visible control only after proving the target URL and current event binding. Allow one action for the current unresolved node, then re-observe. Never bypass host safety prompts or reuse a stale event.

## Protect credentials and systems

- Keep runtime login and API configuration outside the Skill and project tree. Never read, print, copy, summarize, or package secret values, cookies, tokens, or storage state.
- Require explicit user authority before a cost-bearing source such as Google BigQuery.
- Use conservative request rates. On rate limits, service failures, robot checks, or cooldowns, persist the evidence and switch or wait; do not refresh aggressively.
- Authenticate on demand for the current channel. Do not pre-login every restricted source and do not log out an already valid institutional session merely to replay login.
- Do not modify production scripts in response to a suspected source defect unless the user explicitly asks for that change. First report the evidence and affected path.
