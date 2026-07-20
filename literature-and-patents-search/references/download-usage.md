# PDF 下载操作流程

## 导航

- [环境门禁](#2-环境门禁)
- [状态与输入检查](#3-查看批次状态)
- [小批量授权下载](#5-小批量授权下载)
- [精确诊断](#6-精确记录或渠道诊断)
- [认证检查](#7-认证检查)
- [结果验证](#9-验证结果)

## 1. 解析 Skill 与 Python 路径

将包含 `SKILL.md` 的目录设为 `SKILL_ROOT`。环境准备后使用 Skill 自有 Python：

```text
Windows: <SKILL_ROOT>/tools/.venv/Scripts/python.exe
POSIX:   <SKILL_ROOT>/tools/.venv/bin/python
```

PowerShell 示例：

```powershell
$py = Join-Path $skillRoot "tools\.venv\Scripts\python.exe"
if (!(Test-Path $py)) { $py = "python" }
```

所有脚本路径都从 `SKILL_ROOT` 解析，不假设当前工作目录。

## 2. 环境门禁

```powershell
python tools\check_environment.py --check --json
python tools\check_environment.py --prepare --json
```

只有 check 返回 2 时才需要 prepare。prepare 结束后再 check。exit 1 表示检查/安装异常，应停止并报告本机环境问题。

> 若想开启 Skill 的全部能力，需要完成这两件事情：  
> 1. 在普通 Chrome 中安装、启用并连接 Codex Chrome 插件；  
> 2. 为当前任务开启 full CDP 访问权限。

这两项缺失只让后两层浏览器能力降级。不要自动安装插件、开启 CDP 或修改 Chrome。

## 3. 查看批次状态

```powershell
& $py scripts\literature_and_patents_search_scripts.py --batch-name Orbitrap --status
& $py scripts\literature_and_patents_download_scripts.py --batch-name Orbitrap --status
```

状态命令只读。先确认 metadata handoff 存在、批次名称正确，再运行下载。

## 4. 检查渠道与输入

```powershell
& $py scripts\literature_and_patents_download_scripts.py --channel-inventory
& $py scripts\literature_and_patents_download_scripts.py --batch-name Orbitrap --dry-run --disable-channel "Sci-Hub"
```

`--channel-inventory` 是当前渠道顺序真值。dry-run 只验证输入、配置与 map；不证明 parser、远端候选或 PDF 成功。

需要验证一个精确渠道是否会被选中时，用无网络 probe：

```powershell
& $py scripts\literature_and_patents_download_scripts.py --batch-name Orbitrap --probe-channel-plan --literature-only --exact-channel "PubMed" --limit 1 --disable-channel "Sci-Hub"
& $py scripts\literature_and_patents_download_scripts.py --batch-name Orbitrap --probe-channel-plan --patents-only --exact-channel "Google Patents" --limit 1 --disable-channel "Sci-Hub"
```

probe 只证明本地 plan 与 prerequisite 分类，不证明真实网络闭环。

## 5. 小批量授权下载

```powershell
& $py scripts\literature_and_patents_download_scripts.py --batch-name Orbitrap --limit 5 --disable-channel "Sci-Hub"
```

- 只访问公开资源或用户有权访问的来源。
- 正常运行不要传 `--channel` / `--exact-channel`，让 registry 保持完整 fallback 顺序。
- 碰到 rate limit、服务失败、验证、access denied 或 cooldown 时记录原因并继续允许的后续路径；不要高频刷新。
- 每条记录在首个合法且通过校验的 PDF 后停止。

## 6. 精确记录或渠道诊断

```powershell
& $py scripts\literature_and_patents_download_scripts.py --batch-name Orbitrap --literature-only --doi "10.xxxx/example" --exact-channel "PubMed" --limit 1 --disable-channel "Sci-Hub"
& $py scripts\literature_and_patents_download_scripts.py --batch-name Orbitrap --patents-only --publication-number "US1234567A" --exact-channel "Google Patents" --limit 1 --disable-channel "Sci-Hub"
```

这是诊断模式，不是正常生产 traversal。缺 key、401/403/429、no candidate 或认证边界都要如实保留。

## 7. 认证检查

只在当前渠道实际需要认证时运行：

```powershell
& $py scripts\literature_and_patents_download_scripts.py --auth-check --headful --auth-no-state-reuse --exact-auth-channel "<CHANNEL>" --disable-channel "Sci-Hub"
```

认证配置必须位于用户目录；不要打开、打印、复制或打包秘密值。认证通过后重新运行精确认证检查，确认脱敏报告中的 success/state reuse 标记，再恢复当前记录/渠道。

认证成功不证明订阅或 PDF 成功。若当前渠道无法访问，记录边界并按 map 继续。

## 8. 恢复与重新获取

普通中断直接用同一批次重跑。需要新的 logical run 时用 `--no-resume`；只有用户明确要求重新获取时用 `--force`。两者都不跳过 cooldown、安全或认证边界。

## 9. 验证结果

完成后重新运行 `--status`，并联合检查：

1. `download_run_report.json` 的 workflow status、summary、failure reasons 和 cooldown。
2. `download_state.sqlite3` 的 run/record/attempt/artifact 终态。
3. `download_attempts.csv` 的 planned/executed/resolver provenance。
4. success CSV 引用的 PDF 是否存在且通过当前 artifact 校验。

任何 exhausted 记录使总体为 partial。不要把 dry-run、认证、候选发现或 HTML 页面称为 PDF 下载成功。
