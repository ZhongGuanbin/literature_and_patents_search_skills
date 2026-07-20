# 认证、验证与浏览器交接

## 导航

- [敏感配置与 scope](#敏感配置)
- [按需认证流程](#按需认证流程)
- [Hook 接口](#hook-接口)
- [浏览器升级顺序](#浏览器升级顺序)
- [普通 Chrome/CDP 确认](#普通-chromecdp-确认)
- [Windows 可见控制](#windows-可见控制)
- [动态验证与收敛](#动态验证与收敛)

## 适用范围

仅在当前来源真实出现机构登录、站点个人登录、MFA、robot/CAPTCHA/slider 或其它安全验证时使用本流程。认证必须服务于用户有权访问的资源；不得绕过订阅、访问控制、平台条款或宿主安全提示。

## 完整能力提醒

> 若想开启 Skill 的全部能力，需要完成这两件事情：  
> 1. 在普通 Chrome 中安装、启用并连接 Codex Chrome 插件；  
> 2. 为当前任务开启 full CDP 访问权限。

Chrome、Node.js、插件、current-task connection 和 full CDP 属于可选完整能力。缺失时环境报告 `degraded`，公开/API 和前两层浏览器路径仍可运行。

## 敏感配置

运行时登录配置优先级：

1. `LAPS_RUNTIME_CONFIG`
2. `LAPS_AUTH_CONFIG`
3. 用户配置目录中的默认 runtime JSON

API key 由 `LAPS_API_CONFIG` 单独指定。配置必须位于 Skill/项目目录之外。

允许使用脱敏状态确认字段是否已配置；禁止读取、打印、总结、复制或打包账号、密码、API key、cookie、token、storage state、浏览器 profile 和 hook event 内容。认证型低负载操作使用 `thread_num=1`。

## Scope 隔离

- CNKI 文献与专利路径共享 `cnki`，只提交给合法的 CNKI/机构认证节点。
- 万方文献与专利路径共享 `wanfang_data`；只把学校 IdP 凭据提交给经验证的 IdP，不提交到万方自有机构账号表单。
- SpringerLink 与 Springer 可共享同一已验证 publisher scope。
- 度衍使用 `uyanip_account` / `uyanip_password` 和隔离的 `uyanip` scope。只在明确的度衍登录 gate 后发送到允许的度衍 host；不得使用学校、CARSI、通用账号或 IdP 凭据。

不为重放流程而退出一个已经匹配当前机构、仍有效的 session。旧 state 没有有效 attestation 时只能作为隔离 seed；必须在当前来源 URL 重新确认 host、session/access 证据和无 blocker，才能发布新 generation。

## 按需认证流程

1. 进入当前记录的当前渠道。
2. 复用仍有效、与 scope/generation/attestation 一致的 state。
3. 无有效 state 时，先用 bundled Playwright Chromium 执行可见认证检查。
4. 登录后核对真实访问证据，而不是只看 URL、cookie 或页面标题。
5. 保存受控 state/attestation，立即恢复当前渠道和当前记录。
6. 成功取得并校验 PDF 后停止该记录的后续渠道。
7. subscription required、access denied、机构未列出、no candidate、未解决验证、rate limit 或 cooldown 时记录原因并切换。

单渠道认证诊断使用精确名称：

```powershell
python scripts\literature_and_patents_download_scripts.py --auth-check --headful --auth-no-state-reuse --exact-auth-channel "<CHANNEL>" --disable-channel "Sci-Hub"
```

`--auth-channel` 是子串诊断；优先使用 `--exact-auth-channel` 或 exact 形式。认证通过后再次运行精确认证检查，查看脱敏 success/state reuse 标记。

## Hook 接口

安全验证和认证 hook 可由环境变量配置：

```text
LAPS_SEARCH_CHALLENGE_HOOK
LAPS_SECURITY_CHALLENGE_HOOK
LAPS_AUTH_CONTROL_HOOK
LAPS_EXTERNAL_CONTROL_TIMEOUT_SECONDS
LAPS_CHROMIUM_CONTROL_TIMEOUT_SECONDS
LAPS_CHROME_CONTROL_TIMEOUT_SECONDS
LAPS_CODEX_EXTENSION_CONTROL_TIMEOUT_SECONDS
LAPS_VERIFICATION_MANUAL_TIMEOUT_SECONDS
```

请求/响应必须绑定当前 event、request、source/channel、scope、subject 和 challenge/resume URL digest。异步响应只接受当前事件的严格指针；已消费响应不得重放。所有返回 URL 与文件路径仍需通过 outbound/path guard。

hook 事件持久化必须脱敏。自定义 hook 不应接收凭据；只有明确批准且满足绑定/host 限制的 bundled flow 才能在 subprocess 内存中使用当前 scope 所需字段。

## 浏览器升级顺序

固定顺序：

1. Bundled Chromium。
2. Playwright Chrome。
3. 普通 Chrome + Codex Chrome 插件 + current-task full CDP。
4. Windows 可见控制。

只有前两层无法收敛，且当前页仍是可操作的验证/认证节点时，才进入第三层。

## 普通 Chrome/CDP 确认

依次确认：

1. 普通 Chrome 可执行文件存在。
2. Codex Chrome 插件已安装并启用。
3. 插件已连接当前任务，而不是其它任务或旧 tab。
4. 当前任务已获得 full CDP。
5. 在当前任务执行只读 `Page.getFrameTree` 成功。

只有第 5 步成功才把该层标为 ready。每个插件/current-task 与 full-CDP 确认阶段最多等待 5 分钟；每 5 分钟扫描一次，总 setup 流程最多 30 分钟。明确拒绝、策略阻止或超时后，跳过普通 Chrome 层，继续允许的渠道或 cooldown 路径。

不得自动安装插件、开启 CDP、修改 Chrome 设置/profile，或通过环境变量伪造 current-task/CDP attestation。Chrome PDF 设置只能提醒用户自行确认，不能静默更改。

## Windows 可见控制

仅在普通 Chrome/CDP 未解决当前节点时使用。开始前必须证明：

- 当前目标 URL 与 event 中的 digest 一致。
- 当前 tab/session 属于本任务。
- 当前 action 对应仍未解决的页面节点。
- 动作预算为一次。

执行一次点击/输入后立即重新观察并回到正常验证链。不得连续执行未重新绑定的动作、处理 stale event、绕过宿主强制提示或扩大为通用桌面控制。

## 动态验证与收敛

验证可能在重复访问、重定向或请求量上升后才出现。每次在当前页面动态分类，不预判某渠道永远需要或永远不需要 CAPTCHA。

`rate_limited`、`service_unavailable`、`request_timeout` 和 `network_error` 是 cooldown/切换信号，不是打开浏览器的理由。未解决 challenge 也应持久化状态并切换或等待，不高频刷新。

登录成功不等于订阅覆盖，验证成功不等于 parser 成功，候选成功不等于 PDF 成功。最终只以精确 resolver 的已校验 PDF 和一致 ledger/report 作为下载完成证据。
