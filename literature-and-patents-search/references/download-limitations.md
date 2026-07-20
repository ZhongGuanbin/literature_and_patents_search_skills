# PDF 下载限制与边界

## 授权边界

只下载公开内容或用户依法、依合同和机构订阅有权访问的 PDF。不得绕过 paywall、订阅、访问控制、robots、CAPTCHA、MFA、平台条款或宿主安全提示。

用户提供 DOI、公开号、账号或机构信息不等于授权绕过控制。遇到不可用资源时记录真实边界；无法合法取得时明确说明无法完成。

## 渠道顺序

共享 registry 定义文献与专利固定顺序。禁用一个精确渠道只删除该项，不重排其它项。正常下载不要用 substring/exact channel 过滤；这些参数仅用于有界诊断。

同一记录首个合法 PDF 通过 artifact 校验后立即停止。不得因为某个样本失败而全局禁用一个来源，也不得为了追求成功无限重试同一页面。

## 输入与 URL

- 文献 DOI 是优先强身份；专利规范化公开号是优先强身份。
- metadata 的 URL 是候选或 landing，不自动等于 PDF。
- 只接受 API/页面/网络/下载事件真实观察到的 locator。
- 不从 DOI、题名、公开号、aid、raw ID 或 URL pattern 合成未观察到的详情或 PDF URL。
- metadata-only 记录可被明确排除在下载分母之外，但不能伪造为成功。
- v2 handoff 混代、摘要不一致或 alias 未绑定 generation 时 fail closed。

## Dry-run、Probe 与认证证据

`--dry-run` 在记录级渠道 candidate loop 前返回；即使与 `--exact-channel` 同用，也不证明 parser 或 candidate discovery 执行。`--probe-channel-plan` 只证明本地渠道选择和 prerequisite 分类。

认证成功只证明当前 scope/session 的登录节点，不证明用户拥有文章订阅、页面提供 PDF、下载成功或全渠道已验证。只有实际文件通过 artifact 校验才是 PDF 成功。

## 浏览器与验证

固定升级顺序为 bundled Chromium、Playwright Chrome、普通 Chrome/CDP、Windows 可见控制。只有前两层无法收敛才进入普通 Chrome。

进入普通 Chrome 层时依次确认 Chrome、插件安装/启用、current-task connection 和 full CDP；只读 `Page.getFrameTree` 成功后才能标 ready。每阶段 5 分钟确认，每 5 分钟扫描，最多 30 分钟。拒绝、策略阻止或超时只跳过该层。

Windows 可见控制只处理已证明目标 URL、当前事件绑定的一个未解决动作。执行一次后重新观察；不复用旧事件，不绕过宿主提示。

## 请求负载与失败处理

- 认证或诊断使用 `thread_num=1` 和保守延迟。
- rate limit、service unavailable、timeout、network error、access denied、security challenge 和 cooldown 都是停止当前路径并切换/等待的信号。
- 长 Retry-After 持久化为 cooldown，不在进程内无界等待。
- repository candidate 有数量/文件访问预算；达到边界后保留证据并继续后续路径，不扩大抓取范围。
- 不把本机 `environment_bootstrap_*` 问题计入某来源失败。

## 敏感信息

运行时配置、账号、密码、API key、cookie、token、storage state、hook events、截图和浏览器 profile 不得进入发布包。Codex 可以使用脱敏状态与 attestation，但不能读取或输出秘密内容。

CNKI 和万方的机构凭据只用于对应 scope。度衍使用独立个人账号 scope，只能在明确的度衍登录 gate 后发送到其允许 host；不得接收学校、CARSI、通用账号或 IdP 凭据。

## 修改与证据边界

看到 `download_attempts.csv`、日志或状态中的可疑行为时，先报告样本、planned/executed adapter、结构化原因、影响和拟议修复；除非用户明确要求，不修改生产脚本或正式渠道顺序。

E1（代码/registry）、E2（离线 contract）或一次登录都不能冒充真实下载闭环。真实成功必须绑定精确 adapter/resolver 与通过校验的 PDF；一次样本成功也不能外推到其它用户、机构、地区或记录。
