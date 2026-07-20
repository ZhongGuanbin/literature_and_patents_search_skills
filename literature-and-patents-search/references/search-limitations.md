# 元数据检索限制与边界

## “全面检索”的含义

全面检索表示按当前共享 registry 逐来源、逐 query variant 运行，并保留每条路径的终态；它不表示覆盖世界上所有数据库，也不保证任何来源返回全部记录。

以下情况必须报告为边界，不能改写成 complete：缺 key、费用未批准、机构权限不足、服务不可用、限流、cooldown、机器人验证、页面结构变化、超时、从未启动或 cursor 尚未完成。

零结果只是一条来源路径的观测。必须结合 source-run 状态、请求范围、query variant 和 parser 证据解释，不能直接得出“没有相关文献/专利”或“检索已穷尽”。

## Metadata 与证据

- 不伪造题名、作者、摘要、年份、DOI、公开号、URL、来源或字段覆盖。
- DOI 和专利公开号必须规范化，但保留可审计的原始 identifier/provenance。
- 来源返回的 landing 或 PDF 候选仍需在下载阶段验证；metadata 命中不是全文成功。
- 后续 occurrence 可填补空字段和合并列表；非空冲突保留首值并记录冲突，而不是静默覆盖。
- 兼容 CSV 是有损投影。canonical SQLite/JSONL 保留 metadata-only 记录与完整 locator/provenance。

## Adapter、Schema 与 Handoff

检索与下载共用版本化 registry。静态渠道说明可能过期，`--channel-inventory` 才是当前包的顺序、adapter 和能力真值。

正式 v2 handoff 由 canonical SQLite、文献 JSONL、专利 JSONL 和 manifest 组成。manifest 最后替换，是发布提交点。下载端应在同一文件锁下校验 SHA/count、generation、content digest、typed aliases 和完整逻辑记录；混代、截断或不一致应 fail closed。

独立 JSONL 或旧 schema 可以进入受限兼容路径，但不能获得未绑定 generation 的 alias 复用能力。

## Checkpoint 与一致性

- `search_state.sqlite3` 是 adapter run、occurrence、cursor、请求范围和 cooldown 的事务真值。
- 页面 occurrence 提交后才更新 cursor；中断后从已提交位置继续。
- checkpoint 以 record type、keyword、source、path 和 query variant 隔离。
- 旧 checkpoint 缺少请求范围时，只按已观察范围物化，不用新 registry 反向扩张历史任务。
- `--refresh` 和 `--force` 的语义不同；不要用 force 代替普通续跑。
- CSV 或进度 JSON 物化失败不回滚已提交 SQLite，但需要在最终报告中明确 warning。

## 凭证、费用与敏感数据

- 公共来源不因缺少机构配置而停止。
- key-backed 来源缺 key 时记录结构化 prerequisite 并继续其它允许来源。
- Google BigQuery 等计费来源必须由用户明确批准，不能把普通检索授权推断为费用授权。
- 不读取、打印、复制、总结或打包账号、密码、API key、cookie、token 或 storage state。
- CNKI/万方机构 scope 与度衍个人 scope 必须隔离，不能交叉提交凭据。

## 浏览器、验证与认证

任何网页来源都可能动态出现 robot、CAPTCHA、slider、登录或 MFA。先使用 bundled Chromium，再使用 Playwright Chrome；只有两者无法收敛时才进入普通 Chrome/CDP，最后才允许 Windows 单动作可见控制。

登录或验证成功只证明当前 session 节点通过，不证明检索结果完整、机构订阅覆盖或 PDF 可得。未解决验证应保存当前来源、页和 cursor，进入 cooldown 或切换来源；不要高频刷新。

普通 Chrome 插件、current-task connection 与 full CDP 缺失属于完整能力降级。不得自动安装插件、开启 CDP、修改 Chrome profile 或绕过宿主安全提示。

## 规模与服务边界

- 保持来源声明的保守请求间隔和并发限制；认证/诊断运行使用 `thread_num=1`。
- 长 `Retry-After` 应持久化为 host/channel cooldown，不在当前进程内无界等待。
- rate limit、service unavailable、request timeout 和 network error 是冷却/切换信号，不是 CAPTCHA 信号。
- 不为提高覆盖率而无限扩张 repository candidate、重复访问同一验证页或循环更换样本。

## 收敛规则

只有全部请求路径 complete 且 handoff 一致时，search 才是 complete。任一 blocked/incomplete/failed 路径使总体为 partial 或 failed。报告真实边界和仍可采取的下一步；无法解决时明确说明无法完成。
