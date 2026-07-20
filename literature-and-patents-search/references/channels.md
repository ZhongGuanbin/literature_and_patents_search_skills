# 渠道与来源快照

共享 registry 是顺序、adapter、parser、required locator 和能力标签的代码真值。本文只提供发布时的人类可读导航；每次运行前用两个 CLI 的 `--channel-inventory` 读取当前信息。

## 导航

- [核心契约](#核心契约)
- [文献检索来源](#文献检索来源32)
- [专利检索来源](#专利检索来源10)
- [文献下载渠道](#文献下载渠道35)
- [专利下载渠道](#专利下载渠道11)
- [认证 scope](#认证-scope)
- [证据标签](#证据标签)

## 核心契约

- 当前声明：文献检索 32 源、专利检索 10 源、文献下载 35 渠道、专利下载 11 渠道。
- inventory 任一行缺失、重名、错序或缺 parser 属于包契约失败。
- planner 只能跳过结构上不适用的渠道，不能改变剩余顺序。
- 所有下载渠道默认启用并按 registry 顺序初始化；只有显式渠道过滤或禁用才跳过匹配项，剩余渠道不得重排。
- 文献和专利 metadata 的来源不自动等于实际 PDF resolver；attempt 必须分别记录 planned、discovery、resolver 和 delivery provenance。
- 静态来源数量或 map 完整不等于真实网络覆盖或穷尽性。

## 文献检索来源（32）

按当前顺序：

1. Web of Science Starter API (Clarivate)
2. IEEE Xplore API
3. Google Scholar
4. OpenAlex API
5. Semantic Scholar API
6. Crossref API
7. arXiv API
8. The Lens (lens.org)
9. Elsevier
10. SpringerLink
11. Nature
12. ACS Publications
13. RSC Publishing
14. bioRxiv / medRxiv
15. DOAJ (Directory of Open Access Journals)
16. PMC (PubMed Central)
17. PubMed
18. Europe PMC
19. Crossref Metadata Search (search.crossref.org)
20. DataCite Search (search.datacite.org)
21. ChemRxiv
22. Semantic Scholar
23. OpenReview
24. IACR ePrint
25. DBLP
26. ACM metadata
27. USENIX
28. CORE
29. OpenAIRE
30. Springer
31. CNKI (中国知网)
32. 万方数据

API、公开网页、restricted browser 和 alias resolver 是不同证据路径。例如 bioRxiv/medRxiv 检索可通过 Europe PMC resolver，ChemRxiv enrichment 可通过 OpenAlex；不要把 resolver 成功记成名义来源的原生能力。

## 专利检索来源（10）

1. Google Patents
2. EPO Open Patent Services (OPS) API
3. USPTO Open Data Portal
4. WIPO PATENTSCOPE API
5. PQAI API (Patent Quality AI)
6. The Lens (lens.org)
7. Google BigQuery
8. CNKI (中国知网)
9. 万方数据
10. 度衍

Google BigQuery 是计费路径，必须显式授权。WIPO 当前能力标签和实际 adapter 边界应以 inventory/report 为准，不能仅凭名称宣称完整 API 能力。

## 文献下载渠道（35）

当前 registry 顺序为：Sci-Hub、arXiv API、bioRxiv / medRxiv、IACR ePrint、The Lens、Web of Science、doi_resolver、Crossref API、OpenAlex API、Semantic Scholar API、Europe PMC、PMC、PubMed、DOAJ、DataCite、OpenReview、DBLP、CORE、OpenAIRE、ChemRxiv、Google Scholar、Crossref Metadata Search、Semantic Scholar、USENIX、Elsevier、SpringerLink、Springer、IEEE Xplore API、Nature、ACS Publications、RSC Publishing、ACM metadata、Annual Reviews、CNKI、万方数据。

初始化时全部渠道均为启用状态，并严格以 registry 顺序定义优先级。部分名义渠道实际通过公开 API 或 repository resolver 找到文件；报告精确 executed resolver，不把 alias 记为原生 PDF 成功。

CNKI 与万方的追加渠道只处理 metadata `source` 精确匹配的记录，且只接受观察到的详情/PDF locator 或浏览器下载证据，不作为通用 URL 合成器。

## 专利下载渠道（11）

当前顺序：

1. Google Patents
2. The Lens (lens.org)
3. input_url
4. USPTO Open Data Portal
5. PQAI API (Patent Quality AI)
6. EPO Open Patent Services (OPS) API
7. WIPO PATENTSCOPE API
8. Google BigQuery
9. CNKI (中国知网)
10. 万方数据
11. 度衍

`input_url` 只解析 metadata 已有 landing URL，不等于 PDF 直链。USPTO/PQAI/EPO/BigQuery 等 metadata-origin adapter 只消费来源拥有的真实 locator；不得因为已有公开号就无条件生成 Google Patents URL。

度衍只接受观察到的详情路径或实际 patent locator，并使用隔离的站点个人认证 scope。

## 认证 scope

- CNKI 文献/专利检索与下载共享 `cnki`。
- 万方文献/专利检索与下载共享 `wanfang_data`。
- SpringerLink/Springer 共享其 publisher scope。
- 度衍检索与专利下载使用 `uyanip`，不得接收机构或 IdP 凭据。

认证按当前渠道需要执行，不预登录所有 restricted source。一个 scope 的失败不应全局禁用来源；记录当前证据后继续其它允许渠道。

## 证据标签

- E1：代码或 registry 声明。
- E2：离线 parser/contract 证据。
- E3：一个有界真实网络样本。

只有精确 adapter/resolver 取得并校验 PDF 才能称为该路径的下载 E3。缺凭证、未批准费用、401/403/429、验证或人工认证是边界，不是成功。单个 E3 也不能外推到其它记录、用户或机构。
