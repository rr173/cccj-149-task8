# 监管问询答复编排器（Regulatory Inquiry Response Orchestrator）

接收监管方的**问题清单、截止时间和可引用资料范围**，把病例、已发送报文、
适用法规与统计结论的**精确版本**锁定成答复底稿；组稿期间引用变化不会悄悄
混入当前答复，而是产生**带原因的新底稿候选**。资料缺失、引用越权或版本
互相矛盾时阻止定稿，并准确列出尚未满足的问题。

纯 Python 标准库（3.11+，SQLite），独立子包 `reg_inquiry/`、独立数据库
`inquiry.db`，与 `pv_service/` 物理隔离、无第三方依赖。

```bash
# 端到端剧本演示
python3 run_inquiry_demo.py

# 测试（106 个：锁定/漂移/协作/校验/发送恢复/双节点幂等/篡改核对/审计链/
# 分区写作/最小披露/授权修订号/受限上下文/附件边界/封存不改写/更正重授权/
# 旧库迁移）
python3 -m unittest discover -t . -s tests_reg -v
```

## 需求映射

| 需求 | 实现 |
|---|---|
| 冻结问题清单/截止时间/可引用范围 | `inquiries` 只增（触发器拒绝改删），`scope_json` 在登记时固化 |
| 病例/报文/法规/统计**精确版本**锁定 | `materials` 四类只增版本（`(material_id,version)` 唯一、内容指纹去重）；`draft_pins` 冻结版本行 id + content_hash + 引用锚 `CASE:M@3` |
| 资料缺失 / 引用越权阻断并列出未满足项 | `lock_draft` 逐项收集 `MISSING_MATERIALS`（含缺失 id/版本/类别）与 `OUT_OF_SCOPE`（资料 id/类别不在范围），不落任何半成品底稿 |
| 版本互相矛盾阻断 | 资料注册时声明 `fact_key/fact_value`；同 fact_key 不同值在锁定（`ContradictionError`）与定稿（`PIN_CONTRADICTION`）两处拦截并登记 `contradictions` |
| 引用变化不混入当前答复，另立带原因候选 | 注册新版本时 `spawn_drift_candidates` 为引用旧版本的开放 BASE/更正底稿克隆出 `CANDIDATE`（pin 新版本、携带 drift_reason 与 old→new 变化明细、克隆章节/附件并把附件溯源重指新版本）；当前底稿 pins 一个字节不改；同链幂等 |
| 章节独立编辑、多人并行 | `sections (draft_id,qid)` 唯一；不同章节互不干扰，5 撰写人并发同章节仅 1 人成功 |
| 竞争更新以调用方看到的修订为前提 | 乐观修订号：提交必须带 `expected_revision`；过期提交返回 `STALE_REVISION`、不覆盖，冲突独立事务落 `section_conflicts`（不随业务回滚丢失） |
| 定稿：每问唯一可追踪回答 | manifest 为每问生成 `answer_uid=sha256(draft,qid,section,revision)` 与 `body_sha256`；`NO_ANSWER/EMPTY_ANSWER/MULTIPLE_ANSWERS` 阻断 |
| 附件与正文引用一致 | 附件以稳定锚 `@attachment:<id>` 在正文引用；`ATTACHMENT_NOT_CITED/ATTACHMENT_REF_MISSING/ATTACHMENT_REF_NOT_LOCKED` 阻断；附件溯源必须指向已锁定 pin |
| 敏感字段符合收件辖区披露策略 | 辖区只增策略（`REDACT/PROHIBIT/ALLOW`）；`SENSITIVE_NOT_REDACTED/SENSITIVE_PROHIBIT` 按辖区阻断 |
| 不可变提交件 | `submissions` 行触发器只放行发送状态机列；`manifest_hash` 锁定清单；底稿 `OPEN→FINALIZED`，同问询其余开放底稿置 SUPERSEDED |
| 后续改动只能产生更正件，保留原件与回执 | `create_correction_draft` 生成 kind=CORRECTION、带 `corrects_submission_id` 指针的新底稿/新提交件/新编号；原提交件、回执、履历原样保留，`correction_chain` 可遍历 |
| 可恢复作业（组稿/校验/定稿/发送） | `jobs`（LOCK_DRAFT/VALIDATE/FINALIZE/SEND）：幂等键唯一、条件 UPDATE 领取、attempt 租约栅栏、checkpoint 心跳、崩溃恢复孤儿作业与 SENDING 残留 |
| 重复请求/双节点不产生重复件/编号/履历 | 外发编号在 IMMEDIATE 事务内由序列分配 + `outgoing_number UNIQUE`；发送条件领取 + 处理器以提交件当前状态短路重放；`submission_events (sub,type,detail)` 去重；网关以编号为幂等键 |
| 监管回执 | `receipts` 回执号唯一、与提交件外发编号交叉核对；回执已存在时崩溃恢复不再外发 |
| 独立核对 | `verifier.py` 不走组装路径，逐行重算 manifest/正文/附件/pin/编号/履历/回执/更正链/审计哈希链，篡改逐项列出（BODY/MANIFEST/ATTACHMENT/PIN/RECEIPT hash mismatch 等） |
| **分区写作/最小披露** | `access.py` + `identity.py`：OWNER 按问设置可见类别/字段/撰写人（只增版本化 + 问询授权修订号）；受限上下文只给获准证据片段、敏感值稳定占位符；附件上传/下载同一授权边界；转派/离组/收紧后旧授权号保存拒绝且不泄露新证据；相同授权请求幂等不增权、不留重复痕迹；定稿逐问按保存当时授权重放核验，越权只列问题/章节/被拒锚；封存不改写，更正须按当时授权重新撰写；越权独立事务留痕，管理员全量组稿/定稿/发送保持可用，旧库自动迁移（非托管模式） |
| 操作留痕 | 全局只增哈希链 `audit_events`（seq/prev_hash/entry_hash，帧覆盖全部业务字段），幂等键防重复履历；`verify_audit_chain` 离线重放 |

## 关键设计

**为什么引用变化“混不进来”**：底稿锁定时把引用解析成 `materials` 的**具体行**
（版本行 id + 版本号 + content_hash），之后读到的都是冻结快照；新版本注册
只追加、不改旧行（触发器），漂移逻辑另开 CANDIDATE 而不改任何 pin。
定稿使用的 manifest 再次固定 pins 与正文/附件哈希，提交件封存后连状态机
之外的字段都无法 UPDATE。

**为什么双节点/重复请求安全（三层）**：
1. SQLite `BEGIN IMMEDIATE` 使所有写者全局串行；编号在同事务内由
   `UPDATE ... RETURNING last_no+1` 分配，`outgoing_number UNIQUE` 兜底；
2. 作业领取是带 `WHERE status='PENDING' OR 租约过期` 的条件 UPDATE，
   `attempt` 栅栏让租约过期后旧工作者的完成/失败结果写不回；
3. 发送处理器在事务内先看提交件当前状态（SENT/DELIVERED/REJECTED 直接
   幂等返回），外部传输以外发编号为幂等键——即使“网关已受理、本地崩溃”，
   重放只取回同一受理号。

**乐观并发与留痕并存**：过期提交抛 `STALE_REVISION` 会回滚业务事务，
编排器随即在**独立事务**重放冲突留痕，保证“不覆盖”与“冲突可查询”同时成立。

**永久失败可重开**：校验失败（VALIDATION_FAILED）等永久失败作业保留为
FAILED 留痕；补齐内容后以同一幂等键重新定稿时，旧行改名 `#failed-<id>`
保留，新作业占用原键重跑（触发器仅放行这一种键改名）。

## 分区写作与最小披露权限

负责人（OWNER）把答复组稿按问题分区：为**每个问题**单独设置可见资料
类别、可见字段与撰写人名单；撰写人读取章节上下文时只能获得其获准的
证据片段，敏感值以**稳定占位符**替代，附件下载遵守同一授权边界。
未显式启用（无任何成员）的问询保持原有全量组稿行为；管理员的全量
组稿、定稿与发送操作始终可用。

**组成员与身份**：登记人自动成为初始 OWNER；成员事件（加入/角色变更/
离组）只增，当前态由 `group_members` 物化。身份键做 NFKC + casefold +
首尾空白归一（全角/大小写/空白写法等价判为同一人），原始提交值原样
留痕。最后一个 OWNER 不允许离组；旧库迁移后可用
`bootstrap_partitioning` 显式引导首位负责人。

**每问授权（只增版本化）**：`question_grants` 每行冻结
`visible_categories / visible_fields / material_ids / writers`；任何
重设都把旧行置 `SUPERSEDED` 并推进问询级**授权修订号**
（`auth_revision_seq`）。授权只能在问询登记冻结范围与该问询底稿实际
锁定的精确版本内**收紧**（类别与资料白名单必须自洽），撰写人必须是
当前活跃成员；**相同授权请求再次到达幂等返回**——不推进修订号、不
增加权限、不写重复履历。

**授权修订号失效（乐观授权并发）**：章节转派（重设 writers）、人员
离组、权限收紧都在同一 IMMEDIATE 事务内推进授权修订号。撰写人页面
携带读取上下文时看到的 `expected_auth_revision`，**用旧号保存/上传
一律拒绝**（`STALE_AUTH_REVISION`），错误只回传 qid 与当前号，**不
泄露任何新证据**；转派与保存在 SQLite 写锁上严格串行，只能有一个
结果。人员离组时其仍在任的撰写人名单同步收紧（新版本授权）。

**受限上下文读取（最小披露）**：`read_section_context(draft,qid,actor)`
对 WRITER 只返回该问题授权内的证据片段——未获准资料**整段不出现**
（响应里不含其引用锚，仅给拒绝计数），获准资料内未获准字段替换为
`«SECRET:<hmac>»` 稳定占位符（HMAC-SHA256 + 库盐：同一原值跨章节
稳定对照、不可逆、跨库不可链接）。附件只列出其归属问题且溯源资料
当前可被该成员读取的条目。

**保存/上传/下载闸门**：章节保存与附件上传在写事务内复核：在组、
授权号新鲜、被分派到该问题、正文每条 `[..]` 引用与每个
`@attachment:` 都在授权内、正文不得携带未授权字段的**原值**
（占位符允许）。越权抛 `EVIDENCE_ACCESS_DENIED`，`details` 只列
问题、章节、被拒资料引用锚与附件 id，**绝不回显受保护内容**；越权
留痕在业务事务回滚后的独立事务持久化（与 `STALE_REVISION` 冲突留痕
同构）。附件下载走同一资格边界。

**封存不改写、纠正重授权**：封存后的提交件 manifest 不因人员权限
变化而改写（只增触发器 + manifest 哈希）；定稿前逐问按**每次保存
当时有效**的授权重放核验回答者在每条引用与附件上传时的读取资格
（`section_revisions.auth_revision/writer_key` 与附件上的授权快照），
发现越权列出问题、章节、被拒资料锚但不回显值。候选/更正克隆的继承
修订标记 `is_cloned=1`，**更正必须在更正当时有效授权下重新撰写
保存**才能定稿。独立核验器额外比对 manifest 与链头修订的授权快照。

| 能力 | 方法 |
|---|---|
| 成员管理 | `add_member` / `change_member_role` / `remove_member` / `list_members` / `bootstrap_partitioning`（旧库引导） |
| 每问授权 | `put_question_grant`（负责人；相同请求幂等）/ `get_question_grant` / `list_question_grants` |
| 授权修订号 | `current_auth_revision`（读上下文时下发，保存时回传） |
| 受限上下文 | `read_section_context(draft,qid,actor=)`（获准片段+稳定占位符） |
| 受限保存/附件 | `submit_section(...,expected_auth_revision=)` / `add_attachment(...,qid=,expected_auth_revision=)` / `get_attachment(...,actor=)` |
| 授权冲突查询 | `auth_conflicts(inquiry_id=,draft_id=,qid=,reason_code=)`（只含定位锚/原因码） |
| 变更历史 | `auth_history(inquiry_id,qid=)`（授权版本 + 成员事件 + 越权记录 + 当前修订号） |
| 独立核验 | `verify_submission` / `verify_all`（含授权快照一致性） |
| 审计 | `audit_trail`（`MEMBER_*`/`QUESTION_GRANT_SET`/`AUTHZ_DENIED` 入哈希链）/ `verify_audit_chain` |

错误码：`NOT_AUTHORIZED`（非负责人管理操作）/ `NOT_GROUP_MEMBER`
（离组/非成员）/ `NOT_ASSIGNED`（未被分派到问题）/
`STALE_AUTH_REVISION`（旧授权号）/ `EVIDENCE_ACCESS_DENIED`（引用、
附件或受保护字段原值越界）。

## API 一览（`InquiryOrchestrator`）

| 能力 | 方法 |
|---|---|
| 问询登记 | `register_inquiry` / `get_inquiry` / `list_inquiries` |
| 资料/策略 | `register_material`（新版本自动派生漂移候选）/ `put_disclosure_policy` |
| 底稿锁定 | `lock_draft`（直接，幂等）/ `lock_draft_job`（可恢复作业） |
| 章节协作 | `submit_section(draft,qid,body,expected_revision=...)` / `section_history` |
| 附件 | `add_attachment(derived_from_ref=...)` / `get_attachment` |
| 冲突查询 | `conflicts(draft)`（章节冲突/矛盾/漂移事件与警告） |
| 定稿校验 | `validate(draft)`（只读结构化报告）/ `validate_job` |
| 定稿封存 | `finalize(draft)`（校验通过才生成不可变提交件） |
| 发送与重试 | `send(submission_id)`（作业；自动重试/恢复/幂等）/ `submission_status` |
| 回执登记 | `register_receipt(receipt_number,payload)` / `list_receipts` |
| 更正关系 | `create_correction_draft(submission,refs,reason)` / `correction_chain` |
| 独立核对 | `verify_submission` / `verify_all` |
| 操作留痕 | `audit_trail(inquiry_id,event_type)` / `verify_audit_chain` |
| 作业恢复 | `pump()`（工作节点一步）/ `run_job(id)` / `recover()` / `list_jobs` |

引用锚语法：`[CASE:material_id@version]`、`[SENT_REPORT:..@..]`、
`[REG:..@..]`、`[STAT:..@..]`；附件锚 `@attachment:<id>`。
