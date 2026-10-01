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

# 测试（114 个：锁定/漂移/协作/校验/发送恢复/双节点幂等/篡改核对/审计链/
# 分区授权策略/受限上下文/授权号失效/并发转派/附件边界/更正重检/授权独立核验）
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
| 操作留痕 | 全局只增哈希链 `audit_events`（seq/prev_hash/entry_hash，帧覆盖全部业务字段），幂等键防重复履历；`verify_audit_chain` 离线重放 |
| **分区写作与最小披露权限** | `identity.py`（NFKC+casefold 稳定身份键）+ `authz.py`（每问询单调递增**授权修订号**、成员台账、逐问可见类别/字段/撰写人授权只增版本、受限证据投影、稳定占位符、附件同边界、as-of+当前双重复核）；`authz_verifier.py` 独立核验；`authz_denials`/`attachment_requalifications` 只增 |

## 分区写作与最小披露权限

负责人（LEAD）为**每个问题**独立设置：可见资料类别（四类的子集）、
可见字段（`[]`=任何字段值不可见、`["*"]`=全字段）、撰写人名单。
授权只能在问询登记冻结的可引用范围之内再收紧。撰写人读取章节上下文时
只能获得**获准类别的已锁定证据片段**，未获准字段值替换为稳定占位符
`«HIDDEN:<field>#<sha256前10位>»`（同一字段在所有上下文占位符一致，
可比对但不含原值；按字段而非按值生成，不泄露等值关系）；**下载附件
遵守同一授权边界**（归属问题 + 溯源类别获准 + 已合格）。

**启用与缺省**：问询默认保持旧的宽松路径（`authz_revision=0`，
管理员全量组稿/定稿/发送行为完全不变）；负责人 `enroll_authz` 启用后，
名册与逐问授权建立基线修订号 1，此后所有读取/保存/上传/下载/定稿路径
执行授权边界。身份以 `identity.py` NFKC+casefold+首尾空白规范化为
稳定键，空白/非字符串/超长身份一律 `INVALID_ACTOR` 明确拒绝，原始
提交值在成员台账/章节修订/审计中原样留痕。

**授权修订号失效机制（每问询单调递增）**：章节转派（撰写人名单变更）、
人员离组/回组、负责人转派、授权收紧或放宽，都在各自 `BEGIN IMMEDIATE`
事务内把 `inquiry_authz.authz_revision` +1。页面保存必须携带读取时看到
的号；旧号一律 `STALE_AUTHZ_REVISION`，响应只给当前修订号，**不泄露
任何新证据**。推进使用行级 compare-and-set（`WHERE authz_revision=?`
条件 UPDATE），转派与保存、两次授权变更并发时 SQLite 写锁串行，**只能
有一个结果**。完全相同的授权请求再次到达：不推进修订号、不增加权限、
不产生重复留痕（内容比对幂等 + 审计帧 idempotency_key 双重兜底）。

**逐问写入闸门**（在章节乐观修订号检查之前）：

- 撰写人必须当前在册、在该问题名单内、携带新鲜授权号（名单收紧后旧号
  失效）；负责人保留全量组稿能力但同样须带新鲜号（防转派/保存交错）；
- 正文中的**每次引用**都必须在该问题当前获准类别内（在已锁定 pin 之上）；
- 附件上传必须归属问题、溯源类别获准；正文引用他问附件同样拒绝；
- 每次越权逐项写只增 `authz_denials`（只记问题/章节/引用锚/类别/附件 id
  等**标识**，绝不回显受保护内容）；业务事务回滚后由独立事务重放留痕，
  保证“拒绝必可审计”。

**封存不可变 + 更正按当时授权重新检查**：封存后的提交件 manifest 固定
每问 `authz_revision`，之后人员离组/权限收紧**绝不改写**已封存答复
（`verify_submission` 仍通过）。引用漂移候选与更正底稿克隆章节时
`authz_revision` 置 NULL、克隆附件 `upload_authz_revision` 置 NULL：
定稿前逐问复核发现继承内容必须由合格撰写人在**当时有效**授权下重新
保存、克隆附件由负责人或在列撰写人**重新认定**（`requalify_attachment`，
收紧后旧再认定失效须重新认定）。

**定稿前逐问资格复核**（`validate` 只读报告新增阻断码）：

- `SECTION_UNQUALIFIED`：继承章节未在当前授权下重新保存；
- `ANSWER_UNQUALIFIED`：保存时点或当前不具备撰写资格（含已离组）；
- `CITATION_UNQUALIFIED`：引用在保存时点或当前超出授权类别（as-of +
  当前双重复核）；
- `ATTACHMENT_UNQUALIFIED`：附件归属问题不符/溯源类别未获准/未再认定。

每项列出问题、章节与被拒资料标识，不回显受保护内容；同时落
`FINALIZE_CHECK` 越权留痕。

**接口一览（`InquiryOrchestrator`）**：

| 能力 | 方法 |
|---|---|
| 授权策略/问题分派 | `enroll_authz` / `set_question_policy`（`expected_revision` 乐观号） |
| 名册管理 | `add_writers` / `remove_writers` / `reactivate_writers` / `transfer_lead` |
| 策略查询 | `get_question_policy` / `list_question_policies` / `list_members` / `authz_revision` |
| 受限上下文读取 | `read_section_context(draft,qid,actor=)`（获准证据片段+稳定占位符；附件只给元数据） |
| 章节保存 | `submit_section(..., expected_authz_revision=)`（双修订号前提） |
| 附件 | `add_attachment(..., qid=)` / `get_attachment(..., actor=)` / `requalify_attachment` |
| 授权冲突查询 | `authz_conflicts(inquiry_id=/draft_id=/qid=/action=)`（只含标识，无内容） |
| 变更历史 | `authz_history`（启用/名册/转派/政策/再认定/拒绝）/ `grant_history`（逐问版本台账） |
| 独立核验 | `verify_authz(inquiry_id=)`（修订号连续性/台账 as-of/封存资格/再认定/留痕/审计链） |
| 审计 | `audit_trail` / `verify_audit_chain`（新增 `AUTHZ_*`、`ATTACHMENT_REQUALIFIED` 帧） |

```python
o.enroll_authz(inq, lead="lead", writers=["alice", "bob"], grants={
    "Q1": {"categories": ["CASE"], "fields": ["outcome"], "writers": ["alice"]},
    "Q2": {"categories": ["REGULATION"], "fields": ["*"], "writers": ["bob"]}})
ctx = o.read_section_context(draft, "Q1", actor="alice")
# ctx["evidence"] 只含 CASE 片段；patient_name -> «HIDDEN:patient_name#9e2eadf543»»
o.submit_section(draft, "Q1", "恢复 [CASE:MAT-CASE@1]",
                 expected_revision=0, submitted_by="alice",
                 expected_authz_revision=ctx["authz_revision"])
o.set_question_policy(inq, "Q1", categories=[], fields=[], writers=["alice"],
                      expected_revision=1, updated_by="lead")  # 收紧 -> rev 2
# alice 再用旧号 1 保存 -> STALE_AUTHZ_REVISION（响应无新证据，越权留痕可查）
```

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

## 模块

```
identity.py          撰写人身份规范化（NFKC+casefold+首尾空白）与空白/非法拒绝
authz.py             分区授权：授权修订号（行级 CAS 推进）、成员台账、逐问
                     可见类别/字段/撰写人只增版本、受限证据投影与稳定占位符、
                     保存/上传/下载闸门、附件再认定、as-of+当前定稿复核、
                     越权只增留痕、变更历史
authz_verifier.py    授权独立核验：修订号连续性、台账 as-of 重放、封存资格、
                     再认定人资格、留痕完整性、审计哈希链
db.py                schema（授权表 + 不可变触发器 + 旧库加列迁移）
drafts.py            问询登记/底稿锁定/漂移候选/章节协作/附件（携带授权修订号）
validation.py        定稿校验（含逐问授权资格复核；只列问题/章节/被拒资料标识）
submissions.py       不可变提交件（manifest 固定每问授权修订号）/发送/更正
```
