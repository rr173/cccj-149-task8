"""分区写作与最小披露权限（compartmentalized writing / least disclosure）。

负责人（LEAD）为每个问题设置：

- ``categories``：可见资料类别（CASE/SENT_REPORT/REGULATION/STATISTIC 的子集）；
- ``fields``：可见字段名（``[]`` 表示任何字段值都不可见，只给稳定占位符；
  ``["*"]`` 表示可见全部字段）；
- ``writers``：撰写人名单（规范化身份键）。

撰写人读取章节上下文时只能拿到 *获准类别* 的已锁定证据片段，片段中的
未获准字段值以稳定占位符 ``«HIDDEN:<field>#<hash>»`` 替换（同一字段在
所有上下文里占位符稳定，可比对但不泄露原值）；下载附件遵守同一授权边界。

授权修订号
----------
每问询一个单调递增的 ``inquiry_authz.authz_revision``。章节转派、人员
离组、授权收紧/放宽都在各自的 IMMEDIATE 事务内把它 +1；页面保存必须携带
读取时看到的修订号，旧号一律 ``STALE_AUTHZ_REVISION``——响应只给当前
修订号，绝不泄露新证据。

- 授权修订号与章节乐观修订号 *同时* 构成保存前提；转派与保存并发时
  IMMEDIATE 写锁串行，只有一个结果；
- 完全相同的授权请求再次到达不提升修订号、不增加权限、不产生重复留痕
  （内容幂等 + 审计帧 idempotency_key 双重兜底）；
- 封存后的提交件不因人员/权限变化而改写；后续更正（候选/更正底稿克隆
  章节与附件）必须由合格撰写人在 *当时有效* 的授权下重新保存/再认定，
  定稿复核按 as-of + 当前授权双重检查。

启用方式
--------
问询默认保持旧的宽松路径（``authz_revision=0``）；负责人通过
``enroll`` 启用（同事务建立名册与逐问授权基线）。启用后所有读取/保存/
上传/下载/定稿路径都执行授权边界。
"""
from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from . import audit, drafts, identity, materials
from .errors import (AuthzConflictError, ForbiddenError, InvalidActorError,
                     NotFoundError, NotEnrolledError, StaleAuthzRevisionError)
from .util import canonical_json

CATEGORIES = materials.CATEGORIES
PLACEHOLDER_PREFIX = "«HIDDEN"


# ---------------------------------------------------------------------------
# 身份
# ---------------------------------------------------------------------------
def _actor_key(actor) -> str:
    """写路径/受限读取的身份校验：空白/非字符串明确拒绝，绝不静默。"""
    try:
        return identity.validate_identity(actor, field="actor")
    except ValueError as exc:
        raise InvalidActorError(str(exc)) from None


# ---------------------------------------------------------------------------
# 授权状态读取
# ---------------------------------------------------------------------------
def authz_state(conn, inquiry_id: str) -> dict | None:
    """返回问询授权状态；未启用（无 inquiry_authz 行）返回 None。"""
    r = conn.execute("SELECT * FROM inquiry_authz WHERE inquiry_id=?",
                     (inquiry_id,)).fetchone()
    return dict(r) if r else None


def current_revision(conn, inquiry_id: str) -> int:
    st = authz_state(conn, inquiry_id)
    return st["authz_revision"] if st else 0


def is_enrolled(conn, inquiry_id: str) -> bool:
    st = authz_state(conn, inquiry_id)
    return bool(st and st["authz_revision"] > 0)


def is_lead(conn, inquiry_id: str, actor_key: str) -> bool:
    st = authz_state(conn, inquiry_id)
    return bool(st and st["lead_key"] == actor_key)


def membership_at(conn, inquiry_id: str, identity_key: str,
                  revision: int) -> dict | None:
    """as-of：某修订号时点上该身份最新的成员行；无记录返回 None。"""
    r = conn.execute(
        "SELECT * FROM inquiry_members WHERE inquiry_id=? AND identity_key=? "
        "AND since_revision<=? ORDER BY rowid DESC LIMIT 1",
        (inquiry_id, identity_key, revision)).fetchone()
    return dict(r) if r else None


def active_member(conn, inquiry_id: str, identity_key: str,
                  role: str | None = None) -> dict | None:
    """当前在册（最新行 active=1）成员；可限定角色。"""
    rev = current_revision(conn, inquiry_id)
    m = membership_at(conn, inquiry_id, identity_key, rev)
    if not m or not m["active"]:
        return None
    if role and m["role"] != role:
        return None
    return m


def grant_at(conn, inquiry_id: str, qid: str, revision: int) -> dict | None:
    """as-of：某修订号时点上问题 qid 的最新授权行；无记录返回 None。"""
    r = conn.execute(
        "SELECT * FROM question_grants WHERE inquiry_id=? AND qid=? "
        "AND revision<=? ORDER BY revision DESC, rowid DESC LIMIT 1",
        (inquiry_id, qid, revision)).fetchone()
    return _grant_row(r) if r else None


def current_grant(conn, inquiry_id: str, qid: str) -> dict | None:
    return grant_at(conn, inquiry_id, qid, current_revision(conn, inquiry_id))


def list_current_grants(conn, inquiry_id: str) -> list[dict]:
    inq = drafts.get_inquiry(conn, inquiry_id)
    rev = current_revision(conn, inquiry_id)
    return [g for g in (grant_at(conn, inquiry_id, q["qid"], rev)
                        for q in inq["questions"]) if g]


def _grant_row(r) -> dict:
    from .util import loads
    d = dict(r)
    d["categories"] = loads(d.pop("categories_json"), [])
    d["fields"] = loads(d.pop("fields_json"), [])
    d["writer_keys"] = loads(d.pop("writer_keys_json"), [])
    d["writers_raw"] = loads(d.pop("writers_raw_json"), [])
    return d


def list_members(conn, inquiry_id: str, *, active_only: bool = False) -> list[dict]:
    """成员名册。默认返回全部台账行（含离组历史）；active_only 只给当前在册。"""
    rows = conn.execute(
        "SELECT * FROM inquiry_members WHERE inquiry_id=? ORDER BY rowid",
        (inquiry_id,)).fetchall()
    out = [dict(r) for r in rows]
    if active_only:
        latest: dict[str, dict] = {}
        for m in out:
            latest[m["identity_key"]] = m
        out = [m for m in latest.values() if m["active"]]
    return out


# ---------------------------------------------------------------------------
# 授权修订推进（只在实质变化时 +1；调用方须已开启 IMMEDIATE 事务）
# ---------------------------------------------------------------------------
def _bump(conn, inquiry_id: str, now: str, *, lead_key: str | None = None) -> int:
    st = authz_state(conn, inquiry_id)
    if st is None:
        rev = 1
        conn.execute(
            "INSERT INTO inquiry_authz(inquiry_id,authz_revision,lead_key,"
            "updated_at) VALUES(?,?,?,?)", (inquiry_id, rev, lead_key, now))
        return rev
    rev = st["authz_revision"] + 1
    conn.execute(
        "UPDATE inquiry_authz SET authz_revision=?, lead_key=COALESCE(?,lead_key),"
        "updated_at=? WHERE inquiry_id=?", (rev, lead_key, now, inquiry_id))
    return rev


def _bump_cas(conn, inquiry_id: str, now: str, expected: int,
              *, lead_key: str | None = None) -> int:
    """条件推进：只有当前修订号恰为 *expected* 时 +1（行级 CAS）。

    SQLite 写事务全局串行：转派/收紧/保存交错时，后到者的 CAS 命中 0 行，
    调用方据此抛 AUTHZ_CONFLICT（VERSION_MOVED），保证“只有一个结果”。
    返回新修订号；0 表示修订号已被他人推进。
    """
    row = conn.execute(
        "UPDATE inquiry_authz SET authz_revision=authz_revision+1,"
        "lead_key=COALESCE(?,lead_key),updated_at=? "
        "WHERE inquiry_id=? AND authz_revision=? "
        "RETURNING authz_revision",
        (lead_key, now, inquiry_id, expected)).fetchone()
    return row["authz_revision"] if row else 0


def _add_member_row(conn, *, inquiry_id, key, raw, role, active, revision, reason,
                    added_by, now) -> None:
    conn.execute(
        "INSERT INTO inquiry_members(id,inquiry_id,identity_key,raw_identity,role,"
        "active,since_revision,reason,added_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (uuid.uuid4().hex, inquiry_id, key, raw, role, 1 if active else 0,
         revision, reason, added_by, now))


# ---------------------------------------------------------------------------
# 启用 / 名册变更
# ---------------------------------------------------------------------------
def enroll(conn, inquiry_id: str, *, lead: str, writers: list[str] | None = None,
           grants: dict | None = None, enrolled_by: str | None = None,
           idempotency_key: str | None = None, now: str | None = None) -> dict:
    """启用分区授权：建立负责人、撰写人名册与逐问授权基线（修订号 1）。

    - 未启用过：幂等键重放返回同一结果；重复启用（无幂等键）也返回既有状态，
      绝不产生第二个基线修订；
    - 已启用：作为幂等登记处理（不推进修订号、不重复留痕），调用方若要
      变更名册/授权应走 set_members / put_question_policy。

    grants: {qid: {"categories": [...], "fields": [...], "writers": [raw,...]}}，
    省略的问题默认 *零可见*（空类别/空字段/空名单）——最小披露缺省。
    """
    from .util import utc_now_iso
    now = now or utc_now_iso()
    lead_key = _actor_key(lead)
    idem = idempotency_key or f"AUTHZ-ENROLL:{inquiry_id}"
    existing = authz_state(conn, inquiry_id)
    if existing:
        return _enrollment_view(conn, inquiry_id, deduped=True)

    # 解析撰写人名单（重复身份折叠，原始值留痕）
    writer_keys, writers_raw = _normalize_roster(writers or [])
    if lead_key in writer_keys:  # 负责人不必再占撰写人槽
        writer_keys = [k for k in writer_keys if k != lead_key]
        writers_raw = [r for r in writers_raw
                       if identity.normalize_identity(r) != lead_key]

    inq = drafts.get_inquiry(conn, inquiry_id)
    valid_qids = [q["qid"] for q in inq["questions"]]
    grants = grants or {}
    unknown = [q for q in grants if q not in valid_qids]
    if unknown:
        raise AuthzConflictError("授权请求包含问询清单之外的问题",
                                 details={"unknown_qids": unknown})

    rev = _bump(conn, inquiry_id, now, lead_key=lead_key)
    _add_member_row(conn, inquiry_id=inquiry_id, key=lead_key, raw=lead,
                    role="LEAD", active=True, revision=rev, reason="ENROLL",
                    added_by=enrolled_by or lead, now=now)
    for raw, key in zip(writers_raw, writer_keys):
        _add_member_row(conn, inquiry_id=inquiry_id, key=key, raw=raw,
                        role="WRITER", active=True, revision=rev,
                        reason="ENROLL", added_by=enrolled_by or lead, now=now)
    for qid in valid_qids:
        spec = grants.get(qid, {})
        _insert_grant(conn, inquiry_id=inquiry_id, qid=qid, revision=rev,
                      categories=spec.get("categories", []),
                      fields=spec.get("fields", []),
                      writers=spec.get("writers", []), now=now,
                      updated_by=enrolled_by or lead,
                      validate_writers=False)  # 基线行允许名单为空
    audit.append_event(conn, "AUTHZ_ENROLLED",
                       f"分区授权启用（修订号 {rev}，负责人 {lead}，"
                       f"{len(writer_keys)} 名撰写人）",
                       payload={"inquiry_id": inquiry_id, "authz_revision": rev,
                                "lead_key": lead_key,
                                "writer_keys": writer_keys,
                                "qids": valid_qids},
                       actor=enrolled_by or lead, inquiry_id=inquiry_id,
                       idempotency_key=idem, created_at=now)
    return _enrollment_view(conn, inquiry_id, deduped=False)


def _normalize_roster(values: list[str]) -> tuple[list[str], list[str]]:
    """身份名单规范化：折叠等价/重复写法，返回 (keys, 对应首个原始值)。"""
    keys: list[str] = []
    raws: list[str] = []
    for v in values or []:
        k = _actor_key(v)
        if k in keys:
            continue
        keys.append(k)
        raws.append(v)
    return keys, raws


def set_members(conn, inquiry_id: str, *, writers: list[str], action: str,
                updated_by: str, reason: str = "",
                idempotency_key: str | None = None,
                now: str | None = None) -> dict:
    """变更撰写人名册（只有负责人可操作）。

    action='ADD'：加入（已在册的等价身份幂等跳过）；
    action='REMOVE'：离组（置 inactive；旧页面授权修订号随即失效）；
    action='REACTIVATE'：离组后重新加入。

    只有 *实质变化* 推进修订号并留痕；完全相同的请求（无新变化）不推进、
    不重复留痕。相同 idempotency_key 的重放返回当时结果。
    """
    from .util import utc_now_iso
    now = now or utc_now_iso()
    st = _require_enrolled(conn, inquiry_id)
    actor_key = _actor_key(updated_by)
    if st["lead_key"] != actor_key:
        raise ForbiddenError("只有负责人可以变更成员名册")
    if action not in ("ADD", "REMOVE", "REACTIVATE"):
        raise AuthzConflictError(f"未知名册动作: {action}")
    keys, raws = _normalize_roster(writers)
    rev0 = st["authz_revision"]
    idem = idempotency_key or f"AUTHZ-MEMBERS:{inquiry_id}:{action}:" \
                              + hashlib.sha256(canonical_json(keys).encode("utf-8")) \
                              .hexdigest()[:16]
    existing = conn.execute(
        "SELECT id FROM audit_events WHERE idempotency_key=?", (idem,)).fetchone()
    if existing:
        return {"changed": False, "deduped": True,
                "authz_revision": current_revision(conn, inquiry_id)}

    changes: list[dict] = []
    for raw, key in zip(raws, keys):
        m = active_member(conn, inquiry_id, key)
        latest = membership_at(conn, inquiry_id, key, rev0)
        if action == "ADD":
            if m is not None:
                continue  # 已在册（任意角色）：幂等跳过
            changes.append({"identity_key": key, "raw": raw, "action": "ADD"})
        elif action == "REMOVE":
            if m is None or m["role"] != "WRITER":
                continue  # 本就不在册撰写人：幂等跳过（负责人不可由此移除）
            changes.append({"identity_key": key, "raw": raw, "action": "REMOVE"})
        else:  # REACTIVATE
            if m is not None:
                continue
            if latest is None:
                raise AuthzConflictError(
                    f"身份 {raw} 从未加入，不能 REACTIVATE；请使用 ADD",
                    details={"identity": raw})
            changes.append({"identity_key": key, "raw": raw,
                            "action": "REACTIVATE"})

    if not changes:
        return {"changed": False, "deduped": True, "authz_revision": rev0}
    # 行级 CAS：与并发的转派/政策变更/其他名册变更竞争时只有一方成功
    rev = _bump_cas(conn, inquiry_id, now, rev0)
    if not rev:
        raise AuthzConflictError(
            f"授权已被并发更新（期望修订 {rev0}）",
            details={"expected": rev0,
                     "current": current_revision(conn, inquiry_id),
                     "reason": "VERSION_MOVED"})
    for ch in changes:
        _add_member_row(conn, inquiry_id=inquiry_id, key=ch["identity_key"],
                        raw=ch["raw"], role="WRITER",
                        active=0 if ch["action"] == "REMOVE" else 1,
                        revision=rev, reason=reason or ch["action"],
                        added_by=updated_by, now=now)
    audit.append_event(conn, "AUTHZ_MEMBERS_CHANGED",
                       f"成员名册变更（修订号 {rev}，{len(changes)} 人：{action}）",
                       payload={"inquiry_id": inquiry_id, "authz_revision": rev,
                                "action": action,
                                "changes": [{"identity_key": c["identity_key"],
                                             "action": c["action"]}
                                            for c in changes],
                                "reason": reason},
                       actor=updated_by, inquiry_id=inquiry_id,
                       idempotency_key=idem, created_at=now)
    return {"changed": True, "deduped": False, "authz_revision": rev,
            "changes": [{"identity_key": c["identity_key"],
                         "action": c["action"]} for c in changes]}


def transfer_lead(conn, inquiry_id: str, *, new_lead: str, updated_by: str,
                  reason: str = "", idempotency_key: str | None = None,
                  now: str | None = None) -> dict:
    """负责人转派：新负责人必须已是在册成员（先 ADD 再转派）。

    转派立即推进授权修订号；所有撰写人页面携带的旧号失效。
    同一目标的重复转派幂等（不产生第二条留痕）。
    """
    from .util import utc_now_iso
    now = now or utc_now_iso()
    st = _require_enrolled(conn, inquiry_id)
    actor_key = _actor_key(updated_by)
    if st["lead_key"] != actor_key:
        raise ForbiddenError("只有现任负责人可以转派")
    new_key = _actor_key(new_lead)
    if new_key == st["lead_key"]:
        return {"changed": False, "deduped": True,
                "authz_revision": st["authz_revision"]}
    m = active_member(conn, inquiry_id, new_key)
    if m is None:
        raise AuthzConflictError(
            "新负责人必须先以成员身份加入名册",
            details={"new_lead_key": new_key})
    idem = idempotency_key or f"AUTHZ-TRANSFER:{inquiry_id}:{new_key}"
    existing = conn.execute(
        "SELECT id FROM audit_events WHERE idempotency_key=?", (idem,)).fetchone()
    if existing:
        return {"changed": False, "deduped": True,
                "authz_revision": current_revision(conn, inquiry_id)}
    rev0 = st["authz_revision"]
    rev = _bump_cas(conn, inquiry_id, now, rev0, lead_key=new_key)
    if not rev:
        raise AuthzConflictError(
            "授权已被并发更新，转派失败",
            details={"expected": rev0,
                     "current": current_revision(conn, inquiry_id),
                     "reason": "VERSION_MOVED"})
    # 旧负责人保留 LEAD 历史行；新负责人新增 LEAD active 行（同身份可能已有
    # WRITER 行——角色以最新一行判定）。
    _add_member_row(conn, inquiry_id=inquiry_id, key=new_key, raw=new_lead,
                    role="LEAD", active=True, revision=rev,
                    reason=reason or "TRANSFER_LEAD", added_by=updated_by, now=now)
    audit.append_event(conn, "AUTHZ_LEAD_TRANSFERRED",
                       f"负责人转派（修订号 {rev}）：{updated_by} -> {new_lead}",
                       payload={"inquiry_id": inquiry_id, "authz_revision": rev,
                                "old_lead_key": st["lead_key"],
                                "new_lead_key": new_key, "reason": reason},
                       actor=updated_by, inquiry_id=inquiry_id,
                       idempotency_key=idem, created_at=now)
    return {"changed": True, "deduped": False, "authz_revision": rev,
            "lead_key": new_key}


# ---------------------------------------------------------------------------
# 逐问授权
# ---------------------------------------------------------------------------
def _validate_spec(conn, inquiry_id: str, qid: str, categories: list[str],
                   fields: list[str], writers: list[str], *,
                   validate_writers: bool = True
                   ) -> tuple[list[str], list[str], list[str], list[str]]:
    inq = drafts.get_inquiry(conn, inquiry_id)
    if qid not in {q["qid"] for q in inq["questions"]}:
        raise NotFoundError(f"问题 {qid} 不在问询清单中")
    bad_cat = [c for c in categories if c not in CATEGORIES]
    if bad_cat:
        raise AuthzConflictError("授权类别非法",
                                 details={"bad_categories": bad_cat})
    if not isinstance(fields, list) or any(not isinstance(f, str) or not f
                                           for f in fields):
        raise AuthzConflictError("可见字段必须是非空字符串列表（[]=全部隐藏）")
    keys, raws = _normalize_roster(writers)
    if validate_writers:
        for raw, key in zip(raws, keys):
            m = active_member(conn, inquiry_id, key, role="WRITER")
            if m is None:
                raise AuthzConflictError(
                    f"撰写人 {raw} 不是在列在册成员；请先加入名册",
                    details={"writer": raw})
    # 类别不得超出问询冻结的可引用范围（最小披露只能在冻结范围内再收紧）
    scope_cats = set(inq["scope"].get("allowed_categories") or [])
    out_of_scope = sorted(set(categories) - scope_cats)
    if out_of_scope:
        raise AuthzConflictError(
            "授权类别超出问询登记冻结的可引用类别范围",
            details={"out_of_scope_categories": out_of_scope})
    return list(categories), list(fields), keys, raws


def _insert_grant(conn, *, inquiry_id, qid, revision, categories, fields,
                  writers, updated_by, now, validate_writers=True) -> None:
    cats, flds, keys, raws = _validate_spec(
        conn, inquiry_id, qid, list(categories), list(fields), list(writers),
        validate_writers=validate_writers)
    conn.execute(
        "INSERT INTO question_grants(id,inquiry_id,qid,revision,categories_json,"
        "fields_json,writer_keys_json,writers_raw_json,updated_by,created_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?)",
        (uuid.uuid4().hex, inquiry_id, qid, revision,
         json.dumps(cats, ensure_ascii=False, sort_keys=True),
         json.dumps(flds, ensure_ascii=False, sort_keys=True),
         json.dumps(keys, ensure_ascii=False, sort_keys=True),
         json.dumps(raws, ensure_ascii=False, sort_keys=True),
         updated_by, now))


def put_question_policy(conn, inquiry_id: str, qid: str, *, categories: list[str],
                        fields: list[str], writers: list[str],
                        expected_revision: int | None = None,
                        updated_by: str, reason: str = "",
                        idempotency_key: str | None = None,
                        now: str | None = None) -> dict:
    """负责人设置/收紧/放宽某问题的可见类别、可见字段与撰写人名单。

    - ``expected_revision`` 乐观条件：基于过期视图设置返回
      ``AUTHZ_CONFLICT``（VERSION_MOVED）；
    - 与当前授权 *完全相同* 的请求：不推进修订号、不写新版本行、不重复留痕；
    - 任何实质差异（含转派撰写人、收紧、放宽）原子推进授权修订号。
    """
    from .util import utc_now_iso
    now = now or utc_now_iso()
    st = _require_enrolled(conn, inquiry_id)
    actor_key = _actor_key(updated_by)
    if st["lead_key"] != actor_key:
        raise ForbiddenError("只有负责人可以设置逐问授权")
    rev0 = st["authz_revision"]
    if expected_revision is not None and expected_revision != rev0:
        raise AuthzConflictError(
            f"授权已被他人更新（期望修订 {expected_revision}，当前 {rev0}）",
            details={"expected": expected_revision, "current": rev0,
                     "reason": "VERSION_MOVED"})
    cats, flds, keys, raws = _validate_spec(
        conn, inquiry_id, qid, list(categories), list(fields), list(writers))

    cur = grant_at(conn, inquiry_id, qid, rev0)
    cur_spec = None
    if cur:
        cur_spec = (sorted(cur["categories"]), sorted(cur["fields"]),
                    sorted(cur["writer_keys"]))
    new_spec = (sorted(cats), sorted(flds), sorted(keys))
    if cur_spec == new_spec:
        return {"changed": False, "deduped": True, "authz_revision": rev0, "qid": qid}

    idem = idempotency_key or (
        f"AUTHZ-GRANT:{inquiry_id}:{qid}:"
        + hashlib.sha256(canonical_json([sorted(cats), sorted(flds),
                                         sorted(keys)]).encode("utf-8"))
        .hexdigest()[:16])
    if conn.execute("SELECT id FROM audit_events WHERE idempotency_key=?",
                    (idem,)).fetchone():
        return {"changed": False, "deduped": True,
                "authz_revision": current_revision(conn, inquiry_id), "qid": qid}

    rev = _bump_cas(conn, inquiry_id, now, rev0)
    if not rev:
        raise AuthzConflictError(
            f"授权已被并发更新（期望修订 {rev0}）",
            details={"expected": rev0,
                     "current": current_revision(conn, inquiry_id),
                     "reason": "VERSION_MOVED"})
    _insert_grant_raw(conn, inquiry_id=inquiry_id, qid=qid, revision=rev,
                      categories=cats, fields=flds, writer_keys=keys,
                      writers_raw=raws, updated_by=updated_by, now=now)
    change_kind = _describe_grant_change(cur, cats, flds, keys)
    audit.append_event(conn, "AUTHZ_POLICY_CHANGED",
                       f"问题 {qid} 授权变更（修订号 {rev}：{change_kind}）",
                       payload={"inquiry_id": inquiry_id, "qid": qid,
                                "authz_revision": rev,
                                "categories": cats, "fields": flds,
                                "writer_keys": keys, "change_kind": change_kind,
                                "reason": reason},
                       actor=updated_by, inquiry_id=inquiry_id,
                       idempotency_key=idem, created_at=now)
    return {"changed": True, "deduped": False, "authz_revision": rev, "qid": qid,
            "categories": cats, "fields": flds, "writer_keys": keys}


def _insert_grant_raw(conn, *, inquiry_id, qid, revision, categories, fields,
                      writer_keys, writers_raw, updated_by, now) -> None:
    conn.execute(
        "INSERT INTO question_grants(id,inquiry_id,qid,revision,categories_json,"
        "fields_json,writer_keys_json,writers_raw_json,updated_by,created_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?)",
        (uuid.uuid4().hex, inquiry_id, qid, revision,
         json.dumps(categories, ensure_ascii=False, sort_keys=True),
         json.dumps(fields, ensure_ascii=False, sort_keys=True),
         json.dumps(writer_keys, ensure_ascii=False, sort_keys=True),
         json.dumps(writers_raw, ensure_ascii=False, sort_keys=True),
         updated_by, now))


def _describe_grant_change(cur, cats, flds, keys) -> str:
    if cur is None:
        return "INITIAL"
    parts = []
    if set(cats) != set(cur["categories"]):
        parts.append("CATEGORIES")
    if set(flds) != set(cur["fields"]):
        parts.append("FIELDS")
    if set(keys) != set(cur["writer_keys"]):
        parts.append("WRITERS")
    return "+".join(parts) or "NOOP"


# ---------------------------------------------------------------------------
# 受限投影：证据片段 / 字段占位符
# ---------------------------------------------------------------------------
def placeholder(field: str) -> str:
    """同一字段 -> 同一稳定占位符（不含原值；跨上下文可比对）。"""
    h = hashlib.sha256(field.encode("utf-8")).hexdigest()[:10]
    return f"{PLACEHOLDER_PREFIX}:{field}#{h}»"


def project_fields(obj: Any, allowed_fields: list[str]) -> Any:
    """按可见字段投影资料内容。

    - ``["*"]``：全部可见；
    - 具体字段列表：命中的键保留原值，其余键替换为该字段的稳定占位符；
      列表整体不可见时元素替换为占位符（绝不逐个泄露）；
    - ``[]``：任何值不可见（dict 给键+占位符，标量给单个占位符）。
    """
    if allowed_fields == ["*"]:
        return obj
    allow = set(allowed_fields)
    return _project(obj, allow, ())


def _project(obj: Any, allow: set[str], path: tuple[str, ...]) -> Any:
    pname = ".".join(path)
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            kp = path + (str(k),)
            kname = ".".join(kp)
            if str(k) in allow or kname in allow:
                out[k] = _project(v, allow, kp)
            else:
                out[k] = placeholder(str(k))
        return out
    if isinstance(obj, list):
        if pname and pname in allow:
            return obj
        return [_project(v, allow, path + ("[]",)) if isinstance(v, (dict, list))
                else placeholder(pname or "item") for v in obj]
    if pname in allow or (not path and "*" in allow):
        return obj
    return placeholder(pname or "value")


def _pin_category_allowed(conn, inquiry, pin: dict, grant: dict) -> bool:
    if pin["category"] not in grant["categories"]:
        return False
    # 问询冻结范围是外层边界（pin 锁定时已校验，这里复核一次）
    scope = inquiry["scope"]
    allowed_ids = set(scope.get("allowed_material_ids") or [])
    allowed_cats = set(scope.get("allowed_categories") or [])
    return pin["material_id"] in allowed_ids and pin["category"] in allowed_cats


def visible_evidence(conn, draft: dict, grant: dict) -> list[dict]:
    """按问题授权投影该底稿的已锁定证据片段（只含获准类别，字段最小披露）。"""
    inquiry = drafts.get_inquiry(conn, draft["inquiry_id"])
    out = []
    for pin in sorted(draft["pins"], key=lambda p: p["ref"]):
        if not _pin_category_allowed(conn, inquiry, pin, grant):
            continue
        mat = materials.resolve_row(conn, pin["material_row_id"])
        content = materials_loads(mat["content_json"]) if mat else None
        out.append({
            "ref": pin["ref"],
            "material_id": pin["material_id"],
            "version": pin["version"],
            "category": pin["category"],
            "title": mat["title"] if mat else "",
            "content": project_fields(content, grant["fields"]),
            "content_hash": pin["content_hash"],
        })
    return out


def materials_loads(s: str):
    return json.loads(s)


# ---------------------------------------------------------------------------
# 受限上下文读取
# ---------------------------------------------------------------------------
def read_section_context(conn, draft_id: str, qid: str, *, actor: str,
                         now: str | None = None) -> dict:
    """撰写人读取章节上下文：只能拿到获准证据片段（敏感值稳定占位）。

    - 未启用授权：legacy 全量上下文（保持旧行为）；
    - 负责人：可见全部已锁定证据（原值），用于组稿/核对；
    - 在列撰写人：按该问题 *当前* 授权投影；不是该问题撰写人 -> FORBIDDEN；
      被拒类别直接不出现（不确认其存在）；附件只返回获准溯源的元数据，
      下载另行授权；
    - 响应不携带任何被拒资料的内容或新证据。
    """
    from .util import utc_now_iso
    now = now or utc_now_iso()
    draft = drafts.get_draft(conn, draft_id)
    st = authz_state(conn, draft["inquiry_id"])
    if st is None:
        return _legacy_context(conn, draft, qid)
    actor_key = _actor_key(actor)
    rev = st["authz_revision"]
    lead = st["lead_key"] == actor_key
    grant = grant_at(conn, draft["inquiry_id"], qid, rev)
    section = next((s for s in draft["sections"] if s["qid"] == qid), None)

    if not lead:
        m = active_member(conn, draft["inquiry_id"], actor_key, role="WRITER")
        if m is None or grant is None or actor_key not in grant["writer_keys"]:
            raise ForbiddenError(
                "无权读取该问题上下文",
                details={"draft_id": draft_id, "qid": qid,
                         "authz_revision": rev,
                         "_denial": ("READ_CONTEXT", "不是该问题的在列撰写人")})

    if lead:
        evidence = _full_evidence(conn, draft)
        fields_mode = ["*"]
    else:
        evidence = visible_evidence(conn, draft, grant)
        fields_mode = grant["fields"]

    attachments = _visible_attachments(conn, draft, grant, lead=lead)
    return {
        "draft_id": draft_id,
        "qid": qid,
        "authz_revision": rev,
        "section_revision": section["revision"] if section else 0,
        "section_authz_revision": section["authz_revision"] if section else None,
        "section_body": section["body"] if section else "",
        "section_title": section["title"] if section else "",
        "visible_fields": fields_mode,
        "evidence": evidence,
        "attachments": attachments,
    }


def _full_evidence(conn, draft: dict) -> list[dict]:
    out = []
    for pin in sorted(draft["pins"], key=lambda p: p["ref"]):
        mat = materials.resolve_row(conn, pin["material_row_id"])
        out.append({
            "ref": pin["ref"], "material_id": pin["material_id"],
            "version": pin["version"], "category": pin["category"],
            "title": mat["title"] if mat else "",
            "content": materials_loads(mat["content_json"]) if mat else None,
            "content_hash": pin["content_hash"]})
    return out


def _legacy_context(conn, draft: dict, qid: str) -> dict:
    section = next((s for s in draft["sections"] if s["qid"] == qid), None)
    return {
        "draft_id": draft["id"], "qid": qid, "authz_revision": 0,
        "section_revision": section["revision"] if section else 0,
        "section_authz_revision": None,
        "section_body": section["body"] if section else "",
        "section_title": section["title"] if section else "",
        "visible_fields": ["*"], "evidence": _full_evidence(conn, draft),
        "attachments": [{"attachment_id": a["id"], "qid": a["qid"],
                         "filename": a["filename"], "sha256": a["sha256"],
                         "derived_from_ref": a["derived_from_ref"]}
                        for a in draft["attachments"]]}


def _visible_attachments(conn, draft: dict, grant: dict, *, lead: bool
                         ) -> list[dict]:
    """附件元数据遵守同一授权边界：只暴露归属本问题且溯源类别获准的项。"""
    out = []
    pins_by_ref = {p["ref"]: p for p in draft["pins"]}
    for a in draft["attachments"]:
        if not lead:
            if a.get("qid") != grant["qid"]:
                continue
            dref = a["derived_from_ref"]
            pin = pins_by_ref.get(dref)
            if pin is None or pin["category"] not in grant["categories"]:
                continue
            if not attachment_accessible(conn, draft, a, grant):
                continue
        out.append({"attachment_id": a["id"], "qid": a.get("qid"),
                    "filename": a["filename"], "sha256": a["sha256"],
                    "derived_from_ref": a["derived_from_ref"],
                    "size": a.get("size")})
    return out


# ---------------------------------------------------------------------------
# 保存授权：章节 / 附件
# ---------------------------------------------------------------------------
def _require_enrolled(conn, inquiry_id: str) -> dict:
    st = authz_state(conn, inquiry_id)
    if not st or st["authz_revision"] == 0:
        raise NotEnrolledError(f"问询 {inquiry_id} 未启用分区授权")
    return st


def check_section_save(conn, draft: dict, qid: str, *, actor: str,
                       expected_authz_revision: int | None,
                       body: str, now: str | None = None) -> dict:
    """章节保存的授权闸门（在章节乐观修订号检查 *之前* 执行）。

    返回 {"authz_revision": R, "as_lead": bool}；拒绝时抛领域异常。
    拒绝的每一项越权（引用/附件）写只增 authz_denials（只记标识）。
    本函数假定调用方已开启 IMMEDIATE 事务。
    """
    from .util import utc_now_iso
    now = now or utc_now_iso()
    inquiry_id = draft["inquiry_id"]
    st = _require_enrolled(conn, inquiry_id)
    rev = st["authz_revision"]
    actor_key = _actor_key(actor)
    lead = st["lead_key"] == actor_key

    if not lead:
        # 1) 人员离组/非在册 -> 拒绝
        m = active_member(conn, inquiry_id, actor_key, role="WRITER")
        if m is None:
            record_denial(conn, inquiry_id, action="SAVE_SECTION",
                          draft_id=draft["id"], qid=qid, actor_key=actor_key,
                          code="FORBIDDEN", authz_revision=rev,
                          detail="不是在册撰写人", now=now)
            raise ForbiddenError("无权撰写：不是该问询的在册撰写人",
                                 details={"draft_id": draft["id"], "qid": qid,
                                          "authz_revision": rev})
        # 2) 页面旧授权修订号 -> 立即失效（响应不含新证据）
        if expected_authz_revision is None:
            raise StaleAuthzRevisionError(
                "保存必须携带页面读取时的授权修订号",
                details={"draft_id": draft["id"], "qid": qid,
                         "expected": None, "current": rev})
        if expected_authz_revision != rev:
            record_denial(conn, inquiry_id, action="SAVE_SECTION",
                          draft_id=draft["id"], qid=qid, actor_key=actor_key,
                          code="STALE_AUTHZ_REVISION",
                          authz_revision=expected_authz_revision,
                          detail=f"授权修订号已推进到 {rev}", now=now)
            raise StaleAuthzRevisionError(
                "页面授权修订号已失效（章节转派/人员离组/权限收紧）",
                details={"draft_id": draft["id"], "qid": qid,
                         "expected": expected_authz_revision, "current": rev})
        # 3) 必须是该问题的在列撰写人（as-of 页面修订时点 + 当前都在列）
        g_at = grant_at(conn, inquiry_id, qid, expected_authz_revision)
        g_now = grant_at(conn, inquiry_id, qid, rev)
        if g_at is None or actor_key not in g_at["writer_keys"] \
                or g_now is None or actor_key not in g_now["writer_keys"]:
            record_denial(conn, inquiry_id, action="SAVE_SECTION",
                          draft_id=draft["id"], qid=qid, actor_key=actor_key,
                          code="FORBIDDEN", authz_revision=rev,
                          detail="不是该问题的在列撰写人", now=now)
            raise ForbiddenError("无权撰写该问题（撰写人名单未包含本人）",
                                 details={"draft_id": draft["id"], "qid": qid,
                                          "authz_revision": rev})
        denied = _check_body_refs(conn, draft, qid, body, g_now, actor_key,
                                  action="SAVE_SECTION", now=now)
        if denied:
            raise ForbiddenError(
                "正文引用/附件超出本问题授权边界",
                details={"draft_id": draft["id"], "qid": qid,
                         "authz_revision": rev, "denied": denied})
    else:
        # 负责人保存同样要带新鲜修订号（防止转派与保存交错产生双结果）；
        # 负责人不受逐问名单/类别限制（保留原有全量组稿能力）。
        if expected_authz_revision is not None \
                and expected_authz_revision != rev:
            record_denial(conn, inquiry_id, action="SAVE_SECTION",
                          draft_id=draft["id"], qid=qid, actor_key=actor_key,
                          code="STALE_AUTHZ_REVISION",
                          authz_revision=expected_authz_revision,
                          detail=f"负责人旧号保存，当前 {rev}", now=now)
            raise StaleAuthzRevisionError(
                "页面授权修订号已失效",
                details={"draft_id": draft["id"], "qid": qid,
                         "expected": expected_authz_revision, "current": rev})
    return {"authz_revision": rev, "as_lead": lead}


def _check_body_refs(conn, draft: dict, qid: str, body: str, grant: dict,
                     actor_key: str, *, action: str, now: str) -> list[dict]:
    """正文中的每次引用都必须在该问题当前获准类别内（在已锁定 pin 之上）。"""
    denied: list[dict] = []
    pins_by_ref = {p["ref"]: p for p in draft["pins"]}
    for c in drafts.extract_citations(body):
        if not c["version"]:
            continue  # 无版本引用由定稿校验（CITATION_VERSION_MISMATCH）处理
        ref = f"{c['prefix']}:{c['material_id']}@{c['version']}"
        pin = pins_by_ref.get(ref)
        if pin is None:
            continue  # 未锁定引用由定稿校验处理，不属授权边界
        if pin["category"] not in grant["categories"]:
            item = {"qid": qid, "code": "FORBIDDEN", "kind": "CITATION",
                    "denied_ref": ref, "category": pin["category"]}
            denied.append(item)
            record_denial(conn, draft["inquiry_id"], action=action,
                          draft_id=draft["id"], qid=qid, actor_key=actor_key,
                          code="FORBIDDEN", denied_ref=ref,
                          category=pin["category"],
                          authz_revision=current_revision(conn, draft["inquiry_id"]),
                          detail="引用类别未获准", now=now)
    attach_ids = {a["id"] for a in draft["attachments"]}
    for token in validation_attach_refs(body):
        if token not in attach_ids:
            continue  # 不存在附件由定稿校验处理
        a = next((x for x in draft["attachments"] if x["id"] == token), None)
        if a is None:
            continue
        if not attachment_accessible(conn, draft, a, grant):
            item = {"qid": qid, "code": "FORBIDDEN", "kind": "ATTACHMENT",
                    "attachment_id": token,
                    "denied_ref": a["derived_from_ref"], "category": None}
            dref = a["derived_from_ref"]
            pin = pins_by_ref.get(dref) if dref else None
            item["category"] = pin["category"] if pin else None
            denied.append(item)
            record_denial(conn, draft["inquiry_id"], action=action,
                          draft_id=draft["id"], qid=qid, actor_key=actor_key,
                          code="FORBIDDEN", attachment_id=token,
                          denied_ref=dref, category=item["category"],
                          authz_revision=current_revision(conn, draft["inquiry_id"]),
                          detail="附件不在本问题授权边界内", now=now)
    return denied


def validation_attach_refs(body: str) -> list[str]:
    from .validation import _extract_attach_refs
    return _extract_attach_refs(body or "")


def attachment_accessible(conn, draft: dict, attach: dict, grant: dict) -> bool:
    """附件是否在问题授权边界内：归属问题一致 + 溯源类别获准 + 已合格
    （上传于启用后的授权修订号，或在本草被再认定）。"""
    if attach.get("qid") != grant["qid"]:
        return False
    pins_by_ref = {p["ref"]: p for p in draft["pins"]}
    pin = pins_by_ref.get(attach["derived_from_ref"]) \
        if attach.get("derived_from_ref") else None
    if pin is None or pin["category"] not in grant["categories"]:
        return False
    if attach.get("upload_authz_revision") is not None:
        return True
    # 克隆附件：须在本草有再认定记录
    return bool(conn.execute(
        "SELECT 1 FROM attachment_requalifications WHERE draft_id=? "
        "AND attachment_id=? LIMIT 1",
        (draft["id"], attach["id"])).fetchone())


def check_attachment_upload(conn, draft: dict, *, qid: str | None,
                            derived_from_ref: str | None, actor: str,
                            now: str | None = None) -> dict:
    """附件上传授权闸门。返回 {"authz_revision": R, "qid": qid, "as_lead":...}。

    启用授权后：附件必须归属一个问题；撰写人须是该问题在列撰写人，且
    溯源资料类别在该问题获准类别内。下载遵守同一授权边界。
    """
    from .util import utc_now_iso
    now = now or utc_now_iso()
    inquiry_id = draft["inquiry_id"]
    st = _require_enrolled(conn, inquiry_id)
    rev = st["authz_revision"]
    actor_key = _actor_key(actor)
    lead = st["lead_key"] == actor_key
    if lead:
        if qid is None:
            raise AuthzConflictError(
                "启用授权后附件必须归属问题（qid）", details={"qid": None})
        return {"authz_revision": rev, "qid": qid, "as_lead": True}
    if qid is None:
        raise AuthzConflictError("启用授权后附件必须归属问题（qid）")
    m = active_member(conn, inquiry_id, actor_key, role="WRITER")
    if m is None:
        record_denial(conn, inquiry_id, action="UPLOAD_ATTACHMENT",
                      draft_id=draft["id"], qid=qid, actor_key=actor_key,
                      code="FORBIDDEN", authz_revision=rev,
                      detail="不是在册撰写人", now=now)
        raise ForbiddenError("无权上传附件：不是在册撰写人",
                             details={"draft_id": draft["id"], "qid": qid})
    grant = grant_at(conn, inquiry_id, qid, rev)
    if grant is None or actor_key not in grant["writer_keys"]:
        record_denial(conn, inquiry_id, action="UPLOAD_ATTACHMENT",
                      draft_id=draft["id"], qid=qid, actor_key=actor_key,
                      code="FORBIDDEN", authz_revision=rev,
                      detail="不是该问题在列撰写人", now=now)
        raise ForbiddenError("无权向该问题上传附件",
                             details={"draft_id": draft["id"], "qid": qid})
    pin = next((p for p in draft["pins"]
                if p["ref"] == derived_from_ref), None)
    if derived_from_ref is None or pin is None \
            or pin["category"] not in grant["categories"]:
        cat = pin["category"] if pin else None
        record_denial(conn, inquiry_id, action="UPLOAD_ATTACHMENT",
                      draft_id=draft["id"], qid=qid, actor_key=actor_key,
                      code="FORBIDDEN", denied_ref=derived_from_ref,
                      category=cat, authz_revision=rev,
                      detail="附件溯源类别未获准", now=now)
        raise ForbiddenError("附件溯源超出本问题授权类别",
                             details={"draft_id": draft["id"], "qid": qid,
                                      "denied_ref": derived_from_ref,
                                      "category": cat})
    return {"authz_revision": rev, "qid": qid, "as_lead": False}


def check_attachment_download(conn, draft: dict, attach: dict, *, actor: str,
                              now: str | None = None) -> None:
    """下载授权（与读取同一边界；越权逐条留痕，绝不返回内容）。"""
    from .util import utc_now_iso
    now = now or utc_now_iso()
    st = authz_state(conn, draft["inquiry_id"])
    if st is None:
        return  # legacy
    rev = st["authz_revision"]
    actor_key = _actor_key(actor)
    if st["lead_key"] == actor_key:
        return
    m = active_member(conn, draft["inquiry_id"], actor_key, role="WRITER")
    qid = attach.get("qid")
    grant = grant_at(conn, draft["inquiry_id"], qid, rev) if qid else None
    if m is None or grant is None or actor_key not in grant["writer_keys"] \
            or not attachment_accessible(conn, draft, attach, grant):
        record_denial(conn, draft["inquiry_id"], action="DOWNLOAD_ATTACHMENT",
                      draft_id=draft["id"], qid=qid, actor_key=actor_key,
                      code="FORBIDDEN", attachment_id=attach["id"],
                      denied_ref=attach.get("derived_from_ref"),
                      authz_revision=rev, detail="下载越权", now=now)
        raise ForbiddenError("无权下载该附件",
                             details={"draft_id": draft["id"], "qid": qid,
                                      "attachment_id": attach["id"]})


def requalify_attachment(conn, draft_id: str, attachment_id: str, qid: str, *,
                         actor: str, idempotency_key: str | None = None,
                         now: str | None = None) -> dict:
    """克隆附件在当前授权下重新认定（候选/更正定稿前置条件之一）。

    负责人或该问题在列撰写人可操作；溯源类别仍须在当前授权范围内。
    同 (草稿,附件,修订号) 幂等；收紧后旧再认定自然不满足“当前授权”，
    须重新认定（新修订号新行）。
    """
    from .util import utc_now_iso
    now = now or utc_now_iso()
    draft = drafts.get_draft(conn, draft_id)
    st = _require_enrolled(conn, draft["inquiry_id"])
    actor_key = _actor_key(actor)
    rev = st["authz_revision"]
    lead = st["lead_key"] == actor_key
    grant = grant_at(conn, draft["inquiry_id"], qid, rev)
    attach = next((a for a in draft["attachments"] if a["id"] == attachment_id),
                  None)
    if attach is None:
        raise NotFoundError(f"附件不存在: {attachment_id}")
    if not lead:
        m = active_member(conn, draft["inquiry_id"], actor_key, role="WRITER")
        if m is None or grant is None or actor_key not in grant["writer_keys"]:
            raise ForbiddenError("无权再认定该附件",
                                 details={"draft_id": draft_id, "qid": qid,
                                          "attachment_id": attachment_id})
    if grant is None:
        raise AuthzConflictError(f"问题 {qid} 尚无授权")
    pins_by_ref = {p["ref"]: p for p in draft["pins"]}
    pin = pins_by_ref.get(attach["derived_from_ref"]) \
        if attach.get("derived_from_ref") else None
    if attach.get("qid") != qid or pin is None \
            or pin["category"] not in grant["categories"]:
        raise ForbiddenError(
            "附件溯源/归属不在当前授权边界内，不能再认定",
            details={"draft_id": draft_id, "qid": qid,
                     "attachment_id": attachment_id,
                     "denied_ref": attach.get("derived_from_ref"),
                     "category": pin["category"] if pin else None})
    dup = conn.execute(
        "SELECT id FROM attachment_requalifications WHERE draft_id=? "
        "AND attachment_id=? AND authz_revision=?",
        (draft_id, attachment_id, rev)).fetchone()
    if dup:
        return {"deduped": True, "authz_revision": rev,
                "attachment_id": attachment_id, "qid": qid}
    conn.execute(
        "INSERT INTO attachment_requalifications(id,draft_id,attachment_id,qid,"
        "requalified_by_key,requalified_by_raw,authz_revision,created_at)"
        " VALUES(?,?,?,?,?,?,?,?)",
        (uuid.uuid4().hex, draft_id, attachment_id, qid, actor_key, actor,
         rev, now))
    audit.append_event(conn, "ATTACHMENT_REQUALIFIED",
                       f"附件再认定 {attachment_id}（问题 {qid}，修订号 {rev}）",
                       payload={"draft_id": draft_id, "attachment_id": attachment_id,
                                "qid": qid, "authz_revision": rev,
                                "denied_ref": None,
                                "derived_from_ref": attach["derived_from_ref"]},
                       actor=actor, inquiry_id=draft["inquiry_id"],
                       draft_id=draft_id,
                       idempotency_key=idempotency_key
                       or f"REQUAL:{draft_id}:{attachment_id}:{rev}",
                       created_at=now)
    return {"deduped": False, "authz_revision": rev,
            "attachment_id": attachment_id, "qid": qid}


# ---------------------------------------------------------------------------
# 定稿前逐问资格复核（as-of + 当前授权）
# ---------------------------------------------------------------------------
def finalize_authz_checks(conn, draft: dict) -> list[dict]:
    """定稿前逐问确认每次引用/附件上传时都具有读取资格。

    返回越权条目列表（空=全部通过）。每条含问题、章节与被拒资料 *标识*，
    不含受保护内容。对封存后的答复永不运行（提交件不可变）；候选/更正
    克隆的章节（authz_revision IS NULL）必须在当前授权下重新保存，
    克隆附件必须重新认定——即“后续纠正按当时有效的授权重新检查”。
    """
    st = authz_state(conn, draft["inquiry_id"])
    if st is None:
        return []
    rev = st["authz_revision"]
    issues: list[dict] = []
    sections_by_qid = {s["qid"]: s for s in draft["sections"]}

    for s in draft["sections"]:
        qid = s["qid"]
        g_now = grant_at(conn, draft["inquiry_id"], qid, rev)

        # a) 章节内容必须在授权启用后由合格撰写人重新保存（克隆继承内容
        #    为 NULL，必须重存；后续纠正按当时有效授权重新检查）。
        saved_rev = s["authz_revision"]
        was_lead = False
        submitter = identity.normalize_identity(s["updated_by"]) \
            if s["updated_by"] else None
        if saved_rev is None:
            issues.append(_issue(qid, "SECTION_UNQUALIFIED", section_id=s["id"],
                                 message="继承章节未在当前授权下重新保存"))
        elif saved_rev > rev:
            issues.append(_issue(qid, "SECTION_UNQUALIFIED", section_id=s["id"],
                                 message="章节授权修订号异常"))
        else:
            g_then = grant_at(conn, draft["inquiry_id"], qid, saved_rev)
            lead_then = _lead_at(conn, draft["inquiry_id"], saved_rev)
            was_lead = bool(submitter and submitter == lead_then)
            qualified_then = bool(
                g_then and submitter and (
                    submitter in g_then["writer_keys"] or was_lead))
            m_then = membership_at(conn, draft["inquiry_id"],
                                   submitter, saved_rev) if submitter else None
            if not qualified_then:
                issues.append(_issue(qid, "ANSWER_UNQUALIFIED", section_id=s["id"],
                                     message="保存人在保存时点不是该问题合格撰写人"))
            elif not m_then or not m_then["active"]:
                issues.append(_issue(qid, "ANSWER_UNQUALIFIED", section_id=s["id"],
                                     message="保存人在保存时点已离组"))
            elif not was_lead and (
                    g_now is None or submitter not in g_now["writer_keys"]):
                # 撰写人保存的内容：当前名单收紧即阻断；负责人保存的内容
                # 在保存时点合法即合格（负责人保留全量组稿能力）。
                issues.append(_issue(qid, "ANSWER_UNQUALIFIED", section_id=s["id"],
                                     message="保存人当前不在该问题撰写人名单内"))

        # c) 每次引用：保存时点类别获准 + 当前类别仍获准（章节本身不合格
        #    时也独立检查，不遗漏引用越权）。保存时为负责人的章节豁免逐问
        #    类别限制（负责人保留全量组稿能力）。
        pins_by_ref = {p["ref"]: p for p in draft["pins"]}
        g_then = grant_at(conn, draft["inquiry_id"], qid,
                          saved_rev) if saved_rev else None
        if not was_lead:
            for c in drafts.extract_citations(s["body"] + "\n" + s["title"]):
                if not c["version"]:
                    continue
                ref = f"{c['prefix']}:{c['material_id']}@{c['version']}"
                pin = pins_by_ref.get(ref)
                if pin is None:
                    continue
                if g_then is not None and pin["category"] not in g_then["categories"]:
                    issues.append(_issue(qid, "CITATION_UNQUALIFIED",
                                         section_id=s["id"],
                                         denied_ref=ref, category=pin["category"],
                                         message="引用在保存时点超出授权类别"))
                elif g_now is None or pin["category"] not in g_now["categories"]:
                    issues.append(_issue(qid, "CITATION_UNQUALIFIED",
                                         section_id=s["id"],
                                         denied_ref=ref, category=pin["category"],
                                         message="引用在当前授权下已被收紧"))

        # d) 附件：归属问题、当前边界、上传/再认定时点资格（独立检查）。
        #    上传人/再认定人为负责人时豁免逐问类别（但归属问题仍须一致）。
        for token in validation_attach_refs(s["body"]):
            a = next((x for x in draft["attachments"] if x["id"] == token), None)
            if a is None:
                continue
            if a.get("qid") != qid:
                issues.append(_issue(qid, "ATTACHMENT_UNQUALIFIED", section_id=s["id"],
                                     attachment_id=token,
                                     message="附件归属问题与引用章节不一致"))
                continue
            dref = a.get("derived_from_ref")
            pin = pins_by_ref.get(dref) if dref else None
            cat = pin["category"] if pin else None
            up_rev = a.get("upload_authz_revision")
            uploader_was_lead = False
            requalifier_was_lead = False
            if up_rev is not None:
                uploader_key = _identity_of(a.get("uploaded_by"))
                uploader_was_lead = bool(
                    uploader_key and uploader_key
                    == _lead_at(conn, draft["inquiry_id"], up_rev))
                if not uploader_was_lead:
                    g_up = grant_at(conn, draft["inquiry_id"], qid, up_rev)
                    if g_now is None or cat not in g_now["categories"]:
                        issues.append(_issue(qid, "ATTACHMENT_UNQUALIFIED",
                                             section_id=s["id"],
                                             attachment_id=token, denied_ref=dref,
                                             category=cat,
                                             message="附件溯源类别当前未获准"))
                    elif g_up is None or cat not in g_up["categories"]:
                        issues.append(_issue(qid, "ATTACHMENT_UNQUALIFIED",
                                             section_id=s["id"],
                                             attachment_id=token, denied_ref=dref,
                                             category=cat,
                                             message="附件上传时点类别未获准"))
            else:
                rq = conn.execute(
                    "SELECT * FROM attachment_requalifications WHERE draft_id=? "
                    "AND attachment_id=? ORDER BY rowid DESC LIMIT 1",
                    (draft["id"], a["id"])).fetchone()
                if rq is None:
                    issues.append(_issue(qid, "ATTACHMENT_UNQUALIFIED",
                                         section_id=s["id"], attachment_id=token,
                                         denied_ref=dref, category=cat,
                                         message="继承附件未在当前授权下重新认定"))
                else:
                    g_rq = grant_at(conn, draft["inquiry_id"], qid,
                                    rq["authz_revision"])
                    requalifier_was_lead = (
                        rq["requalified_by_key"]
                        == _lead_at(conn, draft["inquiry_id"],
                                    rq["authz_revision"]))
                    if not requalifier_was_lead:
                        if g_now is None or cat not in g_now["categories"]:
                            issues.append(_issue(qid, "ATTACHMENT_UNQUALIFIED",
                                                 section_id=s["id"],
                                                 attachment_id=token,
                                                 denied_ref=dref, category=cat,
                                                 message="附件溯源类别当前未获准"))
                        elif not g_rq or cat not in g_rq["categories"]:
                            issues.append(_issue(qid, "ATTACHMENT_UNQUALIFIED",
                                                 section_id=s["id"],
                                                 attachment_id=token,
                                                 denied_ref=dref, category=cat,
                                                 message="再认定时点类别未获准"))
    return issues


def _identity_of(raw):
    try:
        return identity.normalize_identity(raw) if raw else None
    except Exception:
        return None


def _lead_at(conn, inquiry_id: str, revision: int) -> str | None:
    """负责人在某修订号时点的身份键（由成员台账最新 LEAD 行重放）。"""
    r = conn.execute(
        "SELECT identity_key FROM inquiry_members WHERE inquiry_id=? AND role='LEAD'"
        " AND since_revision<=? ORDER BY rowid DESC LIMIT 1",
        (inquiry_id, revision)).fetchone()
    return r["identity_key"] if r else None


def _issue(qid: str, code: str, *, section_id: str | None = None,
           denied_ref: str | None = None, category: str | None = None,
           attachment_id: str | None = None, message: str = "") -> dict:
    d = {"severity": "blocking", "code": code, "qid": qid, "message": message,
         "section_id": section_id}
    if denied_ref is not None:
        d["denied_ref"] = denied_ref
    if category is not None:
        d["category"] = category
    if attachment_id is not None:
        d["attachment_id"] = attachment_id
    return d


# ---------------------------------------------------------------------------
# 越权留痕 / 变更历史
# ---------------------------------------------------------------------------
def record_denial(conn, inquiry_id: str, *, action: str, draft_id: str | None = None,
                  qid: str | None = None, section_id: str | None = None,
                  actor_key: str | None = None, code: str = "FORBIDDEN",
                  denied_ref: str | None = None, category: str | None = None,
                  attachment_id: str | None = None, authz_revision: int | None = None,
                  detail: str = "", now: str | None = None) -> None:
    from .util import utc_now_iso
    now = now or utc_now_iso()
    conn.execute(
        "INSERT INTO authz_denials(id,inquiry_id,draft_id,qid,section_id,actor_key,"
        "action,code,denied_ref,category,attachment_id,authz_revision,detail,"
        "created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (uuid.uuid4().hex, inquiry_id, draft_id, qid, section_id, actor_key,
         action, code, denied_ref, category, attachment_id, authz_revision,
         detail, now))
    audit.append_event(conn, "AUTHZ_DENIED",
                       f"授权拒绝 {action} 问题={qid} 资料={denied_ref or attachment_id or '-'}",
                       payload={"action": action, "draft_id": draft_id, "qid": qid,
                                "code": code, "denied_ref": denied_ref,
                                "category": category, "attachment_id": attachment_id,
                                "authz_revision": authz_revision,
                                # 只留标识，绝不回显正文/证据内容
                                "detail": detail[:200]},
                       actor=actor_key, inquiry_id=inquiry_id, draft_id=draft_id,
                       created_at=now)


def list_denials(conn, *, inquiry_id: str | None = None, draft_id: str | None = None,
                 qid: str | None = None, action: str | None = None) -> list[dict]:
    where, params = [], []
    if inquiry_id:
        where.append("inquiry_id=?"); params.append(inquiry_id)
    if draft_id:
        where.append("draft_id=?"); params.append(draft_id)
    if qid:
        where.append("qid=?"); params.append(qid)
    if action:
        where.append("action=?"); params.append(action)
    sql = "SELECT * FROM authz_denials"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY rowid"
    return [dict(r) for r in conn.execute(sql, params)]


def change_history(conn, inquiry_id: str, *, qid: str | None = None,
                   limit: int | None = None) -> list[dict]:
    """授权变更历史（只增审计帧的授权视图：启用/名册/转派/逐问政策/再认定/拒绝）。"""
    types = ("AUTHZ_ENROLLED", "AUTHZ_MEMBERS_CHANGED", "AUTHZ_LEAD_TRANSFERRED",
             "AUTHZ_POLICY_CHANGED", "ATTACHMENT_REQUALIFIED", "AUTHZ_DENIED")
    events = audit.list_events(conn, inquiry_id=inquiry_id, limit=limit)
    out = []
    for e in events:
        if e["event_type"] not in types:
            continue
        if qid and e["payload"].get("qid") != qid \
                and e["event_type"] != "AUTHZ_ENROLLED":
            continue
        out.append({"seq": e["seq"], "event_type": e["event_type"],
                    "actor": e["actor"], "summary": e["summary"],
                    "payload": e["payload"], "created_at": e["created_at"]})
    return out


def grant_history(conn, inquiry_id: str, qid: str) -> list[dict]:
    """某问题的逐问授权版本台账（只增）。"""
    return [_grant_row(r) for r in conn.execute(
        "SELECT * FROM question_grants WHERE inquiry_id=? AND qid=? ORDER BY revision",
        (inquiry_id, qid))]


def _enrollment_view(conn, inquiry_id: str, *, deduped: bool) -> dict:
    st = authz_state(conn, inquiry_id)
    return {"inquiry_id": inquiry_id, "authz_revision": st["authz_revision"],
            "lead_key": st["lead_key"], "deduped": deduped,
            "grants": list_current_grants(conn, inquiry_id),
            "members": list_members(conn, inquiry_id, active_only=True)}
