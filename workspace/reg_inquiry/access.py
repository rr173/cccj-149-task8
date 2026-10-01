"""分区写作与最小披露权限（per-question grants / restricted context）。

授权模型
--------
- 每个问询有一个 *授权修订号* 游标（``auth_revision_seq``）：设置授权、
  章节转派、权限收紧、人员离组都在同一 IMMEDIATE 事务内推进它。撰写人
  页面携带读取时看到的修订号；旧号保存/上传一律 ``STALE_AUTH_REVISION``。
- 负责人（OWNER）可为每个问题设置一行当前有效授权（``question_grants``，
  只增版本化）：可见资料类别、可见字段、撰写人名单。相同授权请求再次
  到达返回既有行（不推进修订号、不增加权限、不产生重复留痕）。
- 组成员（``group_member_events`` 只增 + ``group_members`` 物化当前态）：
  离组后旧授权修订号立即失效；保存/上传按 *保存当时* 的成员关系与授权
  重放判定（定稿独立核验时同样按当时有效授权）。
- 无任何负责人/授权的问询处于 *非托管模式*：既有全量组稿行为保持可用
  （管理员原有的组稿/定稿/发送不受影响）。

最小披露
--------
- ``read_section_context`` 只返回该撰写人在该问题上获准的证据片段：
  未获准资料整段不出现（响应里甚至不含其引用锚，仅给出拒绝计数）；
  获准资料内未获准字段以 *稳定占位符* 替代——同一原值在库内始终映射到
  同一占位符（HMAC-SHA256 + 库盐），不可逆、不带原值信息。
- 附件下载遵守同一边界；正文保存/附件上传时复核引用与溯源资格，并扫描
  正文不得携带未授权字段的原值（越权拒绝只列定位锚，不回显受保护内容）。
"""
from __future__ import annotations

import hmac
import json
import uuid
from typing import Any

from . import audit, drafts, identity, materials
from .errors import (EvidenceAccessDeniedError, NotAssignedError,
                     NotAuthorizedError, NotGroupMemberError,
                     StaleAuthRevisionError)
from .util import loads, utc_now_iso

ROLE_OWNER = "OWNER"
ROLE_WRITER = "WRITER"
# 占位符固定形态：«SECRET:ab12...»，与披露策略的 «REDACTED..» 占位区分
_PLACEHOLDER_LEN = 12


# ---------------------------------------------------------------------------
# 库元数据（稳定占位符盐）
# ---------------------------------------------------------------------------
def placeholder_salt(conn) -> str:
    """取（必要时惰性创建）库级占位符盐。

    占位符 = HMAC-SHA256(库盐, 字段名 + 原始值)：同一库内相同字段相同值
    始终得到同一占位符（撰写人跨章节可稳定对照），但无法由占位符反推
    原值，且不同库盐不同（导出后占位符不可跨库链接）。
    """
    row = conn.execute("SELECT value FROM app_meta WHERE key='placeholder_salt'") \
        .fetchone()
    if row:
        return row["value"]
    salt = uuid.uuid4().hex
    conn.execute(
        "INSERT OR IGNORE INTO app_meta(key,value) VALUES('placeholder_salt',?)",
        (salt,))
    got = conn.execute(
        "SELECT value FROM app_meta WHERE key='placeholder_salt'").fetchone()
    return got["value"]


def make_placeholder(conn, field: str, value: Any) -> str:
    salt = placeholder_salt(conn)
    mac = hmac.new(salt.encode("utf-8"),
                   f"{field.casefold()}\0{value}".encode("utf-8"),
                   "sha256").hexdigest()[:_PLACEHOLDER_LEN]
    return f"«SECRET:{mac}»"


# ---------------------------------------------------------------------------
# 授权修订号
# ---------------------------------------------------------------------------
def current_revision(conn, inquiry_id: str) -> int:
    row = conn.execute(
        "SELECT revision FROM auth_revision_seq WHERE inquiry_id=?",
        (inquiry_id,)).fetchone()
    return row["revision"] if row else 0


def bump_revision(conn, inquiry_id: str) -> int:
    """在调用方事务内推进问询授权修订号（不存在则建游标，从 1 起）。"""
    conn.execute(
        "INSERT INTO auth_revision_seq(inquiry_id,revision) VALUES(?,1) "
        "ON CONFLICT(inquiry_id) DO UPDATE SET revision=revision+1",
        (inquiry_id,))
    return current_revision(conn, inquiry_id)


# ---------------------------------------------------------------------------
# 托管模式 / 成员关系
# ---------------------------------------------------------------------------
def is_managed(conn, inquiry_id: str) -> bool:
    """存在任意成员即视为已建立分区协作（进入托管模式）。"""
    return conn.execute(
        "SELECT 1 FROM group_members WHERE inquiry_id=? LIMIT 1",
        (inquiry_id,)).fetchone() is not None


def _member_event_rows(conn, inquiry_id: str, member_key: str) -> list:
    return [dict(r) for r in conn.execute(
        "SELECT * FROM group_member_events WHERE inquiry_id=? AND member_key=? "
        "ORDER BY rowid", (inquiry_id, member_key))]


def member_at(conn, inquiry_id: str, member_key: str, revision: int) -> dict | None:
    """重放成员事件，判定 *revision 当时* 的成员身份。

    返回 {"role": ..., "active": bool}；当时尚未入组/已离组返回 None。
    事件按追加顺序重放：JOINED/ROLE_CHANGED/LEFT，revision 单调。
    """
    state = None
    for ev in _member_event_rows(conn, inquiry_id, member_key):
        ev_rev = ev["auth_revision"]
        if ev_rev is None or ev_rev > revision:
            break
        if ev["action"] == "LEFT":
            state = None
        else:
            state = {"role": ev["role"], "active": True}
    return state


def current_member(conn, inquiry_id: str, member_key: str) -> dict | None:
    r = conn.execute(
        "SELECT * FROM group_members WHERE inquiry_id=? AND member_key=?",
        (inquiry_id, member_key)).fetchone()
    if not r or not r["active"]:
        return None
    return dict(r)


def is_owner_at(conn, inquiry_id: str, member_key: str, revision: int) -> bool:
    m = member_at(conn, inquiry_id, member_key, revision)
    return bool(m and m["role"] == ROLE_OWNER)


def is_active_owner(conn, inquiry_id: str, member_key: str) -> bool:
    m = current_member(conn, inquiry_id, member_key)
    return bool(m and m["role"] == ROLE_OWNER)


def list_members(conn, inquiry_id: str, *, active_only: bool = False) -> list[dict]:
    sql = ("SELECT inquiry_id,member_key,member_raw,role,active,joined_at,left_at "
           "FROM group_members WHERE inquiry_id=?")
    if active_only:
        sql += " AND active=1"
    sql += " ORDER BY rowid"
    return [dict(r) for r in conn.execute(sql, (inquiry_id,))]


def _count_active_owners(conn, inquiry_id: str) -> int:
    return conn.execute(
        "SELECT COUNT(*) AS n FROM group_members WHERE inquiry_id=? AND active=1 "
        "AND role='OWNER'", (inquiry_id,)).fetchone()["n"]


def seed_owner(conn, inquiry_id: str, owner: str | None, *, now: str | None = None
              ) -> None:
    """问询登记时登记人自动成为初始 OWNER（登记人缺省则不进入托管模式）。"""
    if not owner or not isinstance(owner, str) or not owner.strip():
        return
    add_member(conn, inquiry_id, owner, role=ROLE_OWNER, acted_by=owner, now=now)


def bootstrap_owner(conn, inquiry_id: str, owner: str, *,
                    acted_by: str | None = None, now: str | None = None) -> dict:
    """把一个 *非托管* 问询（无任何成员，常见于旧库迁移）显式纳入分区协作：
    登记第一位负责人。仅在尚无成员时可用一次，之后成员管理必须由 OWNER
    进行（避免任意人冒领）。
    """
    drafts.get_inquiry(conn, inquiry_id)
    if is_managed(conn, inquiry_id):
        raise NotAuthorizedError(
            "该问询已在分区协作管理中，不能重复引导负责人",
            details={"inquiry_id": inquiry_id})
    return add_member(conn, inquiry_id, owner, role=ROLE_OWNER,
                      acted_by=acted_by or owner, now=now)


def add_member(conn, inquiry_id: str, member: str, *, role: str = ROLE_WRITER,
               acted_by: str | None = None, now: str | None = None) -> dict:
    """加入成员或重新激活已离组成员（角色以本次为准）。幂等：当前已是该
    角色的活跃成员直接返回，不产生重复履历。
    """
    drafts.get_inquiry(conn, inquiry_id)
    member_key = identity.validate_identity(member)
    if role not in (ROLE_OWNER, ROLE_WRITER):
        raise ValueError("未知角色")
    now = now or utc_now_iso()

    existing = conn.execute(
        "SELECT * FROM group_members WHERE inquiry_id=? AND member_key=?",
        (inquiry_id, member_key)).fetchone()
    if existing and existing["active"] and existing["role"] == role:
        return dict(existing)

    revision = bump_revision(conn, inquiry_id)
    if existing:
        # 重新加入或角色变更：物化行复活/推进
        conn.execute(
            "UPDATE group_members SET member_raw=?, role=?, active=1, joined_at=?, "
            "left_at=NULL WHERE inquiry_id=? AND member_key=?",
            (member, role, now, inquiry_id, member_key))
        action = ("ROLE_CHANGED" if existing["active"] else "JOINED")
    else:
        conn.execute(
            "INSERT INTO group_members(inquiry_id,member_key,member_raw,role,active,"
            "joined_at) VALUES(?,?,?,? ,1,?)",
            (inquiry_id, member_key, member, role, now))
        action = "JOINED"
    conn.execute(
        "INSERT INTO group_member_events(id,inquiry_id,member_key,member_raw,action,"
        "role,auth_revision,acted_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (uuid.uuid4().hex, inquiry_id, member_key, member, action, role, revision,
         acted_by, now))
    audit.append_event(conn, "MEMBER_ADDED",
                       f"成员加入/变更 {member}（{role}）",
                       payload={"inquiry_id": inquiry_id, "member_key": member_key,
                                "role": role, "action": action,
                                "auth_revision": revision},
                       actor=acted_by, inquiry_id=inquiry_id, created_at=now)
    return dict(conn.execute(
        "SELECT * FROM group_members WHERE inquiry_id=? AND member_key=?",
        (inquiry_id, member_key)).fetchone())


def change_member_role(conn, inquiry_id: str, member: str, role: str, *,
                       acted_by: str | None = None, now: str | None = None) -> dict:
    member_key = identity.validate_identity(member)
    cur = current_member(conn, inquiry_id, member_key)
    if cur is None:
        from .errors import NotFoundError
        raise NotFoundError(f"活跃成员不存在: {member}")
    if role not in (ROLE_OWNER, ROLE_WRITER):
        raise ValueError("未知角色")
    if cur["role"] == role:
        return cur
    now = now or utc_now_iso()
    revision = bump_revision(conn, inquiry_id)
    conn.execute("UPDATE group_members SET role=? WHERE inquiry_id=? AND member_key=?",
                 (role, inquiry_id, member_key))
    conn.execute(
        "INSERT INTO group_member_events(id,inquiry_id,member_key,member_raw,action,"
        "role,auth_revision,acted_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (uuid.uuid4().hex, inquiry_id, member_key, cur["member_raw"],
         "ROLE_CHANGED", role, revision, acted_by, now))
    audit.append_event(conn, "MEMBER_ROLE_CHANGED",
                       f"成员角色变更 {cur['member_raw']} -> {role}",
                       payload={"inquiry_id": inquiry_id, "member_key": member_key,
                                "role": role, "auth_revision": revision},
                       actor=acted_by, inquiry_id=inquiry_id, created_at=now)
    return dict(conn.execute(
        "SELECT * FROM group_members WHERE inquiry_id=? AND member_key=?",
        (inquiry_id, member_key)).fetchone())


def remove_member(conn, inquiry_id: str, member: str, *,
                  acted_by: str | None = None, now: str | None = None) -> dict:
    """人员离组：离组事件 + 活跃置 0 + 推进授权修订号（旧页面立即失效），
    并把该成员仍在任的撰写人授权名单同步收紧（另推进修订由名单变化驱动；
    离组本身已推进一次，名单收紧在同一修订号内完成，不重复计数）。
    最后一个 OWNER 不允许离组（避免问询失去负责人）。
    """
    member_key = identity.validate_identity(member)
    cur = current_member(conn, inquiry_id, member_key)
    if cur is None:
        from .errors import NotFoundError
        raise NotFoundError(f"活跃成员不存在: {member}")
    if cur["role"] == ROLE_OWNER and _count_active_owners(conn, inquiry_id) <= 1:
        raise NotAuthorizedError("不能移除最后一个负责人（问询须至少保留一名 OWNER）",
                                 details={"inquiry_id": inquiry_id})
    now = now or utc_now_iso()
    revision = bump_revision(conn, inquiry_id)
    conn.execute(
        "UPDATE group_members SET active=0, left_at=? WHERE inquiry_id=? "
        "AND member_key=?", (now, inquiry_id, member_key))
    conn.execute(
        "INSERT INTO group_member_events(id,inquiry_id,member_key,member_raw,action,"
        "role,auth_revision,acted_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (uuid.uuid4().hex, inquiry_id, member_key, cur["member_raw"], "LEFT",
         cur["role"], revision, acted_by, now))

    # 离组者若仍是某些问题的撰写人，把这些问题的授权整体替换为去掉该成员
    # 的新版本（旧行 SUPERSEDED）。离组已经推进过一次修订号，名单收紧在
    # 同一事务内完成、不再额外推进号段（用同一 revision 标记新版本行）。
    affected_qids: list[str] = []
    for g in conn.execute(
            "SELECT * FROM question_grants WHERE inquiry_id=? AND status='ACTIVE'",
            (inquiry_id,)).fetchall():
        writers = loads(g["writers_json"], [])
        if member_key not in writers:
            continue
        new_writers = [w for w in writers if w != member_key]
        next_ver = conn.execute(
            "SELECT COALESCE(MAX(grant_version),0)+1 AS n FROM question_grants "
            "WHERE inquiry_id=? AND qid=?", (inquiry_id, g["qid"])).fetchone()["n"]
        conn.execute(
            "INSERT INTO question_grants(id,inquiry_id,qid,grant_version,"
            "visible_categories_json,visible_fields_json,material_ids_json,"
            "writers_json,status,auth_revision,created_by,created_at)"
            " VALUES(?,?,?,?,?,?,?,?,'ACTIVE',?,?,?)",
            (uuid.uuid4().hex, inquiry_id, g["qid"], next_ver,
             g["visible_categories_json"], g["visible_fields_json"],
             g["material_ids_json"],
             json.dumps(new_writers, ensure_ascii=False, sort_keys=True),
             revision, acted_by, now))
        conn.execute(
            "UPDATE question_grants SET status='SUPERSEDED',superseded_revision=? "
            "WHERE id=?", (revision, g["id"]))
        affected_qids.append(g["qid"])
    audit.append_event(conn, "MEMBER_REMOVED",
                       f"成员离组 {cur['member_raw']}（授权修订号推进至 {revision}）",
                       payload={"inquiry_id": inquiry_id, "member_key": member_key,
                                "auth_revision": revision,
                                "tightened_qids": affected_qids},
                       actor=acted_by, inquiry_id=inquiry_id, created_at=now)
    return {"member_key": member_key, "active": False,
            "auth_revision": revision, "tightened_qids": affected_qids}


# ---------------------------------------------------------------------------
# 每问授权（问题分派）
# ---------------------------------------------------------------------------
def _grant_row(r) -> dict:
    d = dict(r)
    d["visible_categories"] = loads(d.pop("visible_categories_json"), [])
    d["visible_fields"] = loads(d.pop("visible_fields_json"), [])
    d["material_ids"] = loads(d.pop("material_ids_json"), [])
    d["writers"] = loads(d.pop("writers_json"), [])
    return d


def active_grants(conn, inquiry_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM question_grants WHERE inquiry_id=? AND status='ACTIVE' "
        "ORDER BY qid", (inquiry_id,)).fetchall()
    return [_grant_row(r) for r in rows]


def get_active_grant(conn, inquiry_id: str, qid: str) -> dict | None:
    r = conn.execute(
        "SELECT * FROM question_grants WHERE inquiry_id=? AND qid=? AND "
        "status='ACTIVE'", (inquiry_id, qid)).fetchone()
    return _grant_row(r) if r else None


def grant_at(conn, inquiry_id: str, qid: str, revision: int) -> dict | None:
    """取 *revision 当时* 有效的授权（授权按其创建修订号生效，直到被
    SUPERSEDED——新版本号更大）。非托管/当时未分派返回 None。"""
    rows = conn.execute(
        "SELECT * FROM question_grants WHERE inquiry_id=? AND qid=? "
        "ORDER BY grant_version", (inquiry_id, qid)).fetchall()
    chosen = None
    for r in rows:
        if r["auth_revision"] <= revision:
            g = _grant_row(r)
            # 被取代时，取代发生的修订号之后旧授权失效
            if r["status"] == "ACTIVE" or (r["superseded_revision"] is not None
                                           and r["superseded_revision"] > revision):
                chosen = g
    return chosen


def _same_spec(a: dict, b: dict) -> bool:
    return (sorted(a["visible_categories"]) == sorted(b["visible_categories"])
            and sorted(a["visible_fields"]) == sorted(b["visible_fields"])
            and sorted(a["material_ids"]) == sorted(b["material_ids"])
            and sorted(a["writers"]) == sorted(b["writers"]))


def put_question_grant(conn, inquiry_id: str, qid: str, *,
                       visible_categories: list[str] | None = None,
                       visible_fields: list[str] | None = None,
                       material_ids: list[str] | None = None,
                       writers: list[str] | None = None,
                       actor: str | None = None, now: str | None = None) -> dict:
    """负责人为问题设置授权（旧行 SUPERSEDED，推进授权修订号）。

    - 仅当前 OWNER 可操作；
    - 可见类别/资料不得超出问询登记时冻结的可引用范围（授权只能收紧）；
    - 撰写人必须是当前活跃成员；
    - 与现行授权完全相同的请求幂等返回（不推进修订号、不增权限、不留痕）。
    """
    inquiry = drafts.get_inquiry(conn, inquiry_id)
    actor_key = identity.validate_identity(actor)
    if not is_active_owner(conn, inquiry_id, actor_key):
        raise NotAuthorizedError("只有负责人（OWNER）可以设置问题授权",
                                 details={"qid": qid})
    valid_qids = {q["qid"] for q in inquiry["questions"]}
    if qid not in valid_qids:
        from .errors import NotFoundError
        raise NotFoundError(f"问题 {qid} 不在问询清单中")

    scope = inquiry["scope"]
    scope_cats = set(scope.get("allowed_categories") or materials.CATEGORIES)
    scope_ids = set(scope.get("allowed_material_ids") or [])

    # 授权只能在“该问询底稿实际锁定的证据”内授予：问询范围是登记时的最大
    # 边界，而撰写人可见面不得超出已锁定到具体底稿的精确版本集合。
    pinned = conn.execute(
        "SELECT DISTINCT dp.material_id, dp.category FROM draft_pins dp "
        "JOIN drafts d ON d.id=dp.draft_id WHERE d.inquiry_id=?",
        (inquiry_id,)).fetchall()
    pinned_cats = {r["category"] for r in pinned}
    pinned_ids = {r["material_id"] for r in pinned}

    cats = list(visible_categories) if visible_categories is not None \
        else sorted(pinned_cats or scope_cats)
    bad_cats = [c for c in cats if c not in materials.CATEGORIES]
    if bad_cats:
        raise ValueError(f"未知资料类别: {bad_cats}")
    if any(c not in scope_cats for c in cats):
        raise NotAuthorizedError(
            "可见类别不能超出问询登记时冻结的可引用类别范围",
            details={"qid": qid, "denied_categories":
                     sorted(set(cats) - scope_cats)})
    if any(c not in pinned_cats for c in cats):
        raise NotAuthorizedError(
            "可见类别没有任何已锁定到该问询底稿的证据，不能授予",
            details={"qid": qid, "denied_categories":
                     sorted(set(cats) - pinned_cats)})
    mids = list(material_ids) if material_ids is not None \
        else sorted(pinned_ids or scope_ids)
    if any(m not in scope_ids for m in mids):
        raise NotAuthorizedError(
            "可见资料不能超出问询登记时冻结的可引用资料范围",
            details={"qid": qid, "denied_material_ids":
                     sorted(set(mids) - scope_ids)})
    if any(m not in pinned_ids for m in mids):
        raise NotAuthorizedError(
            "可见资料未锁定到该问询的任何底稿，不能授予",
            details={"qid": qid, "denied_material_ids":
                     sorted(set(mids) - pinned_ids)})
    # 类别与资料必须自洽：点名可见的每一份资料类别都应包含在可见类别内
    # （否则类别收紧会被资料白名单悄悄绕过——授权只能在冻结范围内收紧）。
    mid_set = set(mids)
    if mid_set:
        placeholders = ",".join("?" for _ in mid_set)
        rows = conn.execute(
            f"SELECT DISTINCT material_id, category FROM materials "
            f"WHERE material_id IN ({placeholders})",
            sorted(mid_set)).fetchall()
        known = {r["material_id"]: r["category"] for r in rows}
        cat_by_mid = {m: known[m] for m in mid_set if m in known}
        bad = sorted({m for m, c in cat_by_mid.items() if c not in set(cats)})
        if bad:
            raise NotAuthorizedError(
                "可见资料的类别不在可见类别内（类别与资料白名单必须自洽）",
                details={"qid": qid, "denied_material_ids": bad})
    writer_keys = [identity.validate_identity(w) for w in (writers or [])]
    if len(set(writer_keys)) != len(writer_keys):
        raise ValueError("撰写人名单存在重复身份（规范化后）")
    for wk in writer_keys:
        m = current_member(conn, inquiry_id, wk)
        if m is None:
            raise NotGroupMemberError(
                f"撰写人 {wk} 不是当前活跃成员", details={"qid": qid})

    spec = {"visible_categories": sorted(cats),
            "visible_fields": sorted({f.casefold() for f in (visible_fields or [])})
            if visible_fields is not None else [],
            "material_ids": sorted(mids),
            "writers": sorted(writer_keys)}
    # visible_fields=None 语义为“全部可见”：内部以空列表 + fields_all 标记
    fields_all = visible_fields is None
    current = get_active_grant(conn, inquiry_id, qid)
    if current:
        cur_stored = current["visible_fields"]
        cur_fields_all = cur_stored == []
        cur_fields = [] if cur_stored == ["«NONE»"] else cur_stored
        cur_spec = {"visible_categories": sorted(current["visible_categories"]),
                    "visible_fields": sorted(cur_fields),
                    "material_ids": sorted(current["material_ids"]),
                    "writers": sorted(current["writers"])}
        # “全部可见”（空列表）与显式空名单（哨兵 «NONE»，无字段可见）是
        # 两种不同授权，不能判同；字段集合相同且 fields_all 语义相同才幂等。
        same = _same_spec(cur_spec, spec) and (cur_fields_all == fields_all)
        if same:
            current["deduped"] = True
            return current

    now = now or utc_now_iso()
    revision = bump_revision(conn, inquiry_id)
    next_ver = conn.execute(
        "SELECT COALESCE(MAX(grant_version),0)+1 AS n FROM question_grants "
        "WHERE inquiry_id=? AND qid=?", (inquiry_id, qid)).fetchone()["n"]
    gid = uuid.uuid4().hex
    # fields_all 与显式空名单区分：全部可见存空列表（旧语义），显式空名单
    # 存一个哨兵元素，由过滤逻辑解释。
    stored_fields = spec["visible_fields"]
    if not fields_all and not stored_fields:
        stored_fields = ["«NONE»"]
    conn.execute(
        "INSERT INTO question_grants(id,inquiry_id,qid,grant_version,"
        "visible_categories_json,visible_fields_json,material_ids_json,"
        "writers_json,status,auth_revision,created_by,created_at)"
        " VALUES(?,?,?,?,?,?,?,?,'ACTIVE',?,?,?)",
        (gid, inquiry_id, qid, next_ver,
         json.dumps(spec["visible_categories"], ensure_ascii=False),
         json.dumps(stored_fields, ensure_ascii=False),
         json.dumps(spec["material_ids"], ensure_ascii=False),
         json.dumps(spec["writers"], ensure_ascii=False),
         revision, actor, now))
    if current:
        conn.execute(
            "UPDATE question_grants SET status='SUPERSEDED',superseded_revision=? "
            "WHERE id=?", (revision, current["id"]))
    audit.append_event(conn, "QUESTION_GRANT_SET",
                       f"问题 {qid} 授权设置 v{next_ver}（修订号 {revision}）",
                       payload={"inquiry_id": inquiry_id, "qid": qid,
                                "grant_version": next_ver,
                                "auth_revision": revision,
                                "visible_categories": spec["visible_categories"],
                                "fields_all": fields_all,
                                "field_count": len(spec["visible_fields"]),
                                "material_count": len(spec["material_ids"]),
                                "writers": spec["writers"],
                                "superseded_version":
                                    current["grant_version"] if current else None},
                       actor=actor, inquiry_id=inquiry_id, created_at=now)
    out = get_active_grant(conn, inquiry_id, qid)
    out["deduped"] = False
    return out


def grant_history(conn, inquiry_id: str, qid: str | None = None) -> list[dict]:
    sql = "SELECT * FROM question_grants WHERE inquiry_id=?"
    params: list = [inquiry_id]
    if qid:
        sql += " AND qid=?"
        params.append(qid)
    sql += " ORDER BY rowid"
    return [_grant_row(r) for r in conn.execute(sql, params)]


def list_member_events(conn, inquiry_id: str, qid_unused: str | None = None
                       ) -> list[dict]:
    return [dict(r) for r in conn.execute(
        "SELECT * FROM group_member_events WHERE inquiry_id=? ORDER BY rowid",
        (inquiry_id,))]


# ---------------------------------------------------------------------------
# 资格判定（保存当时 / 读取当前）
# ---------------------------------------------------------------------------
def _fields_all(grant: dict) -> bool:
    return grant["visible_fields"] == []


def _field_allowed(grant: dict, field: str) -> bool:
    vf = grant["visible_fields"]
    if vf == []:
        return True
    if vf == ["«NONE»"]:
        return False
    return field.casefold() in {f.casefold() for f in vf}


def grant_allows_material(grant: dict | None, mat: dict) -> bool:
    if grant is None:
        return False
    if mat["category"] not in grant["visible_categories"]:
        return False
    if grant["material_ids"] and mat["material_id"] not in grant["material_ids"]:
        return False
    return True


def grants_for_writer_at(conn, inquiry_id: str, member_key: str, revision: int
                         ) -> dict[str, dict]:
    """该成员在 revision 当时可撰写的全部问题 -> 当时有效授权（OWNER 除外，
    OWNER 的全权由调用方按角色短路）。"""
    out = {}
    for q in drafts.get_inquiry(conn, inquiry_id)["questions"]:
        g = grant_at(conn, inquiry_id, q["qid"], revision)
        if g and member_key in g["writers"]:
            out[q["qid"]] = g
    return out


def current_writer_grant(conn, inquiry_id: str, qid: str, member_key: str
                         ) -> dict | None:
    g = get_active_grant(conn, inquiry_id, qid)
    if g and member_key in g["writers"]:
        return g
    return None


def _material_row_for_ref(conn, ref: str) -> dict | None:
    category, mid, ver = drafts.pin_ref(ref)
    if ver is None:
        return None
    return materials.resolve(conn, mid, ver)


def check_refs_allowed(grant: dict | None, refs: list[str], conn) -> list[str]:
    """返回 *不* 被授权覆盖的引用锚列表（不读取/不回显资料内容）。"""
    denied = []
    for ref in refs:
        mat = _material_row_for_ref(conn, ref)
        if mat is None or not grant_allows_material(grant, mat):
            denied.append(ref)
    return denied


# ---------------------------------------------------------------------------
# 受限上下文读取（最小披露：获准片段 + 稳定占位符）
# ---------------------------------------------------------------------------
def _redacted_content(conn, content: Any, grant: dict) -> Any:
    if _fields_all(grant):
        return content
    if isinstance(content, dict):
        if grant["visible_fields"] == ["«NONE»"]:
            return {k: make_placeholder(conn, k, v) for k, v in content.items()}
        allowed = {f.casefold() for f in grant["visible_fields"]}
        out = {}
        for k, v in content.items():
            if k.casefold() in allowed:
                out[k] = v
            else:
                out[k] = make_placeholder(conn, k, v)
        return out
    # 非字典顶层内容无法按字段授权：有字段白名单即整体占位
    return make_placeholder(conn, "$", content)


def read_section_context(conn, draft_id: str, qid: str, *, actor: str
                         ) -> dict:
    """撰写人读取章节上下文：只返回其获准的证据片段与可见附件元数据。

    - 非托管问询：返回完整上下文（既有行为）；
    - OWNER：返回完整上下文（full=True）；
    - WRITER：必须在组且当前被分派到该问题；未获准资料 *整段不出现*，
      响应只给出拒绝计数（不含被拒锚点），获准资料内未获准字段以稳定
      占位符替代；附件只列其溯源资料当前可被该成员读取的条目。
    """
    draft = drafts.get_draft(conn, draft_id)
    inquiry_id = draft["inquiry_id"]
    revision = current_revision(conn, inquiry_id)
    section = next((s for s in draft["sections"] if s["qid"] == qid), None)
    question = next((q for q in drafts.get_inquiry(conn, inquiry_id)["questions"]
                     if q["qid"] == qid), None)

    base = {
        "draft_id": draft_id, "inquiry_id": inquiry_id, "qid": qid,
        "question": question, "auth_revision": revision,
        "section_revision": section["revision"] if section else 0,
        "section_body": section["body"] if section else "",
        "section_title": section["title"] if section else "",
    }
    if not is_managed(conn, inquiry_id):
        base.update(full=True, granted=True, evidence=_all_evidence(conn, draft),
                    attachments=_attach_meta(draft), denied_pin_count=0)
        return base

    actor_key = identity.validate_identity(actor)
    member = current_member(conn, inquiry_id, actor_key)
    if member is None:
        raise NotGroupMemberError("当前不是该问询的活跃成员", details={"qid": qid})
    if member["role"] == ROLE_OWNER:
        base.update(full=True, granted=True, evidence=_all_evidence(conn, draft),
                    attachments=_attach_meta(draft), denied_pin_count=0)
        return base

    grant = current_writer_grant(conn, inquiry_id, qid, actor_key)
    if grant is None:
        raise NotAssignedError("未被分派到该问题，无权读取章节上下文",
                               details={"qid": qid})

    evidence = []
    denied = 0
    for pin in draft["pins"]:
        mat = materials.resolve_row(conn, pin["material_row_id"])
        if mat is None or not grant_allows_material(grant, mat):
            denied += 1
            continue
        content = loads(mat["content_json"], {})
        evidence.append({
            "ref": pin["ref"], "category": pin["category"],
            "material_id": pin["material_id"], "version": pin["version"],
            "title": mat["title"],
            "content": _redacted_content(conn, content, grant),
        })
    # 附件：溯源资料在当前授权内（或无溯源但属于本问题 OWNER 上传的不放开；
    # 无溯源附件无法证明授权边界，撰写人不可见）。
    attachments = []
    attach_denied = 0
    for a in draft["attachments"]:
        if a.get("qid") != qid:
            continue
        ref = a.get("derived_from_ref")
        allowed = False
        if ref:
            mat = _material_row_for_ref(conn, ref)
            allowed = mat is not None and grant_allows_material(grant, mat)
        if allowed:
            attachments.append(_one_attach_meta(a))
        else:
            attach_denied += 1
    base.update(full=False, granted=True, evidence=evidence,
                attachments=attachments, denied_pin_count=denied,
                denied_attachment_count=attach_denied,
                visible_categories=grant["visible_categories"],
                fields_all=_fields_all(grant))
    return base


def _all_evidence(conn, draft: dict) -> list[dict]:
    out = []
    for pin in draft["pins"]:
        mat = materials.resolve_row(conn, pin["material_row_id"])
        out.append({
            "ref": pin["ref"], "category": pin["category"],
            "material_id": pin["material_id"], "version": pin["version"],
            "title": mat["title"] if mat else "",
            "content": loads(mat["content_json"], {}) if mat else None,
        })
    return out


def _one_attach_meta(a: dict) -> dict:
    return {"id": a["id"], "filename": a["filename"],
            "content_type": a["content_type"],
            "sha256": a["sha256"],
            "derived_from_ref": a.get("derived_from_ref"),
            "qid": a.get("qid"), "size": a.get("size")}


def _attach_meta(draft: dict) -> list[dict]:
    return [_one_attach_meta(a) for a in draft["attachments"]]


# ---------------------------------------------------------------------------
# 越权留痕（只存定位锚，绝不存正文/资料原值）
# ---------------------------------------------------------------------------
def record_denial(conn, *, inquiry_id: str, reason_code: str,
                  draft_id: str | None = None, qid: str | None = None,
                  section_id: str | None = None, actor_key: str | None = None,
                  denied_refs: list[str] | None = None,
                  denied_attachments: list[str] | None = None,
                  had_auth_revision: int | None = None,
                  detail: str = "", now: str | None = None) -> None:
    now = now or utc_now_iso()
    current = current_revision(conn, inquiry_id)
    conn.execute(
        "INSERT INTO auth_denials(id,inquiry_id,draft_id,qid,section_id,actor_key,"
        "reason_code,denied_refs_json,denied_attachment_ids_json,had_auth_revision,"
        "current_auth_revision,detail,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (uuid.uuid4().hex, inquiry_id, draft_id, qid, section_id, actor_key,
         reason_code, json.dumps(denied_refs or [], ensure_ascii=False),
         json.dumps(denied_attachments or [], ensure_ascii=False),
         had_auth_revision, current, detail, now))
    audit.append_event(conn, "AUTHZ_DENIED",
                       f"授权拒绝 {reason_code}（问题 {qid or '-'}）",
                       payload={"inquiry_id": inquiry_id, "draft_id": draft_id,
                                "qid": qid, "reason_code": reason_code,
                                "actor_key": actor_key,
                                "denied_refs": denied_refs or [],
                                "denied_attachments": denied_attachments or [],
                                "had_auth_revision": had_auth_revision,
                                "current_auth_revision": current},
                       actor=actor_key, inquiry_id=inquiry_id, draft_id=draft_id,
                       created_at=now)


def persist_denial(db_path: str, denial: dict) -> None:
    """在 *独立 IMMEDIATE 事务* 中落一次授权拒绝留痕。

    保存/上传业务事务因授权拒绝而回滚时，留痕不能随之丢失（与既有
    STALE_REVISION 冲突留痕同一设计）。审计哈希链在独立事务里追加，
    链头取提交瞬间值，可能与回滚业务交错但始终成链。
    """
    from . import db as dbmod
    conn = dbmod.connect(db_path)
    try:
        with dbmod.transaction(conn):
            record_denial(conn, **denial)
    finally:
        conn.close()


def list_denials(conn, *, inquiry_id: str | None = None,
                 draft_id: str | None = None, qid: str | None = None,
                 reason_code: str | None = None) -> list[dict]:
    where, params = [], []
    if inquiry_id:
        where.append("inquiry_id=?")
        params.append(inquiry_id)
    if draft_id:
        where.append("draft_id=?")
        params.append(draft_id)
    if qid:
        where.append("qid=?")
        params.append(qid)
    if reason_code:
        where.append("reason_code=?")
        params.append(reason_code)
    sql = "SELECT * FROM auth_denials"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY rowid"
    out = []
    for r in conn.execute(sql, params):
        d = dict(r)
        d["denied_refs"] = loads(d.pop("denied_refs_json"), [])
        d["denied_attachments"] = loads(d.pop("denied_attachment_ids_json"), [])
        out.append(d)
    return out


# ---------------------------------------------------------------------------
# 保存/上传时的授权闸门（供 drafts 层调用；调用方已在写事务内）
#
# 闸门 *不直接写留痕*：授权拒绝会回滚整个业务事务，留痕必须由编排层在
# 独立事务持久化（见 persist_denial）。闸门把留痕描述挂在异常 ``denial``
# 属性上，异常本身只携带定位信息，绝不携带受保护资料原值或正文。
# ---------------------------------------------------------------------------
def _deny(exc: Exception, denial: dict) -> Exception:
    exc.denial = denial  # type: ignore[attr-defined]
    return exc


def gate_section_write(conn, draft: dict, qid: str, body: str, *,
                       actor: str, expected_auth_revision: int | None,
                       section_row=None) -> dict:
    """章节保存授权闸门。返回 {"actor_key","grant","auth_revision"} 快照。

    顺序（任一失败即拒，且不回显受保护内容）：
    1. 非托管 -> 放行（auth_revision=None）；
    2. 身份合法 + 在组（当前活跃）；OWNER 全权但仍须带正确修订号；
    3. 页面授权修订号必须等于当前号（转派/离组/收紧后旧号立即失效）；
    4. WRITER 必须被分派到该问题，正文引用与 @attachment 全部在授权内；
    5. 正文不得携带未授权字段的 *原值*（占位符除外）。
    """
    inquiry_id = draft["inquiry_id"]
    if "pins" not in draft:
        draft = drafts.get_draft(conn, draft["id"])
    if not is_managed(conn, inquiry_id):
        return {"actor_key": None, "grant": None, "auth_revision": None}

    sid = section_row["id"] if section_row is not None else None
    actor_key = identity.validate_identity(actor)
    member = current_member(conn, inquiry_id, actor_key)
    if member is None:
        raise _deny(NotGroupMemberError(
            "不是该问询的活跃成员，不能保存章节", details={"qid": qid}),
            {"inquiry_id": inquiry_id, "reason_code": "NOT_GROUP_MEMBER",
             "draft_id": draft["id"], "qid": qid, "section_id": sid,
             "actor_key": actor_key,
             "had_auth_revision": expected_auth_revision,
             "detail": "保存章节时人员不在组"})
    current = current_revision(conn, inquiry_id)
    if expected_auth_revision is None or expected_auth_revision != current:
        raise _deny(StaleAuthRevisionError(
            "授权已变更（章节转派/人员离组/权限收紧），请刷新后重试",
            details={"qid": qid, "current_auth_revision": current}),
            {"inquiry_id": inquiry_id, "reason_code": "STALE_AUTH_REVISION",
             "draft_id": draft["id"], "qid": qid, "section_id": sid,
             "actor_key": actor_key,
             "had_auth_revision": expected_auth_revision,
             "detail": "用失效的授权修订号保存章节"})

    grant = None
    if member["role"] != ROLE_OWNER:
        grant = current_writer_grant(conn, inquiry_id, qid, actor_key)
        if grant is None:
            raise _deny(NotAssignedError(
                "未被分派到该问题，不能保存章节", details={"qid": qid}),
                {"inquiry_id": inquiry_id, "reason_code": "NOT_ASSIGNED",
                 "draft_id": draft["id"], "qid": qid, "section_id": sid,
                 "actor_key": actor_key, "had_auth_revision": current,
                 "detail": "未分派到该问题"})
        cited = sorted({f"{c['prefix']}:{c['material_id']}@{c['version']}"
                        for c in drafts.extract_citations(body)
                        if c["version"]})
        denied_refs = check_refs_allowed(grant, cited, conn)
        attach_refs = _extract_attach_tokens(body)
        denied_att = _check_attachments_allowed(
            conn, draft["id"], qid, grant, attach_refs)
        # 只在“被引用且授权内”的资料上扫描未授权字段原值（既贴合回答内容，
        # 又不把未授权资料的字段带进判定/错误）。
        allowed_refs = {r for r in cited if r not in set(denied_refs)}
        leaked = scan_protected_values(conn, draft, grant, body,
                                       refs=allowed_refs)
        if denied_refs or denied_att or leaked:
            all_refs = sorted(set(denied_refs)
                              | set(leaked_refs(conn, draft, grant, leaked)))
            raise _deny(EvidenceAccessDeniedError(
                "章节保存越权：引用/附件/字段超出该问题授权",
                details={"qid": qid, "denied_refs": denied_refs,
                         "denied_attachments": denied_att,
                         "protected_field_hits": leaked}),
                {"inquiry_id": inquiry_id, "reason_code":
                     "EVIDENCE_ACCESS_DENIED",
                 "draft_id": draft["id"], "qid": qid, "section_id": sid,
                 "actor_key": actor_key, "had_auth_revision": current,
                 "denied_refs": all_refs, "denied_attachments": denied_att,
                 "detail": "章节保存越出授权边界（不含受保护内容）"})
    return {"actor_key": actor_key, "grant": grant, "auth_revision": current}


def gate_attachment_upload(conn, draft: dict, qid: str | None, *,
                           actor: str, expected_auth_revision: int | None,
                           derived_from_ref: str | None) -> dict:
    """附件上传授权闸门（与章节保存同一授权边界）。"""
    inquiry_id = draft["inquiry_id"]
    if not is_managed(conn, inquiry_id):
        return {"actor_key": None, "auth_revision": None}
    actor_key = identity.validate_identity(actor)
    member = current_member(conn, inquiry_id, actor_key)
    if member is None:
        raise _deny(NotGroupMemberError(
            "不是该问询的活跃成员，不能上传附件"),
            {"inquiry_id": inquiry_id, "reason_code": "NOT_GROUP_MEMBER",
             "draft_id": draft["id"], "qid": qid, "actor_key": actor_key,
             "had_auth_revision": expected_auth_revision,
             "detail": "上传附件时人员不在组"})
    current = current_revision(conn, inquiry_id)
    if expected_auth_revision is None or expected_auth_revision != current:
        raise _deny(StaleAuthRevisionError(
            "授权已变更，请刷新章节上下文后再上传附件",
            details={"qid": qid, "current_auth_revision": current}),
            {"inquiry_id": inquiry_id, "reason_code": "STALE_AUTH_REVISION",
             "draft_id": draft["id"], "qid": qid, "actor_key": actor_key,
             "had_auth_revision": expected_auth_revision,
             "detail": "用失效的授权修订号上传附件"})
    if member["role"] != ROLE_OWNER:
        if not qid:
            raise _deny(EvidenceAccessDeniedError(
                "撰写人上传附件必须声明归属问题 qid"),
                {"inquiry_id": inquiry_id, "reason_code":
                     "EVIDENCE_ACCESS_DENIED",
                 "draft_id": draft["id"], "qid": qid, "actor_key": actor_key,
                 "had_auth_revision": current,
                 "detail": "撰写人上传附件必须声明归属问题 qid"})
        grant = current_writer_grant(conn, inquiry_id, qid, actor_key)
        if grant is None:
            raise _deny(NotAssignedError(
                "未被分派到该问题，不能上传附件", details={"qid": qid}),
                {"inquiry_id": inquiry_id, "reason_code": "NOT_ASSIGNED",
                 "draft_id": draft["id"], "qid": qid, "actor_key": actor_key,
                 "had_auth_revision": current, "detail": "未分派到该问题"})
        denied = check_refs_allowed(
            grant, [derived_from_ref] if derived_from_ref else [], conn)
        if not derived_from_ref or denied:
            raise _deny(EvidenceAccessDeniedError(
                "附件必须溯源到该问题授权内的已锁定资料",
                details={"qid": qid,
                         "denied_refs": [derived_from_ref]
                         if derived_from_ref else []}),
                {"inquiry_id": inquiry_id, "reason_code":
                     "EVIDENCE_ACCESS_DENIED",
                 "draft_id": draft["id"], "qid": qid, "actor_key": actor_key,
                 "had_auth_revision": current,
                 "denied_refs": [derived_from_ref] if derived_from_ref else [],
                 "detail": "附件溯源缺失或越出授权边界"})
    return {"actor_key": actor_key, "auth_revision": current}


def gate_attachment_download(conn, draft: dict, attachment: dict, *,
                             actor: str | None) -> None:
    """下载授权边界：OWNER/非托管放行；WRITER 必须当前对该附件归属问题
    有授权且其溯源资料在授权内。拒绝信息只含附件 id/锚，不含内容。"""
    inquiry_id = draft["inquiry_id"]
    if not is_managed(conn, inquiry_id):
        return
    actor_key = identity.validate_identity(actor)
    member = current_member(conn, inquiry_id, actor_key)
    if member is None:
        record_denial(conn, inquiry_id=inquiry_id, reason_code="NOT_GROUP_MEMBER",
                      draft_id=draft["id"], qid=attachment.get("qid"),
                      actor_key=actor_key,
                      denied_attachments=[attachment["id"]],
                      detail="下载附件时人员不在组")
        raise NotGroupMemberError("不是该问询的活跃成员，不能下载附件")
    if member["role"] == ROLE_OWNER:
        return
    qid = attachment.get("qid")
    grant = current_writer_grant(conn, inquiry_id, qid, actor_key) if qid else None
    ref = attachment.get("derived_from_ref")
    ok = False
    if grant and ref:
        mat = _material_row_for_ref(conn, ref)
        ok = mat is not None and grant_allows_material(grant, mat)
    if not ok:
        record_denial(
            conn, inquiry_id=inquiry_id, reason_code="EVIDENCE_ACCESS_DENIED",
            draft_id=draft["id"], qid=qid, actor_key=actor_key,
            denied_refs=[ref] if ref else [],
            denied_attachments=[attachment["id"]],
            detail="附件下载越出授权边界")
        raise EvidenceAccessDeniedError(
            "无权下载该附件",
            details={"qid": qid, "denied_attachments": [attachment["id"]]})


# ---------------------------------------------------------------------------
# 受保护原值扫描（正文不得携带未获准字段的原值）
# ---------------------------------------------------------------------------
def _iter_hidden_values(conn, draft: dict, grant: dict, *, refs: set[str] | None
                        = None):
    """产出 (ref, field, raw_value)：*该问题授权内* 资料中未获准字段的
    全部标量值。

    刻意只遍历授权内资料：未获准资料整段不属于该问题的授权边界，既不会出
    现在受限上下文里，也不能让“保存检查”借报错存在与否探测到未授权资料
    的字段值（错误响应只列调用方自己写出的引用锚，不泄露其他证据）。
    ``refs`` 给出时还可再收窄到指定引用集合。
    """
    for pin in draft["pins"]:
        if refs is not None and pin["ref"] not in refs:
            continue
        mat = materials.resolve_row(conn, pin["material_row_id"])
        if mat is None or not grant_allows_material(grant, mat):
            continue
        content = loads(mat["content_json"], {})
        if isinstance(content, dict):
            for k, v in content.items():
                if not _field_allowed(grant, k) and isinstance(v, (str, int, float)):
                    yield pin["ref"], k, str(v)


def scan_protected_values(conn, draft: dict, grant: dict, text: str, *,
                          refs: set[str] | None = None) -> list[dict]:
    """正文若包含未授权字段的原值子串即越权（返回 [{field, ref}]，不含值）。

    扫描范围限定为该问题授权内的资料（或其被引用子集 ``refs``）。占位符
    形态（«SECRET:..»/«REDACTED..» 等）本身允许出现；空白与单字符值不
    参与匹配（避免误报）。只报字段名与来源锚，绝不回显命中值。
    """
    hits = []
    hay = text or ""
    for ref, field, value in _iter_hidden_values(conn, draft, grant, refs=refs):
        if len(value.strip()) < 2:
            continue
        if value in hay:
            hits.append({"field": field, "ref": ref})
    return hits


def leaked_refs(conn, draft: dict, grant: dict, hits: list[dict]) -> list[str]:
    return sorted({h["ref"] for h in hits})


def _extract_attach_tokens(text: str) -> list[str]:
    import re
    return sorted(set(re.findall(r"@attachment:([A-Za-z0-9_\-]+)", text or "")))


def _check_attachments_allowed(conn, draft_id: str, qid: str, grant: dict,
                               tokens: list[str]) -> list[str]:
    denied = []
    for aid in tokens:
        row = conn.execute(
            "SELECT * FROM attachments WHERE draft_id=? AND id=?",
            (draft_id, aid)).fetchone()
        if row is None:
            # 引用不存在的附件由既有 ATTACHMENT_REF_MISSING 校验处理
            continue
        if row["qid"] != qid:
            denied.append(aid)
            continue
        ref = row["derived_from_ref"]
        mat = _material_row_for_ref(conn, ref) if ref else None
        if not (mat and grant_allows_material(grant, mat)):
            denied.append(aid)
    return denied
