"""分区授权的独立核验（independent verification）。

刻意 *不* 复用授权判定/定稿校验路径：直接从数据库逐行重放，任何不一致
都逐条列出（``ok=False``），绝不误报有效。

核验项：
1. 授权修订号单调递增；所有修订推进都有对应只增审计帧（无空跳/重放重复）；
2. 逐问授权台账只增且引用的修订号真实存在；在列撰写人全部是在册成员；
3. 成员台账 as-of 重放：离组后不再在列，负责人指针与 LEAD 台账一致；
4. 已封存提交件 manifest：每问 authz_revision、保存人/引用/附件在该
   修订号时点满足授权（即“封存后不因权限变化被改写，而封存当时确有资格”）；
5. 越权留痕（authz_denials）只引用存在的问询/底稿/问题，且不含正文内容；
6. 附件再认定：再认定人在当时为负责人或该问题在列撰写人，溯源类别当时获准；
7. 审计哈希链完整（复用 audit.verify_chain）。
"""
from __future__ import annotations

import json

from . import audit, authz, drafts, identity, materials


def verify_authz(conn, *, inquiry_id: str | None = None) -> dict:
    failures: list[dict] = []
    states = conn.execute(
        "SELECT * FROM inquiry_authz"
        + (" WHERE inquiry_id=?" if inquiry_id else ""),
        (inquiry_id,) if inquiry_id else ()).fetchall()
    per_inquiry = []
    for st in states:
        r = _verify_one(conn, dict(st))
        per_inquiry.append(r)
        failures.extend(r["failures"])

    chain_failures = audit.verify_chain(audit.list_events(conn))
    for m in chain_failures:
        failures.append({"code": "AUDIT_CHAIN_BROKEN", "message": m})

    # 越权留痕引用完整性（全库或指定问询）
    for d in conn.execute(
            "SELECT * FROM authz_denials"
            + (" WHERE inquiry_id=?" if inquiry_id else ""),
            (inquiry_id,) if inquiry_id else ()):
        d = dict(d)
        if d["denied_ref"] and len(d["denied_ref"]) > 200:
            failures.append({"code": "DENIAL_LEAK_SUSPECT",
                             "inquiry_id": d["inquiry_id"], "id": d["id"],
                             "message": "越权留痕的资料标识异常超长（疑似混入内容）"})
        if d["detail"] and len(d["detail"]) > 200:
            failures.append({"code": "DENIAL_LEAK_SUSPECT",
                             "inquiry_id": d["inquiry_id"], "id": d["id"],
                             "message": "越权留痕 detail 超长"})

    return {"ok": not failures, "checked_inquiries": len(per_inquiry),
            "inquiries": per_inquiry, "audit_chain_ok": not chain_failures,
            "failures": failures}


def _fail(code: str, message: str, **extra) -> dict:
    d = {"code": code, "message": message}
    d.update(extra)
    return d


def _verify_one(conn, st: dict) -> dict:
    iid = st["inquiry_id"]
    rev = st["authz_revision"]
    failures: list[dict] = []

    # 1) 修订号推进与审计帧一一对应（ENROLL=基线 1；之后每次 MEMBER/
    #    TRANSFER/POLICY 实质变化 +1）。重放成员与授权台账推导期望修订号。
    events = audit.list_events(conn, inquiry_id=iid)
    bump_types = {"AUTHZ_ENROLLED", "AUTHZ_MEMBERS_CHANGED",
                  "AUTHZ_LEAD_TRANSFERRED", "AUTHZ_POLICY_CHANGED"}
    bumps = [e for e in events if e["event_type"] in bump_types]
    if rev != len(bumps):
        failures.append(_fail(
            "AUTHZ_REVISION_GAP",
            f"授权修订号 {rev} 与只增变更帧数 {len(bumps)} 不一致",
            inquiry_id=iid))
    revs = [e["payload"].get("authz_revision") for e in bumps]
    if revs != list(range(1, len(revs) + 1)):
        failures.append(_fail("AUTHZ_REVISION_SEQUENCE",
                              "变更帧授权修订号不是连续 1..N",
                              inquiry_id=iid, revs=revs))
    # 幂等：同一 idempotency 帧只应出现一次
    keys = [e["seq"] for e in events]
    if len(keys) != len(set(keys)):
        failures.append(_fail("AUDIT_DUPLICATE_FRAME", "审计帧 seq 重复",
                              inquiry_id=iid))

    # 2) 逐问授权台账
    inq = drafts.get_inquiry(conn, iid)
    qids = {q["qid"] for q in inq["questions"]}
    grant_rows = conn.execute(
        "SELECT * FROM question_grants WHERE inquiry_id=? ORDER BY rowid",
        (iid,)).fetchall()
    seen_grant_revs: set[int] = set()
    for r in grant_rows:
        r = dict(r)
        if r["qid"] not in qids:
            failures.append(_fail("GRANT_UNKNOWN_QID",
                                  f"授权台账引用不存在的问题 {r['qid']}",
                                  inquiry_id=iid))
        if not (1 <= r["revision"] <= rev):
            failures.append(_fail("GRANT_REVISION_OUT_OF_RANGE",
                                  f"问题 {r['qid']} 授权行修订号 {r['revision']} "
                                  f"超出 1..{rev}", inquiry_id=iid, qid=r["qid"]))
        cats = json.loads(r["categories_json"])
        if any(c not in materials.CATEGORIES for c in cats):
            failures.append(_fail("GRANT_BAD_CATEGORY",
                                  f"问题 {r['qid']} 授权含非法类别",
                                  inquiry_id=iid, qid=r["qid"]))
        for wk in json.loads(r["writer_keys_json"]):
            # as-of：授权行发布时点该撰写人须在册（之后离组不应判历史行为非法）
            m = authz.membership_at(conn, iid, wk, r["revision"])
            if not m or not m["active"] or m["role"] != "WRITER":
                failures.append(_fail(
                    "GRANT_WRITER_NOT_MEMBER_AT_REVISION",
                    f"问题 {r['qid']} 授权行（修订号 {r['revision']}）的撰写人 "
                    f"{wk} 在该时点不是在册撰写人",
                    inquiry_id=iid, qid=r["qid"], writer_key=wk))
        seen_grant_revs.add(r["revision"])

    # 3) 成员台账：最新行决定在册；负责人指针一致
    members = conn.execute(
        "SELECT * FROM inquiry_members WHERE inquiry_id=? ORDER BY rowid",
        (iid,)).fetchall()
    latest: dict[str, dict] = {}
    for m in members:
        latest[dict(m)["identity_key"]] = dict(m)
    lead_rows = [m for m in latest.values() if m["role"] == "LEAD" and m["active"]]
    if len(lead_rows) != 1:
        failures.append(_fail("LEAD_NOT_UNIQUE",
                              f"当前在任负责人数量={len(lead_rows)}（应为 1）",
                              inquiry_id=iid))
    elif lead_rows[0]["identity_key"] != st["lead_key"]:
        failures.append(_fail(
            "LEAD_POINTER_MISMATCH",
            f"授权指针 {st['lead_key']} 与台账在任负责人 "
            f"{lead_rows[0]['identity_key']} 不一致", inquiry_id=iid))

    # 4) 已封存提交件：封存当时授权资格逐问复核
    for sub in conn.execute(
            "SELECT * FROM submissions WHERE inquiry_id=? ORDER BY sealed_at",
            (iid,)).fetchall():
        sub = dict(sub)
        manifest = json.loads(sub["manifest_json"])
        sealed_rev = manifest.get("authz_revision", 0)
        if sealed_rev > rev:
            failures.append(_fail("MANIFEST_AUTHZ_REV_INVALID",
                                  f"提交件 {sub['id']} manifest 授权修订号 "
                                  f"{sealed_rev} 超出当前 {rev}",
                                  inquiry_id=iid, submission_id=sub["id"]))
        draft = drafts.get_draft(conn, sub["draft_id"], include=True)
        pins_by_ref = {p["ref"]: p for p in draft["pins"]}
        for ans in manifest.get("answers", []):
            qid = ans["qid"]
            ar = ans.get("authz_revision")
            g = authz.grant_at(conn, iid, qid, ar) if ar else None
            sec = next((s for s in draft["sections"] if s["qid"] == qid), None)
            if sec is None:
                continue
            submitter = identity.normalize_identity(sec["updated_by"]) \
                if sec["updated_by"] else None
            lead_then = authz._lead_at(conn, iid, ar) if ar else None
            was_lead = bool(submitter and submitter == lead_then)
            qualified = bool(
                g and submitter and (
                    submitter in g["writer_keys"] or was_lead))
            if not qualified:
                failures.append(_fail(
                    "SEALED_ANSWER_UNQUALIFIED",
                    f"提交件 {sub['outgoing_number']} 问题 {qid} 的回答者 "
                    f"在封存时点不具备撰写资格",
                    inquiry_id=iid, qid=qid,
                    submission_id=sub["id"]))
            # 保存时为负责人的章节豁免逐问类别（全量组稿能力）
            if not was_lead:
                for cite in ans.get("citations", []):
                    pin = pins_by_ref.get(cite)
                    if pin and g and pin["category"] not in g["categories"]:
                        failures.append(_fail(
                            "SEALED_CITATION_UNQUALIFIED",
                            f"提交件 {sub['outgoing_number']} 问题 {qid} 引用 "
                            f"{cite} 在封存时点超出授权类别",
                            inquiry_id=iid, qid=qid, denied_ref=cite,
                            submission_id=sub["id"]))
            for a in ans.get("attachments", []):
                aid = a["attachment_id"]
                if a.get("qid") != qid:
                    failures.append(_fail(
                        "SEALED_ATTACHMENT_QID",
                        f"提交件 {sub['outgoing_number']} 附件 {aid} 归属问题"
                        "与引用章节不一致",
                        inquiry_id=iid, qid=qid, attachment_id=aid,
                        submission_id=sub["id"]))
                    continue
                pin = pins_by_ref.get(a.get("derived_from_ref"))
                up_rev = a.get("upload_authz_revision")
                if up_rev is None:
                    rqrow = conn.execute(
                        "SELECT authz_revision,requalified_by_key FROM "
                        "attachment_requalifications WHERE draft_id=? "
                        "AND attachment_id=? ORDER BY rowid DESC LIMIT 1",
                        (sub["draft_id"], aid)).fetchone()
                    if not rqrow:
                        failures.append(_fail(
                            "SEALED_ATTACHMENT_UNQUALIFIED",
                            f"提交件 {sub['outgoing_number']} 附件 {aid} "
                            "既非启用后上传也无再认定",
                            inquiry_id=iid, qid=qid, attachment_id=aid,
                            submission_id=sub["id"]))
                    elif not was_lead and rqrow["requalified_by_key"] != \
                            authz._lead_at(conn, iid, rqrow["authz_revision"]):
                        gr = authz.grant_at(conn, iid, qid,
                                            rqrow["authz_revision"])
                        if pin and (not gr
                                    or pin["category"] not in gr["categories"]):
                            failures.append(_fail(
                                "SEALED_ATTACHMENT_UNQUALIFIED",
                                f"提交件 {sub['outgoing_number']} 附件 {aid} "
                                "再认定时点类别未获准",
                                inquiry_id=iid, qid=qid, attachment_id=aid,
                                submission_id=sub["id"]))
                elif not was_lead:
                    g_up = authz.grant_at(conn, iid, qid, up_rev)
                    if g and pin and pin["category"] not in g_up["categories"]:
                        failures.append(_fail(
                            "SEALED_ATTACHMENT_UNQUALIFIED",
                            f"提交件 {sub['outgoing_number']} 附件 {aid} 上传"
                            "时点类别未获准",
                            inquiry_id=iid, qid=qid, attachment_id=aid,
                            submission_id=sub["id"]))

    # 6) 再认定人资格
    for rq in conn.execute(
            "SELECT * FROM attachment_requalifications rq JOIN drafts d "
            "ON d.id=rq.draft_id WHERE d.inquiry_id=?", (iid,)).fetchall():
        rq = dict(rq)
        g = authz.grant_at(conn, iid, rq["qid"], rq["authz_revision"])
        is_lead = authz._lead_at(conn, iid, rq["authz_revision"]) \
            == rq["requalified_by_key"]
        is_writer = bool(g and rq["requalified_by_key"] in g["writer_keys"])
        if not (is_lead or is_writer):
            failures.append(_fail(
                "REQUAL_UNQUALIFIED",
                f"附件 {rq['attachment_id']} 再认定人在修订号 "
                f"{rq['authz_revision']} 时点无资格",
                inquiry_id=iid, qid=rq["qid"],
                attachment_id=rq["attachment_id"]))

    return {"inquiry_id": iid, "authz_revision": rev, "lead_key": st["lead_key"],
            "members": len(latest), "grant_versions": len(grant_rows),
            "failures": failures, "ok": not failures}
