"""监管问询答复编排器 —— 端到端剧本演示（无需起任何服务）。

覆盖：问询登记 -> 精确版本锁定 -> 多人章节协作 -> 引用漂移另立候选 ->
定稿校验阻断/补齐 -> 不可变提交件 -> 发送重试/幂等 -> 回执 -> 更正件 ->
独立核对 -> 操作留痕。
"""
from __future__ import annotations

import os
import tempfile

from reg_inquiry import InquiryOrchestrator
from reg_inquiry.transport import RegulatorTransport
from reg_inquiry.util import FixedClock


def main() -> None:
    d = tempfile.mkdtemp(prefix="inquiry-demo-")
    clock = FixedClock("2026-10-01T09:00:00+00:00")
    gw = RegulatorTransport(os.path.join(d, "regulator.db"), clock=clock,
                            fail_times=1)  # 首次外发临时故障，验证自动重试
    o = InquiryOrchestrator(os.path.join(d, "inquiry.db"), transport=gw,
                            clock=clock)

    def step(t): print(f"\n=== {t} ===")

    # 1) 可引用资料（四类）登记，带精确版本与事实键
    step("1. 资料登记（病例/法规/统计结论，精确版本）")
    o.register_material(material_id="CASE-7788", version="1", category="CASE",
                        content={"patient_name": "张三", "event": "皮疹",
                                 "outcome": "恢复"},
                        fact_key="OUTCOME", fact_value="恢复",
                        registered_by="pv-officer")
    o.register_material(material_id="RULE-EXP", version="2026-1",
                        category="REGULATION",
                        content={"expedited_days": 15, "basis": "严重非预期"})
    o.register_material(material_id="STAT-2026Q3", version="3",
                        category="STATISTIC", content={"prr": 2.3, "ci": [1.1, 4.8]})
    print("  三个资料版本已注册")

    # 2) 问询登记：问题清单 + 截止时间 + 可引用资料范围（冻结）
    step("2. 监管问询登记（NMPA/CN，两问，截止 10-20）")
    inq = o.register_inquiry(
        regulator="NMPA", jurisdiction="CN", title="2026 年第 18 号问询",
        questions=[{"qid": "Q1", "text": "病例 7788 的事件与转归？"},
                   {"qid": "Q2", "text": "加急判定依据与统计结论？"}],
        deadline="2026-10-20T00:00:00+00:00",
        allowed_material_ids=["CASE-7788", "RULE-EXP", "STAT-2026Q3"],
        registered_by="intake-desk")
    print("  inquiry:", inq["id"][:12], "scope:",
          inq["scope"]["allowed_material_ids"])

    # 3) 底稿锁定：精确版本
    step("3. 底稿锁定（把引用冻结到精确版本）")
    draft = o.lock_draft(
        inq["id"],
        ["CASE:CASE-7788@1", "REG:RULE-EXP@2026-1", "STAT:STAT-2026Q3@3"],
        created_by="lead")
    for p in draft["pins"]:
        print("  pin:", p["ref"])

    # 3b) 分区写作 / 最小披露：负责人把 alice/bob 加进组并按问题分派
    step("3b. 负责人按问题设置授权（可见类别/字段/撰写人）")
    o.add_member(inq["id"], "alice", role="WRITER", acted_by="intake-desk")
    o.add_member(inq["id"], "bob", role="WRITER", acted_by="intake-desk")
    # Q1：alice 只能看病历（CASE）且仅 event/outcome 字段；patient_name 等
    # 以稳定占位符替代。Q2：bob 可看法规与统计。
    o.put_question_grant(
        inq["id"], "Q1",
        visible_categories=["CASE"],
        visible_fields=["event", "outcome"],
        material_ids=["CASE-7788"], writers=["alice"],
        actor="intake-desk")
    o.put_question_grant(
        inq["id"], "Q2",
        visible_categories=["REGULATION", "STATISTIC"],
        material_ids=["RULE-EXP", "STAT-2026Q3"], writers=["bob"],
        actor="intake-desk")
    auth_rev = o.current_auth_revision(inq["id"])
    print("  当前授权修订号:", auth_rev)
    ctx = o.read_section_context(draft["id"], "Q1", actor="alice")
    ev = ctx["evidence"][0]
    print("  alice 的 Q1 受限证据（只 1 段，未获准资料不出现在响应里）:")
    print("   ", ev["ref"], "内容字段:", ev["content"])

    # 4) 缺失/越权/矛盾会阻断（演示一次越权：另一问询范围只含法规）
    step("4. 引用越权被阻止")
    o.register_material(material_id="OUT-OF-SCOPE", version="1",
                        category="CASE", content={"secret": 1})
    narrow = o.register_inquiry(
        regulator="NMPA", jurisdiction="CN", title="范围受限问询",
        questions=[{"qid": "Q1", "text": "仅可引用法规"}],
        deadline="2026-10-20T00:00:00+00:00",
        allowed_material_ids=["RULE-EXP"], registered_by="intake-desk")
    try:
        o.lock_draft(narrow["id"], ["CASE:OUT-OF-SCOPE@1"])
    except Exception as e:
        print("  阻断:", e.code, "-",
              e.details["out_of_scope"][0]["reason"])

    # 5) 多人协作撰写不同章节（各自只引用授权内证据，携带授权修订号）
    step("5. 两名撰写人并行提交不同章节（最小披露边界内）")
    att = o.add_attachment(draft["id"], filename="病例7788.pdf",
                           content=b"%PDF-1.4 ...case source document...",
                           derived_from_ref="CASE:CASE-7788@1", qid="Q1",
                           expected_auth_revision=auth_rev, uploaded_by="alice")
    o.submit_section(
        draft["id"], "Q1",
        f"病例 7788：2026-09-07 皮疹，转归恢复 [CASE:CASE-7788@1]。"
        f"原件见附件 @attachment:{att['id']}",
        expected_revision=0, expected_auth_revision=auth_rev,
        submitted_by="alice")
    o.submit_section(
        draft["id"], "Q2",
        "严重且非预期，按 15 日加急 [REG:RULE-EXP@2026-1]；"
        "本季度 PRR=2.3（95%CI 1.1-4.8）[STAT:STAT-2026Q3@3]。",
        expected_revision=0, expected_auth_revision=auth_rev,
        submitted_by="bob")
    print("  Q1 by alice, Q2 by bob 已提交")

    # 5b) 越权尝试：alice 试图引用未授权的法规 / 下载 bob 的问题证据
    step("5b. 越权读取/保存被拒（响应不回显受保护内容，只留定位锚）")
    try:
        o.read_section_context(draft["id"], "Q2", actor="alice")
    except Exception as e:
        print("  读 Q2 被拒:", e.code)
    try:
        o.submit_section(
            draft["id"], "Q1", "越权引用法规 [REG:RULE-EXP@2026-1]",
            expected_revision=1, expected_auth_revision=auth_rev,
            submitted_by="alice")
    except Exception as e:
        print("  越权引用被拒:", e.code, "被拒锚:",
              e.details.get("denied_refs"))

    # 6) 乐观修订号：bob 基于过期修订覆盖 Q1 被拒（bob 本就不在 Q1 名单）
    step("6. 竞争更新：过期提交/未分派不得覆盖")
    try:
        o.submit_section(draft["id"], "Q1", "我要用旧视图覆盖",
                         expected_revision=0, expected_auth_revision=auth_rev,
                         submitted_by="bob")
    except Exception as e:
        print("  拒绝:", e.code, "-", {k: v for k, v in e.details.items()
                                       if k != 'denied_refs'})
    print("  授权冲突留痕:", len(o.auth_conflicts(inquiry_id=inq["id"])), "条")

    # 6b) 章节转派：Q1 从 alice 转给 carol，旧授权修订号立即失效
    step("6b. 章节转派 -> 旧页面授权号失效，用旧号保存必须被拒")
    o.add_member(inq["id"], "carol", role="WRITER", acted_by="intake-desk")
    o.put_question_grant(
        inq["id"], "Q1", visible_categories=["CASE"],
        visible_fields=["event", "outcome"], material_ids=["CASE-7788"],
        writers=["carol"], actor="intake-desk")
    new_rev = o.current_auth_revision(inq["id"])
    try:
        o.submit_section(draft["id"], "Q1", "alice 用旧授权号保存",
                         expected_revision=1, expected_auth_revision=auth_rev,
                         submitted_by="alice")
    except Exception as e:
        print("  旧号保存被拒:", e.code, "（当前号", new_rev,
              "，响应不含新证据）")
    # 转派回 alice 以便后续定稿（演示负责人调整分派是常态）
    o.put_question_grant(
        inq["id"], "Q1", visible_categories=["CASE"],
        visible_fields=["event", "outcome"], material_ids=["CASE-7788"],
        writers=["alice"], actor="intake-desk")
    auth_rev = o.current_auth_revision(inq["id"])

    # 7) 组稿期间引用漂移：病例新版本到达，不混入当前底稿，另立候选
    step("7. 引用漂移：病例 v2 到达 -> 带原因的新底稿候选")
    o.register_material(material_id="CASE-7788", version="2", category="CASE",
                        content={"patient_name": "张三", "event": "皮疹",
                                 "outcome": "随访仍有色素沉着"},
                        fact_key="OUTCOME", fact_value="色素沉着",
                        registered_by="pv-officer")
    base_pins = [p["ref"] for p in o.get_draft(draft["id"])["pins"]]
    cands = [d for d in o.list_drafts(inq["id"]) if d["kind"] == "CANDIDATE"]
    print("  当前底稿仍锁定:", [r for r in base_pins if "CASE-7788" in r])
    cand = o.get_draft(cands[0]["id"])
    print("  候选已锁新版本:", [p["ref"] for p in cand["pins"]
                               if "CASE-7788" in p["ref"]])
    print("  原因:", cand["drift_reason"], "（章节/附件已克隆，可独立继续）")

    # 8) 定稿校验：先故意缺一个附件引用，再补齐（这里 BASE 已齐备，演示校验报告）
    step("8. 定稿校验（每问唯一回答 / 引用一致 / 敏感字段）")
    o.put_disclosure_policy(jurisdiction="CN", rules={
        "sensitive_fields": {"patient_identifier": "PROHIBIT"}})
    report = o.validate(draft["id"])
    print("  ok =", report["ok"], "| answered =",
          f"{report['answered_count']}/{report['question_count']}",
        "| warnings =", [w["code"] for w in report["warnings"]])

    # 9) 定稿 -> 不可变提交件 + 外发编号
    step("9. 定稿封存（不可变提交件，分配外发编号）")
    sealed = o.finalize(draft["id"], sealed_by="lead")
    sub = o.submission_status(sealed["submission_id"])
    print("  outgoing_number:", sub["outgoing_number"], "| kind:", sub["kind"])
    print("  manifest_hash:", sub["manifest_hash"][:24], "...")
    print("  每问 answer_uid:",
          [(a["qid"], a["answer_uid"][:8]) for a in sub["manifest"]["answers"]])

    # 10) 发送（网关首次临时故障，自动重试；重复请求不重复外发）
    step("10. 发送（首次临时故障->重试；重复请求幂等）")
    r = o.send(sub["id"])
    print("  发送:", r["status"], "受理号:", r["response"]["receipt_number"],
          "| attempts:", o.submission_status(sub["id"])["attempts"])
    o.send(sub["id"])
    print("  重复发送后网关受理次数 =", gw.accept_count(sub["outgoing_number"]),
          "(必须为 1)")

    # 11) 回执登记
    step("11. 监管回执登记")
    o.register_receipt(sub["id"], receipt_number=r["response"]["receipt_number"],
                       payload={"outgoing_number": sub["outgoing_number"],
                                "regulator": "NMPA"}, registered_by="gateway-bot")
    print("  状态:", o.submission_status(sub["id"])["status"])

    # 12) 定稿后不可改；新情况只能产生更正件（原提交件与回执保留）
    step("12. 提交后更正：产生更正件，原件保留")
    corr_draft = o.create_correction_draft(
        sub["id"], refs=["CASE:CASE-7788@2", "REG:RULE-EXP@2026-1",
                         "STAT:STAT-2026Q3@3"], reason="随访补充转归 v2",
        created_by="alice")
    a1 = corr_draft["attachments"][0]
    # 更正引用病例 v2：负责人把 Q1 可见资料更新为两个版本（仍不超问询范围）
    o.put_question_grant(
        inq["id"], "Q1", visible_categories=["CASE"],
        visible_fields=["event", "outcome"],
        material_ids=["CASE-7788"], writers=["alice"], actor="intake-desk")
    corr_rev = o.current_auth_revision(inq["id"])
    o.submit_section(
        corr_draft["id"], "Q1",
        f"更正：随访仍有色素沉着 [CASE:CASE-7788@2] @attachment:{a1['id']}",
        expected_revision=1, expected_auth_revision=corr_rev,
        submitted_by="alice")
    o.submit_section(corr_draft["id"], "Q2",
                     "依据不变 [REG:RULE-EXP@2026-1]；"
                     "[STAT:STAT-2026Q3@3]", expected_revision=1,
                     expected_auth_revision=corr_rev, submitted_by="bob")
    csealed = o.finalize(corr_draft["id"], sealed_by="lead")
    csub = o.submission_status(csealed["submission_id"])
    cr = o.send(csub["id"])
    print("  更正编号:", csub["outgoing_number"], "| corrects:",
          sub["outgoing_number"], "| 发送:", cr["status"])
    chain = o.correction_chain(sub["id"])
    print("  链: 原件", chain["original"]["outgoing_number"], "-> 更正",
          [c["outgoing_number"] for c in chain["corrections"]])

    # 13) 独立核对 + 审计链
    step("13. 独立核对（提交件/哈希/编号/回执/审计链）")
    v = o.verify_all()
    print("  全库核对 ok =", v["ok"], "| 审计链完好 =", v["audit_chain_ok"])

    step("14. 操作留痕（只增哈希链）")
    types = [e["event_type"] for e in o.audit_trail(inquiry_id=inq["id"])]
    print("  事件序列:")
    for t in dict.fromkeys(types):
        print("   -", t)
    print("\n演示数据库目录:", d)


if __name__ == "__main__":
    main()
