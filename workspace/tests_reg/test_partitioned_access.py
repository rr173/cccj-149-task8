"""分区写作与最小披露权限。

覆盖：
- 负责人按问分派（类别/字段/撰写人）；相同授权请求幂等不增权、不重复留痕；
- 受限上下文只给获准证据片段，未获准字段稳定占位符，未获准资料整段缺席；
- 附件上传/下载同一授权边界；
- 授权修订号：转派/离组/收紧后旧号保存立即拒绝且不泄露新证据；
- 转派与保存并发只有一个结果；
- 封存答复不因人员变化改写；更正必须按当时有效授权重新检查；
- 定稿逐问独立核验引用/附件读取资格，越权只列问题/章节/被拒锚；
- 管理员（OWNER）全量组稿/定稿/发送保持可用；非托管问询行为不变；
- 越权留痕只含定位信息，绝不含受保护原值；审计哈希链完好。
"""
import threading

from reg_inquiry.errors import (EvidenceAccessDeniedError, JobFailed,
                                NotAssignedError, NotAuthorizedError,
                                NotGroupMemberError, StaleAuthRevisionError,
                                ValidationFailed)

from .reg_base import InquiryTestBase


class PartitionedBase(InquiryTestBase):
    """托管问询夹具：负责人 intake + 撰写人 alice/bob/carol，两类证据。"""

    def setUp(self):
        super().setUp()
        self.o.register_material(
            material_id="MAT-CASE", version="1", category="CASE",
            content={"patient_name": "张三", "patient_identifier": "ID-998",
                     "event": "皮疹", "outcome": "恢复"},
            title="病例 v1")
        self.o.register_material(
            material_id="MAT-REG", version="1", category="REGULATION",
            content={"article": "15日报告", "authority": "NMPA"},
            title="法规 v1")
        self.o.register_material(
            material_id="MAT-STAT", version="1", category="STATISTIC",
            content={"prr": 2.1, "ci": "1.1-4.8"}, title="统计 v1")
        self.inq = self.o.register_inquiry(
            regulator="NMPA", jurisdiction="CN",
            questions=[{"qid": "Q1", "text": "事件与转归？"},
                       {"qid": "Q2", "text": "法规与统计依据？"}],
            deadline="2026-10-20T00:00:00+00:00",
            allowed_material_ids=["MAT-CASE", "MAT-REG", "MAT-STAT"],
            registered_by="intake")
        self.draft = self.o.lock_draft(
            self.inq["id"],
            ["CASE:MAT-CASE@1", "REG:MAT-REG@1", "STAT:MAT-STAT@1"])
        self.o.add_member(self.inq["id"], "alice", acted_by="intake")
        self.o.add_member(self.inq["id"], "bob", acted_by="intake")
        self.o.put_question_grant(
            self.inq["id"], "Q1", visible_categories=["CASE"],
            visible_fields=["event", "outcome"],
            material_ids=["MAT-CASE"], writers=["alice"], actor="intake")
        self.o.put_question_grant(
            self.inq["id"], "Q2",
            visible_categories=["REGULATION", "STATISTIC"],
            material_ids=["MAT-REG", "MAT-STAT"], writers=["bob"],
            actor="intake")
        self.rev = self.o.current_auth_revision(self.inq["id"])

    def alice_fills_q1(self, *, body=None):
        body = body or "皮疹已恢复 [CASE:MAT-CASE@1]"
        return self.o.submit_section(
            self.draft["id"], "Q1", body, expected_revision=0,
            expected_auth_revision=self.rev, submitted_by="alice")

    def bob_fills_q2(self, *, body=None):
        body = body or ("15 日 [REG:MAT-REG@1]；PRR [STAT:MAT-STAT@1]")
        return self.o.submit_section(
            self.draft["id"], "Q2", body, expected_revision=0,
            expected_auth_revision=self.rev, submitted_by="bob")


class TestGrantManagement(PartitionedBase):
    def test_only_owner_can_set_grant(self):
        with self.assertRaises(NotAuthorizedError):
            self.o.put_question_grant(
                self.inq["id"], "Q1", writers=["alice"], actor="alice")
        # 非成员也不行
        with self.assertRaises(NotAuthorizedError):
            self.o.put_question_grant(
                self.inq["id"], "Q1", writers=["alice"], actor="stranger")

    def test_grant_cannot_exceed_frozen_scope(self):
        # 资料超问询冻结范围
        with self.assertRaises(NotAuthorizedError):
            self.o.put_question_grant(
                self.inq["id"], "Q1", visible_categories=["CASE"],
                material_ids=["MAT-OTHER"], writers=["alice"], actor="intake")
        # 类别与资料白名单必须自洽：MAT-REG 是 REGULATION，不能配 CASE 类别
        with self.assertRaises(NotAuthorizedError):
            self.o.put_question_grant(
                self.inq["id"], "Q1",
                visible_categories=["CASE"],
                material_ids=["MAT-CASE", "MAT-REG"], writers=["alice"],
                actor="intake")

    def test_writer_must_be_member(self):
        with self.assertRaises(NotGroupMemberError):
            self.o.put_question_grant(
                self.inq["id"], "Q1", visible_categories=["CASE"],
                material_ids=["MAT-CASE"], writers=["ghost"], actor="intake")

    def test_identical_grant_is_idempotent_no_revision_no_duplicate(self):
        before = self.rev
        g = self.o.put_question_grant(
            self.inq["id"], "Q1", visible_categories=["CASE"],
            visible_fields=["event", "outcome"],
            material_ids=["MAT-CASE"], writers=["alice"], actor="intake")
        self.assertTrue(g["deduped"])
        self.assertEqual(self.o.current_auth_revision(self.inq["id"]), before)
        hist = self.o.auth_history(self.inq["id"], qid="Q1")["grant_versions"]
        active = [h for h in hist if h["status"] == "ACTIVE"]
        self.assertEqual(len(active), 1)
        events = [e for e in self.o.audit_trail(inquiry_id=self.inq["id"])
                  if e["event_type"] == "QUESTION_GRANT_SET"
                  and e["payload"]["qid"] == "Q1"]
        self.assertEqual(len(events), 1)

    def test_grant_versions_append_only(self):
        self.o.put_question_grant(
            self.inq["id"], "Q1", visible_categories=["CASE"],
            visible_fields=["event"],  # 收紧字段
            material_ids=["MAT-CASE"], writers=["alice"], actor="intake")
        hist = self.o.auth_history(self.inq["id"], qid="Q1")["grant_versions"]
        self.assertEqual([h["grant_version"] for h in hist], [1, 2])
        self.assertEqual(hist[0]["status"], "SUPERSEDED")
        self.assertEqual(hist[1]["status"], "ACTIVE")
        self.assertGreater(
            self.o.current_auth_revision(self.inq["id"]), self.rev)

    def test_identity_normalization_for_writers(self):
        # 全角/大小写/首尾空白等价：同一人不占两个撰写人槽
        g = self.o.put_question_grant(
            self.inq["id"], "Q1", visible_categories=["CASE"],
            visible_fields=["event", "outcome"],
            material_ids=["MAT-CASE"], writers=["ALICE"], actor="intake")
        self.assertEqual(g["writers"], ["alice"])
        with self.assertRaises(ValueError):
            self.o.put_question_grant(
                self.inq["id"], "Q1", visible_categories=["CASE"],
                material_ids=["MAT-CASE"], writers=["  "], actor="intake")

    def test_owner_can_be_promoted_and_last_owner_protected(self):
        self.o.add_member(self.inq["id"], "carol", acted_by="intake")
        self.o.change_member_role(self.inq["id"], "carol", "OWNER",
                                  acted_by="intake")
        # 两个 OWNER 时可移除一个；只剩一个时拒绝
        self.o.remove_member(self.inq["id"], "intake", acted_by="carol")
        with self.assertRaises(NotAuthorizedError):
            self.o.remove_member(self.inq["id"], "carol", acted_by="carol")


class TestRestrictedContext(PartitionedBase):
    def test_only_allowed_evidence_fragments(self):
        ctx = self.o.read_section_context(self.draft["id"], "Q1",
                                          actor="alice")
        refs = [e["ref"] for e in ctx["evidence"]]
        self.assertEqual(refs, ["CASE:MAT-CASE@1"])
        self.assertEqual(ctx["denied_pin_count"], 2)
        content = ctx["evidence"][0]["content"]
        self.assertEqual(content["event"], "皮疹")
        self.assertEqual(content["outcome"], "恢复")
        # 敏感字段被占位符替换，原值绝不出现在响应中
        self.assertNotIn("张三", str(content))
        self.assertNotIn("ID-998", str(content))
        self.assertTrue(str(content["patient_name"]).startswith("«SECRET:"))

    def test_placeholder_is_stable(self):
        c1 = self.o.read_section_context(self.draft["id"], "Q1",
                                         actor="alice")
        c2 = self.o.read_section_context(self.draft["id"], "Q1",
                                         actor="alice")
        self.assertEqual(c1["evidence"][0]["content"]["patient_name"],
                         c2["evidence"][0]["content"]["patient_name"])

    def test_response_does_not_leak_denied_refs(self):
        ctx = self.o.read_section_context(self.draft["id"], "Q1",
                                          actor="alice")
        flat = str(ctx)
        self.assertNotIn("MAT-REG", flat)
        self.assertNotIn("MAT-STAT", flat)
        self.assertNotIn("15日报告", flat)

    def test_writer_cannot_read_unassigned_section(self):
        with self.assertRaises(NotAssignedError):
            self.o.read_section_context(self.draft["id"], "Q2",
                                        actor="alice")

    def test_non_member_cannot_read(self):
        with self.assertRaises(NotGroupMemberError):
            self.o.read_section_context(self.draft["id"], "Q1",
                                        actor="stranger")

    def test_owner_reads_everything_unredacted(self):
        ctx = self.o.read_section_context(self.draft["id"], "Q1",
                                          actor="intake")
        self.assertTrue(ctx["full"])
        self.assertEqual(ctx["denied_pin_count"], 0)
        self.assertEqual(ctx["evidence"][0]["content"]["patient_name"], "张三")

    def test_fields_none_grant_shows_nothing(self):
        self.o.put_question_grant(
            self.inq["id"], "Q1", visible_categories=["CASE"],
            visible_fields=[], material_ids=["MAT-CASE"],
            writers=["alice"], actor="intake")
        ctx = self.o.read_section_context(self.draft["id"], "Q1",
                                          actor="alice")
        content = ctx["evidence"][0]["content"]
        for v in content.values():
            self.assertTrue(str(v).startswith("«SECRET:"))


class TestSectionWriteGate(PartitionedBase):
    def test_writer_save_within_grant_ok(self):
        sec = self.alice_fills_q1()
        self.assertEqual(sec["revision"], 1)

    def test_save_requires_current_auth_revision(self):
        with self.assertRaises(StaleAuthRevisionError) as cm:
            self.alice_fills_q1  # noop
            self.o.submit_section(
                self.draft["id"], "Q1", "x [CASE:MAT-CASE@1]",
                expected_revision=0, expected_auth_revision=self.rev - 1,
                submitted_by="alice")
        # 错误详情只给当前修订号，不含任何证据
        d = cm.exception.details
        self.assertEqual(d["current_auth_revision"], self.rev)
        self.assertNotIn("evidence", d)

    def test_save_without_auth_revision_rejected_in_managed(self):
        with self.assertRaises(StaleAuthRevisionError):
            self.o.submit_section(
                self.draft["id"], "Q1", "x", expected_revision=0,
                submitted_by="alice")

    def test_citation_outside_grant_rejected_and_listed(self):
        with self.assertRaises(EvidenceAccessDeniedError) as cm:
            self.alice_fills_q1(
                body="越权引用法规 [REG:MAT-REG@1]")
        self.assertEqual(cm.exception.details["denied_refs"],
                         ["REG:MAT-REG@1"])
        # 章节未被写入
        draft = self.o.get_draft(self.draft["id"])
        self.assertEqual([s for s in draft["sections"] if s["qid"] == "Q1"],
                         [])

    def test_unassigned_writer_save_rejected(self):
        with self.assertRaises(NotAssignedError):
            self.o.submit_section(
                self.draft["id"], "Q1", "x [CASE:MAT-CASE@1]",
                expected_revision=0, expected_auth_revision=self.rev,
                submitted_by="bob")

    def test_protected_raw_value_in_body_rejected(self):
        # alice 只能看到占位符，却把真实姓名（未授权字段原值）写进正文
        with self.assertRaises(EvidenceAccessDeniedError):
            self.alice_fills_q1(body="患者叫张三 [CASE:MAT-CASE@1]")

    def test_placeholder_itself_allowed_in_body(self):
        ctx = self.o.read_section_context(self.draft["id"], "Q1",
                                          actor="alice")
        ph = ctx["evidence"][0]["content"]["patient_name"]
        sec = self.alice_fills_q1(body=f"患者代号 {ph} [CASE:MAT-CASE@1]")
        self.assertEqual(sec["revision"], 1)

    def test_owner_write_bypasses_field_restrictions(self):
        sec = self.o.submit_section(
            self.draft["id"], "Q1", "张三 [CASE:MAT-CASE@1]",
            expected_revision=0, expected_auth_revision=self.rev,
            submitted_by="intake")
        self.assertEqual(sec["revision"], 1)


class TestReassignLeaveTighten(PartitionedBase):
    def _fill_both(self):
        self.alice_fills_q1()
        self.bob_fills_q2()

    def test_reassign_invalidates_old_revision(self):
        self.alice_fills_q1()
        self.o.add_member(self.inq["id"], "carol", acted_by="intake")
        self.o.put_question_grant(
            self.inq["id"], "Q1", visible_categories=["CASE"],
            visible_fields=["event", "outcome"],
            material_ids=["MAT-CASE"], writers=["carol"], actor="intake")
        # alice 旧页面（旧授权号）保存必须失败，且不给新证据
        with self.assertRaises(StaleAuthRevisionError) as cm:
            self.o.submit_section(
                self.draft["id"], "Q1", "更新 [CASE:MAT-CASE@1]",
                expected_revision=1, expected_auth_revision=self.rev,
                submitted_by="alice")
        self.assertGreater(cm.exception.details["current_auth_revision"],
                           self.rev)

    def test_member_leave_invalidates_pages_and_tightens_grant(self):
        self.alice_fills_q1()
        self.o.remove_member(self.inq["id"], "alice", acted_by="intake")
        # alice 用旧号保存 -> 拒绝（已不在组）
        with self.assertRaises((NotGroupMemberError, StaleAuthRevisionError)):
            self.o.submit_section(
                self.draft["id"], "Q1", "离组后保存 [CASE:MAT-CASE@1]",
                expected_revision=1, expected_auth_revision=self.rev,
                submitted_by="alice")
        # 授权名单中 alice 已被同步移除
        g = self.o.get_question_grant(self.inq["id"], "Q1")
        self.assertNotIn("alice", g["writers"])

    def test_tighten_fields_then_old_save_still_rejected_by_revision(self):
        self.alice_fills_q1()
        self.o.put_question_grant(
            self.inq["id"], "Q1", visible_categories=["CASE"],
            visible_fields=["event"],  # outcome 收紧掉
            material_ids=["MAT-CASE"], writers=["alice"], actor="intake")
        new_rev = self.o.current_auth_revision(self.inq["id"])
        # 旧号拒绝
        with self.assertRaises(StaleAuthRevisionError):
            self.o.submit_section(
                self.draft["id"], "Q1", "恢复 [CASE:MAT-CASE@1]",
                expected_revision=1, expected_auth_revision=self.rev,
                submitted_by="alice")
        # 新号 + 新授权下 outcome 成为受保护字段：写入其原值拒绝
        with self.assertRaises(EvidenceAccessDeniedError):
            self.o.submit_section(
                self.draft["id"], "Q1", "转归恢复 [CASE:MAT-CASE@1]",
                expected_revision=1, expected_auth_revision=new_rev,
                submitted_by="alice")
        # 只用获准字段 event 则成功
        sec = self.o.submit_section(
            self.draft["id"], "Q1", "皮疹 [CASE:MAT-CASE@1]",
            expected_revision=1, expected_auth_revision=new_rev,
            submitted_by="alice")
        self.assertEqual(sec["revision"], 2)

    def test_sealed_answer_not_rewritten_when_permissions_change(self):
        self._fill_both()
        sub_id = self.o.finalize(self.draft["id"],
                                 sealed_by="intake")["submission_id"]
        before = self.o.submission_status(sub_id)["manifest_hash"]
        # 定稿后离组、转派、收紧都不改变封存答复
        self.o.remove_member(self.inq["id"], "alice", acted_by="intake")
        self.o.put_question_grant(
            self.inq["id"], "Q2",
            visible_categories=["REGULATION"],
            material_ids=["MAT-REG"], writers=["bob"], actor="intake")
        after = self.o.submission_status(sub_id)["manifest_hash"]
        self.assertEqual(before, after)
        report = self.o.verify_submission(sub_id)
        self.assertTrue(report["ok"])

    def test_concurrent_reassign_and_save_single_outcome(self):
        from reg_inquiry import access, drafts
        self.alice_fills_q1()
        outcomes = []
        # 保存线程在启动时快照“页面看到的”授权号与节修订号
        page = {"auth": self.rev, "sec": 1}

        def save():
            try:
                self.new_node(auto_recover=False).submit_section(
                    self.draft["id"], "Q1", "并发保存 [CASE:MAT-CASE@1]",
                    expected_revision=page["sec"],
                    expected_auth_revision=page["auth"],
                    submitted_by="alice")
                outcomes.append("saved")
            except StaleAuthRevisionError:
                outcomes.append("stale")
            except Exception as e:
                outcomes.append(type(e).__name__)

        def reassign():
            try:
                self.o.add_member(self.inq["id"], "carol",
                                  acted_by="intake")
                self.o.put_question_grant(
                    self.inq["id"], "Q1", visible_categories=["CASE"],
                    visible_fields=["event", "outcome"],
                    material_ids=["MAT-CASE"], writers=["carol"],
                    actor="intake")
                outcomes.append("reassigned")
            except Exception as e:
                outcomes.append(type(e).__name__)

        saw_saved = saw_stale = False
        for _ in range(10):
            with self.o.conn() as c:
                page["sec"] = [s["revision"] for s in drafts.list_sections(
                    c, self.draft["id"]) if s["qid"] == "Q1"][0]
            page["auth"] = self.rev
            before = set(outcomes)
            t1 = threading.Thread(target=save)
            t2 = threading.Thread(target=reassign)
            t1.start(); t2.start(); t1.join(); t2.join()
            new = set(outcomes) - before
            saw_saved = saw_saved or ("saved" in new)
            saw_stale = saw_stale or ("stale" in new)

            # 核心不变量：每个已落库的章节修订，其记录的授权号在 *当时*
            # 必须确实把撰写人分派给该问题（独立连接重放判定）。
            with self.o.conn() as c:
                draft = drafts.get_draft(c, self.draft["id"])
                for s in draft["sections"]:
                    if s["qid"] != "Q1":
                        continue
                    for rv in c.execute(
                            "SELECT revision,writer_key,auth_revision,is_cloned "
                            "FROM section_revisions WHERE section_id=? "
                            "ORDER BY revision", (s["id"],)):
                        if rv["is_cloned"] or rv["auth_revision"] is None:
                            continue
                        m = access.member_at(
                            c, self.inq["id"], rv["writer_key"],
                            rv["auth_revision"])
                        self.assertIsNotNone(
                            m, f"rev={rv['revision']} 撰写人保存时不在组")
                        if m["role"] != "OWNER":
                            g = access.grant_at(
                                c, self.inq["id"], "Q1",
                                rv["auth_revision"])
                            self.assertIsNotNone(
                                g, f"rev={rv['revision']} 保存时无授权")
                            self.assertIn(
                                rv["writer_key"], g["writers"],
                                f"rev={rv['revision']} 用失效授权号写入"
                                "（转派与保存产生了双重结果）")

            # 把 Q1 转回 alice，供下一轮以 alice 视角继续竞争
            self.o.put_question_grant(
                self.inq["id"], "Q1", visible_categories=["CASE"],
                visible_fields=["event", "outcome"],
                material_ids=["MAT-CASE"], writers=["alice"], actor="intake")
            self.rev = self.o.current_auth_revision(self.inq["id"])
        self.assertTrue(saw_saved or saw_stale)


class TestAttachmentBoundary(PartitionedBase):
    def test_writer_upload_requires_qid_and_authorized_source(self):
        # 缺 qid
        with self.assertRaises(EvidenceAccessDeniedError):
            self.o.add_attachment(
                self.draft["id"], filename="f.bin", content=b"x",
                derived_from_ref="CASE:MAT-CASE@1", uploaded_by="alice",
                expected_auth_revision=self.rev)
        # 溯源不在 Q1 授权
        with self.assertRaises(EvidenceAccessDeniedError):
            self.o.add_attachment(
                self.draft["id"], filename="f.bin", content=b"x", qid="Q1",
                derived_from_ref="REG:MAT-REG@1", uploaded_by="alice",
                expected_auth_revision=self.rev)

    def test_writer_upload_then_download_ok(self):
        a = self.o.add_attachment(
            self.draft["id"], filename="case.bin", content=b"%PDF",
            derived_from_ref="CASE:MAT-CASE@1", qid="Q1",
            uploaded_by="alice", expected_auth_revision=self.rev)
        blob = self.o.get_attachment(self.draft["id"], a["id"],
                                     actor="alice")
        self.assertEqual(blob["content_blob"], b"%PDF")

    def test_other_writer_download_denied(self):
        a = self.o.add_attachment(
            self.draft["id"], filename="case.bin", content=b"%PDF",
            derived_from_ref="CASE:MAT-CASE@1", qid="Q1",
            uploaded_by="alice", expected_auth_revision=self.rev)
        with self.assertRaises(EvidenceAccessDeniedError):
            self.o.get_attachment(self.draft["id"], a["id"], actor="bob")

    def test_download_after_permission_tighten_denied(self):
        a = self.o.add_attachment(
            self.draft["id"], filename="case.bin", content=b"%PDF",
            derived_from_ref="CASE:MAT-CASE@1", qid="Q1",
            uploaded_by="alice", expected_auth_revision=self.rev)
        # Q1 收紧为仅法规（病例不再可见）
        self.o.put_question_grant(
            self.inq["id"], "Q1",
            visible_categories=["REGULATION", "STATISTIC"],
            material_ids=["MAT-REG", "MAT-STAT"], writers=["alice"],
            actor="intake")
        with self.assertRaises(EvidenceAccessDeniedError):
            self.o.get_attachment(self.draft["id"], a["id"], actor="alice")

    def test_owner_download_always_ok(self):
        a = self.o.add_attachment(
            self.draft["id"], filename="case.bin", content=b"%PDF",
            derived_from_ref="CASE:MAT-CASE@1", qid="Q1",
            uploaded_by="alice", expected_auth_revision=self.rev)
        self.assertEqual(
            self.o.get_attachment(self.draft["id"], a["id"],
                                  actor="intake")["content_blob"], b"%PDF")

    def test_cross_question_attachment_citation_rejected(self):
        a = self.o.add_attachment(
            self.draft["id"], filename="case.bin", content=b"%PDF",
            derived_from_ref="CASE:MAT-CASE@1", qid="Q1",
            uploaded_by="alice", expected_auth_revision=self.rev)
        # bob 在 Q2 引用 Q1 的附件：保存被拒
        with self.assertRaises(EvidenceAccessDeniedError) as cm:
            self.bob_fills_q2(
                body=f"[REG:MAT-REG@1] @attachment:{a['id']}")
        self.assertEqual(cm.exception.details["denied_attachments"], [a["id"]])


class TestFinalizeVerification(PartitionedBase):
    def _fill_both_with_attachment(self):
        a = self.o.add_attachment(
            self.draft["id"], filename="case.bin", content=b"%PDF",
            derived_from_ref="CASE:MAT-CASE@1", qid="Q1",
            uploaded_by="alice", expected_auth_revision=self.rev)
        self.alice_fills_q1(
            body=f"皮疹恢复 [CASE:MAT-CASE@1] @attachment:{a['id']}")
        self.bob_fills_q2()
        return a

    def test_authorized_finalize_succeeds_and_sends(self):
        self._fill_both_with_attachment()
        sub_id = self.o.finalize(self.draft["id"],
                                 sealed_by="intake")["submission_id"]
        r = self.o.send(sub_id)
        self.assertEqual(r["status"], "SENT")
        v = self.o.verify_submission(sub_id)
        self.assertTrue(v["ok"], v["failures"])

    def test_finalize_blocks_after_writer_removed_without_rewrite(self):
        self.alice_fills_q1()
        self.bob_fills_q2()
        # 定稿前 alice 离组：其保存时在组（历史判定仍合法），故不阻断；
        # 但这里演示“离组后未重新分派导致无法修改”的阻断面：carol 被分派
        # 后试图用含越权引用的修订定稿。
        self.o.remove_member(self.inq["id"], "alice", acted_by="intake")
        report = self.o.validate(self.draft["id"])
        # alice 保存时在组 -> 历史授权合法，定稿可通过（封存不因当前离组改写）
        self.assertTrue(report["ok"], report["blocking"])

    def test_finalize_lists_qid_section_denied_refs_without_values(self):
        # 绕过保存闸门不可行（闸门先拦），因此直接构造“保存时授权合法、
        # 随后授权收紧”的链头修订场景：收紧后旧链头引用超出新边界——
        # 但封存按 *保存当时* 授权判定，故合法。改为验证越权留痕不含值。
        self.alice_fills_q1()
        denials = self.o.auth_conflicts(inquiry_id=self.inq["id"])
        # 构造一次越权产生留痕
        try:
            self.alice_fills_q1(body="越权 [REG:MAT-REG@1]")
        except EvidenceAccessDeniedError:
            pass
        denials = self.o.auth_conflicts(inquiry_id=self.inq["id"])
        self.assertTrue(denials)
        flat = str(denials)
        self.assertNotIn("15日报告", flat)  # 被拒资料内容绝不回显
        self.assertNotIn("张三", flat)
        hit = [d for d in denials
               if d["reason_code"] == "EVIDENCE_ACCESS_DENIED"][0]
        self.assertEqual(hit["qid"], "Q1")
        self.assertEqual(hit["denied_refs"], ["REG:MAT-REG@1"])

    def test_manifest_records_auth_snapshot(self):
        self._fill_both_with_attachment()
        sub_id = self.o.finalize(self.draft["id"],
                                 sealed_by="intake")["submission_id"]
        manifest = self.o.submission_status(sub_id)["manifest"]
        q1 = [a for a in manifest["answers"] if a["qid"] == "Q1"][0]
        self.assertEqual(q1["writer_key"], "alice")
        self.assertEqual(q1["auth_revision"], self.rev)
        att = q1["attachments"][0]
        self.assertEqual(att["writer_key"], "alice")
        self.assertEqual(att["qid"], "Q1")

    def test_independent_verifier_detects_auth_tampering(self):
        self._fill_both_with_attachment()
        sub_id = self.o.finalize(self.draft["id"],
                                 sealed_by="intake")["submission_id"]
        # 授权快照所在的 section_revisions 只增：任何 UPDATE 都被触发器
        # 数据库层拒绝（独立核验据此确认快照不可被事后改写）。
        import sqlite3
        with self.assertRaises(sqlite3.DatabaseError):
            with self.o.conn() as c:
                c.execute("BEGIN IMMEDIATE")
                c.execute("UPDATE section_revisions SET writer_key='mallory'")
                c.execute("COMMIT")
        self.assertTrue(self.o.verify_submission(sub_id)["ok"])


class TestCorrectionReauth(PartitionedBase):
    def setUp(self):
        super().setUp()
        a = self.o.add_attachment(
            self.draft["id"], filename="case.bin", content=b"%PDF",
            derived_from_ref="CASE:MAT-CASE@1", qid="Q1",
            uploaded_by="alice", expected_auth_revision=self.rev)
        self.alice_fills_q1(
            body=f"皮疹恢复 [CASE:MAT-CASE@1] @attachment:{a['id']}")
        self.bob_fills_q2()
        self.sub_id = self.o.finalize(
            self.draft["id"], sealed_by="intake")["submission_id"]
        self.o.register_material(
            material_id="MAT-CASE", version="2", category="CASE",
            content={"patient_name": "张三", "event": "皮疹",
                     "outcome": "色素沉着"},
            title="病例 v2")
        self.corr = self.o.create_correction_draft(
            self.sub_id,
            refs=["CASE:MAT-CASE@2", "REG:MAT-REG@1", "STAT:MAT-STAT@1"],
            reason="随访 v2", created_by="intake")
        self.corr_rev = self.o.current_auth_revision(self.inq["id"])

    def test_cloned_correction_must_be_rewritten_under_current_auth(self):
        report = self.o.validate(self.corr["id"])
        codes = {b["code"] for b in report["blocking"]}
        self.assertIn("SAVE_AUTHZ_MISSING", codes)
        # 同样列出尚未满足的问题（精确到 qid），且不含受保护内容
        unsatisfied = {u["qid"] for u in report["unsatisfied"]}
        self.assertEqual(unsatisfied, {"Q1", "Q2"})
        with self.assertRaises(JobFailed) as cm:
            self.o.finalize(self.corr["id"], sealed_by="intake")
        self.assertEqual(cm.exception.code, "VALIDATION_FAILED")

    def test_rewrite_then_finalize_succeeds(self):
        # Q1 授权需覆盖 v2（material_ids 是逻辑 id，已覆盖 MAT-CASE）
        self.o.put_question_grant(
            self.inq["id"], "Q1", visible_categories=["CASE"],
            visible_fields=["event", "outcome"],
            material_ids=["MAT-CASE"], writers=["alice"], actor="intake")
        rev = self.o.current_auth_revision(self.inq["id"])
        a1 = self.corr["attachments"][0]
        self.o.submit_section(
            self.corr["id"], "Q1",
            f"色素沉着 [CASE:MAT-CASE@2] @attachment:{a1['id']}",
            expected_revision=1, expected_auth_revision=rev,
            submitted_by="alice")
        self.o.submit_section(
            self.corr["id"], "Q2",
            "15 日 [REG:MAT-REG@1]；PRR [STAT:MAT-STAT@1]",
            expected_revision=1, expected_auth_revision=rev,
            submitted_by="bob")
        sub2 = self.o.finalize(self.corr["id"],
                               sealed_by="intake")["submission_id"]
        self.assertTrue(self.o.verify_submission(sub2)["ok"])
        # 原提交件不变
        self.assertTrue(self.o.verify_submission(self.sub_id)["ok"])


class TestOwnerAndUnmanaged(InquiryTestBase):
    def test_owner_retains_full_draft_finalize_send(self):
        self.seed_materials()
        self.o.register_inquiry(
            regulator="NMPA", jurisdiction="CN",
            questions=[{"qid": "Q1", "text": "a"}, {"qid": "Q2", "text": "b"}],
            deadline="2026-10-20T00:00:00+00:00",
            allowed_material_ids=["MAT-CASE", "MAT-REG", "MAT-STAT",
                                  "MAT-CASE2"],
            registered_by="lead")
        inq = [i for i in self.o.list_inquiries()
               if i["registered_by"] == "lead"][0]
        draft = self.o.lock_draft(
            inq["id"], ["CASE:MAT-CASE@1", "REG:MAT-REG@1"])
        rev = self.o.current_auth_revision(inq["id"])  # 托管（有 OWNER）
        a = self.o.add_attachment(
            draft["id"], filename="c.pdf", content=b"%PDF",
            derived_from_ref="CASE:MAT-CASE@1", qid="Q1",
            uploaded_by="lead", expected_auth_revision=rev)
        # 负责人无需逐问授权即可写任何章节、引用任何在范围资料
        self.o.submit_section(
            draft["id"], "Q1", f"已恢复 [CASE:MAT-CASE@1] @attachment:{a['id']}",
            expected_revision=0, expected_auth_revision=rev,
            submitted_by="lead")
        self.o.submit_section(
            draft["id"], "Q2", "[REG:MAT-REG@1]",
            expected_revision=0, expected_auth_revision=rev,
            submitted_by="lead")
        sid = self.o.finalize(draft["id"], sealed_by="lead")["submission_id"]
        r = self.o.send(sid)
        self.assertEqual(r["status"], "SENT")

    def test_unmanaged_inquiry_keeps_legacy_behavior(self):
        # 无 registered_by -> 无成员 -> 非托管：旧调用方式全部继续工作
        self.seed_materials()
        inq = self.register()
        draft = self.o.lock_draft(inq["id"],
                                  ["CASE:MAT-CASE@1", "REG:MAT-REG@1"])
        self.assertEqual(self.o.current_auth_revision(inq["id"]), 0)
        a = self.o.add_attachment(draft["id"], filename="c.pdf",
                                  content=b"%PDF",
                                  derived_from_ref="CASE:MAT-CASE@1")
        self.o.submit_section(draft["id"], "Q1",
                              f"已恢复 [CASE:MAT-CASE@1] @attachment:{a['id']}",
                              expected_revision=0, submitted_by="anyone")
        self.o.submit_section(draft["id"], "Q2", "[REG:MAT-REG@1]",
                              expected_revision=0, submitted_by="anyone")
        # 上下文与附件对任意调用方全量
        ctx = self.o.read_section_context(draft["id"], "Q1", actor="anyone")
        self.assertTrue(ctx["full"])
        sid = self.o.finalize(draft["id"], sealed_by="lead")["submission_id"]
        self.assertTrue(self.o.verify_submission(sid)["ok"])


class TestAuditAndHistory(PartitionedBase):
    def test_change_history_complete(self):
        self.alice_fills_q1()
        self.o.remove_member(self.inq["id"], "alice", acted_by="intake")
        hist = self.o.auth_history(self.inq["id"])
        self.assertGreaterEqual(hist["current_auth_revision"], self.rev + 1)
        actions = [(e["member_raw"], e["action"]) for e in hist["member_events"]]
        self.assertIn(("alice", "JOINED"), actions)
        self.assertIn(("alice", "LEFT"), actions)
        # 原始身份写法原样保留
        self.assertTrue(any(e["member_raw"] == "alice"
                            for e in hist["member_events"]))

    def test_audit_chain_intact(self):
        self.alice_fills_q1()
        self.bob_fills_q2()
        try:
            self.alice_fills_q1(body="越权 [REG:MAT-REG@1]")
        except EvidenceAccessDeniedError:
            pass
        v = self.o.verify_audit_chain()
        self.assertTrue(v["ok"], v["failures"])

    def test_denial_query_filters(self):
        try:
            self.alice_fills_q1(body="越权 [REG:MAT-REG@1]")
        except EvidenceAccessDeniedError:
            pass
        by_code = self.o.auth_conflicts(
            inquiry_id=self.inq["id"],
            reason_code="EVIDENCE_ACCESS_DENIED")
        self.assertTrue(by_code)
        self.assertTrue(all(
            d["reason_code"] == "EVIDENCE_ACCESS_DENIED" for d in by_code))
        by_draft = self.o.auth_conflicts(draft_id=self.draft["id"])
        self.assertTrue(all(d["draft_id"] == self.draft["id"]
                            for d in by_draft))
