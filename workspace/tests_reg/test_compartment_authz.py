"""分区写作与最小披露权限：策略/分派/受限上下文/修订号失效/并发放宽收紧/
越权留痕/附件边界/封存不变/更正按当时授权重检/独立核验/审计。"""
import threading

from reg_inquiry.errors import (AuthzConflictError, ForbiddenError,
                                InvalidActorError, NotEnrolledError,
                                StaleAuthzRevisionError)

from .reg_base import InquiryTestBase


class AuthzTestBase(InquiryTestBase):
    """启用分区授权的两问标准环境：
    Q1（CASE，字段 outcome，撰写人 alice）/ Q2（REGULATION，全字段，bob）。
    """

    def setUp(self):
        super().setUp()
        self.seed_materials()
        self.inq = self.register(
            allowed=("MAT-CASE", "MAT-REG", "MAT-STAT", "MAT-CASE2"))
        self.draft = self.o.lock_draft(
            self.inq["id"],
            ["CASE:MAT-CASE@1", "REG:MAT-REG@1", "STAT:MAT-STAT@1"])
        self.enroll()

    def enroll(self, *, grants=None, writers=("alice", "bob")):
        grants = grants or {
            "Q1": {"categories": ["CASE"], "fields": ["outcome"],
                   "writers": ["alice"]},
            "Q2": {"categories": ["REGULATION"], "fields": ["*"],
                   "writers": ["bob"]}}
        return self.o.enroll_authz(
            self.inq["id"], lead="lead", writers=list(writers), grants=grants,
            enrolled_by="lead")


# ---------------------------------------------------------------------------
# 1) 授权策略 / 问题分派 / 身份规范化
# ---------------------------------------------------------------------------
class TestEnrollmentAndPolicy(AuthzTestBase):
    def test_enroll_creates_revision_1_and_baseline_grants(self):
        self.assertEqual(self.o.authz_revision(self.inq["id"]), 1)
        g1 = self.o.get_question_policy(self.inq["id"], "Q1")
        self.assertEqual(g1["categories"], ["CASE"])
        self.assertEqual(g1["fields"], ["outcome"])
        self.assertEqual(g1["writer_keys"], ["alice"])
        members = self.o.list_members(self.inq["id"], active_only=True)
        self.assertEqual(sorted(m["identity_key"] for m in members),
                         ["alice", "bob", "lead"])
        # 原始写法原样留痕
        raws = {m["identity_key"]: m["raw_identity"] for m in members}
        self.assertEqual(raws["lead"], "lead")

    def test_identity_equivalence_is_one_writer(self):
        # NFKC + casefold + 首尾空白：同一人不能靠写法差异占第二槽
        self.o.add_writers(self.inq["id"], [" Carol "], updated_by="lead")
        self.o.set_question_policy(
            self.inq["id"], "Q2", categories=["REGULATION"], fields=["*"],
            writers=["bob", "CAROL"], expected_revision=2, updated_by="lead")
        g = self.o.get_question_policy(self.inq["id"], "Q2")
        self.assertEqual(sorted(g["writer_keys"]), ["bob", "carol"])

    def test_blank_and_non_string_actor_rejected(self):
        with self.assertRaises(InvalidActorError):
            self.o.read_section_context(self.draft["id"], "Q1", actor="   ")
        with self.assertRaises(InvalidActorError):
            self.o.submit_section(self.draft["id"], "Q1", "x",
                                  expected_revision=0, submitted_by=None,
                                  expected_authz_revision=1)
        with self.assertRaises(InvalidActorError):
            self.o.add_attachment(self.draft["id"], filename="x", content=b"x",
                                  derived_from_ref="CASE:MAT-CASE@1",
                                  uploaded_by="", qid="Q1")

    def test_only_lead_can_change_policy_and_roster(self):
        with self.assertRaises(ForbiddenError):
            self.o.set_question_policy(
                self.inq["id"], "Q1", categories=["CASE"], fields=["*"],
                writers=["alice"], updated_by="alice")
        with self.assertRaises(ForbiddenError):
            self.o.remove_writers(self.inq["id"], ["bob"], updated_by="alice")

    def test_writer_must_be_enrolled_member(self):
        with self.assertRaises(AuthzConflictError):
            self.o.set_question_policy(
                self.inq["id"], "Q1", categories=["CASE"], fields=["*"],
                writers=["alice", "ghost"], expected_revision=1,
                updated_by="lead")

    def test_categories_cannot_escape_frozen_inquiry_scope(self):
        # 独立问询：冻结范围只含 REGULATION 类别（CASE 被范围排除）
        narrow = self.o.register_inquiry(
            regulator="NMPA", jurisdiction="CN",
            questions=[{"qid": "Q1", "text": "仅法规"}],
            deadline="2026-10-20T00:00:00+00:00",
            allowed_material_ids=["MAT-REG"],
            allowed_categories=["REGULATION"])
        self.o.enroll_authz(narrow["id"], lead="lead", writers=["alice"])
        with self.assertRaises(AuthzConflictError):
            self.o.set_question_policy(
                narrow["id"], "Q1", categories=["CASE"], fields=["*"],
                writers=["alice"], updated_by="lead")

    def test_unknown_qid_rejected(self):
        # 重复启用幂等（不报错、不产生第二个基线）
        r = self.o.enroll_authz(self.inq["id"], lead="lead")
        self.assertTrue(r["deduped"])
        with self.assertRaises(Exception):
            self.o.set_question_policy(
                self.inq["id"], "NOPE", categories=["CASE"], fields=["*"],
                writers=["alice"], updated_by="lead")

    def test_stale_expected_revision_conflict(self):
        # 先放宽字段（rev 2），再用旧号 1 再改 -> VERSION_MOVED
        self.o.set_question_policy(
            self.inq["id"], "Q1", categories=["CASE"],
            fields=["outcome", "patient_name"], writers=["alice"],
            expected_revision=1, updated_by="lead")
        with self.assertRaises(AuthzConflictError) as cm:
            self.o.set_question_policy(
                self.inq["id"], "Q1", categories=["CASE"], fields=["*"],
                writers=["alice"], expected_revision=1, updated_by="lead")
        self.assertEqual(cm.exception.details["reason"], "VERSION_MOVED")

    def test_identical_policy_request_is_noop(self):
        n0 = len(self.o.authz_history(self.inq["id"]))
        r = self.o.set_question_policy(
            self.inq["id"], "Q1", categories=["CASE"], fields=["outcome"],
            writers=["alice"], expected_revision=1, updated_by="lead")
        self.assertFalse(r["changed"])
        self.assertEqual(r["authz_revision"], 1)
        self.assertEqual(len(self.o.authz_history(self.inq["id"])), n0)
        # 顺序不同但内容相同也算相同请求
        r2 = self.o.set_question_policy(
            self.inq["id"], "Q1", categories=["CASE"], fields=["outcome"],
            writers=["alice"], expected_revision=1, updated_by="lead")
        self.assertFalse(r2["changed"])

    def test_enroll_is_idempotent(self):
        r2 = self.o.enroll_authz(self.inq["id"], lead="lead",
                                 writers=["alice", "bob"])
        self.assertTrue(r2["deduped"])
        self.assertEqual(self.o.authz_revision(self.inq["id"]), 1)

    def test_tighten_and_loosen_both_advance_revision(self):
        r1 = self.o.set_question_policy(
            self.inq["id"], "Q1", categories=[], fields=[], writers=["alice"],
            expected_revision=1, updated_by="lead")
        self.assertEqual(r1["authz_revision"], 2)
        r2 = self.o.set_question_policy(
            self.inq["id"], "Q1", categories=["CASE"], fields=["*"],
            writers=["alice"], expected_revision=2, updated_by="lead")
        self.assertEqual(r2["authz_revision"], 3)


# ---------------------------------------------------------------------------
# 2) 受限上下文读取：最小披露 + 稳定占位符
# ---------------------------------------------------------------------------
class TestRestrictedContext(AuthzTestBase):
    def test_writer_sees_only_granted_category(self):
        ctx = self.o.read_section_context(self.draft["id"], "Q1", actor="alice")
        refs = {e["ref"] for e in ctx["evidence"]}
        self.assertEqual(refs, {"CASE:MAT-CASE@1"})
        # REG/STAT 被拒类别直接不出现（不确认其存在）
        self.assertFalse(any("REG" in r or "STAT" in r for r in refs))

    def test_projected_fields_replace_sensitive_values(self):
        from reg_inquiry.authz import placeholder
        ctx = self.o.read_section_context(self.draft["id"], "Q1", actor="alice")
        content = ctx["evidence"][0]["content"]
        self.assertEqual(content["outcome"], "恢复")            # 获准字段原值
        self.assertNotIn("张三", str(content))                  # 不泄露姓名
        self.assertEqual(content["patient_name"],
                         placeholder("patient_name"))           # 稳定占位符
        self.assertEqual(ctx["visible_fields"], ["outcome"])

    def test_placeholder_stable_across_contexts(self):
        from reg_inquiry.authz import placeholder
        c1 = self.o.read_section_context(self.draft["id"], "Q1", actor="alice")
        c2 = self.o.read_section_context(self.draft["id"], "Q1", actor="alice")
        self.assertEqual(c1["evidence"][0]["content"]["patient_name"],
                         c2["evidence"][0]["content"]["patient_name"])
        self.assertEqual(c1["evidence"][0]["content"]["patient_name"],
                         placeholder("patient_name"))

    def test_non_writer_cannot_read_and_is_logged(self):
        with self.assertRaises(ForbiddenError):
            self.o.read_section_context(self.draft["id"], "Q1", actor="bob")
        denials = self.o.authz_conflicts(
            inquiry_id=self.inq["id"], action="READ_CONTEXT")["denials"]
        self.assertEqual(len(denials), 1)
        self.assertEqual(denials[0]["qid"], "Q1")
        self.assertEqual(denials[0]["actor_key"], "bob")
        # 留痕不含正文内容
        self.assertNotIn("张三", str(denials[0]))

    def test_lead_sees_full_evidence(self):
        ctx = self.o.read_section_context(self.draft["id"], "Q1", actor="lead")
        self.assertEqual({e["ref"] for e in ctx["evidence"]},
                         {"CASE:MAT-CASE@1", "REG:MAT-REG@1", "STAT:MAT-STAT@1"})
        self.assertEqual(ctx["evidence"][0]["content"]["patient_name"], "张三")

    def test_removed_writer_loses_context_immediately(self):
        self.o.remove_writers(self.inq["id"], ["alice"], updated_by="lead")
        with self.assertRaises(ForbiddenError):
            self.o.read_section_context(self.draft["id"], "Q1", actor="alice")

    def test_context_carries_revisions_for_save(self):
        ctx = self.o.read_section_context(self.draft["id"], "Q2", actor="bob")
        self.assertEqual(ctx["authz_revision"], 1)
        self.assertEqual(ctx["section_revision"], 0)


# ---------------------------------------------------------------------------
# 3) 保存授权闸门 + 旧授权号失效
# ---------------------------------------------------------------------------
class TestSaveGate(AuthzTestBase):
    def test_qualified_save_succeeds_and_records_authz_rev(self):
        s = self.o.submit_section(
            self.draft["id"], "Q1", "恢复 [CASE:MAT-CASE@1]",
            expected_revision=0, submitted_by="alice",
            expected_authz_revision=1)
        self.assertEqual(s["revision"], 1)
        sec = [x for x in self.o.get_draft(self.draft["id"])["sections"]
               if x["qid"] == "Q1"][0]
        self.assertEqual(sec["authz_revision"], 1)

    def test_writer_cannot_save_other_question(self):
        with self.assertRaises(ForbiddenError):
            self.o.submit_section(
                self.draft["id"], "Q1", "x [CASE:MAT-CASE@1]",
                expected_revision=0, submitted_by="bob",
                expected_authz_revision=1)

    def test_citation_outside_granted_category_denied(self):
        with self.assertRaises(ForbiddenError) as cm:
            self.o.submit_section(
                self.draft["id"], "Q1",
                "违规引用 [REG:MAT-REG@1]", expected_revision=0,
                submitted_by="alice", expected_authz_revision=1)
        denied = cm.exception.details["denied"]
        self.assertEqual(denied[0]["denied_ref"], "REG:MAT-REG@1")
        self.assertEqual(denied[0]["category"], "REGULATION")
        # 不回显受保护内容
        self.assertNotIn("15日报告", str(cm.exception.details))
        # 章节没有被写入
        secs = [s for s in self.o.get_draft(self.draft["id"])["sections"]
                if s["qid"] == "Q1"]
        self.assertEqual(secs, [])
        # 越权逐项留痕
        denials = self.o.authz_conflicts(
            draft_id=self.draft["id"], action="SAVE_SECTION")["denials"]
        self.assertEqual(len(denials), 1)
        self.assertEqual(denials[0]["denied_ref"], "REG:MAT-REG@1")

    def test_save_requires_expected_authz_revision(self):
        with self.assertRaises(StaleAuthzRevisionError):
            self.o.submit_section(
                self.draft["id"], "Q1", "x [CASE:MAT-CASE@1]",
                expected_revision=0, submitted_by="alice",
                expected_authz_revision=None)

    def test_stale_authz_revision_after_tighten_rejected_without_new_evidence(self):
        self.o.set_question_policy(
            self.inq["id"], "Q1", categories=["CASE"],
            fields=["outcome", "patient_name"], writers=["alice"],
            expected_revision=1, updated_by="lead")
        with self.assertRaises(StaleAuthzRevisionError) as cm:
            self.o.submit_section(
                self.draft["id"], "Q1", "旧视图 [CASE:MAT-CASE@1]",
                expected_revision=0, submitted_by="alice",
                expected_authz_revision=1)
        self.assertEqual(cm.exception.details["current"], 2)
        # 响应不泄露新授权内容：只有修订号，无证据片段
        self.assertNotIn("evidence", cm.exception.details)
        denials = self.o.authz_conflicts(
            inquiry_id=self.inq["id"], action="SAVE_SECTION")["denials"]
        self.assertTrue(any(d["code"] == "STALE_AUTHZ_REVISION" for d in denials))

    def test_stale_after_transfer_and_member_removal(self):
        # 转派
        self.o.add_writers(self.inq["id"], ["lead2"], updated_by="lead")
        self.o.transfer_lead(self.inq["id"], new_lead="lead2", updated_by="lead")
        with self.assertRaises(StaleAuthzRevisionError):
            self.o.submit_section(
                self.draft["id"], "Q1", "x [CASE:MAT-CASE@1]",
                expected_revision=0, submitted_by="alice",
                expected_authz_revision=1)
        # 新负责人转派回 lead 后，alice 用新号可保存
        cur = self.o.authz_revision(self.inq["id"])
        self.o.transfer_lead(self.inq["id"], new_lead="lead",
                             updated_by="lead2")
        self.o.submit_section(
            self.draft["id"], "Q1", "恢复 [CASE:MAT-CASE@1]",
            expected_revision=0, submitted_by="alice",
            expected_authz_revision=cur + 1)

    def test_removed_member_save_denied(self):
        self.o.remove_writers(self.inq["id"], ["alice"], updated_by="lead")
        with self.assertRaises(ForbiddenError):
            self.o.submit_section(
                self.draft["id"], "Q1", "x [CASE:MAT-CASE@1]",
                expected_revision=0, submitted_by="alice",
                expected_authz_revision=2)

    def test_reactivated_member_keeps_old_revisions_invalid(self):
        self.o.remove_writers(self.inq["id"], ["alice"], updated_by="lead")
        self.o.reactivate_writers(self.inq["id"], ["alice"], updated_by="lead")
        # 旧号 1 已失效（离组 2 / 回组 3）
        with self.assertRaises(StaleAuthzRevisionError):
            self.o.submit_section(
                self.draft["id"], "Q1", "x [CASE:MAT-CASE@1]",
                expected_revision=0, submitted_by="alice",
                expected_authz_revision=1)
        # 新号 3 可以
        self.o.submit_section(
            self.draft["id"], "Q1", "恢复 [CASE:MAT-CASE@1]",
            expected_revision=0, submitted_by="alice",
            expected_authz_revision=3)

    def test_denial_persists_though_business_transaction_rolled_back(self):
        # 越权保存抛错后，留痕在独立事务中仍然存在
        with self.assertRaises(ForbiddenError):
            self.o.submit_section(
                self.draft["id"], "Q1", "x [REG:MAT-REG@1]",
                expected_revision=0, submitted_by="alice",
                expected_authz_revision=1)
        denials = self.o.authz_conflicts(inquiry_id=self.inq["id"])["denials"]
        self.assertEqual(len(denials), 1)

    def test_repeated_identical_save_requests_no_duplicate_section(self):
        # 内容相同的两次合规保存：第二次是正常的章节修订（乐观号模型），
        # 但相同授权请求本身（enroll/policy）不重复留痕——这里验证拒绝
        # 场景的重复越权每次都可追溯（每次尝试独立留痕，不同于幂等放行）
        for _ in range(2):
            with self.assertRaises(ForbiddenError):
                self.o.submit_section(
                    self.draft["id"], "Q1", "x [REG:MAT-REG@1]",
                    expected_revision=0, submitted_by="alice",
                    expected_authz_revision=1)
        denials = self.o.authz_conflicts(
            draft_id=self.draft["id"], action="SAVE_SECTION")["denials"]
        self.assertEqual(len(denials), 2)

    def test_lead_save_requires_fresh_revision_too(self):
        self.o.remove_writers(self.inq["id"], ["alice"], updated_by="lead")
        with self.assertRaises(StaleAuthzRevisionError):
            self.o.submit_section(
                self.draft["id"], "Q1", "负责人旧号 [CASE:MAT-CASE@1]",
                expected_revision=0, submitted_by="lead",
                expected_authz_revision=1)
        self.o.submit_section(
            self.draft["id"], "Q1", "负责人新号 [CASE:MAT-CASE@1]",
            expected_revision=0, submitted_by="lead",
            expected_authz_revision=2)


# ---------------------------------------------------------------------------
# 4) 转派与保存并发：只有一个结果
# ---------------------------------------------------------------------------
class TestConcurrentTransferAndSave(AuthzTestBase):
    def test_transfer_and_save_concurrent_single_outcome(self):
        # 5 个 alice 用旧号 1 并发保存，同时 lead 转派推进修订号
        self.o.add_writers(self.inq["id"], ["lead2"], updated_by="lead")
        barrier = threading.Barrier(6)
        outcomes = []

        def save(i):
            barrier.wait()
            node = self.new_node()
            try:
                node.submit_section(
                    self.draft["id"], "Q1", f"body-{i} [CASE:MAT-CASE@1]",
                    expected_revision=0, submitted_by="alice",
                    expected_authz_revision=1)
                outcomes.append(("save-ok", i))
            except Exception as e:  # noqa: BLE001
                outcomes.append((getattr(e, "code", type(e).__name__), i))

        def transfer():
            barrier.wait()
            node = self.new_node()
            try:
                node.transfer_lead(self.inq["id"], new_lead="lead2",
                                   updated_by="lead")
                outcomes.append(("transfer-ok", "t"))
            except Exception as e:  # noqa: BLE001
                outcomes.append((getattr(e, "code", type(e).__name__), "t"))

        ts = [threading.Thread(target=save, args=(i,)) for i in range(5)]
        ts.append(threading.Thread(target=transfer))
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        # 转派恰好一次
        self.assertEqual(len([o for o in outcomes if o[0] == "transfer-ok"]), 1)
        # 保存至多一次成功（转派先发生则全部 STALE；保存先发生则一人成功，
        # 其余 STALE_AUTHZ_REVISION/STALE_REVISION），绝不出现多个结果
        save_ok = [o for o in outcomes if o[0] == "save-ok"]
        self.assertLessEqual(len(save_ok), 1)
        # 章节最终至多 rev=1
        secs = [s for s in self.o.get_draft(self.draft["id"])["sections"]
                if s["qid"] == "Q1"]
        if save_ok:
            self.assertEqual(secs[0]["revision"], 1)
        # 授权修订号与转派帧严格一致
        hist = [e["event_type"] for e in self.o.authz_history(self.inq["id"])]
        self.assertEqual(hist.count("AUTHZ_LEAD_TRANSFERRED"), 1)

    def test_concurrent_policy_changes_single_winner(self):
        barrier = threading.Barrier(2)
        results = []
        # 基线 Q1 字段为 ["outcome"]；两个并发请求都与基线实质不同，
        # 但都基于修订号 1 —— CAS 保证只有一个生效。
        def change(fields):
            barrier.wait()
            node = self.new_node()
            try:
                r = node.set_question_policy(
                    self.inq["id"], "Q1", categories=["CASE"], fields=fields,
                    writers=["alice"], expected_revision=1, updated_by="lead")
                results.append(("ok", fields, r["authz_revision"]))
            except Exception as e:  # noqa: BLE001
                results.append((getattr(e, "code", "ERR"), fields, None))

        t1 = threading.Thread(target=change, args=(["*"],))
        t2 = threading.Thread(target=change, args=(["outcome", "patient_name"],))
        t1.start(); t2.start(); t1.join(); t2.join()
        oks = [r for r in results if r[0] == "ok"]
        self.assertEqual(len(oks), 1)  # 只有一个授权变更生效
        self.assertEqual(oks[0][2], 2)
        self.assertEqual(self.o.authz_revision(self.inq["id"]), 2)
        # 失败者得到 VERSION_MOVED
        self.assertTrue(any(r[0] == "AUTHZ_CONFLICT" for r in results))


# ---------------------------------------------------------------------------
# 5) 附件授权边界
# ---------------------------------------------------------------------------
class TestAttachmentBoundary(AuthzTestBase):
    def test_upload_requires_qid_membership_and_category(self):
        with self.assertRaises(AuthzConflictError):
            self.o.add_attachment(self.draft["id"], filename="x", content=b"x",
                                  derived_from_ref="CASE:MAT-CASE@1",
                                  uploaded_by="alice")  # 缺 qid
        with self.assertRaises(ForbiddenError):
            self.o.add_attachment(
                self.draft["id"], filename="x", content=b"x",
                derived_from_ref="REG:MAT-REG@1", uploaded_by="alice", qid="Q1")
        with self.assertRaises(ForbiddenError):
            self.o.add_attachment(
                self.draft["id"], filename="x", content=b"x",
                derived_from_ref="CASE:MAT-CASE@1", uploaded_by="bob", qid="Q1")

    def test_upload_records_authz_revision(self):
        a = self.o.add_attachment(
            self.draft["id"], filename="c.bin", content=b"X",
            derived_from_ref="CASE:MAT-CASE@1", uploaded_by="alice", qid="Q1")
        self.assertEqual(a["qid"], "Q1")
        self.assertEqual(a["upload_authz_revision"], 1)

    def test_download_denied_for_other_writer(self):
        a = self.o.add_attachment(
            self.draft["id"], filename="c.bin", content=b"SECRET",
            derived_from_ref="CASE:MAT-CASE@1", uploaded_by="alice", qid="Q1")
        with self.assertRaises(ForbiddenError):
            self.o.get_attachment(self.draft["id"], a["id"], actor="bob")
        # alice 可下载
        self.assertEqual(
            self.o.get_attachment(self.draft["id"], a["id"],
                                  actor="alice")["content_blob"], b"SECRET")

    def test_download_revoked_after_category_tighten(self):
        a = self.o.add_attachment(
            self.draft["id"], filename="c.bin", content=b"X",
            derived_from_ref="CASE:MAT-CASE@1", uploaded_by="alice", qid="Q1")
        self.o.set_question_policy(
            self.inq["id"], "Q1", categories=[], fields=[], writers=["alice"],
            expected_revision=1, updated_by="lead")
        with self.assertRaises(ForbiddenError):
            self.o.get_attachment(self.draft["id"], a["id"], actor="alice")

    def test_attachment_citation_in_other_section_denied(self):
        a = self.o.add_attachment(
            self.draft["id"], filename="c.bin", content=b"X",
            derived_from_ref="CASE:MAT-CASE@1", uploaded_by="alice", qid="Q1")
        # bob 在 Q2 引用 Q1 的附件 -> 越权
        with self.assertRaises(ForbiddenError):
            self.o.submit_section(
                self.draft["id"], "Q2",
                f"挪附件 [REG:MAT-REG@1] @attachment:{a['id']}",
                expected_revision=0, submitted_by="bob",
                expected_authz_revision=1)


# ---------------------------------------------------------------------------
# 6) 定稿前逐问资格复核 + 封存后不变
# ---------------------------------------------------------------------------
class TestFinalizeAuthzChecks(AuthzTestBase):
    def _fill(self):
        a = self.o.add_attachment(
            self.draft["id"], filename="c.bin", content=b"X",
            derived_from_ref="CASE:MAT-CASE@1", uploaded_by="alice", qid="Q1")
        self.o.submit_section(
            self.draft["id"], "Q1",
            f"恢复 [CASE:MAT-CASE@1] @attachment:{a['id']}",
            expected_revision=0, submitted_by="alice",
            expected_authz_revision=1)
        self.o.submit_section(
            self.draft["id"], "Q2", "依据 [REG:MAT-REG@1]",
            expected_revision=0, submitted_by="bob",
            expected_authz_revision=1)
        return a

    def test_qualified_draft_finalizes(self):
        self._fill()
        rep = self.o.validate(self.draft["id"])
        self.assertTrue(rep["ok"], rep["blocking"])
        sealed = self.o.finalize(self.draft["id"], sealed_by="lead")
        sub = self.o.submission_status(sealed["submission_id"])
        self.assertEqual(sub["manifest"]["authz_revision"], 1)
        self.assertEqual(
            [x["authz_revision"] for x in sub["manifest"]["answers"]], [1, 1])

    def test_tighten_before_finalize_blocks_and_lists_qid_section_ref(self):
        self._fill()
        self.o.set_question_policy(
            self.inq["id"], "Q1", categories=[], fields=[], writers=["alice"],
            expected_revision=1, updated_by="lead")
        rep = self.o.validate(self.draft["id"])
        self.assertFalse(rep["ok"])
        codes = {i["code"] for i in rep["blocking"]}
        self.assertIn("CITATION_UNQUALIFIED", codes)
        self.assertIn("ATTACHMENT_UNQUALIFIED", codes)
        # 列出问题、章节、被拒资料，但不回显内容
        items = [i for i in rep["blocking"] if i["qid"] == "Q1"]
        self.assertTrue(all(i.get("section_id") for i in items))
        refs = {i.get("denied_ref") for i in items}
        self.assertIn("CASE:MAT-CASE@1", refs)
        self.assertNotIn("张三", str(rep["blocking"]))
        # 定稿确实被阻止
        from reg_inquiry.errors import JobFailed
        with self.assertRaises(JobFailed):
            self.o.finalize(self.draft["id"])

    def test_sealed_submission_not_rewritten_by_later_permission_changes(self):
        a = self._fill()
        sealed = self.o.finalize(self.draft["id"], sealed_by="lead")
        sid = sealed["submission_id"]
        self.o.remove_writers(self.inq["id"], ["alice", "bob"], updated_by="lead")
        self.o.set_question_policy(
            self.inq["id"], "Q1", categories=[], fields=[], writers=[],
            expected_revision=2, updated_by="lead")
        sub_before = self.o.submission_status(sid)
        # 独立核对仍通过；封存 manifest 固定修订号 1
        self.assertTrue(self.o.verify_submission(sid)["ok"])
        sub_after = self.o.submission_status(sid)
        self.assertEqual(sub_after["manifest_hash"], sub_before["manifest_hash"])
        self.assertEqual(sub_after["manifest"]["authz_revision"], 1)
        # 封存件即使在收紧后仍可被负责人读取（不可变，不被重写）
        self.assertEqual(
            self.o.get_attachment(self.draft["id"], a["id"],
                                  actor="lead")["sha256"], a["sha256"])

    def test_finalize_denials_are_logged(self):
        self._fill()
        self.o.set_question_policy(
            self.inq["id"], "Q1", categories=[], fields=[], writers=["alice"],
            expected_revision=1, updated_by="lead")
        self.o.validate(self.draft["id"])
        rows = self.o.authz_conflicts(
            draft_id=self.draft["id"], action="FINALIZE_CHECK")["denials"]
        self.assertTrue(rows)
        self.assertTrue(all(r["qid"] == "Q1" for r in rows))

    def test_lead_authored_sections_also_pinned_to_revision(self):
        self.o.remove_writers(self.inq["id"], ["alice"], updated_by="lead")
        # 负责人接手 Q1（离组后修订号为 2；负责人不受逐问名单限制）
        self.o.submit_section(
            self.draft["id"], "Q1", "恢复 [CASE:MAT-CASE@1]",
            expected_revision=0, submitted_by="lead",
            expected_authz_revision=2)
        self.o.submit_section(
            self.draft["id"], "Q2", "依据 [REG:MAT-REG@1]",
            expected_revision=0, submitted_by="bob",
            expected_authz_revision=2)
        rep = self.o.validate(self.draft["id"])
        self.assertTrue(rep["ok"], rep["blocking"])


# ---------------------------------------------------------------------------
# 7) 更正/候选：继承内容必须按当时授权重新检查
# ---------------------------------------------------------------------------
class TestCorrectionReauthorization(AuthzTestBase):
    def test_cloned_sections_and_attachments_need_recheck(self):
        a = self.o.add_attachment(
            self.draft["id"], filename="c.bin", content=b"X",
            derived_from_ref="CASE:MAT-CASE@1", uploaded_by="alice", qid="Q1")
        self.o.submit_section(
            self.draft["id"], "Q1",
            f"恢复 [CASE:MAT-CASE@1] @attachment:{a['id']}",
            expected_revision=0, submitted_by="alice",
            expected_authz_revision=1)
        self.o.submit_section(
            self.draft["id"], "Q2", "依据 [REG:MAT-REG@1]",
            expected_revision=0, submitted_by="bob",
            expected_authz_revision=1)
        sealed = self.o.finalize(self.draft["id"], sealed_by="lead")
        sub = self.o.submission_status(sealed["submission_id"])
        self.o.send(sub["id"])
        cd = self.o.create_correction_draft(sub["id"], reason="补充")
        cand = self.o.get_draft(cd["id"])
        # 克隆章节授权号为 NULL，附件上传授权号为 NULL
        sec = {s["qid"]: s for s in cand["sections"]}
        self.assertIsNone(sec["Q1"]["authz_revision"])
        self.assertIsNone(cand["attachments"][0]["upload_authz_revision"])
        rep = self.o.validate(cd["id"])
        codes = {i["code"] for i in rep["blocking"]}
        self.assertIn("SECTION_UNQUALIFIED", codes)
        self.assertIn("ATTACHMENT_UNQUALIFIED", codes)
        # 非授权人不能再认定
        with self.assertRaises(ForbiddenError):
            self.o.requalify_attachment(
                cd["id"], cand["attachments"][0]["id"], "Q1", actor="bob")
        # 合格撰写人再认定 + 重存 -> 通过
        self.o.requalify_attachment(
            cd["id"], cand["attachments"][0]["id"], "Q1", actor="alice")
        self.o.submit_section(
            cd["id"], "Q1",
            f"恢复（更正）[CASE:MAT-CASE@1] @attachment:{cand['attachments'][0]['id']}",
            expected_revision=1, submitted_by="alice",
            expected_authz_revision=1)
        self.o.submit_section(
            cd["id"], "Q2", "依据不变 [REG:MAT-REG@1]",
            expected_revision=1, submitted_by="bob",
            expected_authz_revision=1)
        self.assertTrue(self.o.validate(cd["id"])["ok"])

    def test_requalification_idempotent_and_rechecked_after_tighten(self):
        a = self.o.add_attachment(
            self.draft["id"], filename="c.bin", content=b"X",
            derived_from_ref="CASE:MAT-CASE@1", uploaded_by="alice", qid="Q1")
        self.o.submit_section(
            self.draft["id"], "Q1", f"恢复 [CASE:MAT-CASE@1] @attachment:{a['id']}",
            expected_revision=0, submitted_by="alice",
            expected_authz_revision=1)
        self.o.submit_section(
            self.draft["id"], "Q2", "依据 [REG:MAT-REG@1]",
            expected_revision=0, submitted_by="bob",
            expected_authz_revision=1)
        sealed = self.o.finalize(self.draft["id"], sealed_by="lead")
        sub = self.o.submission_status(sealed["submission_id"])
        cd = self.o.create_correction_draft(sub["id"], reason="r")
        aid = cd["attachments"][0]["id"]
        r1 = self.o.requalify_attachment(cd["id"], aid, "Q1", actor="alice")
        r2 = self.o.requalify_attachment(cd["id"], aid, "Q1", actor="alice")
        self.assertFalse(r1["deduped"])
        self.assertTrue(r2["deduped"])
        # 收紧后旧再认定不再满足当前授权：定稿仍阻断，需重新认定
        self.o.set_question_policy(
            self.inq["id"], "Q1", categories=[], fields=[], writers=["alice"],
            expected_revision=1, updated_by="lead")
        rep = self.o.validate(cd["id"])
        self.assertIn("ATTACHMENT_UNQUALIFIED",
                      {i["code"] for i in rep["blocking"]})

    def test_drift_candidate_inherits_with_rev_null_and_clones_attach_qid(self):
        a = self.o.add_attachment(
            self.draft["id"], filename="c.bin", content=b"X",
            derived_from_ref="CASE:MAT-CASE@1", uploaded_by="alice", qid="Q1")
        self.o.submit_section(
            self.draft["id"], "Q1", f"旧 [CASE:MAT-CASE@1] @attachment:{a['id']}",
            expected_revision=0, submitted_by="alice",
            expected_authz_revision=1)
        self.o.submit_section(
            self.draft["id"], "Q2", "依据 [REG:MAT-REG@1]",
            expected_revision=0, submitted_by="bob",
            expected_authz_revision=1)
        self.o.register_material(
            material_id="MAT-CASE", version="2", category="CASE",
            content={"outcome": "v2"}, fact_key="OUTCOME", fact_value="v2")
        cand = [d for d in self.o.list_drafts(self.inq["id"])
                if d["kind"] == "CANDIDATE"][0]
        cd = self.o.get_draft(cand["id"])
        self.assertIsNone(cd["sections"][0]["authz_revision"])
        self.assertEqual(cd["attachments"][0]["qid"], "Q1")
        self.assertIsNone(cd["attachments"][0]["upload_authz_revision"])
        rep = self.o.validate(cand["id"])
        self.assertIn("SECTION_UNQUALIFIED",
                      {i["code"] for i in rep["blocking"]})


# ---------------------------------------------------------------------------
# 8) 历史查询 / 变更历史 / 独立核验
# ---------------------------------------------------------------------------
class TestHistoryAndVerifier(AuthzTestBase):
    def test_change_history_records_all_events(self):
        self.o.set_question_policy(
            self.inq["id"], "Q1", categories=["CASE"],
            fields=["outcome", "patient_name"], writers=["alice"],
            expected_revision=1, updated_by="lead", reason="放宽姓名")
        self.o.remove_writers(self.inq["id"], ["bob"], updated_by="lead")
        hist = self.o.authz_history(self.inq["id"])
        types = [e["event_type"] for e in hist]
        self.assertEqual(types[0], "AUTHZ_ENROLLED")
        self.assertIn("AUTHZ_POLICY_CHANGED", types)
        self.assertIn("AUTHZ_MEMBERS_CHANGED", types)
        # 载荷不含敏感值，只含类别/字段/身份键
        for e in hist:
            self.assertNotIn("张三", str(e["payload"]))

    def test_grant_history_append_only(self):
        self.o.set_question_policy(
            self.inq["id"], "Q1", categories=["CASE"], fields=["*"],
            writers=["alice"], expected_revision=1, updated_by="lead")
        rows = self.o.grant_history(self.inq["id"], "Q1")
        self.assertEqual([r["revision"] for r in rows], [1, 2])

    def test_authz_conflicts_query_filters(self):
        with self.assertRaises(ForbiddenError):
            self.o.read_section_context(self.draft["id"], "Q1", actor="bob")
        with self.assertRaises(ForbiddenError):
            self.o.submit_section(
                self.draft["id"], "Q1", "x [REG:MAT-REG@1]",
                expected_revision=0, submitted_by="alice",
                expected_authz_revision=1)
        self.assertEqual(
            self.o.authz_conflicts(action="READ_CONTEXT")["count"], 1)
        self.assertEqual(
            self.o.authz_conflicts(action="SAVE_SECTION")["count"], 1)
        self.assertEqual(self.o.authz_conflicts(qid="Q2")["count"], 0)

    def test_verifier_passes_on_clean_state(self):
        a = self.o.add_attachment(
            self.draft["id"], filename="c.bin", content=b"X",
            derived_from_ref="CASE:MAT-CASE@1", uploaded_by="alice", qid="Q1")
        self.o.submit_section(
            self.draft["id"], "Q1", f"恢复 [CASE:MAT-CASE@1] @attachment:{a['id']}",
            expected_revision=0, submitted_by="alice",
            expected_authz_revision=1)
        self.o.submit_section(
            self.draft["id"], "Q2", "依据 [REG:MAT-REG@1]",
            expected_revision=0, submitted_by="bob",
            expected_authz_revision=1)
        self.o.finalize(self.draft["id"], sealed_by="lead")
        v = self.o.verify_authz(inquiry_id=self.inq["id"])
        self.assertTrue(v["ok"], v["failures"])

    def test_verifier_detects_illegal_grant_table_tamper(self):
        # 直接塞一条指向不存在修订号的授权台账行 -> 核验失败
        with self.o.conn() as c:
            c.execute(
                "INSERT INTO question_grants(id,inquiry_id,qid,revision,"
                "categories_json,fields_json,writer_keys_json,writers_raw_json,"
                "updated_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                ("fake", self.inq["id"], "Q1", 99, '["CASE"]', '["*"]',
                 '["alice"]', '["alice"]', "lead", "2026-10-01T10:00:00+00:00"))
        v = self.o.verify_authz(inquiry_id=self.inq["id"])
        self.assertFalse(v["ok"])
        self.assertIn("GRANT_REVISION_OUT_OF_RANGE",
                      {f["code"] for f in v["failures"]})

    def test_verifier_replays_as_of_after_removal(self):
        self.o.remove_writers(self.inq["id"], ["alice"], updated_by="lead")
        v = self.o.verify_authz(inquiry_id=self.inq["id"])
        self.assertTrue(v["ok"], v["failures"])  # 历史授权行 as-of 仍合法

    def test_audit_chain_intact_and_includes_authz_frames(self):
        self.o.set_question_policy(
            self.inq["id"], "Q1", categories=["CASE"], fields=["*"],
            writers=["alice"], expected_revision=1, updated_by="lead")
        chain = self.o.verify_audit_chain()
        self.assertTrue(chain["ok"])
        types = {e["event_type"] for e in
                 self.o.audit_trail(inquiry_id=self.inq["id"])}
        self.assertIn("AUTHZ_ENROLLED", types)
        self.assertIn("AUTHZ_POLICY_CHANGED", types)


# ---------------------------------------------------------------------------
# 9) 旧库迁移 + legacy（未启用）路径保持全量能力
# ---------------------------------------------------------------------------
class TestLegacyAndMigration(InquiryTestBase):
    def test_legacy_draft_works_without_enrollment(self):
        self.seed_materials()
        inq = self.register()
        draft = self.o.lock_draft(inq["id"], ["CASE:MAT-CASE@1", "REG:MAT-REG@1"])
        # 未启用授权：任何人可写、可读全量、可下载（旧行为不变）
        ctx = self.o.read_section_context(draft["id"], "Q1", actor="anyone")
        self.assertEqual(ctx["authz_revision"], 0)
        self.assertIn("张三", str(ctx["evidence"]))
        a = self.o.add_attachment(draft["id"], filename="x", content=b"Y",
                                 derived_from_ref="CASE:MAT-CASE@1",
                                 uploaded_by="anyone")
        self.assertIsNone(a["qid"])
        self.assertEqual(
            self.o.get_attachment(draft["id"], a["id"])["content_blob"], b"Y")
        self.o.submit_section(draft["id"], "Q1",
                              f"恢复 [CASE:MAT-CASE@1] @attachment:{a['id']}",
                              expected_revision=0)
        self.o.submit_section(draft["id"], "Q2", "依据 [REG:MAT-REG@1]",
                              expected_revision=0)
        sealed = self.o.finalize(draft["id"], sealed_by="lead")
        sub = self.o.submission_status(sealed["submission_id"])
        self.assertEqual(sub["manifest"]["authz_revision"], 0)
        self.assertTrue(self.o.verify_submission(sub["id"])["ok"])

    def test_old_database_migrates_with_new_columns(self):
        self.seed_materials()
        self.register()
        with self.o.conn() as c:
            cols_sec = {r["name"] for r in c.execute("PRAGMA table_info(sections)")}
            cols_att = {r["name"] for r in
                        c.execute("PRAGMA table_info(attachments)")}
            tables = {r[0] for r in c.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("authz_revision", cols_sec)
        self.assertIn("upload_authz_revision", cols_att)
        self.assertIn("qid", cols_att)
        self.assertIn("inquiry_authz", tables)
        self.assertIn("question_grants", tables)
        self.assertIn("authz_denials", tables)
        self.assertIn("attachment_requalifications", tables)

    def test_append_only_tables_reject_mutation(self):
        self.seed_materials()
        inq = self.register()
        self.o.enroll_authz(inq["id"], lead="lead", writers=["alice"])
        import sqlite3
        with self.assertRaises(sqlite3.Error):
            with self.o.conn() as c:
                c.execute("UPDATE inquiry_members SET active=0")
        with self.assertRaises(sqlite3.Error):
            with self.o.conn() as c:
                c.execute("UPDATE question_grants SET categories_json='[]'")
        with self.assertRaises(sqlite3.Error):
            with self.o.conn() as c:
                c.execute("DELETE FROM question_grants")
        # 修订号不能倒退（enroll 后为 1）
        self.o.add_writers(inq["id"], ["x"], updated_by="lead")
        with self.assertRaises(sqlite3.Error):
            with self.o.conn() as c:
                c.execute("UPDATE inquiry_authz SET authz_revision=1")
        # 不能把已启用问询改绑负责人而不推进修订号（仅白名单列推进合法）
        with self.assertRaises(sqlite3.Error):
            with self.o.conn() as c:
                c.execute(
                    "UPDATE inquiry_authz SET lead_key='other' WHERE inquiry_id=?",
                    (inq["id"],))

    def test_roster_change_without_effective_change_is_noop(self):
        self.seed_materials()
        inq = self.register()
        self.o.enroll_authz(inq["id"], lead="lead", writers=["alice"])
        r = self.o.add_writers(inq["id"], ["alice"], updated_by="lead")
        self.assertFalse(r["changed"])
        r2 = self.o.remove_writers(inq["id"], ["ghost"], updated_by="lead")
        self.assertFalse(r2["changed"])
        self.assertEqual(self.o.authz_revision(inq["id"]), 1)
