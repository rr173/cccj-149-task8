"""旧库迁移：引入分区写作授权列之前的 inquiry.db 可平滑升级。

旧章节修订/附件无授权快照（auth_revision/writer_key=NULL、is_cloned=0）；
旧库没有任何成员/授权（非托管模式），故历史数据按既有行为继续可读、
可定稿、可发送。
"""
import os
import sqlite3
import tempfile
import unittest

from reg_inquiry import db as dbmod
from reg_inquiry.orchestrator import InquiryOrchestrator
from reg_inquiry.transport import RegulatorTransport

# 与 tests_reg 已用流程等价的最小旧 schema：只建到本次改动前所需的表，
# 并插入一份已协作的开放底稿（旧 section_revisions / attachments 无新列）。
OLD_SCHEMA_TABLES = [
    "inquiries", "materials", "disclosure_policies", "drafts", "draft_pins",
    "sections", "section_revisions", "section_conflicts", "attachments",
    "drift_events", "contradictions", "submissions", "submission_events",
    "receipts", "jobs", "outgoing_number_seq", "audit_events",
]


class TestLegacyMigration(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ri-mig-")
        self.path = os.path.join(self.dir, "inquiry.db")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_legacy_db_opens_and_finalizes(self):
        # 1) 用当前代码建一份库，制造数据，再“降级”删掉新列/新表，
        #    模拟旧版本数据库（比手写旧 schema 更可靠地覆盖触发器依赖）。
        gw = RegulatorTransport(os.path.join(self.dir, "gw.db"))
        o = InquiryOrchestrator(self.path, transport=gw)
        o.register_material(material_id="M1", version="1", category="CASE",
                            content={"a": 1}, title="t")
        inq = o.register_inquiry(
            regulator="R", jurisdiction="CN",
            questions=[{"qid": "Q1", "text": "q"}],
            deadline="2026-10-20T00:00:00+00:00",
            allowed_material_ids=["M1"])
        d = o.lock_draft(inq["id"], ["CASE:M1@1"])
        att = o.add_attachment(d["id"], filename="f", content=b"x",
                               derived_from_ref="CASE:M1@1")
        o.submit_section(d["id"], "Q1",
                         f"正文 [CASE:M1@1] @attachment:{att['id']}",
                         expected_revision=0, submitted_by="u")
        del o
        self._downgrade()

        # 2) 重新打开：迁移补列，既有数据仍在
        o2 = InquiryOrchestrator(self.path, transport=gw)
        # 非托管（旧库无成员）
        self.assertEqual(o2.current_auth_revision(inq["id"]), 0)
        draft = o2.get_draft(d["id"])
        self.assertEqual(len(draft["sections"]), 1)
        self.assertTrue(draft["attachments"][0]["is_cloned"] == 0)
        # 旧修订无授权快照，但非托管定稿不要求
        sid = o2.finalize(d["id"], sealed_by="lead")["submission_id"]
        self.assertTrue(o2.verify_submission(sid)["ok"])

    def test_migrate_then_enable_managed_mode(self):
        gw = RegulatorTransport(os.path.join(self.dir, "gw2.db"))
        o = InquiryOrchestrator(self.path, transport=gw)
        o.register_material(material_id="M1", version="1", category="CASE",
                            content={"secret": "x", "ok": "y"})
        inq = o.register_inquiry(
            regulator="R", jurisdiction="CN",
            questions=[{"qid": "Q1", "text": "q"}],
            deadline="2026-10-20T00:00:00+00:00",
            allowed_material_ids=["M1"], registered_by="lead")
        d = o.lock_draft(inq["id"], ["CASE:M1@1"])
        del o
        self._downgrade()

        o2 = InquiryOrchestrator(self.path, transport=gw)
        # 迁移后显式引导首位负责人，进入托管模式
        o2.bootstrap_partitioning(inq["id"], "lead")
        o2.add_member(inq["id"], "w", acted_by="lead")
        o2.put_question_grant(
            inq["id"], "Q1", visible_categories=["CASE"],
            visible_fields=["ok"], material_ids=["M1"],
            writers=["w"], actor="lead")
        rev = o2.current_auth_revision(inq["id"])
        sec = o2.submit_section(d["id"], "Q1", "y [CASE:M1@1]",
                                expected_revision=0,
                                expected_auth_revision=rev, submitted_by="w")
        self.assertEqual(sec["revision"], 1)

    def _downgrade(self):
        """删除新列与新表，重建被新表引用的旧 inquiries 外键关系不变。

        SQLite 不支持 DROP COLUMN（3.35 前），这里通过整表重建两张旧表，
        保留旧列集合。
        """
        conn = sqlite3.connect(self.path, isolation_level=None)
        try:
            conn.execute("PRAGMA foreign_keys=OFF")
            for t in ("group_member_events", "group_members",
                      "question_grants", "auth_revision_seq", "auth_denials",
                      "app_meta"):
                conn.execute(f"DROP TABLE IF EXISTS {t}")
            conn.execute("ALTER TABLE section_revisions RENAME TO sr_old")
            conn.execute(
                "CREATE TABLE section_revisions (id TEXT PRIMARY KEY,"
                "section_id TEXT NOT NULL,revision INTEGER NOT NULL,"
                "body TEXT NOT NULL,title TEXT NOT NULL DEFAULT '',"
                "submitted_by TEXT,submitted_at TEXT NOT NULL,"
                "UNIQUE(section_id,revision))")
            conn.execute(
                "INSERT INTO section_revisions(id,section_id,revision,body,"
                "title,submitted_by,submitted_at) "
                "SELECT id,section_id,revision,body,title,submitted_by,"
                "submitted_at FROM sr_old")
            conn.execute("DROP TABLE sr_old")
            conn.execute("ALTER TABLE attachments RENAME TO at_old")
            conn.execute(
                "CREATE TABLE attachments (id TEXT NOT NULL,draft_id TEXT NOT "
                "NULL,filename TEXT NOT NULL,content_type TEXT NOT NULL "
                "DEFAULT 'application/octet-stream',content_blob BLOB NOT "
                "NULL,sha256 TEXT NOT NULL,derived_from_ref TEXT,uploaded_by "
                "TEXT,created_at TEXT NOT NULL,PRIMARY KEY(draft_id,id))")
            conn.execute(
                "INSERT INTO attachments(id,draft_id,filename,content_type,"
                "content_blob,sha256,derived_from_ref,uploaded_by,created_at)"
                " SELECT id,draft_id,filename,content_type,content_blob,"
                "sha256,derived_from_ref,uploaded_by,created_at FROM at_old")
            conn.execute("DROP TABLE at_old")
            # 删除依赖新表的触发器（initialize 会用当前 SCHEMA 重建）
            for tr in ("trg_member_events_no_update",
                       "trg_member_events_no_delete", "trg_members_guard",
                       "trg_members_no_delete", "trg_grants_guard",
                       "trg_grants_no_delete", "trg_denials_no_update",
                       "trg_denials_no_delete", "trg_meta_no_update",
                       "trg_meta_no_delete"):
                conn.execute(f"DROP TRIGGER IF EXISTS {tr}")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("VACUUM")
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
