"""领域异常：全部带稳定错误码，调用方可据此重试或阻断。"""
from __future__ import annotations


class InquiryError(Exception):
    """编排器领域错误基类。"""

    code = "INQUIRY_ERROR"

    def __init__(self, message: str = "", *, details=None):
        super().__init__(message or self.code)
        self.details = details if details is not None else {}


class NotFoundError(InquiryError):
    code = "NOT_FOUND"


class MissingMaterialsError(InquiryError):
    """底稿锁定/更正引用了尚不存在（或尚无该精确版本）的资料。

    ``details['missing']`` 逐项给出资料逻辑 id / 要求版本 / 类别与原因；
    缺失未补齐前不得锁定、不得定稿。
    """

    code = "MISSING_MATERIALS"


class OutOfScopeError(InquiryError):
    """引用越权：资料不在问询登记的可引用资料范围内。"""

    code = "OUT_OF_SCOPE"


class VersionConflictError(InquiryError):
    """调用方基于过期修订提交章节（乐观并发）。详情含当前修订号。"""

    code = "STALE_REVISION"


class StaleRevisionError(VersionConflictError):
    """VersionConflictError 的旧名兼容别名。"""


class DraftSealedError(InquiryError):
    """底稿已定稿/被取代：章节与附件不可再改，只能走更正件。"""

    code = "DRAFT_SEALED"


class ContradictionError(InquiryError):
    """底稿锁定/定稿时被引用版本之间存在互相矛盾的事实。"""

    code = "CONTRADICTION"


class ValidationFailed(InquiryError):
    """定稿校验未通过。``details['report']`` 是完整结构化校验报告，
    ``details['unsatisfied']`` 精确列出尚未满足的问题。"""

    code = "VALIDATION_FAILED"

    def __init__(self, report: dict):
        super().__init__("定稿校验未通过：%d 个阻断项"
                         % len(report.get("blocking", [])),
                         details={"report": report,
                                  "unsatisfied": report.get("unsatisfied", [])})
        self.report = report


class JobFailed(InquiryError):
    """可恢复作业最终失败（永久错误或重试耗尽）。"""

    code = "JOB_FAILED"

    def __init__(self, job: dict, *, cause: Exception | None = None):
        super().__init__("作业 %s 失败：%s" % (job.get("id"), job.get("error_code")))
        self.job = job
        self.cause = cause
        self.code = job.get("error_code") or "JOB_FAILED"


class TransportTempError(InquiryError):
    """外发传输临时失败（可重试）。"""

    code = "TRANSPORT_TEMP"


class TransportRejectError(InquiryError):
    """监管网关明确拒收（终态，不重试）。"""

    code = "TRANSPORT_REJECT"


# ---------------------------------------------------------------------------
# 分区写作 / 最小披露权限
# ---------------------------------------------------------------------------
class AuthzError(InquiryError):
    """授权相关拒绝基类（响应中绝不包含被保护资料/正文内容）。"""

    code = "AUTHZ_ERROR"


class NotAuthorizedError(AuthzError):
    """非负责人/越权管理操作（如非 OWNER 试图设置授权）。"""

    code = "NOT_AUTHORIZED"


class NotGroupMemberError(AuthzError):
    """人员已离组或从未入组，却试图读取章节上下文/保存/上传。"""

    code = "NOT_GROUP_MEMBER"


class NotAssignedError(AuthzError):
    """撰写人在该问题上没有任何有效授权（未被分派）。详情只含 qid。"""

    code = "NOT_ASSIGNED"


class StaleAuthRevisionError(AuthzError):
    """页面携带的授权修订号已失效（转派/离组/权限收紧后用旧号保存）。

    ``details`` 只回传 qid 与当前修订号供刷新页面，不泄露新证据内容。
    """

    code = "STALE_AUTH_REVISION"


class EvidenceAccessDeniedError(AuthzError):
    """引用/附件/下载越出该问题授权边界，或正文携带了未授权字段原值。

    ``details['denied_refs']`` / ``denied_attachments`` 只含引用锚与附件 id
    （定位信息），绝不回显资料原值或正文。
    """

    code = "EVIDENCE_ACCESS_DENIED"
