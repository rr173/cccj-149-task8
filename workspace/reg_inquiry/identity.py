"""撰写人/负责人身份的规范化与校验（分区授权的身份判定基础）。

与 ``pv_service/identity.py`` 同一口径：NFKC 兼容性折叠 + ``casefold``
大小写归一 + 仅去首尾空白。规范化键只用于授权判定与比较；每次调用的
原始字符串原样留痕（成员台账/章节修订/审计），全程可追溯。

    "alice"  "  alice  "  "ALICE"  "Ａlice"（全角）  "Å"(U+212B)/"Å"(U+00C5)

规范化后是同一个稳定身份键，同一撰写人无法靠表面写法差异拿到第二份授权。
内部空白有意义："a b" 与 "ab" 是两个人。
"""
from __future__ import annotations

import unicodedata

MAX_IDENTITY_LEN = 256


def normalize_identity(value: str) -> str:
    """把提交值规范化为稳定身份键（假定 value 是非空字符串）。"""
    return unicodedata.normalize("NFKC", value).casefold().strip()


def validate_identity(value, *, field: str = "actor") -> str:
    """校验并规范化身份，返回稳定身份键。

    - 非字符串 -> ValueError（INVALID_ACTOR）
    - 空白     -> ValueError（BLANK_ACTOR）
    - 超长     -> ValueError（ACTOR_TOO_LONG）
    """
    if not isinstance(value, str):
        raise ValueError(f"INVALID_ACTOR:{field} 必须是字符串")
    if not value.strip():
        raise ValueError(f"BLANK_ACTOR:缺少 {field} 身份（不能为空白）")
    key = normalize_identity(value)
    if len(key) > MAX_IDENTITY_LEN:
        raise ValueError(f"ACTOR_TOO_LONG:{field} 身份超长")
    return key
