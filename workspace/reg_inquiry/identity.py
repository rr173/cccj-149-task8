"""组成员身份的规范化与校验（分区写作/最小披露的身份判定基础）。

与 pv_service.identity 同一套确定性规则，但域语言是“成员/撰写人”：

1. 必须是字符串；
2. NFKC 兼容性分解组合（全角/半角、兼容字符、组合序列等价折叠）；
3. ``str.casefold`` 大小写归一；
4. 仅去 *首尾* 空白（保留内部空白）；归一后为空即“空白身份”，必须拒绝。

规范化键只用于身份判定与比较；调用方提交的原始字符串仍原样留痕
（``member_raw``），全程可追溯。
"""
from __future__ import annotations

import unicodedata

MAX_MEMBER_LEN = 256


def normalize_identity(value: str) -> str:
    """把成员提交值规范化为稳定身份键（假定 value 是非空字符串）。"""
    return unicodedata.normalize("NFKC", value).casefold().strip()


def validate_identity(value) -> str:
    """校验并规范化成员身份，返回稳定身份键。

    非字符串 -> ValueError(INVALID_IDENTITY)；空白 -> BLANK_IDENTITY；
    超长 -> IDENTITY_TOO_LONG。
    """
    if not isinstance(value, str):
        raise ValueError("INVALID_IDENTITY:成员身份必须是字符串")
    if not value.strip():
        raise ValueError("BLANK_IDENTITY:缺少成员身份（不能为空白）")
    key = normalize_identity(value)
    if len(key) > MAX_MEMBER_LEN:
        raise ValueError("IDENTITY_TOO_LONG:成员身份超长")
    return key
