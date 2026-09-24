import re
import secrets

_ID_RE = re.compile(r"^[0-9a-f]{16}$")


def new_id() -> str:
    return secrets.token_hex(8)  # 64-bit, URL-safe, non-enumerable


def is_valid_id(s: str) -> bool:
    return bool(_ID_RE.fullmatch(s or ""))
