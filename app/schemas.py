import base64
import binascii

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .config import get_settings

_s = get_settings()

E2E_MIN_BYTES = 12 + 1 + 16  # client IV + at least 1 byte of ciphertext + GCM tag


class CreateSecretIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)  # strict: "3600" / true are rejected

    secret: str = Field(min_length=1)
    ttl_seconds: int = Field(default=3600, ge=1, le=_s.max_ttl)
    max_views: int = Field(default=1, ge=1, le=_s.max_views)
    password: str | None = Field(default=None, min_length=1, max_length=1024)  # stretch S2
    e2e: bool = False  # stretch S3: `secret` is base64(iv || ciphertext) made by the client

    @field_validator("secret")
    @classmethod
    def _size(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("must not be blank")
        if len(v.encode("utf-8")) > _s.max_secret_bytes:
            raise ValueError("too large")
        return v

    @model_validator(mode="after")
    def _e2e_payload(self):
        if self.e2e:
            try:
                raw = base64.b64decode(self.secret, validate=True)
            except (binascii.Error, ValueError):
                raise ValueError("e2e secret must be base64") from None
            if len(raw) < E2E_MIN_BYTES:
                raise ValueError("e2e secret is too short to be iv + ciphertext + tag")
        return self


class CreateSecretOut(BaseModel):  # the handout contract, plus the optional S1 field
    id: str
    view_url: str
    expires_at: str
    views_remaining: int
    fingerprint: str | None = None  # omitted from the response unless VAULT_FINGERPRINT=1


class BurnIn(BaseModel):  # optional body; a bare POST still works
    model_config = ConfigDict(extra="forbid", strict=True)

    password: str | None = Field(default=None, max_length=1024)  # stretch S2


class BurnOut(BaseModel):  # the handout contract, plus the optional S3 flag
    secret: str
    views_remaining: int
    burned: bool
    e2e: bool | None = None  # present (true) only for end-to-end encrypted secrets
