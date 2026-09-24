from pydantic import BaseModel, ConfigDict, Field, field_validator

from .config import get_settings

_s = get_settings()


class CreateSecretIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)  # strict: "3600" / true are rejected

    secret: str = Field(min_length=1)
    ttl_seconds: int = Field(default=3600, ge=1, le=_s.max_ttl)
    max_views: int = Field(default=1, ge=1, le=_s.max_views)

    @field_validator("secret")
    @classmethod
    def _size(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("must not be blank")
        if len(v.encode("utf-8")) > _s.max_secret_bytes:
            raise ValueError("too large")
        return v


class CreateSecretOut(BaseModel):  # exactly the handout contract
    id: str
    view_url: str
    expires_at: str
    views_remaining: int


class BurnOut(BaseModel):
    secret: str
    views_remaining: int
    burned: bool
