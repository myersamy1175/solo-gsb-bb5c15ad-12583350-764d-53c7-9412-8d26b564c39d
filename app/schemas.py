"""请求 / 响应数据模型。"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, field_validator

MAX_TEXT_LEN = 2_000_000
MAX_SPANS = 5_000
MAX_TTL_REQ = 7 * 86400


class SpanIn(BaseModel):
    start: int = Field(..., ge=0, description="起始 Unicode 码位偏移（含）")
    end: int = Field(..., ge=0, description="结束 Unicode 码位偏移（不含）")
    priority: int = Field(0, ge=0, le=10_000, description="数值越大优先级越高")
    category: str = Field(..., max_length=32)

    @field_validator("category")
    @classmethod
    def _category(cls, v: str) -> str:
        return v.strip().upper()


class SubmitRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=MAX_TEXT_LEN)
    spans: list[SpanIn] = Field(..., min_length=1, max_length=MAX_SPANS)
    ttl: int | None = Field(None, ge=1, le=MAX_TTL_REQ, description="映射有效期（秒）")


class FragmentOut(BaseModel):
    placeholder: str
    category: str
    start: int
    end: int
    priority: int
    kept: bool
    drop_reason: str | None = None


class SubmitResponse(BaseModel):
    document_id: str
    redacted_text: str
    fragments: list[FragmentOut]
    restore_token: str = Field(..., description="一次性恢复令牌，仅本次响应返回明文，请妥善保存")
    expires_at: datetime
    token_expires_at: datetime


class DocumentResponse(BaseModel):
    document_id: str
    redacted_text: str
    fragments: list[FragmentOut]
    expires_at: datetime


class RestoreRequest(BaseModel):
    token: str = Field(..., min_length=1, max_length=128)
    placeholders: list[str] = Field(..., min_length=1, max_length=100)


class RestoredOccurrence(BaseModel):
    start: int
    end: int
    priority: int


class RestoredItem(BaseModel):
    placeholder: str
    category: str
    value: str
    occurrences: list[RestoredOccurrence]


class RestoreResponse(BaseModel):
    restored: list[RestoredItem]
    restore_token: str = Field(..., description="轮换后的新一次性令牌")
    token_expires_at: datetime
