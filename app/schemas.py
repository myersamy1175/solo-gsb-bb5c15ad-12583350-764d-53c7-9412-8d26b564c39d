"""请求 / 响应数据模型。"""
from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel, Field, field_validator, model_validator

MAX_TEXT_LEN = 2_000_000
MAX_SPANS = 5_000
MAX_TTL_REQ = 7 * 86400
MAX_RULES = 100
MAX_PATTERN_LEN = 1_000

RULE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


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
    spans: list[SpanIn] = Field(default_factory=list, max_length=MAX_SPANS)
    policy_id: str | None = Field(
        None,
        min_length=1,
        max_length=64,
        description="可选：自动脱敏策略 ID，服务端按策略规则在原文上生成自动片段",
    )
    ttl: int | None = Field(None, ge=1, le=MAX_TTL_REQ, description="映射有效期（秒）")

    @model_validator(mode="after")
    def _spans_or_policy(self) -> "SubmitRequest":
        if not self.spans and not self.policy_id:
            raise ValueError("spans 与 policy_id 至少提供其一")
        return self


class FragmentOut(BaseModel):
    placeholder: str
    category: str
    start: int
    end: int
    priority: int
    kept: bool
    drop_reason: str | None = None
    source: str = Field(..., description='片段来源："manual" 或命中规则的 rule_id')


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


class PolicyRuleIn(BaseModel):
    rule_id: str = Field(..., min_length=1, max_length=64, description="策略内唯一的规则标识")
    category: str = Field(..., max_length=32)
    pattern: str = Field(..., min_length=1, max_length=MAX_PATTERN_LEN, description="正则表达式")
    priority: int = Field(0, ge=0, le=10_000, description="数值越大优先级越高")

    @field_validator("rule_id")
    @classmethod
    def _rule_id(cls, v: str) -> str:
        if not RULE_ID_PATTERN.match(v):
            raise ValueError("非法 rule_id：需匹配 [A-Za-z0-9][A-Za-z0-9_-]{0,63}")
        return v

    @field_validator("category")
    @classmethod
    def _category(cls, v: str) -> str:
        return v.strip().upper()


class PolicyCreateRequest(BaseModel):
    rules: list[PolicyRuleIn] = Field(..., min_length=1, max_length=MAX_RULES)

    @field_validator("rules")
    @classmethod
    def _unique_rule_ids(cls, v: list[PolicyRuleIn]) -> list[PolicyRuleIn]:
        ids = [r.rule_id for r in v]
        if len(set(ids)) != len(ids):
            raise ValueError("rule_id 在策略内必须唯一")
        return v


class PolicyRuleOut(BaseModel):
    rule_id: str
    category: str
    pattern: str
    priority: int


class PolicyResponse(BaseModel):
    policy_id: str
    rules: list[PolicyRuleOut]
    created_at: datetime
