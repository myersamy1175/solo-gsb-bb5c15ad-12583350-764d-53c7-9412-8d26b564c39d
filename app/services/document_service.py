"""文档脱敏、查询、恢复的业务逻辑。"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import aiosqlite

from app.crypto import CryptoBox, random_token
from app.redaction import (
    PLACEHOLDER_PATTERN,
    InputSpan,
    redact,
    validate_category,
)
from app.schemas import (
    FragmentOut,
    RestoredItem,
    RestoredOccurrence,
    SubmitRequest,
)
from app.services.errors import (
    ExpiredError,
    NotFoundError,
    ServiceError,
    UnauthorizedError,
)

# ISO-8601 UTC，固定 6 位微秒，保证字符串字典序与时间顺序一致，可直接用于 SQL 比较
ISO = "%Y-%m-%dT%H:%M:%S.%fZ"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(ISO)


def from_iso(s: str) -> datetime:
    return datetime.strptime(s, ISO).replace(tzinfo=timezone.utc)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class DocumentService:
    def __init__(
        self,
        db: aiosqlite.Connection,
        crypto: CryptoBox,
        default_ttl: int,
        max_ttl: int,
        token_ttl: int,
    ) -> None:
        self.db = db
        self.crypto = crypto
        self.default_ttl = default_ttl
        self.max_ttl = max_ttl
        self.token_ttl = token_ttl

    # ---------- 提交脱敏 ----------

    async def submit(self, req: SubmitRequest) -> dict:
        ttl = req.ttl if req.ttl is not None else self.default_ttl
        if not 1 <= ttl <= self.max_ttl:
            raise ServiceError(f"ttl 必须在 1..{self.max_ttl} 秒之间", 422)

        # 位置校验：必须落在原文内且非空区间
        for i, s in enumerate(req.spans):
            if not (0 <= s.start < s.end <= len(req.text)):
                raise ServiceError(
                    f"spans[{i}] 位置非法：需满足 0 <= start < end <= 文本长度"
                    f"（{len(req.text)}）",
                    422,
                )
            try:
                validate_category(s.category)
            except ValueError as exc:
                raise ServiceError(str(exc), 422) from exc

        inputs = [
            InputSpan(
                start=s.start,
                end=s.end,
                priority=s.priority,
                category=s.category,
                ordinal=i,
            )
            for i, s in enumerate(req.spans)
        ]
        result = redact(req.text, inputs)

        doc_id = uuid.uuid4().hex
        now = utcnow()
        doc_expires = now + timedelta(seconds=ttl)
        token = random_token()
        # 令牌有效期不超过文档映射本身
        token_expires = min(now + timedelta(seconds=self.token_ttl), doc_expires)

        async with self.db.cursor() as cur:
            await cur.execute(
                "INSERT INTO documents (id, ciphertext, redacted, expires_at)"
                " VALUES (?, ?, ?, ?)",
                (
                    doc_id,
                    self.crypto.encrypt(req.text),
                    result.redacted_text,
                    to_iso(doc_expires),
                ),
            )
            await cur.executemany(
                "INSERT INTO fragments (document_id, placeholder, category,"
                " start_offset, end_offset, priority, kept, drop_reason, cipher_value)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        doc_id,
                        sp.placeholder,
                        sp.category,
                        sp.start,
                        sp.end,
                        sp.priority,
                        int(sp.kept),
                        sp.drop_reason,
                        self.crypto.encrypt(sp.value) if sp.kept else None,
                    )
                    for sp in result.spans
                ],
            )
            await cur.execute(
                "INSERT INTO restore_tokens (token_hash, document_id, expires_at, used)"
                " VALUES (?, ?, ?, 0)",
                (hash_token(token), doc_id, to_iso(token_expires)),
            )
            await self.db.commit()

        return {
            "document_id": doc_id,
            "redacted_text": result.redacted_text,
            "fragments": [self._fragment_out(sp) for sp in result.spans],
            "restore_token": token,
            "expires_at": doc_expires,
            "token_expires_at": token_expires,
        }

    # ---------- 查询脱敏结果 ----------

    async def get(self, document_id: str) -> dict:
        async with await self.db.execute(
            "SELECT id, redacted, expires_at FROM documents WHERE id = ?",
            (document_id,),
        ) as cur:
            row = await cur.fetchone()
        if not row:
            raise NotFoundError("文档不存在或已过期删除")
        expires = from_iso(row["expires_at"])
        if expires <= utcnow():
            await self._delete_document(document_id)
            await self.db.commit()
            raise ExpiredError("文档映射已过期")

        async with self.db.execute(
            "SELECT placeholder, category, start_offset, end_offset, priority,"
            " kept, drop_reason FROM fragments WHERE document_id = ?"
            " ORDER BY start_offset",
            (document_id,),
        ) as cur:
            frags = await cur.fetchall()
        return {
            "document_id": document_id,
            "redacted_text": row["redacted"],
            "fragments": [self._row_out(r) for r in frags],
            "expires_at": expires,
        }

    # ---------- 一次性令牌恢复 ----------

    async def restore(self, token: str, placeholders: list[str]) -> dict:
        wanted = self._dedup(placeholders)
        now = utcnow()

        async with self.db.cursor() as cur:
            # 单事务内完成：校验一次性令牌 -> 读出片段 -> 旧令牌作废 -> 轮换新令牌
            await cur.execute("BEGIN IMMEDIATE")
            await cur.execute(
                "SELECT document_id, expires_at, used FROM restore_tokens"
                " WHERE token_hash = ?",
                (hash_token(token),),
            )
            token_row = await cur.fetchone()
            if token_row is None:
                await cur.execute("ROLLBACK")
                raise UnauthorizedError("恢复令牌无效（可能已被使用）")
            if token_row["used"]:
                await cur.execute("ROLLBACK")
                raise UnauthorizedError("恢复令牌已使用")
            if from_iso(token_row["expires_at"]) <= now:
                await cur.execute(
                    "DELETE FROM restore_tokens WHERE token_hash = ?",
                    (hash_token(token),),
                )
                await cur.execute("COMMIT")
                raise UnauthorizedError("恢复令牌已过期，请重新提交文档")

            doc_id = token_row["document_id"]
            await cur.execute("SELECT expires_at FROM documents WHERE id = ?", (doc_id,))
            doc_row = await cur.fetchone()
            if doc_row is None or from_iso(doc_row["expires_at"]) <= now:
                await cur.execute("ROLLBACK")
                raise ExpiredError("文档映射已过期，无法恢复")
            doc_expires = from_iso(doc_row["expires_at"])

            await cur.execute(
                "SELECT placeholder, category, start_offset, end_offset, priority,"
                " cipher_value FROM fragments"
                " WHERE document_id = ? AND kept = 1 ORDER BY start_offset",
                (doc_id,),
            )
            frag_rows = await cur.fetchall()

            by_placeholder: dict[str, list[aiosqlite.Row]] = {}
            for r in frag_rows:
                by_placeholder.setdefault(r["placeholder"], []).append(r)

            unknown = [p for p in wanted if p not in by_placeholder]
            if unknown:
                await cur.execute("ROLLBACK")
                raise ServiceError(f"占位符不属于该文档：{unknown}", 400)

            restored: list[RestoredItem] = []
            for p in wanted:
                rows = by_placeholder[p]
                restored.append(
                    RestoredItem(
                        placeholder=p,
                        category=rows[0]["category"],
                        value=self.crypto.decrypt(rows[0]["cipher_value"]),
                        occurrences=[
                            RestoredOccurrence(
                                start=r["start_offset"],
                                end=r["end_offset"],
                                priority=r["priority"],
                            )
                            for r in rows
                        ],
                    )
                )

            new_token = random_token()
            new_expires = min(now + timedelta(seconds=self.token_ttl), doc_expires)
            await cur.execute(
                "UPDATE restore_tokens SET used = 1 WHERE token_hash = ?",
                (hash_token(token),),
            )
            await cur.execute(
                "INSERT INTO restore_tokens (token_hash, document_id, expires_at, used)"
                " VALUES (?, ?, ?, 0)",
                (hash_token(new_token), doc_id, to_iso(new_expires)),
            )
            await cur.execute("COMMIT")

        return {
            "restored": restored,
            "restore_token": new_token,
            "token_expires_at": new_expires,
        }

    # ---------- 过期清理 ----------

    async def purge_expired(self) -> None:
        now_iso = to_iso(utcnow())
        await self.db.execute("DELETE FROM documents WHERE expires_at <= ?", (now_iso,))
        await self.db.execute("DELETE FROM restore_tokens WHERE expires_at <= ?", (now_iso,))
        await self.db.commit()

    # ---------- helpers ----------

    async def _delete_document(self, doc_id: str) -> None:
        await self.db.execute("DELETE FROM documents WHERE id = ?", (doc_id,))

    @staticmethod
    def _dedup(placeholders: list[str]) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []
        for p in placeholders:
            if not PLACEHOLDER_PATTERN.fullmatch(p):
                raise ServiceError(f"非法占位符格式：{p!r}", 422)
            if p not in seen:
                seen.add(p)
                ordered.append(p)
        return ordered

    @staticmethod
    def _fragment_out(sp) -> FragmentOut:
        return FragmentOut(
            placeholder=sp.placeholder,
            category=sp.category,
            start=sp.start,
            end=sp.end,
            priority=sp.priority,
            kept=sp.kept,
            drop_reason=sp.drop_reason,
        )

    @staticmethod
    def _row_out(row: aiosqlite.Row) -> FragmentOut:
        return FragmentOut(
            placeholder=row["placeholder"],
            category=row["category"],
            start=row["start_offset"],
            end=row["end_offset"],
            priority=row["priority"],
            kept=bool(row["kept"]),
            drop_reason=row["drop_reason"],
        )
