"""SQLite 初始化与连接管理（aiosqlite 异步驱动）。"""
from __future__ import annotations

import sqlite3

import aiosqlite

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS documents (
    id          TEXT PRIMARY KEY,
    ciphertext  BLOB NOT NULL,           -- Fernet 加密的原文
    redacted    TEXT NOT NULL,
    expires_at  TEXT NOT NULL            -- ISO-8601 UTC
);

CREATE TABLE IF NOT EXISTS fragments (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id   TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    placeholder   TEXT NOT NULL,
    category      TEXT NOT NULL,
    start_offset  INTEGER NOT NULL,
    end_offset    INTEGER NOT NULL,
    priority      INTEGER NOT NULL,
    kept          INTEGER NOT NULL,
    drop_reason   TEXT,
    cipher_value  BLOB                   -- 仅保留片段加密值；丢弃片段为 NULL
);

CREATE INDEX IF NOT EXISTS idx_fragments_document ON fragments(document_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_fragments_unique
    ON fragments(document_id, placeholder, start_offset);

CREATE TABLE IF NOT EXISTS restore_tokens (
    token_hash  TEXT PRIMARY KEY,        -- SHA-256(token)
    document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    expires_at  TEXT NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_tokens_document ON restore_tokens(document_id);
"""


async def init_db(db_path: str = ":memory:") -> None:
    """幂等建表（容器启动与 CLI 共用）。

    ``:memory:`` 由调用方自己维护单一长连接；此处的短连接只用于文件库初始化。
    """
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await db.commit()


def init_db_sync(db_path: str) -> None:
    """CLI 入口使用的同步初始化。"""
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


async def connect(db_path: str) -> aiosqlite.Connection:
    db = await aiosqlite.connect(db_path)
    await db.execute("PRAGMA foreign_keys=ON")
    db.row_factory = aiosqlite.Row
    return db
