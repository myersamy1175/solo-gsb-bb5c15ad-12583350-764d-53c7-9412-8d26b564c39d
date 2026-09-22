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
    source        TEXT NOT NULL DEFAULT 'manual',  -- manual 或命中规则的 rule_id
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

CREATE TABLE IF NOT EXISTS policies (
    id          TEXT PRIMARY KEY,
    rules       TEXT NOT NULL,           -- JSON 数组：rule_id/category/pattern/priority
    created_at  TEXT NOT NULL            -- ISO-8601 UTC；策略创建后不可变、不过期
);
"""

# 对既有数据库的幂等列迁移：(表, 列, DDL)
MIGRATIONS = (
    (
        "fragments",
        "source",
        "ALTER TABLE fragments ADD COLUMN source TEXT NOT NULL DEFAULT 'manual'",
    ),
)


async def _migrate(db: aiosqlite.Connection) -> None:
    for table, column, ddl in MIGRATIONS:
        async with db.execute(f"PRAGMA table_info({table})") as cur:
            cols = {row[1] for row in await cur.fetchall()}
        if cols and column not in cols:
            await db.execute(ddl)


def _migrate_sync(conn: sqlite3.Connection) -> None:
    for table, column, ddl in MIGRATIONS:
        cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if cols and column not in cols:
            conn.execute(ddl)


async def init_db(db_path: str = ":memory:") -> None:
    """幂等建表（容器启动与 CLI 共用）。

    ``:memory:`` 由调用方自己维护单一长连接；此处的短连接只用于文件库初始化。
    """
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA)
        await _migrate(db)
        await db.commit()


def init_db_sync(db_path: str) -> None:
    """CLI 入口使用的同步初始化。"""
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(SCHEMA)
        _migrate_sync(conn)
        conn.commit()
    finally:
        conn.close()


async def connect(db_path: str) -> aiosqlite.Connection:
    db = await aiosqlite.connect(db_path)
    await db.execute("PRAGMA foreign_keys=ON")
    db.row_factory = aiosqlite.Row
    return db
