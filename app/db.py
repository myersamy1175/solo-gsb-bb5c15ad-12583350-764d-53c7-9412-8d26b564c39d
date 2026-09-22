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
    expires_at  TEXT NOT NULL,           -- ISO-8601 UTC
    policy_id   TEXT                     -- 提交时引用的自动脱敏策略（可为空）
);

CREATE TABLE IF NOT EXISTS policies (
    id          TEXT PRIMARY KEY,        -- uuid hex，创建后不可变
    name        TEXT NOT NULL,
    created_at  TEXT NOT NULL            -- ISO-8601 UTC
);

CREATE TABLE IF NOT EXISTS policy_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id   TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    rule_id     TEXT NOT NULL,           -- 策略内唯一的人工可读标识
    category    TEXT NOT NULL,
    pattern     TEXT NOT NULL,           -- Python Unicode 正则源码（策略只存不敏感的匹配规则）
    priority    INTEGER NOT NULL,
    ordinal     INTEGER NOT NULL,        -- 创建时的提交顺序
    UNIQUE(policy_id, rule_id)
);

CREATE INDEX IF NOT EXISTS idx_policy_rules_policy ON policy_rules(policy_id);

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
    cipher_value  BLOB,                  -- 仅保留片段加密值；丢弃片段为 NULL
    source        TEXT NOT NULL DEFAULT 'manual',  -- manual / auto
    rule_id       TEXT                   -- source=auto 时为策略规则标识，否则为 NULL
);

CREATE INDEX IF NOT EXISTS idx_fragments_document ON fragments(document_id);
-- 唯一性只约束保留片段（kept=1）：丢弃片段允许在同一位置重复出现
CREATE UNIQUE INDEX IF NOT EXISTS idx_fragments_unique
    ON fragments(document_id, placeholder, start_offset) WHERE kept = 1;

CREATE TABLE IF NOT EXISTS restore_tokens (
    token_hash  TEXT PRIMARY KEY,        -- SHA-256(token)
    document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    expires_at  TEXT NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_tokens_document ON restore_tokens(document_id);
"""

# 旧版库（在引入自动脱敏策略之前创建）的幂等迁移
_MIGRATIONS = (
    "ALTER TABLE documents ADD COLUMN policy_id TEXT",
    "ALTER TABLE fragments ADD COLUMN source TEXT NOT NULL DEFAULT 'manual'",
    "ALTER TABLE fragments ADD COLUMN rule_id TEXT",
    # 旧的无差别唯一索引会阻止丢弃片段重复，替换为部分索引
    "DROP INDEX IF EXISTS idx_fragments_unique",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_fragments_unique"
    " ON fragments(document_id, placeholder, start_offset) WHERE kept = 1",
)


async def init_db(db_path: str = ":memory:") -> None:
    """幂等建表 / 迁移（容器启动与 CLI 共用）。

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


async def _migrate(db: aiosqlite.Connection) -> None:
    existing = {
        r[1]
        for r in await db.execute_fetchall("PRAGMA table_info(fragments)")
    }
    if "rule_id" not in existing:
        for stmt in _MIGRATIONS:
            await db.execute(stmt)


def _migrate_sync(conn: sqlite3.Connection) -> None:
    existing = {r[1] for r in conn.execute("PRAGMA table_info(fragments)")}
    if "rule_id" not in existing:
        for stmt in _MIGRATIONS:
            conn.execute(stmt)


async def connect(db_path: str) -> aiosqlite.Connection:
    db = await aiosqlite.connect(db_path)
    await db.execute("PRAGMA foreign_keys=ON")
    db.row_factory = aiosqlite.Row
    return db
