# 合同文本脱敏 API（Python / FastAPI）

提交合同原文及一批带 **起止位置、优先级、类别** 的敏感片段，服务端：

1. 按 **原始 Unicode 码位位置** 一次性解析全部片段，确定性消解重叠；
2. 生成 **稳定占位符**（同文档内相同「类别 + 原文」复用同一占位符）；
3. 原文与片段映射经 **Fernet 对称加密** 后存入 SQLite，且 **可过期**（定时 + 懒清理）；
4. 恢复接口仅认 **一次性令牌**：用后作废并轮换，只能还原请求中显式指定的占位符。

---

## 一、单命令启动（Docker Compose）

```bash
docker compose up --build -d
```

- 服务地址：http://localhost:8000
- 交互式文档（Swagger）：http://localhost:8000/docs
- 健康检查：`GET /health`

> 开箱即用的默认主密钥仅用于快速体验；生产环境请先生成并注入自己的密钥：
>
> ```bash
> docker compose run --rm api python -m app.cli keygen
> REDACT_MASTER_KEY=<输出的密钥> docker compose up --build -d
> ```
>
> 也可复制 `.env.example` 为 `.env` 后修改，Compose 会自动加载。

停止 / 清理：

```bash
docker compose down            # 停止（数据保留在命名卷 redaction-data 中）
docker compose down -v         # 同时删除数据卷
```

---

## 二、本地运行（不用 Docker）

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 1) 生成主密钥（可选；未设置时开发环境会生成一次性密钥，重启后旧数据无法解密）
export REDACT_MASTER_KEY="$(python -m app.cli keygen)"

# 2) 初始化 SQLite（幂等，应用启动时也会自动建表）
export REDACT_DATABASE_URL="sqlite:///./data/redaction.db"
python -m app.cli initdb

# 3) 启动
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

测试：

```bash
.venv/bin/pip install -r requirements-dev.txt
python -m pytest -q
```

---

## 三、API 说明

所有位置偏移均为 **Unicode 码位索引（即 Python 对字符串的索引方式），左闭右开**，
不是 UTF-8 字节偏移。例如 `"合同🎉甲方张三"` 中 `张三` 的位置是 `[5, 7)`。

### 1. 提交脱敏 `POST /documents`

请求：

```json
{
  "text": "甲方张三向乙方李四借款人民币10000元。",
  "ttl": 3600,
  "spans": [
    {"start": 2, "end": 4,  "priority": 5, "category": "person"},
    {"start": 7, "end": 9,  "priority": 5, "category": "PERSON"},
    {"start": 11, "end": 20, "priority": 3, "category": "MONEY"},
    {"start": 2, "end": 9,  "priority": 0, "category": "BLOCK"}
  ]
}
```

响应（节选）：

```json
{
  "document_id": "0b0b3e4b…",
  "redacted_text": "甲方{{PERSON:01}}向乙方{{PERSON:02}}借款{{MONEY:01}}。",
  "fragments": [
    {"placeholder": "{{PERSON:01}}", "category": "PERSON", "start": 2, "end": 4,
     "priority": 5, "kept": true,  "drop_reason": null},
    {"placeholder": "{{PERSON:02}}", "category": "PERSON", "start": 7, "end": 9,
     "priority": 5, "kept": true,  "drop_reason": null},
    {"placeholder": "{{MONEY:01}}",  "category": "MONEY",  "start": 11, "end": 20,
     "priority": 3, "kept": true,  "drop_reason": null},
    {"placeholder": "", "category": "BLOCK", "start": 2, "end": 9,
     "priority": 0, "kept": false, "drop_reason": "overlaps_higher_priority"}
  ],
  "restore_token": "6c538c2c…（64 位十六进制，仅此一次返回明文）",
  "expires_at": "2026-09-21T12:00:00.000000Z",
  "token_expires_at": "2026-09-21T11:10:00.000000Z"
}
```

### 2. 查询脱敏结果 `GET /documents/{document_id}`

返回脱敏文本与全部片段明细（含被丢弃片段及原因）。不返回任何原文信息，不需要令牌。
文档过期后返回 `410 Gone`，不存在返回 `404`。

### 3. 一次性令牌恢复 `POST /restore`

```json
{
  "token": "6c538c2c…",
  "placeholders": ["{{MONEY:01}}"]
}
```

```json
{
  "restored": [
    {
      "placeholder": "{{MONEY:01}}",
      "category": "MONEY",
      "value": "人民币10000元",
      "occurrences": [{"start": 11, "end": 20, "priority": 3}]
    }
  ],
  "restore_token": "新的一次性令牌…",
  "token_expires_at": "…"
}
```

规则：

- 令牌只保存 **SHA-256 哈希**，明文仅在创建 / 轮换时出现一次；
- 每次恢复在单个 SQLite 事务中完成：旧令牌置 `used=1` 作废，返回轮换后的新令牌；
- 令牌默认 10 分钟有效（`REDACT_TOKEN_TTL`），且令牌有效期不超过文档 TTL；
- 仅能还原请求中显式列出的、属于该文档的占位符（复用占位符时 `occurrences`
  会返回全部出现位置）；
- 令牌无效 / 已用 / 过期 → `401`；占位符不属于文档 → `400`；文档已过期 → `410`。

### 4. 健康检查 `GET /health` → `{"status": "ok"}`

---

## 四、重叠消解与占位符规则

排序键（全部确定，无随机）：

1. `priority` **数值大者优先**；
2. 同优先级：`start` 小者优先；
3. 仍相同：片段长者优先；
4. 仍相同：按客户端提交顺序（先到先得）。

排序后依次落位：与**任何已占用区间相交**的片段被丢弃，
`drop_reason = "overlaps_higher_priority"`（同优先级被先到者占用也使用此标记）。

占位符：

- 形如 `{{类别:两位序号}}`，如 `{{PERSON:01}}`；序号超过 99 自动加宽；
- 类别先 `strip + 大写`，须匹配 `[A-Z][A-Z0-9_]{0,31}`；
- 同文档内 `(类别, 原文)` 完全相同的片段复用同一占位符；不同文档不复用；
- 渲染替换自后向前进行，保证前序片段的位置不失效。

---

## 五、数据安全与过期

- 文档原文、每个保留片段的原文均以 **Fernet（AES-128-CBC + HMAC，cryptography 库）**
  加密后落库；数据库文件中无明文；
- 主密钥通过 `REDACT_MASTER_KEY` 提供（支持 Fernet 密钥，或任意口令经 SHA-256 派生）；
  `REDACT_ENV=production` 时未配置密钥会直接拒绝启动；
- 文档映射默认 1 天过期（提交时可用 `ttl` 指定，1..604800 秒），
  过期后由后台任务（默认每 300 秒）及访问时的懒检查物理删除；
- 恢复令牌默认 10 分钟过期，过期 / 已用即删或标记作废。

**生产建议**：将 SQLite 数据卷纳入磁盘加密与备份策略；服务部署于内网或加 TLS / 鉴权网关；
按最小需要设置 `REDACT_DEFAULT_TTL` / `REDACT_TOKEN_TTL`；密钥通过环境变量或密钥管理系统注入，不要写入镜像。

---

## 六、配置项（环境变量，前缀 `REDACT_`）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `REDACT_DATABASE_URL` | `/data/redaction.db` | SQLite 路径，支持 `sqlite:///` 前缀 |
| `REDACT_MASTER_KEY` | 空 | Fernet 密钥或任意口令；生产必填 |
| `REDACT_ENV` | `development` | 设为 `production` 强制要求密钥 |
| `REDACT_DEFAULT_TTL` | `86400` | 文档映射默认有效期（秒） |
| `REDACT_MAX_TTL` | `604800` | 允许提交的最大 TTL（秒） |
| `REDACT_TOKEN_TTL` | `600` | 一次性恢复令牌有效期（秒） |
| `REDACT_CLEANUP_INTERVAL` | `300` | 后台过期清理周期（秒） |

---

## 七、项目结构

```
app/
  main.py               FastAPI 入口、生命周期、后台清理、异常映射
  config.py             环境变量配置
  crypto.py             Fernet 加密封装、一次性令牌生成
  db.py                 SQLite 建表（幂等）与连接
  redaction.py          重叠消解 / 稳定占位符 / 渲染（纯函数，易测）
  schemas.py            请求与响应模型
  services/
    document_service.py 提交、查询、恢复、过期清理业务逻辑
    errors.py           服务层错误 -> HTTP 状态码
  routers/__init__.py    /documents、/documents/{id}、/restore、/health
  cli.py                keygen / initdb 命令
tests/                  核心算法单元测试 + API 端到端测试
Dockerfile              非 root 运行、内置健康检查
docker-compose.yml      单命令启动 + 持久化命名卷
```
