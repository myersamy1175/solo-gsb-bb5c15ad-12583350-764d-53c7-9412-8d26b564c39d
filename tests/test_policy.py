"""自动脱敏策略：创建 / 查询 / 不可变 / 空匹配拒绝 / 合并脱敏 / 超时。"""
from app.main import app

PHONE_RULE = {"rule_id": "phone", "category": "phone", "pattern": r"1[3-9]\d{9}", "priority": 2}
MONEY_RULE = {"rule_id": "amount", "category": "MONEY", "pattern": r"\d+(?:\.\d+)?元", "priority": 1}

TEXT = "联系13812345678，借款10000元，再联系13900001111。"
# 码位：联0 系1 1..8(2..12) ，13 借14 款15 1..6(16..21) 元21 ，22 再23 联24 系25 1..9(26..36) 。37


def _policy_body(*rules):
    return {"rules": list(rules)}


async def _create_policy(client, *rules):
    resp = await client.post("/policies", json=_policy_body(*(rules or (PHONE_RULE, MONEY_RULE))))
    assert resp.status_code == 201, resp.text
    return resp.json()


async def test_create_and_get_policy(client):
    created = await _create_policy(client)
    assert created["policy_id"]
    assert created["created_at"]
    # 类别规范化大写；规则按声明顺序返回
    assert created["rules"][0] == {**PHONE_RULE, "category": "PHONE"}
    assert created["rules"][1] == MONEY_RULE

    got = await client.get(f"/policies/{created['policy_id']}")
    assert got.status_code == 200
    assert got.json() == created


async def test_get_missing_policy_404(client):
    resp = await client.get("/policies/" + "0" * 32)
    assert resp.status_code == 404


async def test_policy_is_immutable(client):
    created = await _create_policy(client)
    pid = created["policy_id"]
    # 不提供任何修改 / 删除入口
    for method in ("put", "patch", "delete"):
        resp = getattr(client, method)(f"/policies/{pid}")
        assert (await resp).status_code == 405
    # 再次查询内容不变
    assert (await client.get(f"/policies/{pid}")).json() == created


async def test_policy_rejects_empty_match_pattern(client):
    for pattern in ("a*", r"\d*", "(a|)", ".*"):
        resp = await client.post(
            "/policies",
            json=_policy_body({"rule_id": "r1", "category": "X", "pattern": pattern, "priority": 0}),
        )
        assert resp.status_code == 422, pattern


async def test_policy_rejects_invalid_regex(client):
    resp = await client.post(
        "/policies",
        json=_policy_body({"rule_id": "r1", "category": "X", "pattern": "(", "priority": 0}),
    )
    assert resp.status_code == 422


async def test_policy_rejects_duplicate_rule_ids(client):
    resp = await client.post("/policies", json=_policy_body(PHONE_RULE, PHONE_RULE))
    assert resp.status_code == 422


async def test_policy_rejects_bad_category_and_rule_id(client):
    resp = await client.post(
        "/policies",
        json=_policy_body({"rule_id": "r1", "category": "bad 类别", "pattern": "a+", "priority": 0}),
    )
    assert resp.status_code == 422
    resp = await client.post(
        "/policies",
        json=_policy_body({"rule_id": "bad id!", "category": "X", "pattern": "a+", "priority": 0}),
    )
    assert resp.status_code == 422


async def test_submit_with_policy_only(client):
    policy = await _create_policy(client)
    resp = await client.post("/documents", json={"text": TEXT, "policy_id": policy["policy_id"]})
    assert resp.status_code == 201, resp.text
    data = resp.json()

    assert data["redacted_text"] == "联系{{PHONE:01}}，借款{{MONEY:01}}，再联系{{PHONE:02}}。"
    sources = {f["source"] for f in data["fragments"]}
    assert sources == {"phone", "amount"}  # 自动片段标注 rule_id
    assert all(f["kept"] for f in data["fragments"])

    # 查询接口同样带 source
    got = await client.get(f"/documents/{data['document_id']}")
    assert got.status_code == 200
    assert {f["source"] for f in got.json()["fragments"]} == {"phone", "amount"}

    # 自动片段可通过一次性令牌恢复
    r = await client.post(
        "/restore",
        json={"token": data["restore_token"], "placeholders": ["{{PHONE:01}}", "{{MONEY:01}}"]},
    )
    assert r.status_code == 200, r.text
    values = {item["placeholder"]: item["value"] for item in r.json()["restored"]}
    assert values["{{PHONE:01}}"] == "13812345678"
    assert values["{{MONEY:01}}"] == "10000元"


async def test_manual_wins_exact_tie_with_auto(client):
    policy = await _create_policy(client)
    # 人工片段与 phone 规则命中区间、优先级完全相同 -> 人工优先，自动片段被丢弃
    body = {
        "text": TEXT,
        "policy_id": policy["policy_id"],
        "spans": [{"start": 2, "end": 13, "priority": 2, "category": "PHONE"}],
    }
    resp = await client.post("/documents", json=body)
    assert resp.status_code == 201, resp.text
    frags = resp.json()["fragments"]

    tie = [f for f in frags if f["start"] == 2 and f["end"] == 13]
    assert len(tie) == 2
    manual = next(f for f in tie if f["source"] == "manual")
    auto = next(f for f in tie if f["source"] == "phone")
    assert manual["kept"] and manual["placeholder"] == "{{PHONE:01}}"
    assert not auto["kept"] and auto["drop_reason"] == "overlaps_higher_priority"
    assert resp.json()["redacted_text"].startswith("联系{{PHONE:01}}")


async def test_auto_higher_priority_beats_manual(client):
    policy = await _create_policy(client)
    # 人工低优先级大跨度 vs 自动高优先级手机号 -> 自动片段落位
    body = {
        "text": TEXT,
        "policy_id": policy["policy_id"],
        "spans": [{"start": 0, "end": 14, "priority": 0, "category": "BLOCK"}],
    }
    resp = await client.post("/documents", json=body)
    assert resp.status_code == 201, resp.text
    frags = resp.json()["fragments"]

    manual = next(f for f in frags if f["source"] == "manual")
    assert not manual["kept"]
    phone = next(f for f in frags if f["source"] == "phone" and f["start"] == 2)
    assert phone["kept"]
    assert resp.json()["redacted_text"].startswith("联系{{PHONE:01}}，")


async def test_submit_policy_not_found(client):
    resp = await client.post(
        "/documents",
        json={"text": TEXT, "policy_id": "0" * 32},
    )
    assert resp.status_code == 404


async def test_submit_requires_spans_or_policy(client):
    resp = await client.post("/documents", json={"text": TEXT})
    assert resp.status_code == 422
    resp = await client.post("/documents", json={"text": TEXT, "spans": []})
    assert resp.status_code == 422


async def test_auto_spans_over_limit_rejected(client):
    policy = await _create_policy(
        client, {"rule_id": "pair", "category": "X", "pattern": "ab", "priority": 0}
    )
    resp = await client.post(
        "/documents",
        json={"text": "ab" * 6000, "policy_id": policy["policy_id"]},
    )
    assert resp.status_code == 422


async def test_rule_timeout_returns_422_and_nothing_written(client):
    policy = await _create_policy(
        client, {"rule_id": "evil", "category": "X", "pattern": r"(a|a)+$", "priority": 0}
    )
    # 缩短单规则超时，触发回溯失控保护
    app.state.service.rule_timeout = 0.1

    async with app.state.service.db.execute("SELECT COUNT(*) FROM documents") as cur:
        before = (await cur.fetchone())[0]

    resp = await client.post(
        "/documents",
        json={"text": "a" * 40 + "b", "policy_id": policy["policy_id"]},
    )
    assert resp.status_code == 422
    assert "evil" in resp.json()["detail"]

    # 整次提交失败：未写入任何文档
    async with app.state.service.db.execute("SELECT COUNT(*) FROM documents") as cur:
        after = (await cur.fetchone())[0]
    assert after == before
