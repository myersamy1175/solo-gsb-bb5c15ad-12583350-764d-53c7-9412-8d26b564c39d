"""脱敏核心算法的纯单元测试。"""
from app.redaction import AUTO, MANUAL, InputSpan, redact, resolve_spans, assign_placeholders


def _span(start, end, priority, category, ordinal, source=MANUAL, rule_id=None):
    return InputSpan(start, end, priority, category, ordinal, source=source, rule_id=rule_id)


def test_basic_stable_placeholders():
    text = "张三向李四借款"
    result = redact(
        text,
        [_span(0, 2, 0, "PERSON", 0), _span(3, 5, 0, "PERSON", 1)],
    )
    assert result.redacted_text == "{{PERSON:01}}向{{PERSON:02}}借款"
    assert all(s.kept for s in result.spans)


def test_same_category_value_reuses_placeholder():
    text = "张三认识张三"
    result = redact(
        text,
        [_span(0, 2, 0, "PERSON", 0), _span(4, 6, 0, "PERSON", 1)],
    )
    assert result.redacted_text == "{{PERSON:01}}认识{{PERSON:01}}"
    assert result.spans[0].placeholder == result.spans[1].placeholder


def test_overlapping_higher_priority_wins():
    # 低优先级大片段 vs 高优先级子片段
    text = "甲方：北京某某科技有限公司"
    result = redact(
        text,
        [
            _span(3, 13, 1, "ORG", 0),    # 北京某某科技有限公司 高优先级
            _span(0, 13, 0, "OTHER", 1),  # 整行 低优先级，重叠丢弃
        ]
    )
    assert result.spans[0].kept
    assert result.spans[0].category == "ORG"
    assert not result.spans[1].kept
    assert result.spans[1].drop_reason == "overlaps_higher_priority"
    assert result.redacted_text == "甲方：{{ORG:01}}"


def test_equal_priority_first_come_first_served():
    text = "abcdef"
    result = redact(
        text,
        [_span(0, 3, 0, "A", 0), _span(2, 5, 0, "B", 1)],
    )
    assert result.spans[0].kept
    assert not result.spans[1].kept


def test_unicode_codepoint_offsets():
    # 含 emoji 与中文，按码位计数
    text = "合同🎉甲方张三"
    assert text[3:5] == "甲方"
    result = redact(text, [_span(5, 7, 0, "PERSON", 0)])
    assert result.redacted_text == "合同🎉甲方{{PERSON:01}}"


def test_nested_spans_both_kept_when_not_overlapping_higher_priority():
    # 两个相邻（非重叠）片段均保留
    text = "0123456789"
    result = redact(text, [_span(0, 2, 5, "A", 0), _span(2, 4, 1, "B", 1)])
    assert result.redacted_text == "{{A:01}}{{B:01}}456789"


def test_resolution_is_deterministic_regardless_of_input_order():
    text = "abcdef"
    low_first = redact(text, [_span(2, 5, 0, "B", 0), _span(0, 3, 5, "A", 1)])
    high_first = redact(text, [_span(0, 3, 5, "A", 0), _span(2, 5, 0, "B", 1)])
    assert low_first.redacted_text == high_first.redacted_text == "{{A:01}}def"


def test_assign_placeholders_width_grows():
    spans = resolve_spans(
        "012345678901",
        [
            _span(0, 1, 0, "X", 0),
            _span(1, 2, 0, "X", 1),
            _span(2, 3, 0, "X", 2),
            _span(3, 4, 0, "X", 3),
            _span(4, 5, 0, "X", 4),
            _span(5, 6, 0, "X", 5),
            _span(6, 7, 0, "X", 6),
            _span(7, 8, 0, "X", 7),
            _span(8, 9, 0, "X", 8),
            _span(9, 10, 0, "X", 9),
        ],
    )
    assign_placeholders(spans)
    assert spans[0].placeholder == "{{X:01}}"
    assert spans[9].placeholder == "{{X:10}}"


def test_manual_wins_when_priority_offsets_length_all_equal():
    text = "abcdef"
    # 同起止、同长度、同优先级；ordinal 让自动片段“先到”，仍应由人工片段胜出
    result = redact(
        text,
        [
            _span(0, 3, 0, "AUTO", 0, source=AUTO, rule_id="r1"),
            _span(0, 3, 0, "MANUAL", 1),
        ],
    )
    kept = [s for s in result.spans if s.kept]
    dropped = [s for s in result.spans if not s.kept]
    assert len(kept) == 1 and kept[0].category == "MANUAL"
    assert kept[0].source == MANUAL and kept[0].rule_id is None
    assert len(dropped) == 1 and dropped[0].source == AUTO
    assert dropped[0].rule_id == "r1"
    assert dropped[0].drop_reason == "overlaps_higher_priority"
    assert result.redacted_text == "{{MANUAL:01}}def"


def test_higher_priority_auto_beats_manual():
    text = "abcdef"
    result = redact(
        text,
        [
            _span(0, 3, 5, "AUTO", 0, source=AUTO, rule_id="r1"),
            _span(0, 3, 0, "MANUAL", 1),
        ],
    )
    kept = [s for s in result.spans if s.kept]
    assert kept[0].category == "AUTO" and kept[0].rule_id == "r1"


def test_auto_span_labels_preserved_through_placeholder_assignment():
    text = "张三张三"
    result = redact(text, [_span(0, 2, 0, "PERSON", 0, source=AUTO, rule_id="p")])
    assert result.redacted_text == "{{PERSON:01}}张三"
    assert result.spans[0].source == AUTO and result.spans[0].rule_id == "p"
