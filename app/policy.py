"""自动脱敏策略：正则规则校验与自动片段生成（纯函数，易测）。

* 策略创建后不可变，每条规则含 rule_id / 类别 / 正则 / 优先级；
* 正则必须拒绝空匹配：可匹配空串的表达式在创建策略时被拒绝；
* 每条规则在整篇文档上的执行设有**总超时**，超时抛出
  :class:`RuleTimeoutError`，由服务层映射为 422，且整次提交不写入任何数据。

正则引擎使用第三方 ``regex`` 库：其 C 实现支持 ``timeout`` 参数，
可在回溯失控时可靠中断（标准库 ``re`` 无法做到）。
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import regex


class PolicyError(ValueError):
    """策略相关错误基类。"""


class PatternError(PolicyError):
    """正则无法编译，或可匹配空串。"""


class RuleTimeoutError(PolicyError):
    """单条规则在整篇文档上的执行超出时限。"""

    def __init__(self, rule_id: str) -> None:
        super().__init__(f"规则 {rule_id!r} 执行超时")
        self.rule_id = rule_id


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    category: str
    pattern: str
    priority: int


@dataclass(frozen=True)
class AutoSpan:
    start: int
    end: int
    priority: int
    category: str
    rule_id: str  # 命中规则的 rule_id，用于片段来源标注


def compile_pattern(pattern: str) -> "regex.Pattern":
    """编译并校验规则正则：必须可编译，且拒绝空匹配。"""
    try:
        rx = regex.compile(pattern)
    except regex.error as exc:
        raise PatternError(f"正则无法编译：{exc}") from exc
    if rx.match("") is not None:
        raise PatternError("正则必须拒绝空匹配：该表达式可以匹配空字符串")
    return rx


def find_spans(text: str, rules: list[PolicyRule], timeout: float) -> list[AutoSpan]:
    """在 Unicode 原文上逐规则生成自动片段（左闭右开码位区间）。

    ``timeout`` 为**单条规则**在整篇文本上的总执行时限（秒）；任一规则超时
    抛出 :class:`RuleTimeoutError`。返回顺序为规则声明顺序、同规则内按匹配
    位置升序，供调用方分配稳定序号。
    """
    spans: list[AutoSpan] = []
    for rule in rules:
        rx = compile_pattern(rule.pattern)
        deadline = time.monotonic() + timeout
        pos = 0
        n = len(text)
        while pos <= n:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuleTimeoutError(rule.rule_id)
            try:
                m = rx.search(text, pos, timeout=remaining)
            except TimeoutError as exc:
                raise RuleTimeoutError(rule.rule_id) from exc
            if m is None:
                break
            start, end = m.span()
            if end > start:
                spans.append(
                    AutoSpan(
                        start=start,
                        end=end,
                        priority=rule.priority,
                        category=rule.category,
                        rule_id=rule.rule_id,
                    )
                )
                pos = end
            else:
                # 创建时已拒绝可空正则；此处防御环视等构造出的零宽匹配
                pos = end + 1
    return spans
