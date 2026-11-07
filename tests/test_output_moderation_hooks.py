"""Tests for output_moderation_hooks covering all specification acceptance criteria."""

from __future__ import annotations

import pytest

from output_moderation_hooks import (
    BlockedOutputError,
    Finding,
    ModerationError,
    Moderator,
    Rule,
    load_rules,
)


class DummyClassifier:
    def __init__(
        self,
        scores: dict[str, float] | None = None,
        should_raise: bool = False,
    ) -> None:
        self.scores = scores or {}
        self.should_raise = should_raise

    def classify(self, text: str) -> dict[str, float]:
        if self.should_raise:
            raise RuntimeError("Classifier service unavailable")
        return self.scores


def test_acceptance_1_redact_pattern() -> None:
    """With Rule('r1', 'pii', pattern=r'\b\\d{3}-\\d{2}-\\d{4}\b', action='redact'),

    check('SSN 123-45-6789 ok') returns action 'redact', text 'SSN [REDACTED:pii] ok'
    and findings == (Finding('r1', 'pii', 'redact', 4, 15),)
    """
    rule = Rule("r1", "pii", pattern=r"\b\d{3}-\d{2}-\d{4}\b", action="redact")
    moderator = Moderator([rule])
    decision = moderator.check("SSN 123-45-6789 ok")
    assert decision.action == "redact"
    assert decision.text == "SSN [REDACTED:pii] ok"
    assert decision.findings == (Finding("r1", "pii", "redact", 4, 15),)


def test_acceptance_2_terms_normalization() -> None:
    """A term rule terms=['badword'] with action 'block' blocks 'This is BADWORD.'

    (Decision.text == '') and 'b\u200badword', while 'badwords' is allowed
    """
    rule = Rule("r_term", "profanity", terms=["badword"], action="block")
    moderator = Moderator([rule])

    # Case insensitive
    d1 = moderator.check("This is BADWORD.")
    assert d1.action == "block"
    assert d1.text == ""

    # Zero-width space inserted
    d2 = moderator.check("b\u200badword")
    assert d2.action == "block"
    assert d2.text == ""

    # Word boundary: 'badwords' is allowed
    d3 = moderator.check("badwords")
    assert d3.action == "allow"
    assert d3.text == "badwords"
    assert d3.findings == ()


def test_acceptance_3_action_precedence() -> None:
    """When findings include a 'flag' and a 'redact' rule the Decision.action is 'redact'

    with findings sorted by start; any 'block' finding makes the action 'block'
    """
    r_flag = Rule("r_flag", "info", pattern=r"note", action="flag")
    r_redact = Rule("r_redact", "secret", pattern=r"secret", action="redact")
    moderator = Moderator([r_flag, r_redact])

    # flag + redact -> redact
    decision = moderator.check("a secret note")
    assert decision.action == "redact"
    assert decision.text == "a [REDACTED:secret] note"
    assert [f.action for f in decision.findings] == ["redact", "flag"]
    assert decision.findings[0].start < decision.findings[1].start

    # add block rule
    r_block = Rule("r_block", "banned", pattern=r"forbidden", action="block")
    moderator_block = Moderator([r_flag, r_redact, r_block])
    decision_block = moderator_block.check("a secret forbidden note")
    assert decision_block.action == "block"
    assert decision_block.text == ""


def test_acceptance_4_classifier() -> None:
    """A classifier returning {'toxicity': 0.9} with thresholds {'toxicity': 0.9} blocks with

    a finding whose rule_id is 'classifier:toxicity'; 0.89 is allowed; a classifier that raises
    gives ModerationError with code 'classifier_failed', and with fail_open=True the action
    is 'allow' and on_event receives kind 'classifier_failed'
    """
    events: list[dict] = []

    def record_event(e: dict) -> None:
        events.append(e)

    # Exactly 0.9 -> blocks
    c1 = DummyClassifier({"toxicity": 0.9})
    mod1 = Moderator([], classifiers=[c1], thresholds={"toxicity": 0.9}, on_event=record_event)
    d1 = mod1.check("hello world")
    assert d1.action == "block"
    assert any(f.rule_id == "classifier:toxicity" for f in d1.findings)

    # 0.89 -> allowed
    c2 = DummyClassifier({"toxicity": 0.89})
    mod2 = Moderator([], classifiers=[c2], thresholds={"toxicity": 0.9})
    d2 = mod2.check("hello world")
    assert d2.action == "allow"

    # Classifier raises -> ModerationError classifier_failed
    c_err = DummyClassifier(should_raise=True)
    mod_err = Moderator([], classifiers=[c_err], thresholds={"toxicity": 0.9}, fail_open=False)
    with pytest.raises(ModerationError) as exc_info:
        mod_err.check("some text")
    assert exc_info.value.code == "classifier_failed"

    # With fail_open=True -> allowed, on_event gets classifier_failed
    events.clear()
    mod_fail_open = Moderator(
        [],
        classifiers=[c_err],
        thresholds={"toxicity": 0.9},
        fail_open=True,
        on_event=record_event,
    )
    d_fail_open = mod_fail_open.check("some text")
    assert d_fail_open.action == "allow"
    assert any(e.get("kind") == "classifier_failed" for e in events)


def test_acceptance_5_stream_redact() -> None:
    """stream(['Hello 123-45-', '6789 bye']) yields chunks whose concatenation is

    'Hello [REDACTED:pii] bye' and no yielded chunk contains '123'
    """
    rule = Rule("r_ssn", "pii", pattern=r"\b\d{3}-\d{2}-\d{4}\b", action="redact")
    # holdback_chars >= match length to catch cross-chunk match
    moderator = Moderator([rule], holdback_chars=16)
    chunks = ["Hello 123-45-", "6789 bye"]
    yielded = list(moderator.stream(chunks))
    assert not any("123" in chunk for chunk in yielded)
    assert "".join(yielded) == "Hello [REDACTED:pii] bye"


def test_acceptance_6_stream_block() -> None:
    """stream(['ok ', 'fine ', 'badword here']) raises BlockedOutputError with code 'blocked'

    and category 'banned' after yielding text that never contains 'badword'
    """
    rule = Rule("r_block", "banned", terms=["badword"], action="block")
    moderator = Moderator([rule], holdback_chars=10)
    chunks = ["ok ", "fine ", "badword here"]
    yielded: list[str] = []
    with pytest.raises(BlockedOutputError) as exc_info:
        for item in moderator.stream(chunks):
            yielded.append(item)
    assert exc_info.value.code == "blocked"
    assert exc_info.value.category == "banned"
    assert not any("badword" in y for y in yielded)


def test_acceptance_7_load_rules_and_limits() -> None:
    """load_rules({'rules': [{'id': 'x', 'category': 'c', 'pattern': '(', 'action': 'block'}]})

    raises ModerationError with code 'invalid_rule'; a pattern longer than 500 characters
    or action 'delete' raise 'invalid_rule'; 201 rules raise 'too_many_rules';
    a 100_001-character text raises 'input_too_large'
    """
    # Invalid regex syntax '('
    with pytest.raises(ModerationError) as exc1:
        load_rules({"rules": [{"id": "x", "category": "c", "pattern": "(", "action": "block"}]})
    assert exc1.value.code == "invalid_rule"

    # Pattern longer than 500 characters
    with pytest.raises(ModerationError) as exc2:
        load_rules(
            {
                "rules": [
                    {
                        "id": "x",
                        "category": "c",
                        "pattern": "a" * 501,
                        "action": "block",
                    }
                ]
            }
        )
    assert exc2.value.code == "invalid_rule"

    # Action 'delete'
    with pytest.raises(ModerationError) as exc3:
        load_rules(
            {
                "rules": [
                    {
                        "id": "x",
                        "category": "c",
                        "pattern": "abc",
                        "action": "delete",
                    }
                ]
            }
        )
    assert exc3.value.code == "invalid_rule"

    # 201 rules raise too_many_rules
    rules_201 = [{"id": f"r_{i}", "category": "c", "pattern": "a"} for i in range(201)]
    with pytest.raises(ModerationError) as exc4:
        load_rules({"rules": rules_201})
    assert exc4.value.code == "too_many_rules"

    # 100_001 characters input raises input_too_large
    mod = Moderator([])
    with pytest.raises(ModerationError) as exc5:
        mod.check("a" * 100_001)
    assert exc5.value.code == "input_too_large"


def test_acceptance_8_event_payload_no_sentinel() -> None:
    """on_event payloads contain rule ids, categories, actions and offsets but never the matched

    text: a test with 'SENTINEL-9q' in the input finds it in no payload
    """
    events: list[dict] = []
    rule = Rule("r_sentinel", "secret", pattern=r"SENTINEL-[0-9][a-z]", action="redact")
    moderator = Moderator([rule], on_event=lambda e: events.append(e))
    decision = moderator.check("Prefix SENTINEL-9q suffix")
    assert decision.action == "redact"
    assert len(events) > 0
    for event in events:
        for val in event.values():
            assert "SENTINEL-9q" not in str(val)


def test_rule_validation_edge_cases() -> None:
    # Duplicate rule id
    r1 = Rule("dup", "c", pattern="a")
    r2 = Rule("dup", "c", pattern="b")
    with pytest.raises(ModerationError) as exc:
        Moderator([r1, r2])
    assert exc.value.code == "invalid_rule"

    # Both pattern and terms
    with pytest.raises(ModerationError) as exc:
        Rule("r1", "c", pattern="a", terms=["b"])
    assert exc.value.code == "invalid_rule"

    # Neither pattern nor terms
    with pytest.raises(ModerationError) as exc:
        Rule("r1", "c")
    assert exc.value.code == "invalid_rule"

    # Invalid ID format
    with pytest.raises(ModerationError) as exc:
        Rule("BAD ID!", "c", pattern="a")
    assert exc.value.code == "invalid_rule"

    # Empty category
    with pytest.raises(ModerationError) as exc:
        Rule("r1", "   ", pattern="a")
    assert exc.value.code == "invalid_rule"

    # Too many terms in rule
    with pytest.raises(ModerationError) as exc:
        Rule("r1", "c", terms=[f"t{i}" for i in range(1001)])
    assert exc.value.code == "invalid_rule"

    # Empty term
    with pytest.raises(ModerationError) as exc:
        Rule("r1", "c", terms=["   "])
    assert exc.value.code == "invalid_rule"


def test_load_rules_edge_cases() -> None:
    with pytest.raises(ModerationError) as exc:
        load_rules("not a mapping")  # type: ignore[arg-type]
    assert exc.value.code == "invalid_rule"

    with pytest.raises(ModerationError) as exc:
        load_rules({"rules": "not a list"})
    assert exc.value.code == "invalid_rule"

    with pytest.raises(ModerationError) as exc:
        load_rules({"rules": ["not a mapping"]})
    assert exc.value.code == "invalid_rule"

    with pytest.raises(ModerationError) as exc:
        load_rules({"rules": [{"id": 123, "category": "c", "pattern": "a"}]})
    assert exc.value.code == "invalid_rule"

    with pytest.raises(ModerationError) as exc:
        load_rules({"rules": [{"id": "r1", "category": 123, "pattern": "a"}]})
    assert exc.value.code == "invalid_rule"


def test_overlapping_redactions_merge() -> None:
    # Overlapping redactions merge into one span labeled with first rule's category
    r1 = Rule("r1", "cat_a", pattern=r"abc", action="redact")
    r2 = Rule("r2", "cat_b", pattern=r"bcd", action="redact")
    moderator = Moderator([r1, r2])
    decision = moderator.check("123abcd456")
    assert decision.action == "redact"
    assert decision.text == "123[REDACTED:cat_a]456"


def test_terms_with_spaces_and_unicode() -> None:
    # 'credit card' phrase
    rule = Rule("r_cc", "financial", terms=["credit card"], action="redact")
    mod = Moderator([rule])
    dec = mod.check("My credit card info")
    assert dec.action == "redact"
    assert dec.text == "My [REDACTED:financial] info"
    assert dec.findings[0].start == 3
    assert dec.findings[0].end == 14

    # Unicode before match: offset in unicode code points
    dec2 = mod.check("❤❤ credit card ❤")
    assert dec2.text == "❤❤ [REDACTED:financial] ❤"
    assert dec2.findings[0].start == 3
    assert dec2.findings[0].end == 14


def test_classifier_out_of_range_score() -> None:
    c = DummyClassifier({"risk": 1.5})
    mod = Moderator([], classifiers=[c], thresholds={"risk": 0.5}, fail_open=False)
    with pytest.raises(ModerationError) as exc:
        mod.check("test")
    assert exc.value.code == "classifier_failed"

    # with fail_open, skips bad score
    mod_open = Moderator([], classifiers=[c], thresholds={"risk": 0.5}, fail_open=True)
    dec = mod_open.check("test")
    assert dec.action == "allow"


def test_streaming_max_chars() -> None:
    mod = Moderator([], max_input_chars=10)
    with pytest.raises(ModerationError) as exc:
        list(mod.stream(["12345", "678901"]))
    assert exc.value.code == "input_too_large"


def test_streaming_empty_and_clean() -> None:
    mod = Moderator([])
    yielded = list(mod.stream(["hello ", "world"]))
    assert "".join(yielded) == "hello world"
