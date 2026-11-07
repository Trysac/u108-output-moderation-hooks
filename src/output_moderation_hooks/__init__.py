"""output_moderation_hooks - Moderate LLM output with regex, terms, classifiers,
and streaming holdback.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol, runtime_checkable

__all__ = [
    "Action",
    "BlockedOutputError",
    "ClassifierPort",
    "Decision",
    "EventKind",
    "Finding",
    "ModerationError",
    "ModerationErrorCode",
    "Moderator",
    "Rule",
    "__version__",
    "load_rules",
]

__version__ = "0.1.0"

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

Action = Literal["block", "redact", "flag"]
DecisionAction = Literal["allow", "flag", "redact", "block"]
ModerationErrorCode = Literal[
    "invalid_rule",
    "too_many_rules",
    "input_too_large",
    "classifier_failed",
    "blocked",
]
EventKind = Literal["finding", "classifier_failed", "blocked"]

MAX_RULES = 200
MAX_TERMS_PER_RULE = 1000
MAX_PATTERN_CHARS = 500
DEFAULT_MAX_INPUT_CHARS = 100_000
DEFAULT_HOLDBACK_CHARS = 64

RULE_ID_PATTERN = re.compile(r"^[a-z0-9_.:-]{1,64}$")
ALLOWED_ACTIONS = {"block", "redact", "flag"}

# Characters ignored during normalization (zero-width characters and BOM)
IGNORED_CHARS = frozenset(
    {
        "\u200b",  # ZERO WIDTH SPACE
        "\u200c",  # ZERO WIDTH NON-JOINER
        "\u200d",  # ZERO WIDTH JOINER
        "\u2060",  # WORD JOINER
        "\ufeff",  # ZERO WIDTH NO-BREAK SPACE / BOM
    }
)


class ModerationError(Exception):
    """Base exception for output moderation errors."""

    def __init__(self, code: ModerationErrorCode, message: str) -> None:
        # Ensure error message does not leak raw text over 200 chars
        safe_message = message[:200]
        super().__init__(safe_message)
        self.code: ModerationErrorCode = code


class BlockedOutputError(ModerationError):
    """Raised when content is blocked during stream processing or check."""

    def __init__(self, category: str, message: str = "Content blocked") -> None:
        super().__init__("blocked", message)
        self.category: str = category


@dataclass(frozen=True)
class Finding:
    """Finding of a moderation rule violation."""

    rule_id: str
    category: str
    action: Action
    start: int
    end: int


@dataclass(frozen=True)
class Decision:
    """Result of evaluating moderation rules and classifiers on text."""

    action: DecisionAction
    text: str
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class Rule:
    """A rule matching output text either by regex pattern or list of terms."""

    id: str
    category: str
    pattern: str | None = None
    terms: Sequence[str] = ()
    action: Action = "flag"

    def __init__(
        self,
        id: str,
        category: str,
        *,
        pattern: str | None = None,
        terms: Sequence[str] = (),
        action: Action = "flag",
    ) -> None:
        object.__setattr__(self, "id", id)
        object.__setattr__(self, "category", category)
        object.__setattr__(self, "pattern", pattern)
        object.__setattr__(self, "terms", tuple(terms))
        object.__setattr__(self, "action", action)
        self._validate()

    def _validate(self) -> None:
        if not isinstance(self.id, str) or not RULE_ID_PATTERN.match(self.id):
            raise ModerationError("invalid_rule", f"Rule id '{self.id}' is invalid")
        if not isinstance(self.category, str) or not self.category.strip():
            raise ModerationError("invalid_rule", "Category must be a non-empty string")
        if self.action not in ALLOWED_ACTIONS:
            raise ModerationError("invalid_rule", f"Invalid action '{self.action}'")

        has_pattern = self.pattern is not None
        has_terms = len(self.terms) > 0
        if (has_pattern and has_terms) or (not has_pattern and not has_terms):
            raise ModerationError(
                "invalid_rule",
                "Exactly one of pattern or terms must be specified",
            )

        if has_pattern:
            if not isinstance(self.pattern, str) or len(self.pattern) > MAX_PATTERN_CHARS:
                raise ModerationError(
                    "invalid_rule",
                    f"Pattern must be at most {MAX_PATTERN_CHARS} characters",
                )
            try:
                re.compile(self.pattern)
            except re.error as exc:
                raise ModerationError("invalid_rule", f"Invalid regex pattern: {exc}") from exc

        if has_terms:
            if len(self.terms) > MAX_TERMS_PER_RULE:
                raise ModerationError(
                    "invalid_rule",
                    f"Terms list exceeds maximum of {MAX_TERMS_PER_RULE} terms",
                )
            for term in self.terms:
                if not isinstance(term, str) or not term.strip():
                    raise ModerationError(
                        "invalid_rule",
                        "Each term must be a non-empty string",
                    )


@runtime_checkable
class ClassifierPort(Protocol):
    """External classifier interface for scoring output categories."""

    def classify(self, text: str) -> Mapping[str, float]:
        """Return a mapping of category -> confidence score in [0.0, 1.0]."""
        ...


def _normalize_with_map(text: str) -> tuple[str, list[int], list[int]]:
    """Normalize text per-character NFKC, casefold, and strip zero-width characters.

    Returns:
        (norm_text, norm_to_orig_start, norm_to_orig_end) where for norm_text[i],
        original code point span is [norm_to_orig_start[i], norm_to_orig_end[i]].
    """
    norm_chars: list[str] = []
    orig_starts: list[int] = []
    orig_ends: list[int] = []

    for idx, char in enumerate(text):
        if char in IGNORED_CHARS:
            continue
        nfkc_char = unicodedata.normalize("NFKC", char)
        for c in nfkc_char:
            if c in IGNORED_CHARS:
                continue
            folded = c.casefold()
            for fc in folded:
                norm_chars.append(fc)
                orig_starts.append(idx)
                orig_ends.append(idx + 1)

    return "".join(norm_chars), orig_starts, orig_ends


def _is_word_char(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


class Moderator:
    """Moderate LLM text output and chunk streams using rules and classifiers."""

    def __init__(
        self,
        rules: Sequence[Rule],
        *,
        classifiers: Sequence[ClassifierPort] = (),
        thresholds: Mapping[str, float] | None = None,
        fail_open: bool = False,
        holdback_chars: int = DEFAULT_HOLDBACK_CHARS,
        max_input_chars: int = DEFAULT_MAX_INPUT_CHARS,
        on_event: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        if len(rules) > MAX_RULES:
            raise ModerationError("too_many_rules", f"Maximum {MAX_RULES} rules allowed")

        # Rule IDs must be unique
        seen_ids: set[str] = set()
        for rule in rules:
            if rule.id in seen_ids:
                raise ModerationError("invalid_rule", f"Duplicate rule id '{rule.id}'")
            seen_ids.add(rule.id)

        self.rules: tuple[Rule, ...] = tuple(rules)
        self.classifiers: tuple[ClassifierPort, ...] = tuple(classifiers)
        self.thresholds: Mapping[str, float] = dict(thresholds or {})
        self.fail_open = fail_open
        self.holdback_chars = holdback_chars
        self.max_input_chars = max_input_chars
        self.on_event = on_event

        # Pre-compile regexes for pattern rules
        self._compiled_patterns: list[tuple[Rule, re.Pattern[str]]] = []
        self._term_rules: list[tuple[Rule, list[str]]] = []
        for rule in self.rules:
            if rule.pattern is not None:
                self._compiled_patterns.append((rule, re.compile(rule.pattern)))
            elif rule.terms:
                # Normalize terms to match against normalized text
                norm_terms: list[str] = []
                for t in rule.terms:
                    norm_t, _, _ = _normalize_with_map(t)
                    if norm_t:
                        norm_terms.append(norm_t)
                self._term_rules.append((rule, norm_terms))

    def _find_rule_matches(self, text: str) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Regex patterns
        for rule, pattern in self._compiled_patterns:
            for m in pattern.finditer(text):
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        category=rule.category,
                        action=rule.action,
                        start=m.start(),
                        end=m.end(),
                    )
                )

        # 2. Terms
        if self._term_rules:
            norm_text, orig_starts, orig_ends = _normalize_with_map(text)
            norm_len = len(norm_text)
            for rule, terms in self._term_rules:
                for term in terms:
                    term_len = len(term)
                    if term_len == 0 or term_len > norm_len:
                        continue
                    idx = 0
                    while idx <= norm_len - term_len:
                        found = norm_text.find(term, idx)
                        if found == -1:
                            break
                        idx = found + 1
                        # Check word boundaries on normalized text
                        left_word = found > 0 and _is_word_char(norm_text[found - 1])
                        right_word = found + term_len < norm_len and _is_word_char(
                            norm_text[found + term_len]
                        )
                        if left_word or right_word:
                            continue

                        # Map back to original indices
                        orig_start = orig_starts[found]
                        orig_end = orig_ends[found + term_len - 1]
                        findings.append(
                            Finding(
                                rule_id=rule.id,
                                category=rule.category,
                                action=rule.action,
                                start=orig_start,
                                end=orig_end,
                            )
                        )

        # Sort findings by start offset, then rule order
        findings.sort(key=lambda f: (f.start, f.end))
        return findings

    def _emit_event(
        self,
        kind: EventKind,
        *,
        rule_id: str | None = None,
        category: str | None = None,
        action: str | None = None,
        start: int | None = None,
        end: int | None = None,
    ) -> None:
        if self.on_event is not None:
            payload: dict[str, Any] = {
                "kind": kind,
                "rule_id": rule_id,
                "category": category,
                "action": action,
                "start": start,
                "end": end,
            }
            self.on_event(payload)

    def check(self, text: str) -> Decision:
        """Evaluate rules and classifiers against the full text output."""
        if len(text) > self.max_input_chars:
            raise ModerationError(
                "input_too_large",
                f"Input length {len(text)} exceeds limit {self.max_input_chars}",
            )

        all_findings = self._find_rule_matches(text)

        # Run classifiers in order on the original text
        text_len = len(text)
        for classifier in self.classifiers:
            try:
                scores = classifier.classify(text)
            except Exception as exc:
                self._emit_event("classifier_failed", action="block", start=0, end=text_len)
                if not self.fail_open:
                    raise ModerationError(
                        "classifier_failed",
                        "Classifier execution failed",
                    ) from exc
                scores = {}

            for cat, score in scores.items():
                if not isinstance(score, (int, float)) or score < 0.0 or score > 1.0:
                    self._emit_event(
                        "classifier_failed",
                        category=cat,
                        action="block",
                        start=0,
                        end=text_len,
                    )
                    if not self.fail_open:
                        raise ModerationError(
                            "classifier_failed",
                            f"Classifier score {score} for '{cat}' outside [0, 1]",
                        )
                    continue

                if cat in self.thresholds and score >= self.thresholds[cat]:
                    all_findings.append(
                        Finding(
                            rule_id=f"classifier:{cat}",
                            category=cat,
                            action="block",
                            start=0,
                            end=text_len,
                        )
                    )

        # Emit findings events
        for f in all_findings:
            self._emit_event(
                "finding",
                rule_id=f.rule_id,
                category=f.category,
                action=f.action,
                start=f.start,
                end=f.end,
            )

        # Precedence: block > redact > flag > allow
        has_block = any(f.action == "block" for f in all_findings)
        has_redact = any(f.action == "redact" for f in all_findings)
        has_flag = any(f.action == "flag" for f in all_findings)

        # Findings sorted by start offset
        sorted_findings = tuple(sorted(all_findings, key=lambda f: (f.start, f.end)))

        if has_block:
            first_block = next(f for f in sorted_findings if f.action == "block")
            self._emit_event(
                "blocked",
                rule_id=first_block.rule_id,
                category=first_block.category,
                action="block",
                start=first_block.start,
                end=first_block.end,
            )
            return Decision(action="block", text="", findings=sorted_findings)

        if has_redact:
            redacted_text = self._apply_redactions(text, sorted_findings)
            return Decision(action="redact", text=redacted_text, findings=sorted_findings)

        if has_flag:
            return Decision(action="flag", text=text, findings=sorted_findings)

        return Decision(action="allow", text=text, findings=())

    def _apply_redactions(self, text: str, findings: tuple[Finding, ...]) -> str:
        """Redact text based on redact findings, merging overlapping spans."""
        redact_findings = [f for f in findings if f.action == "redact"]
        if not redact_findings:
            return text

        # Merge overlapping/adjacent redaction spans
        # Merged span gets category of the first rule in that span
        redact_findings.sort(key=lambda f: (f.start, f.end))
        merged: list[tuple[int, int, str]] = []
        for f in redact_findings:
            if not merged:
                merged.append((f.start, f.end, f.category))
            else:
                prev_start, prev_end, prev_cat = merged[-1]
                if f.start <= prev_end:
                    # Overlapping or contiguous
                    merged[-1] = (prev_start, max(prev_end, f.end), prev_cat)
                else:
                    merged.append((f.start, f.end, f.category))

        parts: list[str] = []
        cursor = 0
        for span_start, span_end, category in merged:
            if span_start > cursor:
                parts.append(text[cursor:span_start])
            parts.append(f"[REDACTED:{category}]")
            cursor = span_end
        if cursor < len(text):
            parts.append(text[cursor:])
        return "".join(parts)

    def stream(self, chunks: Iterable[str]) -> Iterator[str]:
        """Stream chunks with holdback window redaction and blocking.

        Note: Classifiers do not run in stream (documented limitation).
        """
        buffer = ""
        total_chars = 0
        committed_cursor = 0  # index in buffer that has already been yielded or redacted

        for chunk in chunks:
            total_chars += len(chunk)
            if total_chars > self.max_input_chars:
                raise ModerationError(
                    "input_too_large",
                    f"Input length exceeds limit {self.max_input_chars}",
                )
            buffer += chunk

            # If buffer length allows safe yielding (buffer beyond holdback)
            while True:
                safe_boundary = len(buffer) - self.holdback_chars
                if safe_boundary <= committed_cursor:
                    break

                # Look for findings in the entire buffer
                findings = self._find_rule_matches(buffer)

                # Check for block action in findings up to safe_boundary
                for f in findings:
                    if f.action == "block" and f.start < safe_boundary:
                        self._emit_event(
                            "blocked",
                            rule_id=f.rule_id,
                            category=f.category,
                            action="block",
                            start=f.start,
                            end=f.end,
                        )
                        raise BlockedOutputError(category=f.category)

                # Find earliest redaction overlapping or before safe_boundary
                redactions = [
                    f for f in findings if f.action == "redact" and f.end > committed_cursor
                ]
                redactions.sort(key=lambda f: (f.start, f.end))

                # Merge overlapping redactions
                merged: list[tuple[int, int, str]] = []
                for f in redactions:
                    if not merged:
                        merged.append((f.start, f.end, f.category))
                    else:
                        p_s, p_e, p_c = merged[-1]
                        if f.start <= p_e:
                            merged[-1] = (p_s, max(p_e, f.end), p_c)
                        else:
                            merged.append((f.start, f.end, f.category))

                if not merged:
                    # No redactions pending; yield up to safe_boundary
                    to_yield = buffer[committed_cursor:safe_boundary]
                    committed_cursor = safe_boundary
                    if to_yield:
                        yield to_yield
                    break

                # There is at least one redaction
                first_red = merged[0]
                r_start, r_end, r_cat = first_red
                if r_start > committed_cursor:
                    # Yield plain text before this redaction, up to min(r_start, safe_boundary)
                    advance = min(r_start, safe_boundary)
                    to_yield = buffer[committed_cursor:advance]
                    committed_cursor = advance
                    if to_yield:
                        yield to_yield
                    if advance < r_start:
                        break
                elif r_end <= safe_boundary:
                    # Full redaction span is within safe boundary, yield replacement
                    for f in findings:
                        if f.action == "redact" and f.start >= r_start and f.end <= r_end:
                            self._emit_event(
                                "finding",
                                rule_id=f.rule_id,
                                category=f.category,
                                action=f.action,
                                start=f.start,
                                end=f.end,
                            )
                    yield f"[REDACTED:{r_cat}]"
                    committed_cursor = r_end
                else:
                    # Redaction span reaches beyond safe boundary; must hold back
                    break

        # Flush remaining buffer at end of stream
        findings = self._find_rule_matches(buffer)
        for f in findings:
            if f.action == "block":
                self._emit_event(
                    "blocked",
                    rule_id=f.rule_id,
                    category=f.category,
                    action="block",
                    start=f.start,
                    end=f.end,
                )
                raise BlockedOutputError(category=f.category)

        # Emit findings for any remaining items
        for f in findings:
            if f.end > committed_cursor:
                self._emit_event(
                    "finding",
                    rule_id=f.rule_id,
                    category=f.category,
                    action=f.action,
                    start=f.start,
                    end=f.end,
                )

        remaining_text = buffer[committed_cursor:]
        if remaining_text:
            # Apply redactions to remaining text with offset shifted by committed_cursor
            tail_findings = tuple(
                Finding(
                    rule_id=f.rule_id,
                    category=f.category,
                    action=f.action,
                    start=max(0, f.start - committed_cursor),
                    end=max(0, f.end - committed_cursor),
                )
                for f in findings
                if f.end > committed_cursor
            )
            redacted_tail = self._apply_redactions(remaining_text, tail_findings)
            if redacted_tail:
                yield redacted_tail


def load_rules(data: Mapping[str, Any]) -> list[Rule]:
    """Load and validate a list of rules from a dictionary (e.g. JSON config)."""
    if not isinstance(data, Mapping):
        raise ModerationError("invalid_rule", "Data must be a mapping")
    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list):
        raise ModerationError("invalid_rule", "'rules' must be a list")
    if len(raw_rules) > MAX_RULES:
        raise ModerationError("too_many_rules", f"Too many rules: {len(raw_rules)} > {MAX_RULES}")

    rules: list[Rule] = []
    for item in raw_rules:
        if not isinstance(item, Mapping):
            raise ModerationError("invalid_rule", "Each rule item must be a mapping")
        rule_id = item.get("id")
        category = item.get("category")
        pattern = item.get("pattern")
        terms = item.get("terms", ())
        action = item.get("action", "flag")

        if not isinstance(rule_id, str):
            raise ModerationError("invalid_rule", "Rule id must be a string")
        if not isinstance(category, str):
            raise ModerationError("invalid_rule", "Rule category must be a string")

        rule = Rule(
            id=rule_id,
            category=category,
            pattern=pattern,
            terms=list(terms) if isinstance(terms, (list, tuple)) else (),
            action=action,
        )
        rules.append(rule)

    return rules
