# output-moderation-hooks

Moderate LLM output with configurable regex and term rules, categories, block, redact and flag actions, optional classifiers and streaming holdback.

## Installation

```bash
pip install output-moderation-hooks
```

## Usage

```python
from output_moderation_hooks import Moderator, Rule

rules = [Rule("r1", "pii", pattern=r"\b\d{3}-\d{2}-\d{4}\b", action="redact")]
moderator = Moderator(rules)
decision = moderator.check("SSN 123-45-6789 ok")
print(decision.action, decision.text)
# Output: redact SSN [REDACTED:pii] ok
```

## Public API Summary

- `Rule(id: str, category: str, *, pattern: str | None = None, terms: Sequence[str] = (), action: Literal['block', 'redact', 'flag'] = 'flag')`: Define validation rules.
- `ClassifierPort(Protocol)`: Interface for external scoring. Implements `classify(self, text: str) -> Mapping[str, float]`.
- `Moderator(...)`: Main engine. Accepts rules, classifiers, thresholds, fail_open, holdback_chars (default 64), and max_input_chars (default 100,000).
- `Moderator.check(text: str) -> Decision`: Evaluate all rules and classifiers against static text.
- `Moderator.stream(chunks: Iterable[str]) -> Iterator[str]`: Evaluate rules against a stream with a holdback window.
- `load_rules(data: Mapping[str, Any]) -> list[Rule]`: Loader for rule configuration.

Errors include `ModerationError` (with codes `invalid_rule`, `too_many_rules`, `input_too_large`, `classifier_failed`) and `BlockedOutputError`.

## Why not <best-known alternative>

Existing guardrails frameworks often introduce large dependency trees or are designed for monolithic application rather than low-latency stream processing. `output-moderation-hooks` provides a lightweight, dependency-free utility with deterministic precedence logic and native streaming support via a holdback window.

## Security

See [docs/SECURITY.md](docs/SECURITY.md) for threat model and limits.
