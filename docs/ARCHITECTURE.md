# Architecture

`trysac-output-moderation-hooks` provides guardrail utilities for filtering and redacting LLM text responses, both statically and in streaming mode.

## Pipeline

1. **Rule Evaluation**:
   - Regex patterns are checked against raw input.
   - Terms are checked case-insensitively with boundary checks against a normalized view (NFKC, casefold, stripped zero-width characters) and mapped back to code point offsets.
2. **Classifier Evaluation**:
   - Executed only during whole-text `check()` calls (not in streaming mode).
   - Results >= threshold trigger a synthetic `classifier:<category>` block finding.
3. **Action Precedence**:
   - `block`: Emits blocked event, returns empty string `""` or raises `BlockedOutputError` in streaming mode.
   - `redact`: Merges overlapping findings, replacing text spans with `[REDACTED:<category>]`.
   - `flag`: Preserves original text, returns `flag` action.
   - `allow`: No findings triggered.
4. **Streaming Holdback**:
   - Maintains a sliding holdback window (`holdback_chars`) so regex and term boundaries across token chunks are caught before being emitted to callers.
