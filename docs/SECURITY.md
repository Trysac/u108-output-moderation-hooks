# Security

## Threat Model

### Defended
- **Data Leakage in Audits**: `on_event` callbacks and error messages never include matched text. Payloads only include `rule_id`, `category`, `action`, and character offsets.
- **Unvalidated Input**: The library enforces strict bounds: max 200 rules, 1000 terms per rule, 500 characters per regex, and a total text length capped at `max_input_chars` (default 100,000).
- **Classifier Stability**: Scores are validated against the `[0.0, 1.0]` range. Exceptions in external classifiers are caught and trigger `classifier_failed`. When `fail_open` is `False`, the system blocks instead of proceeding.

### Not Defended
- **Regex Denial of Service (ReDoS)**: Regex patterns are provided by the operator and are treated as trusted configuration. No deep analysis of pattern complexity is performed. Operators are responsible for ensuring patterns do not exhibit exponential backtracking.
