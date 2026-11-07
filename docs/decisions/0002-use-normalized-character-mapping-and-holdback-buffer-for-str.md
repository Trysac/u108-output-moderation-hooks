# Use Normalized Character Mapping and Holdback Buffer for Stream Moderation

Status: accepted (generated, pending human review)

## Context

LLM output moderation requires exact unicode offset tracking while tolerating adversarial obfuscation (such as zero-width spaces and varied unicode casing) as well as cross-chunk token boundaries in streaming responses.

## Decision

Implement term matching using per-character NFKC normalization and zero-width code point stripping with a reverse index mapping to original code point offsets. Streaming maintains a configurable holdback window to catch split tokens without running classifiers per-chunk.

## Consequences

Maintains zero external dependencies, guarantees accurate byte and code point offsets for overlapping redactions, and provides streaming safety with predictable latency.
