# Project record

## Objective

Moderate LLM output with configurable regex and term rules, categories, block, redact and flag actions, optional classifiers and streaming holdback.

## Scope

- In scope: Implementation of rule-based moderation (regex and terms) with action precedence, support for external classifiers via `ClassifierPort`, and stream processing with a configurable holdback window. Support for rule loading via `load_rules`.
- Out of scope: The library does not include bundled category taxonomies or word lists, it does not perform input moderation, nor does it detect prompt injection. It does not perform classifier evaluation during stream mode.

## Factory run u108 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | gemini-3.8-flash | yes | 4286 | 11975 | 0 | 0 | 0.0241 |
| fix-1 | gemini-3.8-flash | no | 96919 | 1981 | 0 | 784724 | 0.1390 |
| fix-2 | gemini-3.8-flash | no | 27236 | 334 | 0 | 47409 | 0.0252 |
| audit | gemini-3.1-flash-lite | no | 47528 | 502 | 0 | 148804 | 0.0164 |
| docs | gemini-3.1-flash-lite | no | 144695 | 1253 | 0 | 0 | 0.0381 |

Total: $0.2427. Prices: Anthropic list prices.
