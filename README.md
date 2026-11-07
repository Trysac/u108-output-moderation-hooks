# output-moderation-hooks

[![PyPI version](https://img.shields.io/pypi/v/trysac-output-moderation-hooks)](https://pypi.org/project/trysac-output-moderation-hooks/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-output-moderation-hooks)](LICENSE)
[![CI](https://github.com/Trysac/u108-output-moderation-hooks/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u108-output-moderation-hooks/actions/workflows/ci.yml)

Moderate LLM output with configurable regex and term rules, categories, block, redact and flag actions, optional classifiers and streaming holdback

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-output-moderation-hooks
# or
uv add trysac-output-moderation-hooks
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import output_moderation_hooks

# normalize() trims surrounding whitespace and lower-cases the text.
print(output_moderation_hooks.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    output_moderation_hooks.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
