# Testing

## Running

```sh
uv run pytest --cov=output_moderation_hooks
```

## Coverage

The tests reside in `tests/test_output_moderation_hooks.py` and cover the following:

- **Acceptance Criteria**: The test suite covers the specific acceptance scenarios defined in the project specification, including rule application (`redact`, `block`, `flag`), action precedence, term normalization (NFKC, casefold, and zero-width character stripping), classifier integration and error handling, and the streaming holdback mechanism.
- **Error Handling**: Tests verify that invalid rule definitions raise `ModerationError` with appropriate codes (`invalid_rule`, `too_many_rules`, `input_too_large`), and that classifier failures raise expected exceptions when not `fail_open`.
- **Event Emission**: Tests confirm `on_event` receives correct metadata without leaking sensitive matched content.
