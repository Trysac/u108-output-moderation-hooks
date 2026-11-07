"""Behavior tests for the public API of output_moderation_hooks."""

from __future__ import annotations

import pytest

import output_moderation_hooks


def test_normalize_trims_and_lowercases() -> None:
    assert output_moderation_hooks.normalize("  Hello World ") == "hello world"


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_normalize_rejects_blank_input(value: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        output_moderation_hooks.normalize(value)


def test_version_is_semver() -> None:
    parts = output_moderation_hooks.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
