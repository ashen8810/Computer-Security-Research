"""Reproducible, varied synthetic plaintext generation."""

from __future__ import annotations

import random

_WORDS = (
    "amber", "archive", "cipher", "cloud", "data", "garden", "harbor",
    "island", "lantern", "machine", "meadow", "network", "ocean", "research",
    "signal", "silver", "system", "violet", "window", "winter",
)
_SENTENCES = (
    "The {word} signal crossed the quiet harbor at midnight.",
    "Researchers compare {word} samples to understand changing patterns.",
    "A small {word} machine recorded the result near the old garden.",
    "Every {word} archive preserves a different part of the story.",
)
_ALPHANUMERIC = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_SPECIALS = "!@#$%^&*()-_=+[]{};:,.?/ "


def _random_text(rng: random.Random, alphabet: str, length: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(length))


def _make_plaintext(rng: random.Random, index: int) -> str:
    kind = index % 6
    if kind == 0:
        return rng.choice(("Hi!", "OK", "Yes.", "No."))
    if kind == 1:
        return rng.choice(_SENTENCES).format(word=rng.choice(_WORDS))
    if kind == 2:
        return _random_text(rng, _ALPHANUMERIC, rng.randint(8, 40))
    if kind == 3:
        return _random_text(rng, "0123456789-+., ", rng.randint(12, 48))
    if kind == 4:
        return _random_text(rng, _ALPHANUMERIC + _SPECIALS, rng.randint(80, 240))

    sentence_count = rng.randint(4, 10)
    sentences = [
        rng.choice(_SENTENCES).format(word=rng.choice(_WORDS))
        for _ in range(sentence_count)
    ]
    return " ".join(sentences)


def generate_plaintexts(count: int, rng: random.Random | None = None) -> list[str]:
    """Return a varied plaintext pool using the supplied random generator."""
    if count < 0:
        raise ValueError("count must not be negative.")
    source = rng or random.Random()
    return [_make_plaintext(source, index) for index in range(count)]
