# Copyright 2026 Canonical Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-only
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

"""Tests for the envquote template helper.

Each case asserts exact bytes because escaping operator-supplied secrets must
not permit injection into systemd EnvironmentFile= lines.
"""

import pytest

from charmlibs.seceng.template import envquote

PEM = '-----BEGIN PRIVATE KEY-----\nMIIfoo==\n-----END PRIVATE KEY-----\n'


@pytest.mark.parametrize(
    ('value', 'expected'),
    [
        # A single quote is not special inside double quotes, so it passes
        # through verbatim. It cannot be transported inside single quotes
        # because systemd.exec(5) recognises no escape there and the quote would
        # terminate the value.
        ("a'b", "\"a'b\""),
        ('a"b', '"a\\"b"'),
        ('a\\b', '"a\\\\b"'),
        ('a$b', '"a\\$b"'),
        ('a`b', '"a\\`b"'),
        # A backslash immediately before a quote: escaping the quote first
        # would double the backslash the quote escape introduces, so the
        # backslash-first order is load-bearing.
        ('a\\"b', '"a\\\\\\"b"'),
        # A trailing backslash must become a doubled backslash, so it cannot
        # pair with a following newline into a line continuation.
        ('a\\', '"a\\\\"'),
    ],
)
def test_envquote_renders_exact_bytes(value: str, expected: str) -> None:
    assert envquote(value) == expected


def test_envquote_preserves_a_multiline_pem_value_verbatim() -> None:
    """Newlines pass through untouched: the PEM must survive byte for byte."""
    quoted = envquote(PEM)
    assert quoted == f'"{PEM}"'
    assert quoted.count('\n') == PEM.count('\n') == 3


def test_envquote_neutralises_an_injection_attempt() -> None:
    """The single-quote breakout form must produce exactly one assignment.

    Rendered into an EnvironmentFile, the value is one double-quoted string:
    the quote the attacker sent is escaped, so everything after it, including
    the newline, stays inside the value instead of starting a new KEY=VALUE
    assignment.
    """
    assert envquote('x"\nEVIL=1') == '"x\\"\nEVIL=1"'


def test_envquote_wraps_an_empty_value() -> None:
    assert envquote('') == '""'


def test_envquote_rejects_nul() -> None:
    with pytest.raises(ValueError, match='NUL'):
        envquote('before\x00after')


@pytest.mark.parametrize('value', [None, 5, True, b'x', ['x']])
def test_envquote_rejects_non_str(value: object) -> None:
    """Non-str input is a template bug, not something to stringify quietly."""
    with pytest.raises(TypeError, match='requires a str'):
        envquote(value)  # type: ignore[arg-type]
