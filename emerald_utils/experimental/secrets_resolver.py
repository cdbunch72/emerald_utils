# SPDX-License-Identifier: MPL-2.0
# Copyright 2026,
# emerald_utils/experimental/secrets_resolver.py

from __future__ import annotations

import os
from functools import lru_cache
from typing import Callable, Optional

from emerald_utils.encrypted_fields import (
    decrypt_string,
    is_encrypted_prefix,
    parse_encrypted_field,
    KeyContext,
)
from emerald_utils.experimental.sqlexp import get_secret


# ---------------------------------------------------------------------------
# Global cache + keyctx resolver
# ---------------------------------------------------------------------------

_cache = {}

_keyctx_resolver: Optional[Callable[[int], KeyContext]] = None


def set_keyctx_resolver(func: Callable[[int], KeyContext]) -> None:
    """
    Register a resolver that, given a keyid, returns the correct KeyContext.
    The application must call this at startup.
    """
    global _keyctx_resolver
    _keyctx_resolver = func


def _resolve_keyctx_for_ciphertext(value: str) -> KeyContext:
    if _keyctx_resolver is None:
        raise RuntimeError("set_keyctx_resolver(...) must be called before resolving encrypted secrets")

    _, keyid, _ = parse_encrypted_field(value)
    return _keyctx_resolver(keyid)


# ---------------------------------------------------------------------------
# env:
# ---------------------------------------------------------------------------

def resolve_env(varname: str) -> str:
    if varname in _cache:
        return _cache[varname]

    value = os.environ.get(varname)
    if value is None:
        raise KeyError(f"missing environment variable {varname}")

    _cache[varname] = value

    # scrub environment variable after first read
    if varname in os.environ:
        del os.environ[varname]

    return value


# ---------------------------------------------------------------------------
# file:
# ---------------------------------------------------------------------------

def resolve_file(path: str) -> str:
    if path in _cache:
        return _cache[path]

    with open(path, "r", encoding="utf-8") as f:
        value = f.read().strip()

    _cache[path] = value
    return value


# ---------------------------------------------------------------------------
# secret:
# ---------------------------------------------------------------------------

def resolve_secretfile(name: str) -> str:
    if name in _cache:
        return _cache[name]

    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")

    search_paths = [
        os.path.join(cred_dir, name) if cred_dir else None,
        f"/run/secrets/{name}",
        f"/var/run/secrets/{name}",
    ]

    for path in search_paths:
        if not path:
            continue
        try:
            value = resolve_file(path)
            _cache[name] = value
            return value
        except FileNotFoundError:
            continue

    raise FileNotFoundError(f"secret '{name}' not found in known secret directories")


# ---------------------------------------------------------------------------
# sqlexp:
# ---------------------------------------------------------------------------

def resolve_sqlexp(session, logical_key: str) -> str | None:
    stored = get_secret(session, logical_key)
    if stored is None:
        return None

    if is_encrypted_prefix(stored):
        keyctx = _resolve_keyctx_for_ciphertext(stored)
        return decrypt_string(stored, keyctx)

    return stored


# ---------------------------------------------------------------------------
# main dispatcher
# ---------------------------------------------------------------------------

def resolve_secret(value: str, *, session=None):
    """
    Resolve a secret reference:
      - env:VAR
      - file:/path
      - secret:name
      - sqlexp:key
      - encrypted field
      - literal string
    """
    if value.startswith("env:"):
        return resolve_env(value[4:])

    if value.startswith("file:"):
        return resolve_file(value[5:])

    if value.startswith("secret:"):
        return resolve_secretfile(value[7:])

    if value.startswith("sqlexp:"):
        if session is None:
            raise RuntimeError("sqlexp: requires a SQLAlchemy session")
        return resolve_sqlexp(session, value[7:])

    if is_encrypted_prefix(value):
        keyctx = _resolve_keyctx_for_ciphertext(value)
        return decrypt_string(value, keyctx)

    return value
