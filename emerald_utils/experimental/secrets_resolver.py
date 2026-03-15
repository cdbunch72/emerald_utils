# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch. All rights reserved.
# emerald_utils/experimental/secrets_resolver.py

from __future__ import annotations

import os
from functools import lru_cache

from emerald_utils.encrypted_fields import decrypt_string, is_encrypted_prefix
from emerald_utils.experimental.sqlexp import get_secret


_cache = {}


def resolve_env(varname: str) -> str:
    if varname in _cache:
        return _cache[varname]

    value = os.environ.get(varname)
    if value is None:
        raise KeyError(f"missing environment variable {varname}")

    _cache[varname] = value
    if varname in os.environ:
        del os.environ[varname]

    return value


def resolve_file(path: str) -> str:
    if path in _cache:
        return _cache[path]

    with open(path, "r", encoding="utf-8") as f:
        value = f.read().strip()

    _cache[path] = value
    return value
def resolve_secretfile(name: str) -> str:
    """
    Resolve secret:name by searching known secret directories.
    Caches the value after first read.
    """
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



def resolve_sqlexp(session, keyctx, logical_key: str) -> str | None:
    stored = get_secret(session, logical_key)
    if stored is None:
        return None
    return decrypt_string(stored, keyctx)


def resolve_secret(value: str, *, session=None, keyctx=None):
    if value.startswith("env:"):
        return resolve_env(value[4:])

    if value.startswith("file:"):
        return resolve_file(value[5:])

    if value.startswith("secret:"):
        return resolve_secretfile(value[7:])

    if value.startswith("sqlexp:"):
        if session is None or keyctx is None:
            raise RuntimeError("sqlexp: requires session and keyctx")
        return resolve_sqlexp(session, keyctx, value[7:])

    if is_encrypted_prefix(value):
        if keyctx is None:
            raise RuntimeError("encrypted field requires keyctx")
        return decrypt_string(value, keyctx)

    return value
