# SPDX-License-Identifier: MPL-2.0
# Copyright 2026,
# gemstone_utils/experimental/pathspec/pydantic.py

"""Optional Pydantic Annotated types for path specifier expansion.

Requires ``gemstone_utils[pydantic]`` (Pydantic v2).

Pass a :class:`~gemstone_utils.experimental.pathspec.PathSpecifierContext`
via ``model_validate(..., context={"paths": ctx})`` (see
:data:`~gemstone_utils.experimental.pathspec.CONTEXT_KEY`).

Application toggle: use :data:`ResolvedFsPath` for plain filesystem paths, or
:data:`ResolvedSecretRef` / ``path_field(secrets=True)`` to expand then
:func:`~gemstone_utils.experimental.secrets_resolver.resolve_secret`
(e.g. ``file:%E/myapp/secrets/key``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

from pydantic import AfterValidator, BeforeValidator, ValidationInfo

from gemstone_utils.experimental.pathspec import (
    CONTEXT_KEY,
    PathSpecifierContext,
    expand_path_specifiers,
)
from gemstone_utils.experimental.secrets_resolver import resolve_secret

__all__ = [
    "ResolvedFsPath",
    "ResolvedSecretRef",
    "path_field",
]


def _require_context(info: ValidationInfo) -> PathSpecifierContext:
    ctx_map = info.context
    if not ctx_map or CONTEXT_KEY not in ctx_map:
        raise ValueError(
            f"missing ValidationInfo.context[{CONTEXT_KEY!r}] "
            "(PathSpecifierContext from build_path_context)"
        )
    ctx = ctx_map[CONTEXT_KEY]
    if not isinstance(ctx, PathSpecifierContext):
        raise TypeError(
            f"context[{CONTEXT_KEY!r}] must be PathSpecifierContext, "
            f"got {type(ctx).__name__}"
        )
    return ctx


def _expand_paths(value: Any, info: ValidationInfo) -> Any:
    if not isinstance(value, str):
        return value
    return expand_path_specifiers(value, _require_context(info))


def _require_absolute(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    path = Path(value)
    # Accept POSIX absolute paths on Windows (leading /) for systemd-style roots.
    if not (path.is_absolute() or value.startswith("/")):
        raise ValueError(f"path must be absolute after expansion: {value!r}")
    if value.startswith("/"):
        return value.replace("\\", "/")
    return path.as_posix()


def _resolve_secret_ref(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    return resolve_secret(value)


ResolvedFsPath = Annotated[
    str,
    BeforeValidator(_expand_paths),
    AfterValidator(_require_absolute),
]
"""Expand path specifiers, then require an absolute filesystem path."""

ResolvedSecretRef = Annotated[
    str,
    BeforeValidator(_resolve_secret_ref),
    BeforeValidator(_expand_paths),
]
"""Expand path specifiers, then resolve ``file:`` / ``secret:`` / ``env:`` refs.

BeforeValidators run last-declared first, so ``_expand_paths`` runs before
``_resolve_secret_ref``.
"""


def path_field(*, secrets: bool = False) -> Any:
    """Return :data:`ResolvedSecretRef` if ``secrets`` else :data:`ResolvedFsPath`.

    Args:
        secrets: When ``True``, expand then :func:`resolve_secret`.

    Returns:
        The corresponding ``Annotated`` type alias.
    """
    return ResolvedSecretRef if secrets else ResolvedFsPath
