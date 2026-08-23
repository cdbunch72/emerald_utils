# SPDX-License-Identifier: MPL-2.0
# Copyright 2026,
# gemstone_utils/experimental/pathspec/__init__.py

"""Experimental systemd-style path specifier expansion.

**Stability:** Experimental. The API and behavior may change.

Specifiers (bare roots; no automatic app-name suffix)::

    %t  runtime   SYSTEM /run ; USER XDG_RUNTIME_DIR (+ fallbacks)
    %S  state     SYSTEM /var/lib ; USER XDG_STATE_HOME
    %E  config    SYSTEM /etc ; USER XDG_CONFIG_HOME
    %C  cache     SYSTEM /var/cache ; USER XDG_CACHE_HOME
    %D  data      SYSTEM /usr/share ; USER XDG_DATA_HOME
                  (library data root; not a systemd unit specifier)
    %L  log       SYSTEM /var/log ; USER {state}/log
    %%  literal percent

Credentials stay on ``secret:`` / ``file:`` via
:mod:`gemstone_utils.experimental.secrets_resolver` (no ``%d``).

Optional Pydantic Annotated types live in
:mod:`gemstone_utils.experimental.pathspec.pydantic` (requires
``gemstone_utils[pydantic]``).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Mapping, Optional, Union

__all__ = [
    "CONTEXT_KEY",
    "PathLayout",
    "PathSpecifierContext",
    "build_path_context",
    "expand_path_specifiers",
]

CONTEXT_KEY = "paths"

PathLike = Union[str, os.PathLike[str]]


class PathLayout(Enum):
    """Which directory roots to use when building a context."""

    SYSTEM = "system"
    USER = "user"
    AUTO = "auto"


@dataclass(frozen=True, slots=True)
class PathSpecifierContext:
    """Resolved bare roots for path specifier expansion.

    Attributes:
        runtime_dir: Root for ``%t``.
        state_dir: Root for ``%S``.
        config_dir: Root for ``%E``.
        cache_dir: Root for ``%C``.
        data_dir: Root for ``%D``.
        log_dir: Root for ``%L``.
    """

    runtime_dir: Path
    state_dir: Path
    config_dir: Path
    cache_dir: Path
    data_dir: Path
    log_dir: Path


def _default_euid() -> int:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None:
        return int(geteuid())
    return 0


def _path_string_has_tilde(text: str) -> bool:
    return text.startswith("~") or "/~" in text.replace("\\", "/")


def _is_absolute_path(path: Path, text: str) -> bool:
    """True for native absolute paths or POSIX-style roots (leading ``/``).

    systemd-style roots such as ``/etc`` must be accepted even when running
    tests on Windows, where :meth:`pathlib.Path.is_absolute` is False for them.
    """
    return path.is_absolute() or text.startswith("/")


def _normalize_root_path(value: PathLike, *, label: str) -> Path:
    text = os.fspath(value)
    if not text:
        raise ValueError(f"{label} must not be empty")
    if _path_string_has_tilde(text):
        raise ValueError(f"{label} must not use ~")
    path = Path(text)
    if not _is_absolute_path(path, text):
        raise ValueError(f"{label} must be absolute: {text!r}")
    return path


def _xdg_or_home(
    environ: Mapping[str, str],
    var: str,
    home_relative: str,
) -> Path:
    raw = environ.get(var)
    if raw:
        return Path(raw)
    return Path.home() / home_relative


def _user_runtime_dir(environ: Mapping[str, str], euid: int) -> Path:
    raw = environ.get("XDG_RUNTIME_DIR")
    if raw:
        return Path(raw)
    run_user = Path(f"/run/user/{euid}")
    if run_user.is_dir():
        return run_user
    return Path(f"/tmp/runtime-{euid}")


def _resolve_layout(
    layout: PathLayout,
    *,
    euid: int,
) -> PathLayout:
    if layout is PathLayout.AUTO:
        return PathLayout.SYSTEM if euid == 0 else PathLayout.USER
    return layout


def _system_roots() -> dict[str, Path]:
    return {
        "runtime_dir": Path("/run"),
        "state_dir": Path("/var/lib"),
        "config_dir": Path("/etc"),
        "cache_dir": Path("/var/cache"),
        "data_dir": Path("/usr/share"),
        "log_dir": Path("/var/log"),
    }


def _user_roots(environ: Mapping[str, str], euid: int) -> dict[str, Path]:
    state = _xdg_or_home(environ, "XDG_STATE_HOME", ".local/state")
    return {
        "runtime_dir": _user_runtime_dir(environ, euid),
        "state_dir": state,
        "config_dir": _xdg_or_home(environ, "XDG_CONFIG_HOME", ".config"),
        "cache_dir": _xdg_or_home(environ, "XDG_CACHE_HOME", ".cache"),
        "data_dir": _xdg_or_home(environ, "XDG_DATA_HOME", ".local/share"),
        "log_dir": state / "log",
    }


def build_path_context(
    *,
    layout: PathLayout = PathLayout.AUTO,
    environ: Optional[Mapping[str, str]] = None,
    euid: Optional[int] = None,
    runtime_dir: Optional[PathLike] = None,
    state_dir: Optional[PathLike] = None,
    config_dir: Optional[PathLike] = None,
    cache_dir: Optional[PathLike] = None,
    data_dir: Optional[PathLike] = None,
    log_dir: Optional[PathLike] = None,
) -> PathSpecifierContext:
    """Build a :class:`PathSpecifierContext` from layout, env, and overrides.

    Classic daemons that start as root and later drop privileges should pass
    ``layout=PathLayout.SYSTEM`` (or build once as root and reuse the context).
    ``AUTO`` snapshots ``euid`` at call time only.

    Programmatic overrides (CLI, tests) replace individual roots. Paths must be
    absolute; ``~`` is rejected. There is no TOML ``[paths]`` helper — by the
    time config is loaded, ``%E`` or an explicit config path is already known.

    Args:
        layout: ``SYSTEM``, ``USER``, or ``AUTO`` (root → system, else user).
        environ: Environment mapping (default ``os.environ``).
        euid: Effective uid for ``AUTO`` and user runtime fallbacks.
        runtime_dir: Override for ``%t``.
        state_dir: Override for ``%S``.
        config_dir: Override for ``%E`` (e.g. CLI ``--config-root``).
        cache_dir: Override for ``%C``.
        data_dir: Override for ``%D``.
        log_dir: Override for ``%L``.

    Returns:
        Frozen context with bare roots (no app-name suffix).

    Raises:
        ValueError: If an override is empty, relative, or contains ``~``.
    """
    env = environ if environ is not None else os.environ
    uid = euid if euid is not None else _default_euid()
    resolved = _resolve_layout(layout, euid=uid)

    if resolved is PathLayout.SYSTEM:
        roots = _system_roots()
    else:
        roots = _user_roots(env, uid)

    overrides = {
        "runtime_dir": runtime_dir,
        "state_dir": state_dir,
        "config_dir": config_dir,
        "cache_dir": cache_dir,
        "data_dir": data_dir,
        "log_dir": log_dir,
    }
    for key, value in overrides.items():
        if value is not None:
            roots[key] = _normalize_root_path(value, label=key)

    return PathSpecifierContext(**roots)


_SPECIFIER_ATTRS: dict[str, str] = {
    "t": "runtime_dir",
    "S": "state_dir",
    "E": "config_dir",
    "C": "cache_dir",
    "D": "data_dir",
    "L": "log_dir",
}


def expand_path_specifiers(value: str, ctx: PathSpecifierContext) -> str:
    """Expand ``%t``, ``%S``, ``%E``, ``%C``, ``%D``, ``%L``, and ``%%`` in ``value``.

    Roots are inserted as POSIX strings without a forced trailing slash.
    Paths need not exist; symlinks are not resolved.

    Args:
        value: Input string that may contain path specifiers.
        ctx: Context from :func:`build_path_context`.

    Returns:
        Expanded string.

    Raises:
        ValueError: Unknown specifier or trailing lone ``%``.
    """
    out: list[str] = []
    i = 0
    n = len(value)
    while i < n:
        ch = value[i]
        if ch != "%":
            out.append(ch)
            i += 1
            continue
        if i + 1 >= n:
            raise ValueError("trailing '%' in path specifier string")
        code = value[i + 1]
        if code == "%":
            out.append("%")
            i += 2
            continue
        attr = _SPECIFIER_ATTRS.get(code)
        if attr is None:
            raise ValueError(f"unknown path specifier %{code}")
        root: Path = getattr(ctx, attr)
        out.append(_root_posix(root))
        i += 2
    return "".join(out)


def _root_posix(root: Path) -> str:
    text = os.fspath(root)
    if text.startswith("/") or text.startswith("\\"):
        return text.replace("\\", "/")
    return root.as_posix()
