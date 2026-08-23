# SPDX-License-Identifier: MPL-2.0

from pathlib import Path

import pytest

from gemstone_utils.experimental.pathspec import (
    CONTEXT_KEY,
    PathLayout,
    build_path_context,
    expand_path_specifiers,
)
import gemstone_utils.experimental.secrets_resolver as secrets_resolver
from gemstone_utils.experimental.secrets_resolver import set_allowed_file_path_prefixes


@pytest.fixture(autouse=True)
def _reset_resolver_state():
    secrets_resolver._file_path_prefixes = None
    secrets_resolver._strict_prefix_dispatch = False
    secrets_resolver._cache.clear()
    yield
    secrets_resolver._file_path_prefixes = None
    secrets_resolver._strict_prefix_dispatch = False
    secrets_resolver._cache.clear()


def test_system_layout_roots():
    ctx = build_path_context(layout=PathLayout.SYSTEM, euid=0)
    assert ctx.runtime_dir == Path("/run")
    assert ctx.state_dir == Path("/var/lib")
    assert ctx.config_dir == Path("/etc")
    assert ctx.cache_dir == Path("/var/cache")
    assert ctx.data_dir == Path("/usr/share")
    assert ctx.log_dir == Path("/var/log")


def test_user_layout_xdg_and_fallbacks(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))

    env = {
        "XDG_RUNTIME_DIR": "/run/user/1000",
        "XDG_STATE_HOME": str(tmp_path / "state"),
        "XDG_CONFIG_HOME": str(tmp_path / "config"),
        "XDG_CACHE_HOME": str(tmp_path / "cache"),
        "XDG_DATA_HOME": str(tmp_path / "data"),
    }
    ctx = build_path_context(layout=PathLayout.USER, environ=env, euid=1000)
    assert ctx.runtime_dir == Path("/run/user/1000")
    assert ctx.state_dir == tmp_path / "state"
    assert ctx.config_dir == tmp_path / "config"
    assert ctx.cache_dir == tmp_path / "cache"
    assert ctx.data_dir == tmp_path / "data"
    assert ctx.log_dir == tmp_path / "state" / "log"


def test_user_layout_home_fallbacks(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))

    ctx = build_path_context(layout=PathLayout.USER, environ={}, euid=1000)
    assert ctx.runtime_dir == Path("/tmp/runtime-1000")
    assert ctx.state_dir == home / ".local" / "state"
    assert ctx.config_dir == home / ".config"
    assert ctx.cache_dir == home / ".cache"
    assert ctx.data_dir == home / ".local" / "share"
    assert ctx.log_dir == home / ".local" / "state" / "log"


def test_auto_layout_uses_euid():
    sys_ctx = build_path_context(layout=PathLayout.AUTO, euid=0)
    assert sys_ctx.config_dir == Path("/etc")
    user_ctx = build_path_context(layout=PathLayout.AUTO, euid=1000, environ={})
    assert user_ctx.config_dir != Path("/etc")


def test_expand_all_specifiers_and_percent():
    ctx = build_path_context(layout=PathLayout.SYSTEM)
    # Joining two absolute roots with '/' yields a double slash (literal expand).
    assert expand_path_specifiers("%t/%S/%E/%C/%D/%L/%%done", ctx) == (
        "/run//var/lib//etc//var/cache//usr/share//var/log/%done"
    )
    assert expand_path_specifiers("%E/axinite/foo", ctx) == "/etc/axinite/foo"


def test_expand_unknown_and_trailing_percent():
    ctx = build_path_context(layout=PathLayout.SYSTEM)
    with pytest.raises(ValueError, match="unknown path specifier"):
        expand_path_specifiers("%h/x", ctx)
    with pytest.raises(ValueError, match="trailing"):
        expand_path_specifiers("foo%", ctx)


def test_config_dir_override_only_changes_e():
    ctx = build_path_context(
        layout=PathLayout.SYSTEM,
        config_dir="/opt/cfg",
    )
    assert expand_path_specifiers("%E/app", ctx) == "/opt/cfg/app"
    assert expand_path_specifiers("%t", ctx) == "/run"
    assert expand_path_specifiers("%S", ctx) == "/var/lib"


def test_override_rejects_relative_and_tilde():
    with pytest.raises(ValueError, match="absolute"):
        build_path_context(layout=PathLayout.SYSTEM, config_dir="relative")
    with pytest.raises(ValueError, match="~"):
        build_path_context(layout=PathLayout.SYSTEM, runtime_dir="~/run")


def test_other_root_overrides():
    ctx = build_path_context(
        layout=PathLayout.SYSTEM,
        runtime_dir="/custom/run",
        state_dir="/custom/state",
        cache_dir="/custom/cache",
        data_dir="/custom/data",
        log_dir="/custom/log",
    )
    assert expand_path_specifiers("%t%S%C%D%L", ctx) == (
        "/custom/run/custom/state/custom/cache/custom/data/custom/log"
    )


@pytest.fixture
def _pydantic():
    return pytest.importorskip("pydantic")


def test_pydantic_resolved_fs_path(_pydantic):
    from pydantic import BaseModel, ValidationError

    from gemstone_utils.experimental.pathspec.pydantic import ResolvedFsPath

    class FsModel(BaseModel):
        path: ResolvedFsPath

    ctx = build_path_context(layout=PathLayout.SYSTEM)
    m = FsModel.model_validate(
        {"path": "%E/axinite/data"},
        context={CONTEXT_KEY: ctx},
    )
    assert m.path == "/etc/axinite/data"

    with pytest.raises(ValidationError):
        FsModel.model_validate({"path": "relative"}, context={CONTEXT_KEY: ctx})
    with pytest.raises(ValidationError):
        FsModel.model_validate({"path": "%E/x"})


def test_pydantic_resolved_secret_ref_file(tmp_path, _pydantic):
    from pydantic import BaseModel

    from gemstone_utils.experimental.pathspec.pydantic import ResolvedSecretRef

    class SecretModel(BaseModel):
        secret: ResolvedSecretRef

    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "key").write_text("hunter2\n", encoding="utf-8")
    set_allowed_file_path_prefixes([secrets_dir])

    ctx = build_path_context(layout=PathLayout.SYSTEM, config_dir=tmp_path)
    m = SecretModel.model_validate(
        {"secret": "file:%E/secrets/key"},
        context={CONTEXT_KEY: ctx},
    )
    assert m.secret == "hunter2"


def test_path_field_factory(_pydantic):
    from pydantic import BaseModel

    from gemstone_utils.experimental.pathspec.pydantic import path_field

    class ToggleModel(BaseModel):
        path: path_field(secrets=False)
        secret: path_field(secrets=True)

    ctx = build_path_context(layout=PathLayout.SYSTEM, config_dir="/cfg")
    m = ToggleModel.model_validate(
        {"path": "%E/data", "secret": "literal:plain"},
        context={CONTEXT_KEY: ctx},
    )
    assert m.path == "/cfg/data"
    assert m.secret == "plain"
