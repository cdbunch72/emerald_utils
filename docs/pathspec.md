# Experimental path specifiers

The package `gemstone_utils.experimental.pathspec` expands systemd-style path
specifiers in configuration strings. It is intended for **config bootstrap**
(plain strings or Pydantic `Annotated` fields), not for inventing app directory
layouts beyond bare roots.

**Stability:** Experimental. The API and behavior may change; see the
[Experimental components](https://github.com/gemstone-software-dev/gemstone_utils#experimental-components)
section in the repository README.

Optional Pydantic types require **`gemstone_utils[pydantic]`**.

## Specifiers

Roots are **bare** (no automatic app-name suffix). Applications write
`%E/myapp/...` themselves, matching systemd.

| Token | Meaning | `PathLayout.SYSTEM` | `PathLayout.USER` |
|-------|---------|---------------------|-------------------|
| `%t` | Runtime | `/run` | `XDG_RUNTIME_DIR`, else `/run/user/<uid>`, else `/tmp/runtime-<uid>` |
| `%S` | State | `/var/lib` | `XDG_STATE_HOME` → `~/.local/state` |
| `%E` | Config | `/etc` | `XDG_CONFIG_HOME` → `~/.config` |
| `%C` | Cache | `/var/cache` | `XDG_CACHE_HOME` → `~/.cache` |
| `%D` | Data | `/usr/share` | `XDG_DATA_HOME` → `~/.local/share` |
| `%L` | Log | `/var/log` | `{state}/log` |
| `%%` | Literal `%` | | |

`%D` is a **library data root** (XDG data / `/usr/share`). It is not a systemd
unit specifier. There is no `%h` or `%d`; credentials stay on `secret:` /
`file:` via [secrets-resolver.md](secrets-resolver.md).

`PathLayout.AUTO` chooses SYSTEM when `euid == 0`, otherwise USER (snapshot at
`build_path_context` time). Classic daemons that drop privileges later should
pass `layout=PathLayout.SYSTEM` (or build once as root and reuse the context).

## Core API

```python
from gemstone_utils.experimental.pathspec import (
    PathLayout,
    build_path_context,
    expand_path_specifiers,
)

ctx = build_path_context(layout=PathLayout.SYSTEM)
expand_path_specifiers("%E/axinite/secrets", ctx)
# '/etc/axinite/secrets'
```

Programmatic overrides (CLI, tests) replace individual roots. Paths must be
absolute; `~` is rejected. Example: CLI `--config-root` → `config_dir=...`
overrides `%E` only.

There is **no TOML `[paths]` helper**. By the time a config file is loaded,
`%E` (or an explicit config path) is already known.

## Pydantic annotations

```python
from pydantic import BaseModel
from gemstone_utils.experimental.pathspec import CONTEXT_KEY, build_path_context, PathLayout
from gemstone_utils.experimental.pathspec.pydantic import ResolvedFsPath, ResolvedSecretRef

class Config(BaseModel):
    data_dir: ResolvedFsPath
    api_token: ResolvedSecretRef  # expand then resolve_secret

ctx = build_path_context(layout=PathLayout.SYSTEM, config_dir=cli_config_root)
Config.model_validate(raw, context={CONTEXT_KEY: ctx})
```

- **`ResolvedFsPath`** — expand `%…`, then require an absolute path.
- **`ResolvedSecretRef`** — expand `%…`, then `resolve_secret` (e.g.
  `file:%E/myapp/secrets/key`).
- **`path_field(secrets=False|True)`** — factory returning one of the above
  (application toggle per field).

## Suggested bootstrap (with secrets allowlist)

1. `ctx = build_path_context(...)` (optional `config_dir=` from CLI).
2. Expand allowlist prefixes, e.g. `expand_path_specifiers("%E/myapp/secrets", ctx)`.
3. `set_allowed_file_path_prefixes([...])`.
4. Validate models with `context={"paths": ctx}`.

## API notes

- **`build_path_context(...)`** — layout, injectable `environ` / `euid`, optional root overrides.
- **`expand_path_specifiers(value, ctx)`** — pure substitution; unknown `%X` or trailing `%` raises `ValueError`.
- **`PathSpecifierContext`** — frozen dataclass of six roots.
- **`CONTEXT_KEY`** — `"paths"` for Pydantic `ValidationInfo.context`.
