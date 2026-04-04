# gemstone_utils release notes

## Pre-release naming (gemstone_utils)

Pre-release versions follow **[PEP 440](https://packaging.python.org/en/latest/specifications/version-specifiers/)** ordering (`dev` &lt; `a` &lt; `b` &lt; `rc` &lt; final). For **this project**, the qualifiers mean:

- **`dev` (e.g. `0.3.0.dev0`):** Development on the main integration line; not a promise that every commit is green. Intended for contributors and early git installs, not as a stability guarantee.
- **`a` (alpha, e.g. `0.3.0a1`):** New features and API changes are still allowed. The tree is expected to **build**, and **happy-path tests** pass under normal CI conditions—not a promise of production readiness.
- **`b` (beta, e.g. `0.3.0b1`):** **API stable** for that line; suitable for **real-world integration** testing and feedback. Further changes should be fixes and polish, not redesign.
- **`rc` (release candidate, e.g. `0.3.0rc1`):** Treated as **release-ready** pending last checks; **feature freeze** except for regressions, docs, and blockers. If nothing new surfaces, the final release matches the RC artifact.

**Releases before 1.0** may skip stages (for example a minor may go straight from `0.2.x` to `0.3.0` without publishing an alpha or beta) when the change set is small.

---

## v0.3.0.dev0 (in development)

**Tag:** *(not yet published)*  
**PyPI:** install from a git checkout or sdist built locally; version string is `0.3.0.dev0`.

### Overview

Development toward **v0.3.0**. This entry is updated incrementally until the stable `v0.3.0` release.

### Encrypted field wire format (incremental)

- **New canonical form (five `$`-separated segments):** `$A256GCM$<keyid>$<params_b64>$<blob_b64>`.
  - `<params_b64>` is URL-safe base64 (same alphabet as the ciphertext segment) of **UTF-8 JSON** encoding a single **JSON object** of algorithm parameters. For **`A256GCM`** today, writers emit **`{}`** (empty object). The segment is reserved for future algorithms or optional nonce/AAD-style metadata without changing the overall framing.
  - `<blob_b64>` is unchanged from v0.2.x: the opaque ciphertext blob produced by `encrypt_with_alg` (for `A256GCM`, nonce + ciphertext as today).
- **Legacy four-part strings** (`$A256GCM$<keyid>$<blob_b64>`) are still **accepted** for decrypt and for parsing; reading them emits a **`DeprecationWarning`**. They are **deprecated** in v0.3.x and **scheduled for removal in v0.9.0** (before **1.0**). New writes use the five-part form only.
- **Migration:** Re-encrypting stored fields during a **key rotation** on gemstone_utils **≥ 0.3.0** replaces legacy strings with the new form.

### API changes (incremental)

- **`parse_encrypted_field(value)`** now returns a **4-tuple** `(alg_id, keyid, params, blob)` where `params` is a `dict` (empty for legacy four-part values).

### Requirements

Unchanged from v0.2.1 unless noted later in this section.

---

## v0.2.1 (latest stable)

**Tag:** `v0.2.1`

### Overview

This release **renames the distribution and Python package** from `emerald_utils` to **`gemstone_utils`** (top-level package directory and `pip install` name). Behavior and public APIs are otherwise unchanged from v0.2.0; this is a branding and clarity update.

The project homepage URL is [github.com/cdbunch72/gemstone_utils](https://github.com/cdbunch72/gemstone_utils). If your Git remote or older docs still reference `emerald_utils`, update them when you migrate.

### Highlights

- **Breaking — package name:** PyPI/install name is **`gemstone_utils`**; import paths use the **`gemstone_utils`** package (for example `gemstone_utils.types`, `gemstone_utils.crypto`).
- **Optional extras:** Use `pip install 'gemstone_utils[azure]'` instead of `emerald_utils[azure]`.

### Migration notes (from v0.2.0 / `emerald_utils`)

1. `pip uninstall emerald_utils` (if installed) and `pip install gemstone_utils` (pin `gemstone_utils==0.2.1` if you want an exact version).
2. Replace import prefixes `emerald_utils` → `gemstone_utils` across your codebase (including experimental subpackages).
3. Update dependency declarations (for example `pyproject.toml` / `requirements.txt`) from `emerald_utils` to `gemstone_utils`.

Encrypted data, `KeyContext`, and SQLAlchemy column behavior are unchanged; only names and install targets move.

### Requirements

- Python ≥ 3.10  
- Core: `cryptography` ≥ 41, `sqlalchemy` ≥ 2.0  
- Optional: `pip install 'gemstone_utils[azure]'` for Key Vault

### Installation

```bash
pip install gemstone_utils
```

Or from a GitHub release asset (after you publish `v0.2.1`):

```bash
pip install https://github.com/cdbunch72/gemstone_utils/releases/download/v0.2.1/gemstone_utils-0.2.1.tar.gz
```

If the GitHub repository slug is still `emerald_utils`, use `.../emerald_utils/releases/download/...` and the matching sdist filename until the repo is renamed.

### License

[Mozilla Public License 2.0 (MPL-2.0)](LICENSE)

---

## v0.2.0

**Tag:** `v0.2.0`  
**PyPI / import name (that release):** `emerald_utils` — use **v0.2.1+** (`gemstone_utils`) for the renamed package.

### Overview

This release extends **emerald_utils** with key rotation–friendly SQLAlchemy APIs, shared types for keys and records, a small database bootstrap layer, optional Azure Key Vault resolution, pluggable secret backends, and SQL-backed leader election. Crypto gains algorithm-dispatch helpers for future symmetric algorithms; PBKDF2 derivation is renamed for accuracy (KEK vs data key).

Stable areas remain **crypto**, **encrypted fields**, and **SQLAlchemy** integration. Experimental modules are still minimal and not the final vault design.

### Highlights

- **Breaking — `KeyContext`:** Moved to `emerald_utils.types`. Fields are now `keyid`, `key`, and optional `alg` (default `"A256GCM"`). The former `dk` field is **`key`**.
- **Breaking — KDF helper:** `derive_dk_from_passphrase` in `emerald_utils.crypto` is renamed to **`derive_kek_from_passphrase`**.
- **Breaking — `EncryptedString`:** Replaces `set_keyctx()` with **`set_current_keyctx()`** for the active write key and **`set_keyctx_resolver(callable)`** to resolve the correct `KeyContext` per stored `keyid` on read (supports rotation and multiple keys).
- **Crypto:** `encrypt_with_alg` / `decrypt_with_alg` for JWA-style symmetric dispatch (currently `A256GCM`); fixes that blocked correct key rotation behavior.
- **`KeyRecord`:** New type in `emerald_utils.types` for encrypted key material (`keyid`, `alg`, `encrypted_key`).
- **`key_mgmt`:** KEK verification (`KEKVerificationError`), KDF registry (`register_kdf`, `derive_kek`), wrap/unwrap, and helpers to build `KeyContext` from stored records (replaces the old `dk.py` direction).
- **`emerald_utils.db`:** Central DB setup with **dynamic schema registration** so modules and plugins can attach their own SQLAlchemy metadata.
- **`emerald_utils.election`:** Optional SQL-backed **leader election** (candidates, heartbeats, leases, namespaces).
- **Experimental — `azexp:`:** Azure Key Vault URLs via `emerald_utils.experimental.azexp_backend`; install **`emerald_utils[azure]`** (`azure-identity`, `azure-keyvault-secrets`).
- **Experimental — `secrets_resolver`:** Pluggable backends with register/unregister; caching refined for env, file, and secret sources; README updated for current backend usage.
- **`sqlexp` / `sqlexp_backend`:** Fixes for handling older keys; backend wiring updates for the new DB and resolver patterns.

### Migration notes (from v0.1.0)

1. Import `KeyContext` from `emerald_utils.types` (not `encrypted_fields`). Replace `keyctx.dk` with `keyctx.key`; set `alg` if you need a non-default algorithm.
2. Replace `derive_dk_from_passphrase(...)` with `derive_kek_from_passphrase(...)`.
3. Replace `EncryptedString.set_keyctx(ctx)` with `EncryptedString.set_current_keyctx(ctx)` and implement `EncryptedString.set_keyctx_resolver(lambda keyid: ...)` so reads can decrypt rows written with other key IDs.

### Requirements

- Python ≥ 3.10  
- Core: `cryptography` ≥ 41, `sqlalchemy` ≥ 2.0  
- Optional: `pip install 'emerald_utils[azure]'` for Key Vault

### Installation

```bash
pip install emerald_utils
```

Or from a GitHub release asset (after you publish `v0.2.0`):

```bash
pip install https://github.com/cdbunch72/emerald_utils/releases/download/v0.2.0/emerald_utils-0.2.0.tar.gz
```

### License

[Mozilla Public License 2.0 (MPL-2.0)](LICENSE)

---

## v0.1.0

**Tag:** [`v0.1.0`](https://github.com/cdbunch72/emerald_utils/releases/tag/v0.1.0)  
**Commit:** `271bd51`  
**Released:** 15 Mar 2026 (per [GitHub release](https://github.com/cdbunch72/emerald_utils/releases/tag/v0.1.0))

### Overview

First public version of **emerald_utils**: a small, dependency-light utility library with AES-GCM helpers, PBKDF2 key derivation, a standard encrypted-field format, transparent SQLAlchemy encrypted columns, and an experimental secret resolver plus minimal SQL backend.

Stable components (crypto, encrypted fields, SQLAlchemy) are intended for long-term use. Experimental pieces are intentionally minimal and not part of the future vault/meta-manager.

### Included artifacts

- Source distribution (`emerald_utils-<version>.tar.gz`) — `pip install <url>`
- Wheel (`emerald_utils-<version>-py3-none-any.whl`)

### Installation

```bash
pip install https://github.com/cdbunch72/emerald_utils/releases/download/v0.1.0/emerald_utils-0.1.0.tar.gz
```

Or from a clone:

```bash
pip install .
```

### Highlights

#### Cryptography

- AES-256-GCM encryption and decryption  
- PBKDF2-HMAC-SHA256 key derivation  
- URL-safe base64 helpers  

#### Encrypted fields

- `$A256GCM$keyid$base64` format  
- `KeyContext` for data key + keyid  
- `encrypt_string()` / `decrypt_string()`  

#### SQLAlchemy integration

- `EncryptedString` TypeDecorator  
- Lazy decryption via `LazySecret`  
- Prevents double-encryption  
- Central `set_keyctx()` initialization  

#### Experimental secret resolver

Supports:

- `env:`  
- `file:`  
- `secret:` (systemd + container orchestrators)  
- `sqlexp:`  
- Encrypted values  

#### Experimental SQL backend (`sqlexp`)

- Simple key/value table  
- Stores encrypted values  
- Intended for bootstrap use only  

### License

Mozilla Public License 2.0 (MPL-2.0). You may use this library in proprietary applications; modifications to this library must remain MPL-licensed.
