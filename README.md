# emerald_utils

**emerald_utils** provides a small, stable core of cryptographic helpers, transparent AES‑GCM encrypted SQLAlchemy fields, and a minimal experimental secrets resolver suitable for Pydantic’s `BeforeValidator`. It is designed for applications that need reversible secret storage with minimal plaintext exposure and predictable operational behavior.

The package is licensed under the **MPL‑2.0**, allowing use in both open‑source and proprietary projects while keeping modifications to this library itself open.

---

## Features

### 🔐 Cryptography core
- AES‑256‑GCM encryption and decryption
- PBKDF2‑HMAC‑SHA256 key derivation (no extra dependencies)
- URL‑safe base64 encoding helpers
- Minimal, dependency‑light design

### 🧩 Encrypted fields
- `$A256GCM$keyid$base64` encrypted‑field format
- `KeyContext` for managing DK + keyid
- `encrypt_string()` and `decrypt_string()` helpers

### 🗄️ SQLAlchemy integration
- `EncryptedString` TypeDecorator
- Transparent encryption on write
- Lazy decryption on read via `LazySecret`
- Prevents accidental double‑encryption
- Centralized `set_keyctx()` initialization

### 🧪 Experimental secret resolver
Suitable for Pydantic `BeforeValidator`:

Supports:
- `env:` — environment variables (cached + scrubbed)
- `file:` — read from filesystem
- `secret:` — systemd / container secret directories
- `sqlexp:` — minimal SQL key/value store
- `$A256GCM$keyid$base64` encrypted values

Not intended to be the final vault/meta‑manager.

### 🧪 Experimental SQL backend (`sqlexp`)
- Simple key/value table using SQLAlchemy
- Stores encrypted values
- No ACLs, hierarchy, or versioning
- Intended for bootstrap use only

---

## Installation

```
pip install emerald_utils
```

Or from a source tarball:

```
pip install emerald_utils-0.1.0.tar.gz
```

---

## Quick Start

### 1. Derive a DK and initialize the encrypted field system

```python
from emerald_utils.crypto import derive_dk_from_passphrase
from emerald_utils.encrypted_fields import KeyContext
from emerald_utils.sqlalchemy.encrypted_type import EncryptedString

passphrase = resolve_secrets("env:APP_DK_PASSPHRASE")
salt = resolve_secrets("env:APP_DK_SALT").encode("utf-8")

dk = derive_dk_from_passphrase(passphrase, salt)
EncryptedString.set_keyctx(KeyContext(keyid=1, dk=dk))
```

### 2. Use encrypted fields in SQLAlchemy models

```python
from sqlalchemy import Column, Integer
from emerald_utils.sqlalchemy.encrypted_type import EncryptedString

class OAuthToken(Base):
    __tablename__ = "oauth_tokens"

    id = Column(Integer, primary_key=True)
    refresh_token = Column(EncryptedString, nullable=False)
```

### 3. Use the experimental secrets resolver with Pydantic

```python
from pydantic import BaseModel, field_validator
from emerald_utils.experimental.secrets_resolver import resolve_secret

class Config(BaseModel):
    api_token: str

    @field_validator("api_token", mode="before")
    def load_secret(cls, v):
        return resolve_secret(v, session=db_session, keyctx=global_keyctx)
```

Config example:

```
api_token = "secret:my_api_token"
```

---

## Secret Resolver Backends

### `env:VAR`
Reads from environment, caches, and scrubs the variable.

### `file:/path/to/file`
Reads a file once and caches it.

### `secret:name`
Searches:
- `$CREDENTIALS_DIRECTORY/name`
- `/run/secrets/name`
- `/var/run/secrets/name`

### `sqlexp:key`
Reads from the experimental SQL key/value store.

### `$A256GCM$keyid$base64`
Automatically decrypted using the active `KeyContext`.

---

## Experimental Components

The following modules are intentionally minimal and **will not** be part of the future vault/meta‑manager:

- `emerald_utils.experimental.secrets_resolver`
- `emerald_utils.experimental.vault_sqlexp`

They exist to support early projects (EmeraldOps, Thaum, WebexCalling bridge) without constraining the design of the full resolver.

---

## License

This project is licensed under the **Mozilla Public License 2.0 (MPL‑2.0)**.  
You may use this library in proprietary applications, but modifications to this library itself must be published under the MPL.
