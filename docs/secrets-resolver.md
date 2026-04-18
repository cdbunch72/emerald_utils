# Experimental secrets resolver

The module `gemstone_utils.experimental.secrets_resolver` resolves string references to secret values (environment, files, container secret mounts, and optional plugins). It is intended for **configuration bootstrap** (for example Pydantic `BeforeValidator`), not as a full secrets manager.

**Stability:** Experimental. The API and behavior may change; see [README.md](../README.md#experimental-components).

## Schemes

| Prefix | Behavior |
|--------|----------|
| `env:VAR` | Read `os.environ[VAR]`, cache, then **delete** the variable from the environment (scrub). |
| `file:/path` | Read UTF-8 file once, strip, cache. |
| `secret:name` | Search `CREDENTIALS_DIRECTORY`, `/run/secrets/`, `/var/run/secrets/` (via `resolve_file`). |
| `azexp:https://...` | Optional Azure Key Vault — import `gemstone_utils.experimental.azexp_backend`; requires `gemstone_utils[azure]`. |

Unknown prefixes can be registered with `register_backend(prefix, resolver, ...)`.

## Encrypted wire values (`$A256GCM$...`)

If the resolved string looks like an encrypted field (`is_encrypted_prefix`), it is decrypted with **`decrypt_string`** after resolving a `KeyContext` via **`set_keyctx_resolver`**.

- Segment 2 of the wire is a **canonical UUID string** (logical key id), same as `EncryptedString` column ciphertext.
- **`secrets_resolver.set_keyctx_resolver`** is **separate** from **`EncryptedString.set_keyctx_resolver`**. If you use both encrypted config values and encrypted columns, register both (often with the same underlying lookup).

## API notes

- **`set_keyctx_resolver(func: Callable[[str], KeyContext])`** — must be called before resolving encrypted secrets.
- **`resolve_secret(value: str) -> str`** — dispatches on prefix or decrypts encrypted blobs.

## Operational caveats

- **`env:` scrubbing** removes variables after first read; behavior is process-global.
- **Caching** applies to env, file, and secret paths; treat the process as holding secrets in memory.
- **Plugin** `azexp` is optional and must be explicitly imported to register.

For backend-specific details, see [README.md](../README.md#secret-resolver-backends).
