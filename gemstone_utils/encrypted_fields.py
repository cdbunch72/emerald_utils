# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch. All rights reserved.
# gemstone_utils/encrypted_fields.py

from __future__ import annotations

import json
import warnings
from typing import Any, Dict, Optional, Tuple

from .crypto import encrypt_with_alg, decrypt_with_alg, b64encode, b64decode
from .types import KeyContext

ALG_ID = "A256GCM"  # field-level algorithm id


def is_encrypted_prefix(value: str) -> bool:
    return isinstance(value, str) and value.startswith(f"${ALG_ID}$")


def _params_json_bytes(params: Dict[str, Any]) -> bytes:
    return json.dumps(params, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _encode_params_segment(params: Dict[str, Any]) -> str:
    return b64encode(_params_json_bytes(params))


def _decode_params_segment(segment: str) -> Dict[str, Any]:
    raw = b64decode(segment)
    try:
        data = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError("invalid algorithm parameters (not valid JSON)") from e
    if not isinstance(data, dict):
        raise ValueError("algorithm parameters must be a JSON object")
    return data


def format_encrypted_field(
    keyid: int,
    blob: bytes,
    params: Optional[Dict[str, Any]] = None,
) -> str:
    p = {} if params is None else params
    return f"${ALG_ID}${keyid}${_encode_params_segment(p)}${b64encode(blob)}"


def parse_encrypted_field(value: str) -> Tuple[str, int, Dict[str, Any], bytes]:
    parts = value.split("$")
    if parts[0] != "":
        raise ValueError("invalid encrypted field format")

    if len(parts) == 4:
        warnings.warn(
            "Four-part encrypted fields (no algorithm-parameters segment) are deprecated "
            "and will be removed in gemstone_utils 0.9.0; re-encrypt or run a key rotation "
            "with gemstone_utils >= 0.3.0 to migrate.",
            DeprecationWarning,
            stacklevel=2,
        )
        alg_id = parts[1]
        keyid = int(parts[2])
        blob = b64decode(parts[3])
        return alg_id, keyid, {}, blob

    if len(parts) == 5:
        alg_id = parts[1]
        keyid = int(parts[2])
        params = _decode_params_segment(parts[3])
        blob = b64decode(parts[4])
        return alg_id, keyid, params, blob

    raise ValueError("invalid encrypted field format")


def _validate_alg_params(alg_id: str, params: Dict[str, Any]) -> None:
    if alg_id == "A256GCM" and params:
        raise ValueError(f"A256GCM does not accept algorithm parameters (got {params!r})")


def encrypt_string(plaintext: Optional[str], keyctx: KeyContext) -> Optional[str]:
    if plaintext is None:
        return None
    blob = encrypt_with_alg(keyctx.alg, keyctx.key, plaintext.encode("utf-8"))
    return format_encrypted_field(keyctx.keyid, blob, {})


def decrypt_string(value: Optional[str], keyctx: KeyContext) -> Optional[str]:
    if value is None:
        return None

    alg_id, keyid, params, blob = parse_encrypted_field(value)

    if alg_id != keyctx.alg:
        raise ValueError(f"unsupported algorithm: {alg_id}")
    if keyid != keyctx.keyid:
        raise ValueError(f"unexpected keyid {keyid}")

    _validate_alg_params(alg_id, params)

    return decrypt_with_alg(keyctx.alg, keyctx.key, blob).decode("utf-8")
