# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026, Clinton Bunch.  All rights reserved.
# emerald_utils/encrypted_fields.py

from __future__ import annotations

from dataclasses import dataclass

from .crypto import aesgcm_encrypt, aesgcm_decrypt, b64encode, b64decode

ALG_ID = "A256GCM"


def is_encrypted_prefix(value: str) -> bool:
    return isinstance(value, str) and value.startswith(f"${ALG_ID}$")


def format_encrypted_field(keyid: int, blob: bytes) -> str:
    return f"${ALG_ID}${keyid}${b64encode(blob)}"


def parse_encrypted_field(value: str) -> tuple[str, int, bytes]:
    parts = value.split("$")
    if len(parts) != 4 or parts[0] != "":
        raise ValueError("invalid encrypted field format")

    alg_id = parts[1]
    keyid = int(parts[2])
    blob = b64decode(parts[3])
    return alg_id, keyid, blob


@dataclass
class KeyContext:
    keyid: int
    dk: bytes


def encrypt_string(plaintext: str | None, keyctx: KeyContext) -> str | None:
    if plaintext is None:
        return None
    blob = aesgcm_encrypt(keyctx.dk, plaintext.encode("utf-8"))
    return format_encrypted_field(keyctx.keyid, blob)


def decrypt_string(value: str | None, keyctx: KeyContext) -> str | None:
    if value is None:
        return None

    alg_id, keyid, blob = parse_encrypted_field(value)

    if alg_id != ALG_ID:
        raise ValueError(f"unsupported algorithm: {alg_id}")
    if keyid != keyctx.keyid:
        raise ValueError(f"unexpected keyid {keyid}")

    return aesgcm_decrypt(keyctx.dk, blob).decode("utf-8")
