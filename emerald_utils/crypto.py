# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch. All rights reserved
# emerald_utils/crypto.py

from __future__ import annotations

import os
from base64 import urlsafe_b64encode, urlsafe_b64decode

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_dk_from_passphrase(
    passphrase: str,
    salt: bytes,
    iterations: int = 200_000,
) -> bytes:
    if not isinstance(passphrase, str):
        raise TypeError("passphrase must be a str")
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt must be bytes")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def aesgcm_encrypt(dk: bytes, plaintext: bytes, aad: bytes | None = None) -> bytes:
    aesgcm = AESGCM(dk)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ciphertext


def aesgcm_decrypt(dk: bytes, blob: bytes, aad: bytes | None = None) -> bytes:
    if len(blob) < 12 + 16:
        raise ValueError("ciphertext blob too short")

    nonce = blob[:12]
    ciphertext = blob[12:]
    aesgcm = AESGCM(dk)
    return aesgcm.decrypt(nonce, ciphertext, aad)


def b64encode(data: bytes) -> str:
    return urlsafe_b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    return urlsafe_b64decode(data.encode("ascii"))
