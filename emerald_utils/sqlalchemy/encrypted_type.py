# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch. All rights reserved.
# emerald_utils/sqlalchemy/encrypted_type.py

from __future__ import annotations

from sqlalchemy.types import TypeDecorator, Text

from emerald_utils.encrypted_fields import encrypt_string, is_encrypted_prefix
from .lazy_secret import LazySecret


class EncryptedString(TypeDecorator):
    impl = Text
    cache_ok = True
    _keyctx = None

    @classmethod
    def set_keyctx(cls, keyctx):
        cls._keyctx = keyctx

    @classmethod
    def get_keyctx(cls):
        if cls._keyctx is None:
            raise RuntimeError("EncryptedString.set_keyctx(...) must be called before use")
        return cls._keyctx

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if is_encrypted_prefix(value):
            raise ValueError("Encrypted values must not be assigned directly")
        return encrypt_string(value, self.get_keyctx())

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return LazySecret(value, self.get_keyctx())
