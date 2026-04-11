#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch. All rights reserved.
"""
Skeleton for migrating databases from integer key ids to UUIDv7 string key ids.

This repository does not ship a one-size-fits-all migrator: applications must
enumerate their own ``EncryptedString`` columns and re-encrypt rows after
installing new ``gemstone_key_*`` schema and DEK rows (see README and
RELEASE_NOTES for v0.3.0).

Intended workflow (high level):
  1. With old code + old DB, export or decrypt data as needed.
  2. Create new KEK slot rows (``gemstone_key_kdf``) with ``set_kdf_params``,
     ``set_kek_canary``, new string ``key_id`` values, and optional
     ``app_reencrypt_pending``.
  3. Generate new DEK material per slot, insert DEK rows with ``put_keyrecord``.
  4. Rewrite application rows so ciphertext uses the five-part wire format with
     UUID segment 2 (see ``gemstone_utils.key_id.new_key_id``).
  5. Clear ``app_reencrypt_pending`` when done.

Support for this migration path is documented through **v0.9.0**; native
``Uuid`` SQLAlchemy columns for key ids are planned for that release line.

This file is documentation-only unless extended by your application.
"""

from __future__ import annotations

if __name__ == "__main__":
    print(__doc__)
