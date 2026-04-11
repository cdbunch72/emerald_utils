# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch. All rights reserved.

from uuid import UUID

from gemstone_utils.key_id import new_key_id, normalize_key_id


def test_new_key_id_is_uuid_v7_string():
    s = new_key_id()
    u = UUID(s)
    assert u.version == 7
    assert s == str(u)


def test_normalize_key_id():
    u = new_key_id()
    assert normalize_key_id(u) == u
    assert normalize_key_id(u.upper()) == u
