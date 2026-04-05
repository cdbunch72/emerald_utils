# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch. All rights reserved.

from gemstone_utils.crypto import derive_pbkdf2_hmac_sha256
from gemstone_utils.key_mgmt import derive_kek, pbkdf2_hmac_sha256_params


def test_pbkdf2_params_then_derive_kek_matches_primitive():
    salt = b"eight-bytes-salt!!"
    p = "unit-test-pass"
    params = pbkdf2_hmac_sha256_params(salt, iterations=50_000)
    expected = derive_pbkdf2_hmac_sha256(p, salt, iterations=50_000, length=32)
    assert derive_kek(p, params) == expected


def test_pbkdf2_hmac_sha256_params_roundtrip_json_shape():
    salt = b"another-salt-here!"
    params = pbkdf2_hmac_sha256_params(salt, iterations=10_000)
    assert params["kdf"] == "pbkdf2-hmac-sha256"
    assert params["iterations"] == 10_000
    p = "x"
    assert derive_kek(p, params) == derive_pbkdf2_hmac_sha256(
        p, salt, iterations=10_000, length=32
    )
