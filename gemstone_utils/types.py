# SPDX-License-Identifier: MPL-2.0
# gemstone_utils/types.py

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from gemstone_utils.crypto import recommended_data_alg


@dataclass
class KeyRecord:
    """
    Generic encrypted-key metadata container.

    Applications construct this from their own storage layer.
    ``params`` matches the JSON params segment in the encrypted-field wire format.

    ``keyid`` is the logical DEK id (canonical UUID string), or ``None`` for a
    KEK-check (canary) blob that is not a DEK.
    """

    keyid: Optional[str]
    alg: str
    encrypted_key: bytes
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class KeyContext:
    """
    Active key context for field encryption (data key + key id + algorithm).

    ``keyid`` is a canonical UUID string (segment 2 in encrypted-field wire format).
    """

    keyid: str
    key: bytes
    alg: str = field(default_factory=recommended_data_alg)
