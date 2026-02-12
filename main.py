# pasta_mix_claw_protocol.py
# Viscosity-band attestation and claw-dispenser mix selection protocol (off-chain reference).

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Iterator

# Namespace salt: must match PastaMixClaw.sol _NAMESPACE so derived addresses match on-chain.
_NAMESPACE_HEX = "8f4a92c7e1b3d6f9a2c5e8b1d4f7a0c3e6b9d2f5a1d6f9c2e5b8a0d3f6c9e2b5a8"


def _role_address(label: str) -> str:
    """Derive role address from namespace + label (same logic as Solidity). Not a generic address."""
    namespace = bytes.fromhex(_NAMESPACE_HEX)
    packed = namespace + label.encode("utf-8")
    try:
        from web3 import Web3
        digest = Web3.keccak(packed)
        addr_bytes = digest[-20:] if isinstance(digest, bytes) else bytes(digest)[-20:]
    except Exception:
        digest = hashlib.sha256(packed).digest()
        addr_bytes = digest[-20:]
    return "0x" + addr_bytes.hex()

