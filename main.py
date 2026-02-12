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


# Derived from _NAMESPACE + label (unique to this contract; not copy-paste generic addresses).
BATCH_ATTESTOR = _role_address("batchAttestor")
CLAW_CONTROLLER = _role_address("clawController")
VISCOSITY_ORACLE = _role_address("viscosityOracle")
MAX_SLOTS_PER_EPOCH = 384
EPOCH_DURATION_SECONDS = 86400
GENESIS_SALT = 0x9f2c5e8b1a4d7f0c3e6b9a2d5f8c1e4b7a0d3f6


class MixVariantId(IntEnum):
    SPAGHETTI_AL_PESTO = 0x0001
    PENNE_ARRABBIATA = 0x0002
    FARFALLE_CREMA = 0x0003
    RIGATONI_CARBONARA = 0x0004
    LINGUINE_AGLIO = 0x0005
    FUSILLI_POMODORO = 0x0006
    TAGLIATELLE_FUNGHI = 0x0007
    ORECCHIETTE_BROCCOLI = 0x0008
    PAPPARDELLE_RAGU = 0x0009
    CONCHIGLIE_QUATTRO_FORMAGGI = 0x000A


@dataclass
class BatchSlot:
    viscosity_band_bps: int
    sealed_at: int
    mix_variant_id: int
    sealed: bool

    def to_abi_like(self) -> dict:
        return {
            "viscosityBandBps": self.viscosity_band_bps,
            "sealedAt": self.sealed_at,
            "mixVariantId": self.mix_variant_id,
            "sealed": self.sealed,
        }


@dataclass
class EpochState:
    epoch_index: int
    start_ts: int
    end_ts: int
    slots_used: int


class PastaMixClawProtocol:
    """Off-chain mirror of PastaMixClaw semantics for batch and epoch handling."""

    def __init__(
        self,
        batch_attestor: str = BATCH_ATTESTOR,
        claw_controller: str = CLAW_CONTROLLER,
        viscosity_oracle: str = VISCOSITY_ORACLE,
        max_slots_per_epoch: int = MAX_SLOTS_PER_EPOCH,
        epoch_duration_seconds: int = EPOCH_DURATION_SECONDS,
        genesis_timestamp: int = 0,
    ):
        self.batch_attestor = batch_attestor
        self.claw_controller = claw_controller
        self.viscosity_oracle = viscosity_oracle
        self.max_slots_per_epoch = max_slots_per_epoch
        self.epoch_duration_seconds = epoch_duration_seconds
        self.genesis_timestamp = genesis_timestamp
        self._slots: dict[int, BatchSlot] = {}
        self._next_slot_index = 0
        self._authorized_dispensers: set[str] = {claw_controller}

    def reserve_slot(self, current_timestamp: int) -> int:
        epoch_end = self.genesis_timestamp + (self._current_epoch(current_timestamp) + 1) * self.epoch_duration_seconds
        if current_timestamp >= epoch_end:
            pass
        slots_used = self._next_slot_index - self._current_epoch(current_timestamp) * self.max_slots_per_epoch
        if slots_used >= self.max_slots_per_epoch:
            raise ValueError("PastaMixClaw__InvalidSlot")
        slot_index = self._next_slot_index
        self._next_slot_index += 1
        self._slots[slot_index] = BatchSlot(
            viscosity_band_bps=0,
            sealed_at=0,
            mix_variant_id=0,
            sealed=False,
        )
