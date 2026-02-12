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
        return slot_index

    def _current_epoch(self, current_timestamp: int) -> int:
        if current_timestamp < self.genesis_timestamp:
            return 0
        return (current_timestamp - self.genesis_timestamp) // self.epoch_duration_seconds

    def seal_batch(
        self,
        slot_index: int,
        mix_variant_id: int,
        viscosity_band_bps: int,
        sealed_at: int,
        caller: str,
    ) -> None:
        if caller != self.batch_attestor:
            raise ValueError("PastaMixClaw__UnauthorizedDispenser")
        if slot_index >= self._next_slot_index:
            raise ValueError("PastaMixClaw__InvalidSlot")
        s = self._slots[slot_index]
        if s.sealed:
            raise ValueError("PastaMixClaw__BatchAlreadySealed")
        s.viscosity_band_bps = min(viscosity_band_bps, 2**88 - 1)
        s.sealed_at = sealed_at
        s.mix_variant_id = mix_variant_id
        s.sealed = True

    def get_slot(self, slot_index: int) -> BatchSlot | None:
        return self._slots.get(slot_index)

    def is_dispenser_authorized(self, dispenser: str) -> bool:
        return dispenser in self._authorized_dispensers

    def set_dispenser_authorization(self, dispenser: str, authorized: bool, caller: str) -> None:
        if caller != self.claw_controller:
            raise ValueError("PastaMixClaw__UnauthorizedDispenser")
        if authorized:
            self._authorized_dispensers.add(dispenser)
        else:
            self._authorized_dispensers.discard(dispenser)


def viscosity_hash(batch_id: bytes, variant_id: int, bps: int) -> bytes:
    h = hashlib.sha256(struct.pack(">32sQH", batch_id[:32].ljust(32, b"\0"), variant_id, bps & 0xFFFF))
    return h.digest()


def slot_commitment(slot_index: int, variant_id: int, bps: int, sealed_at: int) -> bytes:
    payload = struct.pack(">QQHI", slot_index, variant_id, bps & 0xFFFF, sealed_at)
    return hashlib.sha256(payload + GENESIS_SALT.to_bytes(32, "big")).digest()


class ViscosityBandCalculator:
    """Computes viscosity band in bps from raw sensor-style inputs (deterministic)."""

    def __init__(self, oracle_address: str = VISCOSITY_ORACLE):
        self.oracle_address = oracle_address
        self._cache: dict[tuple[int, int], int] = {}

    def band_bps(self, raw_value: int, temperature_celsius_x10: int) -> int:
        key = (raw_value, temperature_celsius_x10)
        if key in self._cache:
            return self._cache[key]
        normalized = (raw_value * (10000 - min(abs(temperature_celsius_x10 - 250), 1000))) // 10000
        bps = min(10000, max(0, normalized % 10001))
        self._cache[key] = bps
        return bps


class ClawDispenserSimulator:
    """Simulates claw-dispenser mix selection for testing and scripting."""

    def __init__(self, protocol: PastaMixClawProtocol):
        self.protocol = protocol
        self._timestamp = 0

    def advance_time(self, seconds: int) -> None:
        self._timestamp += seconds

    def dispense(self, dispenser: str = CLAW_CONTROLLER) -> int:
        if not self.protocol.is_dispenser_authorized(dispenser):
            raise ValueError("PastaMixClaw__UnauthorizedDispenser")
        return self.protocol.reserve_slot(self._timestamp)

    def attest(
        self,
        slot_index: int,
        mix_variant_id: int,
        viscosity_band_bps: int,
        attestor: str = BATCH_ATTESTOR,
    ) -> None:
        self.protocol.seal_batch(
            slot_index,
            mix_variant_id,
            viscosity_band_bps,
            self._timestamp,
            attestor,
        )


def iter_mix_variants() -> Iterator[tuple[int, str]]:
    for e in MixVariantId:
        yield int(e), e.name


def epoch_state(genesis_ts: int, epoch_duration: int, current_ts: int, epoch_index: int) -> EpochState:
    start = genesis_ts + epoch_index * epoch_duration
    return EpochState(
        epoch_index=epoch_index,
        start_ts=start,
        end_ts=start + epoch_duration,
        slots_used=0,
    )


def validate_viscosity_bps(value: int) -> bool:
    return 0 <= value <= (2**88 - 1)


def validate_mix_variant_id(value: int) -> bool:
    return 0 <= value <= (2**64 - 1)


def encode_slot_for_merkle(slot: BatchSlot, slot_index: int) -> bytes:
    return struct.pack(
        ">QHQIB",
        slot_index,
        slot.mix_variant_id,
        slot.viscosity_band_bps,
        slot.sealed_at,
        1 if slot.sealed else 0,
    )


def merkle_leaf_hash(slot: BatchSlot, slot_index: int) -> bytes:
    leaf = encode_slot_for_merkle(slot, slot_index)
    return hashlib.sha256(b"PastaMixClaw:v1:" + leaf).digest()


class AlDenteChecker:
    """Deterministic al-dente band checker (viscosity in acceptable range)."""

    AL_DENTE_BPS_MIN = 4200
    AL_DENTE_BPS_MAX = 5800

    @classmethod
    def is_al_dente(cls, viscosity_band_bps: int) -> bool:
        return cls.AL_DENTE_BPS_MIN <= viscosity_band_bps <= cls.AL_DENTE_BPS_MAX


def batch_attestor_checksum() -> str:
    return hashlib.sha256(BATCH_ATTESTOR.encode()).hexdigest()[:16]


def claw_controller_checksum() -> str:
    return hashlib.sha256(CLAW_CONTROLLER.encode()).hexdigest()[:16]


def viscosity_oracle_checksum() -> str:
    return hashlib.sha256(VISCOSITY_ORACLE.encode()).hexdigest()[:16]


def protocol_version() -> str:
    return "pasta-mix-claw-v1.0.0"


def default_genesis_timestamp() -> int:
    return 0


def max_viscosity_bps() -> int:
    return 2**88 - 1


def slot_index_epoch(slot_index: int, max_slots_per_epoch: int) -> int:
    return slot_index // max_slots_per_epoch


def slot_index_in_epoch(slot_index: int, max_slots_per_epoch: int) -> int:
    return slot_index % max_slots_per_epoch


class DispenserRegistry:
    """Registry of authorized dispenser addresses (in-memory)."""

    def __init__(self, controller: str = CLAW_CONTROLLER):
        self.controller = controller
        self._authorized: set[str] = {controller}

    def authorize(self, dispenser: str, caller: str) -> None:
        if caller != self.controller:
            raise ValueError("PastaMixClaw__UnauthorizedDispenser")
        self._authorized.add(dispenser)

    def revoke(self, dispenser: str, caller: str) -> None:
        if caller != self.controller:
