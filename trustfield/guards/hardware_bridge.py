"""Hardware bridge for STM32 cyber-physical guard integration.

Translates between TrustField's DelegationToken format and the binary
protocol expected by the STM32 hardware guard, enabling real hardware
token validation alongside the software simulation.

Binary wire format (82 bytes total):
    token_id:    16 bytes (SHA-256 truncated hash of UUID)
    origin_hash:  8 bytes (SHA-256 truncated hash of origin_node)
    target_hash:  8 bytes (SHA-256 truncated hash of target_node)
    depth:        1 byte  (uint8)
    max_depth:    1 byte  (uint8)
    timestamp:    4 bytes (uint32 LE)
    ttl:          2 bytes (uint16 LE)
    nonce:        8 bytes (first 8 bytes of decoded hex nonce)
    edge_type:    1 byte  (uint8, see EDGE_TYPE_MAP)
    strictness:   1 byte  (uint8, see STRICTNESS_MAP)
    ---
    hmac:        32 bytes (HMAC-SHA256 over the 50-byte message)

The STM32 independently recomputes the HMAC and validates the token
fields (expiry, depth, nonce replay).  Its text response is parsed
back into a GuardEvent decision.

When a HardwareBridge is passed to GuardNetwork.deploy_guards(), the
first guard in each 3-guard triad becomes a HardwareGuard while the
other two remain software CyberPhysicalGuards.  The 2-of-3 consensus
mechanism works unchanged — the hardware participates as an equal voter.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import struct
import time
from dataclasses import dataclass
from typing import Dict, Optional

from trustfield.verification.delegation_token import (
    DelegationToken,
    TokenGenerator,
)

from .guard_module import (
    CyberPhysicalGuard,
    GuardEvent,
    StrictnessLevel,
)

EDGE_TYPE_MAP: Dict[str, int] = {
    "ASSUME_ROLE": 1,
    "TOKEN_MINT": 2,
    "SECRET_READ": 3,
    "DEPLOY_TO": 4,
    "AUTHENTICATE_AS": 5,
}

STRICTNESS_MAP: Dict[StrictnessLevel, int] = {
    StrictnessLevel.NOMINAL: 1,
    StrictnessLevel.ELEVATED: 2,
    StrictnessLevel.LOCKDOWN: 3,
}


def _hash_to_bytes(value: str, length: int) -> bytes:
    """Hash a string to a fixed-length byte sequence (SHA-256 truncated)."""
    return hashlib.sha256(value.encode()).digest()[:length]


def _parse_stm32_response(response: str) -> tuple:
    """Parse an STM32 text response into (decision, reason).

    The STM32 typically sends a two-line response: a frame-receipt
    acknowledgment (``FRAME OK``) followed by the actual validation
    verdict (e.g. ``ACCESS OK depth=2`` or ``HMAC FAIL diff=0xFF``).

    Failure keywords are checked **before** success keywords so that
    a response like ``"FRAME OK\\nHMAC FAIL"`` is correctly classified
    as BLOCKED rather than ALLOWED.
    """
    upper = response.upper()
    if "HMAC" in upper or "SIGNATURE" in upper:
        if "FAIL" in upper or "ERR" in upper or "INVALID" in upper or "MISMATCH" in upper or "DIFF" in upper:
            return ("BLOCKED", "hw:invalid_signature")
    if "EXPIRE" in upper or "TTL" in upper:
        return ("BLOCKED", "hw:token_expired")
    if "DEPTH" in upper and ("EXCEED" in upper or "FAIL" in upper or "ERR" in upper or "VIOLATION" in upper):
        return ("BLOCKED", "hw:depth_exceeded")
    if "REPLAY" in upper or ("NONCE" in upper and ("FAIL" in upper or "DUP" in upper or "REJECT" in upper)):
        return ("BLOCKED", "hw:nonce_replayed")
    for keyword in ("ACCESS OK", "VALID", "PASS", "ALLOWED"):
        if keyword in upper:
            return ("ALLOWED", "hw:all_checks_passed")
    if "FAIL" in upper or "ERR" in upper or "REJECT" in upper or "DENIED" in upper:
        return ("BLOCKED", f"hw:rejected:{response.strip()[:50]}")
    return ("BLOCKED", f"hw:unrecognized:{response.strip()[:50]}")


@dataclass
class HardwareValidationResult:
    """Result from a single STM32 validation attempt.

    Attributes:
        success: True if the STM32 accepted the token.
        raw_response: Unprocessed text from the STM32.
        decision: ``"ALLOWED"`` or ``"BLOCKED"``.
        reason: Parsed reason string prefixed with ``hw:``.
        round_trip_ms: Wall-clock time for the full send-receive cycle.
    """

    success: bool
    raw_response: str
    decision: str
    reason: str
    round_trip_ms: float


class HardwareBridge:
    """Serial communication bridge to an STM32 hardware guard.

    Manages the UART connection, time synchronization, and binary
    token encoding/decoding.  The bridge is shared across all
    ``HardwareGuard`` instances — each guard calls ``send_token()``
    which serializes access to the single UART line.

    All hardware validation attempts are recorded in ``event_log``
    so they can be included in the dashboard visualization.

    Args:
        port: Serial port (e.g. ``"COM6"`` on Windows, ``"/dev/ttyUSB0"``
            on Linux).
        baudrate: UART baud rate.  Must match the STM32 firmware.
        secret_key: 32-byte HMAC key shared with the STM32.
        timeout: Serial read timeout in seconds.
        byte_delay: Pause between bytes during transmission (seconds).
        response_delay: Pause after the last byte before reading the
            response (seconds).  The STM32 needs time to validate.
    """

    STRUCT_FORMAT = "<16s8s8sBBIH8sBB"
    MESSAGE_SIZE = struct.calcsize(STRUCT_FORMAT)   # 50 bytes
    HMAC_SIZE = 32
    TOTAL_SIZE = MESSAGE_SIZE + HMAC_SIZE           # 82 bytes

    def __init__(
        self,
        port: str,
        baudrate: int = 115200,
        secret_key: bytes = b"my_secret_key_32bytes_padded!!!!",
        timeout: float = 2.0,
        byte_delay: float = 0.001,
        response_delay: float = 1.0,
    ) -> None:
        self._port = port
        self._baudrate = baudrate
        self._secret_key = secret_key
        self._timeout = timeout
        self._byte_delay = byte_delay
        self._response_delay = response_delay
        self._serial = None
        self._connected = False
        self._busy = False
        self.event_log: list[HardwareValidationResult] = []

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """Open the serial port and synchronize the STM32 clock.

        Returns:
            True if both the port opened and time sync succeeded.
        """
        try:
            import serial as pyserial
            self._serial = pyserial.Serial(
                self._port, self._baudrate, timeout=self._timeout
            )
            time.sleep(2)
            self._connected = True
            self.flush_stm32_frame()
            self.sync_time()
            return True
        except Exception:
            self._connected = False
            return False

    def flush_stm32_frame(self) -> None:
        """Send dummy bytes to reset the STM32's frame parser.

        If the STM32 was mid-frame from a previous session (DTR doesn't
        reset all boards), sending 82 null bytes completes whatever
        partial frame it's waiting for.  The resulting HMAC check will
        fail, but the STM32 returns to its idle state ready for the
        next real frame.
        """
        if not self._serial:
            return
        self._serial.reset_input_buffer()
        self._serial.write(b"\x00" * self.TOTAL_SIZE)
        self._serial.flush()
        time.sleep(1)
        self._serial.read_all()
        self._serial.reset_input_buffer()

    def sync_time(self) -> Optional[str]:
        """Send the current UNIX timestamp to the STM32.

        The STM32 expects a ``'T'`` byte followed by a 4-byte
        little-endian uint32 timestamp.

        Returns:
            The STM32 acknowledgment string, or None if not connected.
        """
        if not self._connected or self._serial is None:
            return None
        current_time = int(time.time())
        self._serial.write(b"T")
        self._serial.write(struct.pack("<I", current_time))
        time.sleep(0.5)
        return self._serial.read_all().decode(errors="ignore")

    def resync(self) -> None:
        """Re-sync the STM32 clock and flush the serial buffers.

        Call this before a pipeline run to ensure the STM32's frame
        parser is in a clean state.
        """
        if not self._connected or self._serial is None:
            return
        self._serial.reset_input_buffer()
        self._serial.reset_output_buffer()
        self.sync_time()
        self._serial.reset_input_buffer()

    @property
    def connected(self) -> bool:
        """Whether the bridge has an active serial connection."""
        return self._connected

    @property
    def busy(self) -> bool:
        """Whether the bridge is mid-validation (subprocess has the port)."""
        return self._busy

    def get_event_log(self) -> list:
        """Return all hardware validation events as serializable dicts."""
        return [
            {
                "source": "STM32",
                "port": self._port,
                "decision": ev.decision,
                "reason": ev.reason,
                "raw_response": ev.raw_response.replace("\r", "").strip(),
                "round_trip_ms": round(ev.round_trip_ms, 1),
            }
            for ev in self.event_log
        ]

    def clear_event_log(self) -> None:
        """Clear all recorded hardware events."""
        self.event_log.clear()

    def close(self) -> None:
        """Close the serial port and mark the bridge as disconnected."""
        if self._serial is not None:
            self._serial.close()
            self._serial = None
        self._connected = False

    # ------------------------------------------------------------------
    # Token encoding
    # ------------------------------------------------------------------

    def build_payload(
        self,
        token: DelegationToken,
        strictness: StrictnessLevel = StrictnessLevel.NOMINAL,
    ) -> bytes:
        """Encode a DelegationToken as an 82-byte STM32 binary payload.

        The payload is the 50-byte struct message concatenated with its
        32-byte HMAC-SHA256 digest, computed with the shared secret key.

        Args:
            token: Software delegation token to encode.
            strictness: Current guard operating mode.

        Returns:
            82-byte ``bytes`` object ready for transmission.
        """
        token_id_bytes = _hash_to_bytes(token.token_id, 16)
        origin_bytes = _hash_to_bytes(token.origin_node, 8)
        target_bytes = _hash_to_bytes(token.target_node, 8)

        depth = min(token.delegation_depth, 255)
        max_depth = min(token.max_depth, 255)
        timestamp = int(token.timestamp) & 0xFFFFFFFF
        ttl = min(int(token.ttl_seconds), 65535)

        nonce_bytes = bytes.fromhex(token.nonce)[:8]
        if len(nonce_bytes) < 8:
            nonce_bytes = nonce_bytes.ljust(8, b"\x00")

        edge_type_int = EDGE_TYPE_MAP.get(token.edge_type, 0)
        strictness_int = STRICTNESS_MAP.get(strictness, 1)

        message = struct.pack(
            self.STRUCT_FORMAT,
            token_id_bytes,
            origin_bytes,
            target_bytes,
            depth,
            max_depth,
            timestamp,
            ttl,
            nonce_bytes,
            edge_type_int,
            strictness_int,
        )

        mac = hmac_mod.new(
            self._secret_key, message, hashlib.sha256
        ).digest()

        return message + mac

    # ------------------------------------------------------------------
    # Token transmission
    # ------------------------------------------------------------------

    def send_token(
        self,
        token: DelegationToken,
        strictness: StrictnessLevel = StrictnessLevel.NOMINAL,
    ) -> HardwareValidationResult:
        """Send a token to the STM32 and return its validation decision.

        Bytes are transmitted one at a time with ``byte_delay`` between
        each to match the STM32 UART receive buffer timing.  After the
        last byte, ``response_delay`` seconds are waited before reading
        the response.

        If the bridge is not connected, returns BLOCKED immediately
        (fail-closed).

        Args:
            token: The delegation token to validate on hardware.
            strictness: Current guard strictness level.

        Returns:
            ``HardwareValidationResult`` with the parsed decision.
        """
        if not self._connected or self._serial is None:
            return HardwareValidationResult(
                success=False,
                raw_response="",
                decision="BLOCKED",
                reason="hw:not_connected",
                round_trip_ms=0.0,
            )

        payload = self.build_payload(token, strictness)

        # Flush stale data from previous exchanges
        self._serial.reset_input_buffer()

        start = time.perf_counter()
        for byte in payload:
            self._serial.write(bytes([byte]))
            time.sleep(0.001)
        self._serial.flush()

        if self._response_delay > 0:
            time.sleep(self._response_delay)

        raw = self._serial.read_all().decode(errors="ignore")
        elapsed_ms = (time.perf_counter() - start) * 1000

        decision, reason = _parse_stm32_response(raw)

        result = HardwareValidationResult(
            success=(decision == "ALLOWED"),
            raw_response=raw,
            decision=decision,
            reason=reason,
            round_trip_ms=elapsed_ms,
        )
        self.event_log.append(result)
        return result


class HardwareGuard(CyberPhysicalGuard):
    """A guard that delegates token validation to the STM32 hardware.

    Extends ``CyberPhysicalGuard`` with the identical
    ``validate_transition`` interface.  When the hardware bridge is
    connected, tokens are sent to the STM32 for validation; its
    response becomes the authoritative decision.  When disconnected,
    falls back transparently to software-only validation.

    In the standard deployment, one ``HardwareGuard`` and two
    ``CyberPhysicalGuard`` instances form the 2-of-3 consensus triad
    per edge.

    Args:
        guard_id: Human-readable guard identifier.
        edge: ``(source, target)`` node pair this guard monitors.
        token_generator: Software ``TokenGenerator`` (used for fallback
            and shares the signing key).
        bridge: ``HardwareBridge`` connected to the STM32.
        initial_strictness: Starting operating mode.
    """

    def __init__(
        self,
        guard_id: str,
        edge: tuple,
        token_generator: TokenGenerator,
        bridge: HardwareBridge,
        initial_strictness: StrictnessLevel = StrictnessLevel.NOMINAL,
    ) -> None:
        super().__init__(guard_id, edge, token_generator, initial_strictness)
        self._bridge = bridge

    def validate_transition(self, token: DelegationToken) -> GuardEvent:
        """Validate a token via STM32 hardware, with software fallback.

        Args:
            token: The ``DelegationToken`` to validate.

        Returns:
            A ``GuardEvent`` recording the hardware (or fallback) decision.
        """
        if not self._bridge.connected:
            return super().validate_transition(token)

        hw_result = self._bridge.send_token(token, self._strictness)
        return self._make_event(token, hw_result.decision, hw_result.reason)
