"""Tests for STM32 hardware bridge integration.

 1. _parse_stm32_response: positive keywords → ALLOWED
 2. _parse_stm32_response: HMAC failure keyword → BLOCKED
 3. _parse_stm32_response: expiry keyword → BLOCKED
 4. _parse_stm32_response: depth keyword → BLOCKED
 5. _parse_stm32_response: replay keyword → BLOCKED
 6. _parse_stm32_response: unknown response → BLOCKED (fail-closed)
 7. build_payload: output is exactly 82 bytes (50 message + 32 HMAC)
 8. build_payload: HMAC is valid over the message portion
 9. build_payload: struct fields unpack correctly
10. HardwareGuard: connected bridge → uses hardware decision
11. HardwareGuard: disconnected bridge → falls back to software
12. GuardNetwork: deploy_guards with hardware_bridge → first guard is HardwareGuard
13. GuardNetwork: consensus with mixed hw/sw triad works correctly
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import struct

import pytest

from trustfield.graph.edge_types import EdgeMetadata, EdgeType
from trustfield.graph.node_types import NodeMetadata, NodeType
from trustfield.graph.trust_graph import TrustGraph
from trustfield.verification.delegation_token import TokenGenerator

from trustfield.guards.hardware_bridge import (
    EDGE_TYPE_MAP,
    STRICTNESS_MAP,
    HardwareBridge,
    HardwareGuard,
    HardwareValidationResult,
    _hash_to_bytes,
    _parse_stm32_response,
)
from trustfield.guards.guard_module import CyberPhysicalGuard, StrictnessLevel
from trustfield.guards.guard_network import GuardNetwork


# ---------------------------------------------------------------------------
# Mock serial port
# ---------------------------------------------------------------------------


class MockSerial:
    """Simulates STM32 UART responses for testing without hardware."""

    def __init__(self, responses: list[str]) -> None:
        self._responses = list(responses)
        self._write_buffer = bytearray()
        self._response_idx = 0

    def write(self, data: bytes) -> None:
        self._write_buffer.extend(data)

    def read_all(self) -> bytes:
        if self._response_idx < len(self._responses):
            resp = self._responses[self._response_idx]
            self._response_idx += 1
            return resp.encode()
        return b""

    def close(self) -> None:
        pass

    @property
    def bytes_sent(self) -> bytes:
        return bytes(self._write_buffer)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TEST_KEY = b"test_key_32_bytes_padded_here!!!"


def _make_bridge(**kwargs) -> HardwareBridge:
    """Create a HardwareBridge with test defaults (no real serial)."""
    defaults = dict(
        port="COM_TEST",
        secret_key=TEST_KEY,
        byte_delay=0,
        response_delay=0,
    )
    defaults.update(kwargs)
    return HardwareBridge(**defaults)


def _make_test_token(gen: TokenGenerator | None = None) -> tuple:
    """Create a token and edge metadata for testing.

    Returns (token, edge_metadata, generator).
    """
    if gen is None:
        gen = TokenGenerator()
    edge_meta = EdgeMetadata("e_test", EdgeType.ASSUME_ROLE, 1.0, 6)
    token = gen.generate("node-A", "node-B", edge_meta, current_depth=2)
    return token, edge_meta, gen


def _connect_bridge(bridge: HardwareBridge, responses: list[str]) -> None:
    """Attach a MockSerial to a bridge and mark it connected."""
    bridge._serial = MockSerial(responses)
    bridge._connected = True


@pytest.fixture
def simple_graph() -> TrustGraph:
    g = TrustGraph()
    g.add_node(NodeMetadata("A", NodeType.USER, "User A", 0.3, 0.2))
    g.add_node(NodeMetadata("B", NodeType.SERVICE, "Svc B", 0.5, 0.5))
    g.add_node(NodeMetadata("C", NodeType.ROLE, "Admin C", 0.9, 0.9))
    g.add_edge("A", "B", EdgeMetadata("e1", EdgeType.ASSUME_ROLE, 1.0, 6))
    g.add_edge("B", "C", EdgeMetadata("e2", EdgeType.TOKEN_MINT, 1.0, 6))
    return g


# ---------------------------------------------------------------------------
# 1-6. Response parsing
# ---------------------------------------------------------------------------


class TestParseResponse:
    def test_valid_keyword(self):
        assert _parse_stm32_response("VALID\r\n")[0] == "ALLOWED"

    def test_access_ok(self):
        assert _parse_stm32_response("ACCESS OK depth=2\r\n")[0] == "ALLOWED"

    def test_pass_keyword(self):
        assert _parse_stm32_response("Token PASS\r\n")[0] == "ALLOWED"

    def test_hmac_failure(self):
        decision, reason = _parse_stm32_response("ERR:HMAC_FAIL\r\n")
        assert decision == "BLOCKED"
        assert "signature" in reason

    def test_hmac_fail_with_diff(self):
        decision, reason = _parse_stm32_response("FRAME OK\n\nHMAC FAIL diff=0xFF\r\n")
        assert decision == "BLOCKED"
        assert "signature" in reason

    def test_expired(self):
        decision, reason = _parse_stm32_response("EXPIRED\r\n")
        assert decision == "BLOCKED"
        assert "expired" in reason

    def test_expired_with_frame_ok_prefix(self):
        decision, reason = _parse_stm32_response(
            "FRAME OK\n\nTOKEN EXPIRED now=123 exp=100\r\n"
        )
        assert decision == "BLOCKED"
        assert "expired" in reason

    def test_depth_exceeded(self):
        decision, reason = _parse_stm32_response("DEPTH EXCEEDED\r\n")
        assert decision == "BLOCKED"
        assert "depth" in reason

    def test_replay(self):
        decision, reason = _parse_stm32_response("NONCE REPLAY\r\n")
        assert decision == "BLOCKED"
        assert "replay" in reason

    def test_unknown_response(self):
        decision, reason = _parse_stm32_response("???\r\n")
        assert decision == "BLOCKED"
        assert "unrecognized" in reason

    def test_frame_ok_plus_access_ok_is_allowed(self):
        decision, _ = _parse_stm32_response("FRAME OK\n\nACCESS OK depth=2\r\n")
        assert decision == "ALLOWED"

    def test_failure_beats_frame_ok(self):
        decision, _ = _parse_stm32_response("FRAME OK\nHMAC FAIL diff=0x01\r\n")
        assert decision == "BLOCKED"


# ---------------------------------------------------------------------------
# 7-9. Payload building
# ---------------------------------------------------------------------------


class TestBuildPayload:
    def test_payload_is_82_bytes(self):
        bridge = _make_bridge()
        token, _, _ = _make_test_token()
        payload = bridge.build_payload(token)
        assert len(payload) == 82

    def test_hmac_matches_message(self):
        bridge = _make_bridge()
        token, _, _ = _make_test_token()
        payload = bridge.build_payload(token)

        message = payload[:50]
        mac = payload[50:]
        expected = hmac_mod.new(TEST_KEY, message, hashlib.sha256).digest()
        assert mac == expected

    def test_struct_fields_unpack(self):
        bridge = _make_bridge()
        token, _, _ = _make_test_token()
        payload = bridge.build_payload(token)

        fmt = HardwareBridge.STRUCT_FORMAT
        fields = struct.unpack(fmt, payload[:50])
        # fields: token_id(16), origin(8), target(8), depth, max_depth,
        #         timestamp, ttl, nonce(8), edge_type, strictness

        assert fields[3] == 2          # depth=2
        assert fields[4] == 6          # max_depth=6
        assert fields[8] == EDGE_TYPE_MAP["ASSUME_ROLE"]  # edge_type=1
        assert fields[9] == STRICTNESS_MAP[StrictnessLevel.NOMINAL]

    def test_origin_target_hashes_deterministic(self):
        bridge = _make_bridge()
        token, _, _ = _make_test_token()
        p1 = bridge.build_payload(token)
        p2 = bridge.build_payload(token)
        assert p1[:50] == p2[:50]

    def test_different_strictness_changes_payload(self):
        bridge = _make_bridge()
        token, _, _ = _make_test_token()
        p_nom = bridge.build_payload(token, StrictnessLevel.NOMINAL)
        p_lock = bridge.build_payload(token, StrictnessLevel.LOCKDOWN)
        assert p_nom != p_lock


# ---------------------------------------------------------------------------
# 10. HardwareGuard: connected → uses hardware decision
# ---------------------------------------------------------------------------


class TestHardwareGuardConnected:
    def test_valid_hardware_response(self):
        bridge = _make_bridge()
        _connect_bridge(bridge, ["VALID\r\n"])

        gen = TokenGenerator()
        guard = HardwareGuard(
            "hw_g0", ("A", "B"),
            TokenGenerator(secret_key=gen.key),
            bridge,
        )
        token, _, _ = _make_test_token(gen)
        event = guard.validate_transition(token)

        assert event.decision == "ALLOWED"
        assert "hw:" in event.reason

    def test_hardware_blocked_response(self):
        bridge = _make_bridge()
        _connect_bridge(bridge, ["HMAC_FAIL\r\n"])

        gen = TokenGenerator()
        guard = HardwareGuard(
            "hw_g0", ("A", "B"),
            TokenGenerator(secret_key=gen.key),
            bridge,
        )
        token, _, _ = _make_test_token(gen)
        event = guard.validate_transition(token)

        assert event.decision == "BLOCKED"
        assert "hw:invalid_signature" in event.reason

    def test_hardware_event_logged(self):
        bridge = _make_bridge()
        _connect_bridge(bridge, ["VALID\r\n"])

        gen = TokenGenerator()
        guard = HardwareGuard(
            "hw_g0", ("A", "B"),
            TokenGenerator(secret_key=gen.key),
            bridge,
        )
        token, _, _ = _make_test_token(gen)
        guard.validate_transition(token)

        log = guard.get_event_log()
        assert len(log) == 1
        assert log[0].guard_id == "hw_g0"


# ---------------------------------------------------------------------------
# 11. HardwareGuard: disconnected → software fallback
# ---------------------------------------------------------------------------


class TestHardwareGuardFallback:
    def test_disconnected_uses_software(self):
        bridge = _make_bridge()
        # bridge._connected is False by default

        gen = TokenGenerator()
        guard = HardwareGuard(
            "hw_g0", ("A", "B"),
            TokenGenerator(secret_key=gen.key),
            bridge,
        )
        edge_meta = EdgeMetadata("e1", EdgeType.ASSUME_ROLE, 1.0, 6)
        token = gen.generate("A", "B", edge_meta, current_depth=0)
        event = guard.validate_transition(token)

        assert event.decision == "ALLOWED"
        assert "hw:" not in event.reason

    def test_fallback_still_detects_bad_signature(self):
        bridge = _make_bridge()

        gen = TokenGenerator()
        guard = HardwareGuard(
            "hw_g0", ("A", "B"),
            TokenGenerator(secret_key=gen.key),
            bridge,
        )
        edge_meta = EdgeMetadata("e1", EdgeType.ASSUME_ROLE, 1.0, 6)
        token = gen.generate("A", "B", edge_meta, current_depth=0)
        token.signature = "0" * 64
        event = guard.validate_transition(token)

        assert event.decision == "BLOCKED"
        assert "invalid_signature" in event.reason


# ---------------------------------------------------------------------------
# 12. GuardNetwork: deploy with hardware_bridge
# ---------------------------------------------------------------------------


class TestGuardNetworkHardwareDeploy:
    def test_first_guard_is_hardware(self, simple_graph):
        bridge = _make_bridge()
        _connect_bridge(bridge, [])

        gen = TokenGenerator()
        network = GuardNetwork(simple_graph, gen)
        network.deploy_guards([("A", "B")], hardware_bridge=bridge)

        guards = network._deployed_guards[("A", "B")]
        assert len(guards) == 3
        assert isinstance(guards[0], HardwareGuard)
        assert isinstance(guards[1], CyberPhysicalGuard)
        assert not isinstance(guards[1], HardwareGuard)
        assert not isinstance(guards[2], HardwareGuard)

    def test_hw_guard_id_prefix(self, simple_graph):
        bridge = _make_bridge()
        _connect_bridge(bridge, [])

        gen = TokenGenerator()
        network = GuardNetwork(simple_graph, gen)
        network.deploy_guards([("A", "B")], hardware_bridge=bridge)

        guards = network._deployed_guards[("A", "B")]
        assert guards[0].guard_id.startswith("hw_guard_")
        assert guards[1].guard_id.startswith("guard_")

    def test_no_bridge_all_software(self, simple_graph):
        gen = TokenGenerator()
        network = GuardNetwork(simple_graph, gen)
        network.deploy_guards([("A", "B")])

        guards = network._deployed_guards[("A", "B")]
        for g in guards:
            assert not isinstance(g, HardwareGuard)


# ---------------------------------------------------------------------------
# 13. Consensus with mixed hw/sw triad
# ---------------------------------------------------------------------------


class TestMixedConsensus:
    def test_hw_allow_counts_in_consensus(self, simple_graph):
        """Hardware ALLOWED + 2 software ALLOWED → consensus ALLOWED."""
        bridge = _make_bridge()
        _connect_bridge(bridge, ["VALID\r\n"])

        gen = TokenGenerator()
        network = GuardNetwork(simple_graph, gen)
        network.deploy_guards([("A", "B")], hardware_bridge=bridge)

        edge_meta = simple_graph.get_edge("A", "B")
        token = gen.generate("A", "B", edge_meta, current_depth=0)
        result = network.validate_with_consensus(
            ("A", "B"), token, required_approvals=2
        )

        assert result.consensus_decision == "ALLOWED"
        assert result.approval_count >= 2

    def test_hw_block_counts_in_consensus(self, simple_graph):
        """Hardware BLOCKED + 2 software ALLOWED → consensus ALLOWED (2 of 3)."""
        bridge = _make_bridge()
        _connect_bridge(bridge, ["HMAC_FAIL\r\n"])

        gen = TokenGenerator()
        network = GuardNetwork(simple_graph, gen)
        network.deploy_guards([("A", "B")], hardware_bridge=bridge)

        edge_meta = simple_graph.get_edge("A", "B")
        token = gen.generate("A", "B", edge_meta, current_depth=0)
        result = network.validate_with_consensus(
            ("A", "B"), token, required_approvals=2
        )

        # HW blocks but 2 SW guards allow → 2 approvals → ALLOWED
        assert result.consensus_decision == "ALLOWED"
        assert result.approval_count == 2

    def test_hw_plus_one_sw_block(self, simple_graph):
        """Hardware BLOCKED + 1 software BLOCKED → consensus BLOCKED."""
        bridge = _make_bridge()
        _connect_bridge(bridge, ["HMAC_FAIL\r\n"])

        gen = TokenGenerator()
        network = GuardNetwork(simple_graph, gen)
        network.deploy_guards([("A", "B")], hardware_bridge=bridge)

        # Put second guard in LOCKDOWN (empty whitelist → BLOCKED)
        guards = network._deployed_guards[("A", "B")]
        guards[1].set_strictness(StrictnessLevel.LOCKDOWN)

        edge_meta = simple_graph.get_edge("A", "B")
        token = gen.generate("A", "B", edge_meta, current_depth=0)
        result = network.validate_with_consensus(
            ("A", "B"), token, required_approvals=2
        )

        assert result.consensus_decision == "BLOCKED"
        assert result.approval_count < 2
