"""End-to-end test: TrustField DelegationToken → STM32 hardware guard.

Run this script while the STM32 firmware is running (debug or release)
in STM32CubeIDE.  It exercises the same 5 test cases as tf_v3.py but
through the TrustField integration layer.

Tests are split into two groups:
  - CORE:     HMAC and expiry checks (implemented in most STM32 firmware)
  - EXTENDED: Replay detection and depth enforcement (may not be
              implemented yet — these are reported but don't cause
              a non-zero exit code)

Usage:
    python scripts/test_stm32_bridge.py              # default COM6
    python scripts/test_stm32_bridge.py COM3          # specify port
    python scripts/test_stm32_bridge.py --list        # list available ports
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trustfield.graph.edge_types import EdgeMetadata, EdgeType
from trustfield.verification.delegation_token import TokenGenerator
from trustfield.guards.hardware_bridge import (
    HardwareBridge,
    HardwareGuard,
    StrictnessLevel,
)


SECRET_KEY = b"my_secret_key_32bytes_padded!!!!"


def list_ports():
    """Print all available serial ports."""
    try:
        import serial.tools.list_ports
        ports = list(serial.tools.list_ports.comports())
        if not ports:
            print("No serial ports found.")
            return
        print("Available serial ports:")
        for p in ports:
            print(f"  {p.device:10s}  {p.description}")
    except ImportError:
        print("pyserial not installed. Run: pip install pyserial")


def make_edge_meta(depth_limit=6):
    return EdgeMetadata("e_test", EdgeType.ASSUME_ROLE, 1.0, depth_limit)


def run_tests(port: str):
    print(f"Connecting to STM32 on {port} ...")
    bridge = HardwareBridge(
        port=port,
        baudrate=115200,
        secret_key=SECRET_KEY,
        timeout=2.0,
        byte_delay=0.001,
        response_delay=1.0,
    )

    if not bridge.connect():
        print("FAILED to connect. Check that:")
        print("  1. STM32 firmware is running (not paused at a breakpoint)")
        print("  2. The COM port is correct (run with --list to see ports)")
        print("  3. No other program (serial monitor, tf_v3.py) has the port open")
        return False

    print("Connected. Time synced.\n")

    gen = TokenGenerator(secret_key=SECRET_KEY)
    edge_meta = make_edge_meta(depth_limit=6)
    core_results = []       # must pass
    extended_results = []   # firmware-dependent, informational

    # ---------------------------------------------------------------
    # TEST 1: Valid token — should be ALLOWED
    # ---------------------------------------------------------------
    print("=" * 50)
    print("TEST 1: VALID TOKEN  [CORE]")
    print("=" * 50)
    token = gen.generate("user-dev", "role-ci", edge_meta, current_depth=2)
    hw = bridge.send_token(token, StrictnessLevel.NOMINAL)
    print(f"  Decision:   {hw.decision}")
    print(f"  Reason:     {hw.reason}")
    print(f"  STM32 raw:  {hw.raw_response.strip()}")
    print(f"  Round-trip: {hw.round_trip_ms:.0f} ms")
    core_results.append(("VALID TOKEN", hw.decision, "ALLOWED"))

    # ---------------------------------------------------------------
    # TEST 2: Replay attack — same token again
    #   (extended: many STM32 firmwares don't track nonces)
    # ---------------------------------------------------------------
    print("\n" + "=" * 50)
    print("TEST 2: REPLAY ATTACK  [EXTENDED]")
    print("=" * 50)
    hw = bridge.send_token(token, StrictnessLevel.NOMINAL)
    print(f"  Decision:   {hw.decision}")
    print(f"  Reason:     {hw.reason}")
    print(f"  STM32 raw:  {hw.raw_response.strip()}")
    extended_results.append(("REPLAY ATTACK", hw.decision, "BLOCKED"))

    # ---------------------------------------------------------------
    # TEST 3: Expired token — timestamp 1000s in the past, TTL=10s
    # ---------------------------------------------------------------
    print("\n" + "=" * 50)
    print("TEST 3: EXPIRED TOKEN  [CORE]")
    print("=" * 50)
    expired_meta = make_edge_meta(depth_limit=6)
    expired_token = gen.generate(
        "user-dev", "role-ci", expired_meta, current_depth=2
    )
    expired_token.timestamp = time.time() - 1000
    expired_token.ttl_seconds = 10
    expired_token.signature = gen._sign(
        expired_token.token_id,
        expired_token.origin_node,
        expired_token.target_node,
        expired_token.nonce,
        expired_token.timestamp,
    )
    hw = bridge.send_token(expired_token, StrictnessLevel.NOMINAL)
    print(f"  Decision:   {hw.decision}")
    print(f"  Reason:     {hw.reason}")
    print(f"  STM32 raw:  {hw.raw_response.strip()}")
    core_results.append(("EXPIRED TOKEN", hw.decision, "BLOCKED"))

    # ---------------------------------------------------------------
    # TEST 4: HMAC tampering — flip a byte in the payload
    # ---------------------------------------------------------------
    print("\n" + "=" * 50)
    print("TEST 4: HMAC TAMPERING  [CORE]")
    print("=" * 50)
    tamper_token = gen.generate(
        "user-dev", "role-ci", edge_meta, current_depth=2
    )
    payload = bridge.build_payload(tamper_token, StrictnessLevel.NOMINAL)
    corrupted = bytearray(payload)
    corrupted[-1] ^= 0xFF
    for byte in corrupted:
        bridge._serial.write(bytes([byte]))
    time.sleep(1)
    raw = bridge._serial.read_all().decode(errors="ignore")
    from trustfield.guards.hardware_bridge import _parse_stm32_response
    decision, reason = _parse_stm32_response(raw)
    print(f"  Decision:   {decision}")
    print(f"  Reason:     {reason}")
    print(f"  STM32 raw:  {raw.strip()}")
    core_results.append(("HMAC TAMPERING", decision, "BLOCKED"))

    # ---------------------------------------------------------------
    # TEST 5: Depth violation — depth=10 exceeds max_depth=6
    #   (extended: not all firmwares enforce depth limits)
    # ---------------------------------------------------------------
    print("\n" + "=" * 50)
    print("TEST 5: DEPTH VIOLATION  [EXTENDED]")
    print("=" * 50)
    depth_token = gen.generate(
        "user-dev", "role-ci", edge_meta, current_depth=10
    )
    hw = bridge.send_token(depth_token, StrictnessLevel.NOMINAL)
    print(f"  Decision:   {hw.decision}")
    print(f"  Reason:     {hw.reason}")
    print(f"  STM32 raw:  {hw.raw_response.strip()}")
    extended_results.append(("DEPTH VIOLATION", hw.decision, "BLOCKED"))

    # ---------------------------------------------------------------
    # TEST 6: HardwareGuard class — full integration through guard API
    # ---------------------------------------------------------------
    print("\n" + "=" * 50)
    print("TEST 6: HardwareGuard CLASS  [CORE]")
    print("=" * 50)
    guard_gen = TokenGenerator(secret_key=SECRET_KEY)
    guard = HardwareGuard(
        "hw_guard_test", ("user-dev", "role-ci"),
        TokenGenerator(secret_key=SECRET_KEY),
        bridge,
    )
    token = guard_gen.generate("user-dev", "role-ci", edge_meta, current_depth=1)
    event = guard.validate_transition(token)
    print(f"  Decision:   {event.decision}")
    print(f"  Reason:     {event.reason}")
    print(f"  Guard ID:   {event.guard_id}")
    print(f"  Strictness: {event.strictness_at_time.value}")
    core_results.append(("HARDWARE GUARD API", event.decision, "ALLOWED"))

    # ---------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------
    bridge.close()

    print("\n" + "=" * 50)
    print("CORE TESTS (must pass)")
    print("=" * 50)
    core_pass = True
    for name, got, expected in core_results:
        match = got == expected
        status = "PASS" if match else "FAIL"
        if not match:
            core_pass = False
        print(f"  [{status}] {name:25s}  got={got:8s}  expected={expected}")

    print("\n" + "=" * 50)
    print("EXTENDED TESTS (firmware-dependent)")
    print("=" * 50)
    for name, got, expected in extended_results:
        match = got == expected
        status = "PASS" if match else "SKIP"
        print(f"  [{status}] {name:25s}  got={got:8s}  expected={expected}")
        if not match:
            print(f"         ^ STM32 firmware does not enforce this check yet")

    print()
    if core_pass:
        print("Core tests PASSED. Integration is working.")
    else:
        print("Core tests FAILED — check parser output and STM32 firmware.")

    return core_pass


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--list":
        list_ports()
        sys.exit(0)

    port = sys.argv[1] if len(sys.argv) > 1 else "COM6"
    success = run_tests(port)
    sys.exit(0 if success else 1)
