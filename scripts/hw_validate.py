"""Hardware validation subprocess — mirrors test_stm32_bridge.py exactly.

Usage:
    python scripts/hw_validate.py COM6 user-dev,role-ci role-ci,svc-api
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trustfield.graph.edge_types import EdgeMetadata, EdgeType
from trustfield.verification.delegation_token import TokenGenerator
from trustfield.guards.hardware_bridge import HardwareBridge, StrictnessLevel

SECRET_KEY = b"my_secret_key_32bytes_padded!!!!"


def main():
    if len(sys.argv) < 2:
        print('{"error": "usage: hw_validate.py PORT [src,tgt ...]"}')
        sys.exit(1)

    port = sys.argv[1]
    edge_pairs = []
    for arg in sys.argv[2:]:
        parts = arg.split(",", 1)
        if len(parts) == 2:
            edge_pairs.append((parts[0], parts[1]))

    # --- EXACT same setup as test_stm32_bridge.py ---
    bridge = HardwareBridge(
        port=port,
        baudrate=115200,
        secret_key=SECRET_KEY,
        timeout=2.0,
        byte_delay=0.001,
        response_delay=1.0,
    )

    if not bridge.connect():
        print('{"error": "failed to connect"}')
        sys.exit(1)

    # EXACT same token creation as test_stm32_bridge.py TEST 1
    gen = TokenGenerator(secret_key=SECRET_KEY)
    edge_meta = EdgeMetadata("e_test", EdgeType.ASSUME_ROLE, 1.0, 6)

    # First: send THE EXACT standalone test token to prove it works
    token = gen.generate("user-dev", "role-ci", edge_meta, current_depth=2)
    result = bridge.send_token(token, StrictnessLevel.NOMINAL)
    print(json.dumps({
        "decision": result.decision,
        "reason": result.reason,
        "raw": result.raw_response.replace("\r", "").strip(),
        "ms": round(result.round_trip_ms, 1),
        "edge": "user-dev -> role-ci (CONTROL)",
    }))

    # Now send tokens for the requested edges
    for src, tgt in edge_pairs:
        token = gen.generate(src, tgt, edge_meta, current_depth=2)
        result = bridge.send_token(token, StrictnessLevel.NOMINAL)
        print(json.dumps({
            "decision": result.decision,
            "reason": result.reason,
            "raw": result.raw_response.replace("\r", "").strip(),
            "ms": round(result.round_trip_ms, 1),
            "edge": f"{src} -> {tgt}",
        }))

    # Tampered token
    if edge_pairs:
        src, tgt = edge_pairs[0]
        token = gen.generate(src, tgt, edge_meta, current_depth=2)
        payload = bridge.build_payload(token, StrictnessLevel.NOMINAL)
        corrupted = bytearray(payload)
        corrupted[-1] ^= 0xFF
        bridge._serial.reset_input_buffer()
        for b in corrupted:
            bridge._serial.write(bytes([b]))
            time.sleep(0.001)
        bridge._serial.flush()
        time.sleep(1)
        raw = bridge._serial.read_all().decode(errors="ignore")
        from trustfield.guards.hardware_bridge import _parse_stm32_response
        decision, reason = _parse_stm32_response(raw)
        print(json.dumps({
            "decision": decision,
            "reason": reason,
            "raw": raw.replace("\r", "").strip(),
            "ms": 0,
            "edge": f"{src} -> {tgt} (TAMPERED)",
        }))

    bridge.close()


if __name__ == "__main__":
    main()
