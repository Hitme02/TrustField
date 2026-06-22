import hmac
import hashlib
import struct
import serial
import time

SECRET_KEY = b"my_secret_key_32bytes_padded!!!!"  # must match STM exactly

def build_token():
    token_id    = b'\x01' * 16
    origin_hash = b'\x02' * 8
    target_hash = b'\x03' * 8
    depth       = 4
    max_depth   = 6
    timestamp   = int(time.time())   #  real synced time
    ttl         = 300
    nonce       = b'\x04' * 8
    edge_type   = 1
    strictness  = 1

    message = struct.pack(
        "<16s8s8sBBIH8sBB",
        token_id, origin_hash, target_hash,
        depth, max_depth, timestamp, ttl,
        nonce, edge_type, strictness
    )

    assert len(message) == 50, f"Expected 50, got {len(message)}"

    mac = hmac.new(SECRET_KEY, message, hashlib.sha256).digest()

    payload = message + mac
    print("Computed HMAC:", mac.hex())
    print("Timestamp:", timestamp)

    return payload


# Open serial
ser = serial.Serial('COM6', 115200, timeout=2)
time.sleep(2)

current_time = int(time.time())
print("Syncing time:", current_time)

ser.write(b'T')  # identifier
ser.write(struct.pack("<I", current_time))

time.sleep(0.5)  # allow STM to process

# Read STM response 
print("STM:", ser.read_all())


payload = build_token()

#  First send
print("Sending first time...")

for b in payload:
    ser.write(bytes([b]))
    time.sleep(0.001)

time.sleep(1)
print("STM:", ser.read_all().decode(errors="ignore"))

#  Second send (same payload)
print("Sending second time (replay)...")
for b in payload:
    ser.write(bytes([b]))
    time.sleep(0.001)

time.sleep(1)  # wait for STM processing

response = ser.read_all()
print("STM Response:", response.decode(errors="ignore"))