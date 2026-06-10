#!/usr/bin/env python3
"""
generate_seeds.py  –  produce binary seed corpus files for the fuzzer.

Each seed is a syntactically valid (or near-valid) packet that exercises
a different code path.  The fuzzer will mutate these to find crashes.
"""

import struct, os, pathlib

OUT = pathlib.Path("corpus/seeds")
OUT.mkdir(parents=True, exist_ok=True)

MAGIC = 0xDEAD

def make_packet(version, fields, label=b"test\x00"):
    """fields: list of (type:int, value:bytes)"""
    body = struct.pack(">HBB", MAGIC, version, len(fields))
    for ftype, fval in fields:
        body += struct.pack(">BH", ftype, len(fval)) + fval
    body += label
    return body

# Seed 0: minimal valid packet, no fields
s0 = make_packet(1, [], b"minimal\x00")
(OUT / "seed_minimal.bin").write_bytes(s0)

# Seed 1: single short field
s1 = make_packet(1, [(0x01, b"hello")], b"one_field\x00")
(OUT / "seed_one_field.bin").write_bytes(s1)

# Seed 2: max valid fields (16)
s2 = make_packet(1, [(i, bytes([i]*4)) for i in range(16)], b"max_fields\x00")
(OUT / "seed_max_fields.bin").write_bytes(s2)

# Seed 3: field length near MAX_FIELD_LEN boundary
s3 = make_packet(1, [(0x01, b"A"*63), (0x02, b"B"*64)], b"boundary\x00")
(OUT / "seed_boundary_len.bin").write_bytes(s3)

# Seed 4: num_fields = 17  →  triggers BUG-2 immediately
s4_header = struct.pack(">HBB", MAGIC, 1, 17)   # claim 17 fields
# provide 17 fields actually in the wire
s4_fields = b""
for i in range(17):
    s4_fields += struct.pack(">BH", i, 2) + bytes([i, i])
(OUT / "seed_overflow_fields.bin").write_bytes(s4_header + s4_fields + b"lbl\x00")

# Seed 5: label = 33 bytes (1 over label[] size)  →  triggers BUG-5
s5 = make_packet(1, [], b"A"*33 + b"\x00")
(OUT / "seed_long_label.bin").write_bytes(s5)

# Seed 6: flen = 256  →  triggers BUG-1 (uint8_t truncation → 0)
s6_body = struct.pack(">HBB", MAGIC, 1, 1)
s6_body += struct.pack(">BH", 0xAA, 256) + b"X"*256
s6_body += b"trunc\x00"
(OUT / "seed_flen_256.bin").write_bytes(s6_body)

print(f"Wrote {len(list(OUT.iterdir()))} seed files to {OUT}/")
for f in sorted(OUT.iterdir()):
    print(f"  {f.name}  ({f.stat().st_size} bytes)")
