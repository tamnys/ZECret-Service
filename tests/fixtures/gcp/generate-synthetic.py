#!/usr/bin/env python3
"""Generate unmistakably synthetic parser inputs, never approval material.

Run only in the managed build container. Uses standard hashlib and struct;
the resulting values are unit-test examples, not actual artifact measurements.
"""
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parent
u32 = lambda n: struct.pack("<I", n)
spec = b"Spec ID Event03\0" + u32(0) + bytes([0, 2, 0, 2]) + u32(1) + struct.pack("<HHB", 12, 48, 0)
ccel = u32(1) + u32(3) + bytes(20) + u32(len(spec)) + spec
registers = [bytes(48) for _ in range(4)]
events = []
for index, kind, data in [
    (1, 0x80000001, b"SYNTHETIC_BOOT_POLICY"),
    (2, 0x80000003, b"SYNTHETIC_UKI_DESCRIPTOR"),
    (3, 13, b"SYNTHETIC_KERNEL"),
]:
    digest = hashlib.sha384(data).digest()
    ccel += u32(index) + u32(kind) + u32(1) + struct.pack("<H", 12) + digest + u32(len(data)) + data
    registers[index - 1] = hashlib.sha384(registers[index - 1] + digest).digest()
    events.append(dict(mr_index=index, event_type=kind, digest_sha384=digest.hex(), event_data_sha256=hashlib.sha256(data).hexdigest()))
policy = dict(schema_version=1, mrtd=(bytes([1]) * 48).hex(),
    spec_id_sha256=hashlib.sha256(spec).hexdigest(), uki_event_index=1,
    expected_events=events)
policy.update({f"rtmr{i}": value.hex() for i, value in enumerate(registers)})
artifact_fields = ["firmware_endorsement_sha256", "uki_sha256", "rootfs_verity_sha256", "kernel_command_line_sha256", "boot_policy_sha256", "wrapper_sha256", "zebra_sha256", "quote_broker_sha256", "measurement_recipe_sha256"]
policy["artifacts"] = {key: (bytes([i + 1]) * 32).hex() for i, key in enumerate(artifact_fields)}
policy["artifacts"]["uki_pe_coff_sha384"] = events[1]["digest_sha384"]
(ROOT / "policy.synthetic.json").write_text(json.dumps(policy, indent=2) + "\n")
(ROOT / "ccel.synthetic.bin").write_bytes(ccel)
