"""
Unit tests for ECMA-335 CIL method body decoder and IL heuristics (Phase 13 / 16).
Tests tiny/fat header parsing, opcode disassembly, switch target parsing, and CFF/stub heuristics.
"""

import struct
from netdetect.il import (
    read_method_body,
    iter_instructions,
    analyze_method_il,
)


class MockPE:
    def __init__(self, data_map):
        self.data_map = data_map

    def get_data(self, rva, size):
        for start_rva, buf in self.data_map.items():
            if start_rva <= rva < start_rva + len(buf):
                offset = rva - start_rva
                return buf[offset : offset + size]
        return b""


def test_tiny_header_parsing():
    # Tiny header: low 2 bits are 0x02, top 6 bits are code size
    code = b"\x00\x2a"  # nop; ret
    header_byte = 0x02 | (len(code) << 2)
    raw = bytes([header_byte]) + code

    pe = MockPE({0x1000: raw})
    body = read_method_body(pe, 0x1000)

    assert body is not None
    assert body["type"] == "tiny"
    assert body["code_size"] == 2
    assert body["code"] == code


def test_fat_header_parsing():
    code = b"\x17\x18\x58\x2a"  # ldc.i4.1; ldc.i4.2; add; ret
    code_size = len(code)
    # Fat header: flags=3, size=3 (3*4=12 bytes) -> 0x3003
    header = struct.pack("<HHII", 0x3003, 8, code_size, 0x11000001)
    raw = header + code

    pe = MockPE({0x2000: raw})
    body = read_method_body(pe, 0x2000)

    assert body is not None
    assert body["type"] == "fat"
    assert body["code_size"] == code_size
    assert body["max_stack"] == 8
    assert body["local_var_sig_tok"] == 0x11000001
    assert body["code"] == code


def test_iter_instructions_single_byte_and_two_byte():
    # nop (0x00), ldc.i4.5 (0x1B), fe 01 (ceq), ret (0x2A)
    code = b"\x00\x1b\xfe\x01\x2a"
    insns = iter_instructions(code)

    assert len(insns) == 4
    assert insns[0][1] == "nop"
    assert insns[1][1] == "ldc.i4.5"
    assert insns[2][1] == "ceq"
    assert insns[3][1] == "ret"


def test_iter_instructions_switch():
    # switch with 3 targets: 0x45, count=3, targets=[10, 20, 30]
    switch_data = b"\x45" + struct.pack("<Iiii", 3, 10, 20, 30) + b"\x2a"
    insns = iter_instructions(switch_data)

    assert len(insns) == 2
    assert insns[0][1] == "switch"
    assert insns[0][2] == [10, 20, 30]
    assert insns[1][1] == "ret"


def test_analyze_method_il_empty_stub():
    # Just ret
    res = analyze_method_il(b"\x2a")
    assert res["is_empty_stub"] is True
    assert res["instruction_count"] == 1

    # nop; ret
    res_nop_ret = analyze_method_il(b"\x00\x2a")
    assert res_nop_ret["is_empty_stub"] is True


def test_analyze_method_il_cff():
    # Construct flattened dispatch: switch with 8 targets + arithmetic ops + length >= 20
    switch_part = b"\x45" + struct.pack("<I" + "i" * 8, 8, 1, 2, 3, 4, 5, 6, 7, 8)
    # add some arithmetic (xor: 0x61, mul: 0x5a) and nops to reach >= 20 instructions
    body = switch_part + (b"\x00" * 20) + b"\x61\x5a\x2a"
    res = analyze_method_il(body)

    assert res["has_cff"] is True
    assert len(res["switch_cases"]) == 1
    assert res["switch_cases"][0] == 8
