"""
ECMA-335 CIL (Common Intermediate Language) method body decoder and IL heuristics (Phase 13).
Extracts method body bytes, parses instructions, and detects control-flow flattening (CFF),
VM interpreter loops, string decryptor call clusters, and proxy call delegates.
"""

from typing import List, Dict, Any, Optional, Tuple
from collections import Counter
import struct

# Operand types and their byte lengths
_OPERAND_SIZES = {
    "InlineNone": 0,
    "ShortInlineI": 1,
    "ShortInlineR": 4,
    "ShortInlineVar": 1,
    "ShortInlineBrTarget": 1,
    "InlineVar": 2,
    "InlineI": 4,
    "InlineR": 8,
    "InlineI8": 8,
    "InlineMethod": 4,
    "InlineField": 4,
    "InlineType": 4,
    "InlineString": 4,
    "InlineSig": 4,
    "InlineTok": 4,
    "InlineBrTarget": 4,
}

# 1-byte opcodes table: opcode_byte -> (name, operand_type)
_ONE_BYTE_OPCODES = {
    0x00: ("nop", "InlineNone"),
    0x01: ("break", "InlineNone"),
    0x02: ("ldarg.0", "InlineNone"),
    0x03: ("ldarg.1", "InlineNone"),
    0x04: ("ldarg.2", "InlineNone"),
    0x05: ("ldarg.3", "InlineNone"),
    0x06: ("ldloc.0", "InlineNone"),
    0x07: ("ldloc.1", "InlineNone"),
    0x08: ("ldloc.2", "InlineNone"),
    0x09: ("ldloc.3", "InlineNone"),
    0x0A: ("stloc.0", "InlineNone"),
    0x0B: ("stloc.1", "InlineNone"),
    0x0C: ("stloc.2", "InlineNone"),
    0x0D: ("stloc.3", "InlineNone"),
    0x0E: ("ldarg.s", "ShortInlineVar"),
    0x0F: ("ldarga.s", "ShortInlineVar"),
    0x10: ("starg.s", "ShortInlineVar"),
    0x11: ("ldloc.s", "ShortInlineVar"),
    0x12: ("ldloca.s", "ShortInlineVar"),
    0x13: ("stloc.s", "ShortInlineVar"),
    0x14: ("ldnull", "InlineNone"),
    0x15: ("ldc.i4.m1", "InlineNone"),
    0x16: ("ldc.i4.0", "InlineNone"),
    0x17: ("ldc.i4.1", "InlineNone"),
    0x18: ("ldc.i4.2", "InlineNone"),
    0x19: ("ldc.i4.3", "InlineNone"),
    0x1A: ("ldc.i4.4", "InlineNone"),
    0x1B: ("ldc.i4.5", "InlineNone"),
    0x1C: ("ldc.i4.6", "InlineNone"),
    0x1D: ("ldc.i4.7", "InlineNone"),
    0x1E: ("ldc.i4.8", "InlineNone"),
    0x1F: ("ldc.i4.s", "ShortInlineI"),
    0x20: ("ldc.i4", "InlineI"),
    0x21: ("ldc.i8", "InlineI8"),
    0x22: ("ldc.r4", "ShortInlineR"),
    0x23: ("ldc.r8", "InlineR"),
    0x25: ("dup", "InlineNone"),
    0x26: ("pop", "InlineNone"),
    0x27: ("jmp", "InlineMethod"),
    0x28: ("call", "InlineMethod"),
    0x29: ("calli", "InlineSig"),
    0x2A: ("ret", "InlineNone"),
    0x2B: ("br.s", "ShortInlineBrTarget"),
    0x2C: ("brfalse.s", "ShortInlineBrTarget"),
    0x2D: ("brtrue.s", "ShortInlineBrTarget"),
    0x2E: ("beq.s", "ShortInlineBrTarget"),
    0x2F: ("bge.s", "ShortInlineBrTarget"),
    0x30: ("bgt.s", "ShortInlineBrTarget"),
    0x31: ("ble.s", "ShortInlineBrTarget"),
    0x32: ("blt.s", "ShortInlineBrTarget"),
    0x33: ("bne.un.s", "ShortInlineBrTarget"),
    0x34: ("bge.un.s", "ShortInlineBrTarget"),
    0x35: ("bgt.un.s", "ShortInlineBrTarget"),
    0x36: ("ble.un.s", "ShortInlineBrTarget"),
    0x37: ("blt.un.s", "ShortInlineBrTarget"),
    0x38: ("br", "InlineBrTarget"),
    0x39: ("brfalse", "InlineBrTarget"),
    0x3A: ("brtrue", "InlineBrTarget"),
    0x3B: ("beq", "InlineBrTarget"),
    0x3C: ("bge", "InlineBrTarget"),
    0x3D: ("bgt", "InlineBrTarget"),
    0x3E: ("ble", "InlineBrTarget"),
    0x3F: ("blt", "InlineBrTarget"),
    0x40: ("bne.un", "InlineBrTarget"),
    0x41: ("bge.un", "InlineBrTarget"),
    0x42: ("bgt.un", "InlineBrTarget"),
    0x43: ("ble.un", "InlineBrTarget"),
    0x44: ("blt.un", "InlineBrTarget"),
    0x45: ("switch", "InlineSwitch"),
    0x58: ("add", "InlineNone"),
    0x59: ("sub", "InlineNone"),
    0x5A: ("mul", "InlineNone"),
    0x5B: ("div", "InlineNone"),
    0x5C: ("div.un", "InlineNone"),
    0x5D: ("rem", "InlineNone"),
    0x5E: ("rem.un", "InlineNone"),
    0x5F: ("and", "InlineNone"),
    0x60: ("or", "InlineNone"),
    0x61: ("xor", "InlineNone"),
    0x62: ("shl", "InlineNone"),
    0x63: ("shr", "InlineNone"),
    0x64: ("shr.un", "InlineNone"),
    0x65: ("neg", "InlineNone"),
    0x66: ("not", "InlineNone"),
    0x6F: ("callvirt", "InlineMethod"),
    0x72: ("ldstr", "InlineString"),
    0x73: ("newobj", "InlineMethod"),
    0x74: ("castclass", "InlineType"),
    0x75: ("isinst", "InlineType"),
    0x79: ("unbox", "InlineType"),
    0x7A: ("throw", "InlineNone"),
    0x7B: ("ldfld", "InlineField"),
    0x7C: ("ldflda", "InlineField"),
    0x7D: ("stfld", "InlineField"),
    0x7E: ("ldsfld", "InlineField"),
    0x7F: ("ldsflda", "InlineField"),
    0x80: ("stsfld", "InlineField"),
    0x8C: ("box", "InlineType"),
    0x8D: ("newarr", "InlineType"),
    0x8E: ("ldlen", "InlineNone"),
    0xA3: ("leave", "InlineBrTarget"),
    0xDE: ("leave.s", "ShortInlineBrTarget"),
}

# 2-byte opcodes with prefix 0xFE
_TWO_BYTE_OPCODES = {
    0x01: ("ceq", "InlineNone"),
    0x02: ("cgt", "InlineNone"),
    0x03: ("cgt.un", "InlineNone"),
    0x04: ("clt", "InlineNone"),
    0x05: ("clt.un", "InlineNone"),
    0x06: ("ldftn", "InlineMethod"),
    0x07: ("ldvirtftn", "InlineMethod"),
    0x09: ("ldarg", "InlineVar"),
    0x0A: ("ldarga", "InlineVar"),
    0x0B: ("starg", "InlineVar"),
    0x0C: ("ldloc", "InlineVar"),
    0x0D: ("ldloca", "InlineVar"),
    0x0E: ("stloc", "InlineVar"),
    0x14: ("unaligned.", "ShortInlineI"),
    0x15: ("volatile.", "InlineNone"),
    0x16: ("tail.", "InlineNone"),
    0x17: ("initobj", "InlineType"),
    0x19: ("constrained.", "InlineType"),
    0x1A: ("cpblk", "InlineNone"),
    0x1B: ("initblk", "InlineNone"),
    0x1E: ("rethrow", "InlineNone"),
    0x22: ("readonly.", "InlineNone"),
}


def read_method_body(pe: Any, rva: int) -> Optional[Dict[str, Any]]:
    """
    Parses the ECMA-335 method header at the given RVA and returns the raw CIL code.
    Returns None if RVA is 0 or header is invalid.
    """
    if not rva or rva == 0:
        return None

    try:
        # Read leading bytes for header inspection
        raw = pe.get_data(rva, 16)
        if not raw or len(raw) < 1:
            return None

        header_byte = raw[0]
        header_type = header_byte & 0x03

        if header_type == 0x02:  # Tiny header
            code_size = header_byte >> 2
            code = pe.get_data(rva + 1, code_size)
            return {
                "type": "tiny",
                "code_size": code_size,
                "max_stack": 8,
                "local_var_sig_tok": 0,
                "code": code,
            }

        elif header_type == 0x03:  # Fat header
            if len(raw) < 12:
                return None
            flags_size, max_stack, code_size, local_sig = struct.unpack("<HHII", raw[:12])
            header_size = (flags_size >> 12) * 4
            if header_size < 12:
                header_size = 12
            code = pe.get_data(rva + header_size, code_size)
            return {
                "type": "fat",
                "code_size": code_size,
                "max_stack": max_stack,
                "local_var_sig_tok": local_sig,
                "code": code,
            }
    except Exception:
        return None

    return None


def iter_instructions(code: bytes) -> List[Tuple[int, str, Any]]:
    """
    Disassembles CIL byte code into a list of (offset, opcode_name, operand).
    """
    if not code:
        return []

    instructions: List[Tuple[int, str, Any]] = []
    offset = 0
    code_len = len(code)

    while offset < code_len:
        curr_offset = offset
        b = code[offset]
        offset += 1

        if b == 0xFE:
            if offset >= code_len:
                break
            b2 = code[offset]
            offset += 1
            op_info = _TWO_BYTE_OPCODES.get(b2, (f"unknown.fe.{b2:02x}", "InlineNone"))
        else:
            op_info = _ONE_BYTE_OPCODES.get(b, (f"unknown.{b:02x}", "InlineNone"))

        op_name, op_type = op_info
        operand = None

        if op_type == "InlineSwitch":
            if offset + 4 <= code_len:
                count = struct.unpack("<I", code[offset : offset + 4])[0]
                offset += 4
                targets = []
                for _ in range(count):
                    if offset + 4 <= code_len:
                        t = struct.unpack("<i", code[offset : offset + 4])[0]
                        targets.append(t)
                        offset += 4
                    else:
                        break
                operand = targets
        else:
            sz = _OPERAND_SIZES.get(op_type, 0)
            if sz > 0 and offset + sz <= code_len:
                if sz == 1:
                    operand = code[offset]
                elif sz == 2:
                    operand = struct.unpack("<H", code[offset : offset + 2])[0]
                elif sz == 4:
                    operand = struct.unpack("<I", code[offset : offset + 4])[0]
                elif sz == 8:
                    operand = struct.unpack("<Q", code[offset : offset + 8])[0]
                offset += sz

        instructions.append((curr_offset, op_name, operand))

    return instructions


def analyze_method_il(code: bytes) -> Dict[str, Any]:
    """
    Analyzes instructions in a single method body for structural obfuscation indicators.
    """
    insns = iter_instructions(code)
    op_counts = Counter(op for _, op, _ in insns)

    switch_cases: List[int] = []
    call_targets: List[int] = []
    ldc_call_pairs = 0
    calli_count = op_counts.get("calli", 0)

    for i, (_, op, operand) in enumerate(insns):
        if op == "switch" and isinstance(operand, list):
            switch_cases.append(len(operand))
        elif op in ("call", "callvirt", "newobj") and isinstance(operand, int):
            call_targets.append(operand)
            # Check for ldc (int or string) immediately preceding call
            if i > 0 and insns[i - 1][1].startswith("ldc."):
                ldc_call_pairs += 1

    # Control flow flattening pattern:
    # A method with a switch, loop jumps (backward branches), and arithmetic ops (xor, mul, rem, sub)
    has_cff = False
    if switch_cases and len(insns) >= 20:
        has_arith = any(op in op_counts for op in ("xor", "mul", "rem", "rem.un", "sub"))
        has_backward_br = any(
            op.startswith("br") and isinstance(operand, int) and operand < 0
            for _, op, operand in insns
        )
        if has_arith or has_backward_br or any(c >= 8 for c in switch_cases):
            has_cff = True

    # Empty stub pattern: just 'ret', or 'ldnull; throw'
    is_empty_stub = False
    if len(insns) <= 2:
        names = [op for _, op, _ in insns]
        if names == ["ret"] or names == ["nop", "ret"] or "throw" in names:
            is_empty_stub = True

    return {
        "instruction_count": len(insns),
        "op_counts": op_counts,
        "switch_cases": switch_cases,
        "call_targets": call_targets,
        "calli_count": calli_count,
        "ldc_call_pairs": ldc_call_pairs,
        "has_cff": has_cff,
        "is_empty_stub": is_empty_stub,
    }


def evaluate_assembly_il(pe: Any, method_rows: List[Any], max_methods: int = 2500) -> Dict[str, Any]:
    """
    Decodes method bodies across the assembly up to a budget and computes global IL metrics.
    """
    analyzed = 0
    cff_count = 0
    empty_stub_count = 0
    calli_total = 0
    max_cases = 0
    all_call_targets: Counter = Counter()

    for m in method_rows[:max_methods]:
        rva = getattr(m, "Rva", 0)
        if rva == 0:
            continue
        try:
            body = read_method_body(pe, rva)
            if not body or not body.get("code"):
                continue
            res = analyze_method_il(body["code"])
            analyzed += 1

            if res["has_cff"]:
                cff_count += 1
            if res["is_empty_stub"]:
                empty_stub_count += 1
            calli_total += res["calli_count"]
            if res["switch_cases"]:
                max_cases = max(max_cases, max(res["switch_cases"]))
            all_call_targets.update(res["call_targets"])
        except Exception:
            continue

    # Detect high string decryptor call clusters: single token called >= 25 times
    decryptor_target = None
    if all_call_targets:
        most_common_tok, hits = all_call_targets.most_common(1)[0]
        if hits >= 25:
            decryptor_target = (most_common_tok, hits)

    cff_ratio = round(cff_count / max(analyzed, 1), 3)

    return {
        "methods_analyzed": analyzed,
        "cff_count": cff_count,
        "cff_ratio": cff_ratio,
        "max_switch_cases": max_cases,
        "calli_total": calli_total,
        "empty_stub_count": empty_stub_count,
        "decryptor_target": decryptor_target,
    }
