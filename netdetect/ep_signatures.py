"""
Native Entry Point pattern matching engine (Phase 14).
Supports PEiD-style byte patterns with wildcards ('??') to detect native packers and protectors.
"""

from typing import List, Dict, Any, Optional
import re


NATIVE_EP_PATTERNS = [
    {
        "name": "UPX",
        "pattern": "60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB",
        "description": "Standard UPX decompression stub (pushad; mov esi, ...)",
    },
    {
        "name": "MPRESS",
        "pattern": "60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ??",
        "description": "MPRESS unpacker prologue (pushad; call +0; pop ebp)",
    },
    {
        "name": "Themida / WinLicense",
        "pattern": "B8 00 00 00 00 60 0B C0 74 08 E8 ?? ?? ?? ?? 58",
        "description": "Themida / WinLicense native entry point dispatcher",
    },
    {
        "name": "Enigma Protector",
        "pattern": "60 E8 00 00 00 00 58 83 E8 ?? 50 83 C0 ?? 50",
        "description": "Enigma Protector anti-tamper startup sequence",
    },
    {
        "name": "VMProtect",
        "pattern": "68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C3",
        "description": "VMProtect stub entry (push addr; call dispatcher; ret)",
    },
    {
        "name": "ASPack",
        "pattern": "60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 8B C5",
        "description": "ASPack compressor unpacker sequence",
    },
]


def _compile_peid_pattern(pat_str: str) -> re.Pattern:
    """
    Converts a space-separated hex pattern with '??' wildcards into a compiled regex.
    """
    tokens = pat_str.strip().split()
    parts = []
    for t in tokens:
        if t == "??" or t == "?":
            parts.append(b".")
        else:
            val = int(t, 16)
            parts.append(re.escape(bytes([val])))
    return re.compile(b"".join(parts), re.DOTALL)


class EntryPointMatcher:
    def __init__(self):
        self._compiled = []
        for entry in NATIVE_EP_PATTERNS:
            try:
                rx = _compile_peid_pattern(entry["pattern"])
                self._compiled.append({
                    "name": entry["name"],
                    "regex": rx,
                    "description": entry["description"],
                })
            except Exception:
                continue

    def match(self, ep_bytes: bytes) -> Optional[Dict[str, Any]]:
        """
        Matches up to 64 bytes at the native entry point against known packer patterns.
        """
        if not ep_bytes:
            return None

        # Check against first 64 bytes
        sample = ep_bytes[:64]
        for item in self._compiled:
            if item["regex"].match(sample):
                return {
                    "name": item["name"],
                    "description": item["description"],
                }
        return None
