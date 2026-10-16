"""
PE Overlay inspection and embedded container detection (Phase 14).
Scans appended data beyond the last section for archives (ZIP, 7z, RAR),
embedded executables (MZ), and virtualized container headers (Enigma, BoxedApp).
"""

from typing import List, Dict, Any


def inspect_overlay(overlay_bytes: bytes) -> List[Dict[str, Any]]:
    """
    Inspects raw overlay bytes for signatures of embedded payloads.
    """
    if not overlay_bytes or len(overlay_bytes) < 4:
        return []

    findings: List[Dict[str, Any]] = []

    # 1. ZIP Archive (PK\x03\x04 or PK\x05\x06 empty)
    if overlay_bytes.startswith(b"PK\x03\x04") or overlay_bytes.startswith(b"PK\x05\x06"):
        findings.append({
            "type": "ZIP Archive",
            "magic": "PK",
            "details": "Overlay contains a standard ZIP archive (Costura, AppHost, or embedded assets).",
        })

    # 2. 7-Zip Archive (7z\xBC\xAF\x27\x1C)
    elif overlay_bytes.startswith(b"7z\xbc\xaf\x27\x1c"):
        findings.append({
            "type": "7-Zip Archive",
            "magic": "7z",
            "details": "Overlay contains a 7-Zip compressed archive container.",
        })

    # 3. RAR Archive (Rar!\x1A\x07)
    elif overlay_bytes.startswith(b"Rar!\x1a\x07"):
        findings.append({
            "type": "RAR Archive",
            "magic": "Rar!",
            "details": "Overlay contains a RAR archive container.",
        })

    # 4. Embedded Portable Executable (MZ)
    elif overlay_bytes.startswith(b"MZ"):
        findings.append({
            "type": "Embedded PE Executable",
            "magic": "MZ",
            "details": "Overlay contains a nested Windows Portable Executable (dropper or packed payload).",
        })

    # 5. Enigma Virtual Box
    if b"EVB\x00" in overlay_bytes[:256] or b"BoxedApp" in overlay_bytes[:256]:
        findings.append({
            "type": "Virtual File System Container",
            "magic": "EVB/BoxedApp",
            "details": "Overlay contains Enigma Virtual Box or BoxedApp virtualization filesystem.",
        })

    return findings
