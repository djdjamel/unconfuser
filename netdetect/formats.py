"""
Packaging, runtime, and ahead-of-time (AOT) format detection (Phase 14).
Detects:
- .NET Single-File Bundles (.NET Core 3.1, .NET 5/6/7/8/9 AppHost bundles)
- Native AOT (.NET 7/8/9 Native AOT binaries)
- ReadyToRun (R2R) composite/crossgen images
- C++/CLI mixed-mode assemblies
"""

import struct
from typing import Dict, Any, Optional, List


# 32-byte bundle marker: SHA-256 hash of ".net core bundle" string
BUNDLE_MARKER = bytes.fromhex("8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae")


def detect_single_file_bundle(raw_bytes: bytes) -> Optional[Dict[str, Any]]:
    """
    Scans raw PE bytes for the Microsoft .NET Single-File AppHost bundle marker.
    If found, extracts the bundle header offset and file list metadata.
    """
    if not raw_bytes or len(raw_bytes) < 64:
        return None

    # Search for the bundle marker signature
    idx = raw_bytes.find(BUNDLE_MARKER)
    if idx == -1:
        return None

    marker_offset = idx
    # The 8 bytes following the marker contain the int64 bundle manifest offset
    bundle_manifest_offset = None
    if idx + 32 + 8 <= len(raw_bytes):
        try:
            bundle_manifest_offset = struct.unpack("<q", raw_bytes[idx + 32 : idx + 32 + 8])[0]
        except Exception:
            pass

    return {
        "format": ".NET Single-File AppHost Bundle",
        "marker_offset": marker_offset,
        "bundle_manifest_offset": bundle_manifest_offset,
        "details": "Self-contained .NET Single-File bundle with embedded assemblies and host.",
    }


def detect_native_aot(pe: Any, analysis_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Detects .NET Native AOT binaries compiled directly to machine code without a CLR metadata header.
    Indicators:
    - Non-.NET PE header (no CLR Directory entry)
    - Section named '.managed' or 'hydrated'
    - Exported symbol 'DotNetRuntimeDebugHeader'
    """
    if analysis_result.get("is_dotnet", False):
        return None  # Standard managed .NET with CLR header

    sections = [s.get("name", "").lower() for s in analysis_result.get("pe_sections", [])]
    has_managed_sec = any(sec in (".managed", "hydrated", ".clr") for sec in sections)

    has_aot_export = False
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
        for sym in getattr(pe.DIRECTORY_ENTRY_EXPORT, "symbols", []):
            sym_name = str(getattr(sym, "name", b"") or b"")
            if "DotNetRuntimeDebugHeader" in sym_name or "RhRegisterReadyToRunModule" in sym_name:
                has_aot_export = True
                break

    if has_managed_sec or has_aot_export:
        return {
            "format": ".NET Native AOT",
            "has_managed_section": has_managed_sec,
            "has_aot_export": has_aot_export,
            "details": "Ahead-of-Time (AOT) compiled native executable with embedded .NET runtime.",
        }

    return None


def detect_readytorun(dotnet_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Detects ReadyToRun (R2R) precompiled IL+native code images.
    """
    if dotnet_info.get("is_readytorun", False):
        return {
            "format": "ReadyToRun (R2R)",
            "details": "Contains precompiled machine code (crossgen / RTR) alongside managed IL.",
        }
    return None


def detect_mixed_mode(dotnet_info: Dict[str, Any], import_dlls: List[str]) -> Optional[Dict[str, Any]]:
    """
    Detects C++/CLI mixed-mode assemblies (managed IL + unmanaged native C++).
    """
    flags = dotnet_info.get("flags", {})
    ilonly = flags.get("ILOnly", True)
    has_crt = any(dll.startswith("msvcr") or dll.startswith("vcruntime") for dll in import_dlls)

    if not ilonly and has_crt:
        return {
            "format": "C++/CLI Mixed-Mode",
            "details": "Mixed managed/native assembly with CRT runtime dependencies.",
        }
    return None
