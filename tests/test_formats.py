"""
Unit tests for packaging formats, overlay inspection, and native EP signatures (Phase 14 / 16).
"""

import struct
from netdetect.formats import (
    BUNDLE_MARKER,
    detect_single_file_bundle,
    detect_readytorun,
    detect_mixed_mode,
)
from netdetect.overlay import inspect_overlay
from netdetect.ep_signatures import EntryPointMatcher


def test_single_file_bundle_detection():
    # Build a synthetic buffer containing the 32-byte BUNDLE_MARKER + 8-byte manifest offset
    padding = b"\x90" * 128
    manifest_offset = 0x123456
    buf = padding + BUNDLE_MARKER + struct.pack("<q", manifest_offset) + padding

    res = detect_single_file_bundle(buf)
    assert res is not None
    assert res["format"] == ".NET Single-File AppHost Bundle"
    assert res["marker_offset"] == 128
    assert res["bundle_manifest_offset"] == manifest_offset


def test_readytorun_detection():
    dn_info = {"is_readytorun": True}
    res = detect_readytorun(dn_info)
    assert res is not None
    assert "ReadyToRun" in res["format"]

    dn_clean = {"is_readytorun": False}
    assert detect_readytorun(dn_clean) is None


def test_mixed_mode_detection():
    dn_info = {"flags": {"ILOnly": False}}
    import_dlls = ["msvcr120.dll", "kernel32.dll"]
    res = detect_mixed_mode(dn_info, import_dlls)
    assert res is not None
    assert "Mixed-Mode" in res["format"]


def test_overlay_inspection():
    # ZIP
    res_zip = inspect_overlay(b"PK\x03\x04\x14\x00\x00\x00")
    assert any(item["type"] == "ZIP Archive" for item in res_zip)

    # 7-Zip
    res_7z = inspect_overlay(b"7z\xbc\xaf\x27\x1c\x00\x00")
    assert any(item["type"] == "7-Zip Archive" for item in res_7z)

    # Embedded PE
    res_mz = inspect_overlay(b"MZ\x90\x00\x03\x00\x00\x00")
    assert any(item["type"] == "Embedded PE Executable" for item in res_mz)

    # Enigma Virtual Box
    res_evb = inspect_overlay(b"padding EVB\x00 data...")
    assert any("Virtual File System" in item["type"] for item in res_evb)


def test_native_ep_matcher():
    matcher = EntryPointMatcher()

    # UPX entry point: 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB
    upx_bytes = bytes.fromhex("60 BE 10 20 30 40 8D BE 50 60 70 80 57 83 CD FF EB 00")
    match_upx = matcher.match(upx_bytes)
    assert match_upx is not None
    assert match_upx["name"] == "UPX"

    # Clean code: standard MSVC prologue (push ebp; mov ebp, esp)
    clean_bytes = bytes.fromhex("55 8B EC 83 EC 10 53 56 57")
    match_clean = matcher.match(clean_bytes)
    assert match_clean is None
