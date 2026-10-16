"""
Test suite verifying detection rules, heuristics, and scoring logic.
Covers Phases 1-6 of the gap-coverage implementation plan.
"""

from netdetect.detector import ObfuscatorDetector
from netdetect.heuristics import analyze_identifier, evaluate_identifier_collection


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _base_analysis(**overrides):
    """Returns a minimal valid analysis dict, merged with overrides."""
    base = {
        "is_valid_pe": True,
        "is_dotnet": True,
        "pe_timestamp": 12345,
        "has_rich_header": True,
        "has_import_table": True,
        "import_dlls": [],
        "suspicious_sections": [],
        "high_entropy_sections": [],
        "pe_sections": [],
        "has_overlay": False,
        "overlay_size": 0,
        "overlay_ratio": 0.0,
        "overlay_entropy": 0.0,
        "dotnet_info": {
            "custom_attributes": [],
            "type_names": [],
            "namespaces": [],
            "assembly_refs": [],
            "user_strings": [],
            "metadata_strings": [],
            "resources": [],
            "high_entropy_resources": [],
            "member_refs": [],
            "field_names": [],
            "clr_stream_names": [],
            "cctor_count": 0,
            "has_module_cctor": False,
            "has_suppress_ildasm": False,
            "is_mixed_assembly": False,
            "empty_rva_methods_count": 0,
            "anti_metadata": {},
            "identifier_metrics": {
                "total_count": 5,
                "short_count": 0,
                "short_ratio": 0.0,
                "invisible_count": 0,
                "invisible_detected": [],
                "high_entropy_name_count": 0,
                "high_entropy_name_ratio": 0.0,
            },
        },
    }
    # Shallow-merge dotnet_info if provided
    if "dotnet_info" in overrides:
        merged_dn = dict(base["dotnet_info"])
        merged_dn.update(overrides.pop("dotnet_info"))
        base["dotnet_info"] = merged_dn
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Original tests (kept unchanged)
# ---------------------------------------------------------------------------

def test_confuserex_signature():
    analysis = _base_analysis(dotnet_info={
        "custom_attributes": [{"name": "ConfusedByAttribute", "namespace": "", "full_name": "ConfusedByAttribute"}],
        "type_names": ["Program"],
        "namespaces": ["MyCompany"],
        "user_strings": ["Confuser.Core v1.6.0"],
        "identifier_metrics": {"total_count": 1, "short_count": 0, "short_ratio": 0.0,
                               "invisible_count": 8, "invisible_detected": ["Zero-Width Space"],
                               "high_entropy_name_count": 0, "high_entropy_name_ratio": 0.0},
        "has_module_cctor": True,
    })
    result = ObfuscatorDetector(analysis).detect()
    assert result["detected"] is True
    assert "Confuser" in result["primary_detector"]
    assert result["confidence"] == "HIGH"
    print("[PASS] ConfuserEx detection")


def test_smartassembly_signature():
    analysis = _base_analysis(dotnet_info={
        "custom_attributes": [{"name": "PoweredByAttribute", "namespace": "SmartAssembly.Attributes",
                               "full_name": "SmartAssembly.Attributes.PoweredByAttribute"}],
        "type_names": ["{SmartAssembly}", "Worker"],
        "namespaces": ["SmartAssembly.Zip"],
        "user_strings": ["Powered by SmartAssembly"],
        "identifier_metrics": {"total_count": 2, "short_count": 0, "short_ratio": 0.1,
                               "invisible_count": 0, "invisible_detected": [],
                               "high_entropy_name_count": 0, "high_entropy_name_ratio": 0.0},
    })
    result = ObfuscatorDetector(analysis).detect()
    assert result["detected"] is True
    assert "SmartAssembly" in result["primary_detector"]
    assert result["confidence"] == "HIGH"
    print("[PASS] SmartAssembly detection")


def test_renaming_heuristics():
    analysis = _base_analysis(dotnet_info={
        "type_names": ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"],
        "identifier_metrics": {"total_count": 11, "short_count": 11, "short_ratio": 1.0,
                               "invisible_count": 0, "invisible_detected": [],
                               "high_entropy_name_count": 0, "high_entropy_name_ratio": 0.0},
    })
    result = ObfuscatorDetector(analysis).detect()
    assert result["detected"] is True
    techs = [t["technique"] for t in result["generic_techniques"]]
    assert any("Symbol Renaming" in t for t in techs)
    print("[PASS] Renaming heuristics")


# ---------------------------------------------------------------------------
# Phase 2 — new signature entries
# ---------------------------------------------------------------------------

def test_phoenix_signature():
    analysis = _base_analysis(dotnet_info={
        "custom_attributes": [{"name": "PhoenixAttribute", "namespace": "Phoenix",
                               "full_name": "Phoenix.PhoenixAttribute"}],
        "user_strings": ["Phoenix Protector"],
    })
    result = ObfuscatorDetector(analysis).detect()
    assert result["detected"] is True
    assert "Phoenix" in result["primary_detector"]
    assert result["confidence"] in ("HIGH", "MEDIUM")
    print("[PASS] Phoenix Protector detection")


def test_mpress_section():
    analysis = _base_analysis(
        is_dotnet=False,
        suspicious_sections=[{"name": ".mpress1", "entropy": 7.8}],
    )
    result = ObfuscatorDetector(analysis).detect()
    assert result["detected"] is True
    assert "MPRESS" in result["primary_detector"]
    assert result["confidence"] == "HIGH"
    print("[PASS] MPRESS section detection")


def test_upx_section():
    analysis = _base_analysis(
        is_dotnet=False,
        suspicious_sections=[{"name": "upx0", "entropy": 7.9}],
    )
    result = ObfuscatorDetector(analysis).detect()
    assert result["detected"] is True
    assert "UPX" in result["primary_detector"]
    print("[PASS] UPX section detection")


def test_eazfuscator_v4_types():
    analysis = _base_analysis(dotnet_info={
        "type_names": ["_eaz_helper", "DataService"],
        "user_strings": ["Eazfuscator.NET"],
    })
    result = ObfuscatorDetector(analysis).detect()
    assert result["detected"] is True
    assert "Eazfuscator" in result["primary_detector"]
    print("[PASS] Eazfuscator v4+ detection")


def test_de4dot_output():
    analysis = _base_analysis(dotnet_info={
        "type_names": ["GClass1", "GClass2", "GEnum1"],
        "user_strings": ["smethod_0", "field_1"],
    })
    result = ObfuscatorDetector(analysis).detect()
    assert any("de4dot" in p["name"] for p in result["protectors"])
    print("[PASS] de4dot output detection")


# ---------------------------------------------------------------------------
# Phase 3 — new analyzer data fields
# ---------------------------------------------------------------------------

def test_netz_resource_name():
    analysis = _base_analysis(dotnet_info={
        "resources": [
            {"name": "netz_r", "size": 50000, "entropy": 7.9, "magic_bytes": "1f8b08000000"}
        ],
    })
    result = ObfuscatorDetector(analysis).detect()
    assert result["detected"] is True
    assert any("Netz" in p["name"] for p in result["protectors"])
    print("[PASS] Netz resource name detection")


def test_costura_magic_bytes():
    analysis = _base_analysis(dotnet_info={
        "resources": [
            {"name": "costura.mylib.dll.compressed", "size": 120000,
             "entropy": 7.6, "magic_bytes": "1f8b08000000"}
        ],
        "user_strings": ["costura."],
    })
    result = ObfuscatorDetector(analysis).detect()
    assert result["detected"] is True
    assert any("Costura" in p["name"] for p in result["protectors"])
    print("[PASS] Costura resource magic-byte detection")


def test_ezirizvm_stream():
    analysis = _base_analysis(dotnet_info={
        "clr_stream_names": ["#Strings", "#US", "#GUID", "#Blob", "#~", "#EzirizVM"],
    })
    result = ObfuscatorDetector(analysis).detect()
    assert result["detected"] is True
    # Should detect either EzirizVM signature entry or custom stream
    all_names = [p["name"] for p in result["protectors"]]
    assert any("EzirizVM" in n or "Custom CLR Stream" in n for n in all_names)
    print("[PASS] EzirizVM CLR stream detection")


def test_clr_custom_stream_generic():
    analysis = _base_analysis(dotnet_info={
        "clr_stream_names": ["#Strings", "#US", "#~", "ILProtect"],
    })
    result = ObfuscatorDetector(analysis).detect()
    assert result["detected"] is True
    stream_findings = [p for p in result["protectors"] if "Custom CLR Stream" in p["name"] or "ILProtector" in p["name"]]
    assert len(stream_findings) > 0
    print("[PASS] Generic custom CLR stream detection")


# ---------------------------------------------------------------------------
# Phase 4 — detection engine upgrades
# ---------------------------------------------------------------------------

def test_enigma_import():
    analysis = _base_analysis(
        is_dotnet=False,
        import_dlls=["enigma_mscoree.dll", "kernel32.dll"],
    )
    result = ObfuscatorDetector(analysis).detect()
    assert result["detected"] is True
    assert any("Enigma" in p["name"] for p in result["protectors"])
    assert result["confidence"] == "HIGH"
    print("[PASS] Enigma Protector IAT import detection")


def test_import_table_dotnet_wrapper():
    analysis = _base_analysis(
        import_dlls=["asprotect.dll", "kernel32.dll"],
    )
    result = ObfuscatorDetector(analysis).detect()
    assert result["detected"] is True
    assert any("ASProtect" in p["name"] or "ASPack" in p["name"] for p in result["protectors"])
    print("[PASS] ASProtect IAT import detection (.NET path)")


def test_false_positive_protect_string():
    """Bare 'Protect' string alone must NOT trigger ILProtector detection."""
    analysis = _base_analysis(dotnet_info={
        "user_strings": ["We protect your data", "protect your privacy"],
        "type_names": ["DataService", "ProtectionLayer"],
    })
    result = ObfuscatorDetector(analysis).detect()
    ilp_findings = [p for p in result["protectors"] if "ILProtector" in p["name"]]
    assert len(ilp_findings) == 0, f"False positive: {ilp_findings}"
    print("[PASS] ILProtector false-positive fix verified")


def test_mindlated_disambiguation():
    """Invisible chars + 'mindlated' string -> MindLated, not ConfuserEx."""
    analysis = _base_analysis(dotnet_info={
        "metadata_strings": ["mindlated"],
        "identifier_metrics": {
            "total_count": 20, "short_count": 0, "short_ratio": 0.0,
            "invisible_count": 5, "invisible_detected": ["Zero-Width Space"],
            "high_entropy_name_count": 0, "high_entropy_name_ratio": 0.0,
        },
        "has_module_cctor": True,
    })
    result = ObfuscatorDetector(analysis).detect()
    assert result["detected"] is True
    assert "MindLated" in result["primary_detector"]
    # primary must NOT be attributed to plain ConfuserEx brand entry
    assert not result["primary_detector"].startswith("ConfuserEx / Confuser")
    print("[PASS] MindLated vs ConfuserEx disambiguation")


def test_cctor_density():
    """High .cctor / type ratio should produce a virtualizer indicator technique."""
    analysis = _base_analysis(dotnet_info={
        "type_names": [f"T{i}" for i in range(50)],
        "cctor_count": 15,
    })
    result = ObfuscatorDetector(analysis).detect()
    techs = [t["technique"] for t in result["generic_techniques"]]
    assert any(".cctor" in t for t in techs), f"Techniques: {techs}"
    print("[PASS] .cctor density virtualizer indicator")


def test_zeroed_timestamp():
    """PE timestamp == 0 should surface as a generic technique."""
    analysis = _base_analysis(pe_timestamp=0)
    result = ObfuscatorDetector(analysis).detect()
    techs = [t["technique"] for t in result["generic_techniques"]]
    assert any("TimeDateStamp" in t for t in techs), f"Techniques: {techs}"
    print("[PASS] Zeroed TimeDateStamp detection")


# ---------------------------------------------------------------------------
# Phase 5 — heuristic improvements
# ---------------------------------------------------------------------------

def test_high_entropy_names():
    """High-entropy identifier ratio >= 0.30 should produce a technique."""
    analysis = _base_analysis(dotnet_info={
        "identifier_metrics": {
            "total_count": 30,
            "short_count": 0,
            "short_ratio": 0.0,
            "invisible_count": 0,
            "invisible_detected": [],
            "high_entropy_name_count": 12,
            "high_entropy_name_ratio": 0.40,
        },
    })
    result = ObfuscatorDetector(analysis).detect()
    techs = [t["technique"] for t in result["generic_techniques"]]
    assert any("High-Entropy" in t for t in techs), f"Techniques: {techs}"
    print("[PASS] High-entropy identifier name detection")


def test_widened_short_threshold_3char():
    """3-character names should now be flagged as short (was <= 2)."""
    analysis = analyze_identifier("abc")
    assert analysis["is_short"] is True
    print("[PASS] 3-char identifier flagged as short (widened threshold)")


def test_widened_short_threshold_digit_pattern():
    """Names like 'a1', 'b22', 'aB3' should be flagged as short."""
    for name in ["a1", "b22", "aB3", "c001"]:
        r = analyze_identifier(name)
        assert r["is_short"] is True, f"'{name}' not flagged as short"
    print("[PASS] Letter+digit pattern identifiers flagged as short")


def test_identifier_entropy_high():
    """Random-looking name should have is_high_entropy_name == True."""
    result = analyze_identifier("xKqR7pVw")
    assert result["is_high_entropy_name"] is True
    print("[PASS] High-entropy identifier name flagged")


def test_identifier_entropy_normal():
    """Normal camelCase name should NOT be flagged as high entropy."""
    result = analyze_identifier("CustomerService")
    assert result["is_high_entropy_name"] is False
    print("[PASS] Normal camelCase name not flagged as high-entropy")


def test_field_names_in_rename_ratio():
    """Field names should be included in the evaluate_identifier_collection count."""
    # Simulate: types + methods (all normal) + fields (all obfuscated/short)
    names = ["CustomerService", "OrderManager", "DataProcessor",  # normal
             "a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]  # short (field names)
    metrics = evaluate_identifier_collection(names)
    assert metrics["short_count"] == 10
    assert metrics["short_ratio"] > 0.7
    print("[PASS] Field names included in rename ratio calculation")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Original tests
    test_confuserex_signature()
    test_smartassembly_signature()
    test_renaming_heuristics()

    # Phase 2 - new signatures
    test_phoenix_signature()
    test_mpress_section()
    test_upx_section()
    test_eazfuscator_v4_types()
    test_de4dot_output()

    # Phase 3 - analyzer data
    test_netz_resource_name()
    test_costura_magic_bytes()
    test_ezirizvm_stream()
    test_clr_custom_stream_generic()

    # Phase 4 - engine upgrades
    test_enigma_import()
    test_import_table_dotnet_wrapper()
    test_false_positive_protect_string()
    test_mindlated_disambiguation()
    test_cctor_density()
    test_zeroed_timestamp()

    # Phase 5 - heuristics
    test_high_entropy_names()
    test_widened_short_threshold_3char()
    test_widened_short_threshold_digit_pattern()
    test_identifier_entropy_high()
    test_identifier_entropy_normal()
    test_field_names_in_rename_ratio()

    print("\nAll tests passed successfully!")
