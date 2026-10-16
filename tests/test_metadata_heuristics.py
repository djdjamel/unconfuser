"""
Unit tests for metadata heuristics and API behavioral indicators (Phase 12 / 16).
"""

from netdetect.api_indicators import evaluate_api_indicators
from netdetect.heuristics import evaluate_identifier_collection, analyze_identifier
from netdetect.detector import ObfuscatorDetector


def test_api_indicators_anti_debug():
    member_refs = [
        {"parent": "System.Diagnostics.Debugger", "name": "get_IsAttached"},
    ]
    pinvokes = [
        {"dll": "kernel32.dll", "name": "IsDebuggerPresent"},
    ]
    techs = evaluate_api_indicators(member_refs, pinvokes)
    names = [t["technique"] for t in techs]
    assert "Anti-Debugging Checks" in names


def test_api_indicators_dynamic_loader():
    member_refs = [
        {"parent": "System.Reflection.Assembly", "name": "Load"},
        {"parent": "System.AppDomain", "name": "add_AssemblyResolve"},
    ]
    pinvokes = []
    techs = evaluate_api_indicators(member_refs, pinvokes)
    names = [t["technique"] for t in techs]
    assert "Dynamic Assembly Resolution & In-Memory Loading" in names


def test_csharp_keyword_identifiers():
    names = ["if", "else", "while", "class", "struct", "for", "switch", "case", "try", "catch", "MyCleanMethod"]
    res = evaluate_identifier_collection(names)
    assert res["keyword_name_count"] == 10

    single = analyze_identifier("while")
    assert single["is_csharp_keyword"] is True

    clean = analyze_identifier("CalculateTax")
    assert clean["is_csharp_keyword"] is False


def test_cjk_confusable_identifiers():
    # Chinese characters commonly used in Babel / Crypto obfuscator
    cjk_names = ["\u4e00\u4e01", "\u4e02\u4e03", "\u4e08\u4e09", "\u4e0a\u4e0b", "\u4e0c\u4e0d"]
    res = evaluate_identifier_collection(cjk_names)
    assert res["cjk_confusable_count"] == 5
    assert res["cjk_confusable_ratio"] == 1.0


def test_duplicate_stream_technique():
    analysis_data = {
        "file_path": "test.dll",
        "file_size": 1024,
        "is_valid_pe": True,
        "is_dotnet": True,
        "dotnet_info": {
            "duplicate_streams": ["#~", "#Strings"],
            "type_names": ["TestClass"],
        },
    }
    det = ObfuscatorDetector(analysis_data)
    res = det.detect()

    tech_names = [t["technique"] for t in res["generic_techniques"]]
    assert "Duplicate Metadata Stream Names (Anti-Dump)" in tech_names


def test_encrypted_field_rva_technique():
    analysis_data = {
        "file_path": "test.dll",
        "file_size": 10240,
        "is_valid_pe": True,
        "is_dotnet": True,
        "dotnet_info": {
            "field_rva_blobs": [
                {"field": "encData", "size": 8192, "entropy": 7.8, "magic": "01020304"}
            ],
            "type_names": ["TestClass"],
        },
    }
    det = ObfuscatorDetector(analysis_data)
    res = det.detect()

    tech_names = [t["technique"] for t in res["generic_techniques"]]
    assert "Encrypted Field Initial Values (Static Constant Array)" in tech_names
