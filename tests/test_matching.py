"""
Unit tests for netdetect.matching (Phase 8).
Verifies tokenization, modes, and regression guards for false positives.
"""

import pytest
from netdetect.matching import split_identifier, Pattern, compile_pattern, MIN_CONTAINS_LEN


def test_split_identifier():
    assert split_identifier("InternetZoneManager") == ["internet", "zone", "manager"]
    assert split_identifier("System.Collections.Specialized") == ["system", "collections", "specialized"]
    assert split_identifier("uncompressedDataLength") == ["uncompressed", "data", "length"]
    assert split_identifier("tagENUMLOGFONTEXDVW") == ["tag", "enumlogfontexdvw"]
    assert split_identifier("_ConfusedBy_Attribute") == ["confused", "by", "attribute"]
    assert split_identifier("<Module>") == ["module"]
    assert split_identifier("a1b2") == ["a", "1", "b", "2"]


def test_token_mode_fp_regressions():
    # netz should NOT match InternetZoneManager
    p_netz = Pattern("netz", mode="token")
    assert not p_netz.matches("InternetZoneManager")
    assert not p_netz.matches("__MIDL_IInternetZoneManager_0002")
    assert p_netz.matches("netz.starter")
    assert p_netz.matches("Netz")

    # MPRESS should NOT match uncompressedDataLength
    p_mpress = Pattern("MPRESS", mode="token")
    assert not p_mpress.matches("uncompressedDataLength")
    assert not p_mpress.matches("IHttpsCompressionFeature")
    assert not p_mpress.matches("DoNotCompress")
    assert p_mpress.matches(".MPRESS1")
    assert p_mpress.matches("MPRESS")

    # GEnum should NOT match StringEnumerator
    p_genum = Pattern("GEnum", mode="token")
    assert not p_genum.matches("StringEnumerator")
    assert not p_genum.matches("System.Collections.Specialized.StringEnumerator")
    assert p_genum.matches("GEnum")
    assert p_genum.matches("MyNamespace.GEnum")


def test_matching_modes():
    p_exact = Pattern("ConfusedBy", mode="exact")
    assert p_exact.matches("confusedby")
    assert not p_exact.matches("ConfusedByAttribute")

    p_prefix = Pattern("costura.", mode="prefix")
    assert p_prefix.matches("costura.myassembly.dll")
    assert not p_prefix.matches("other.costura.dll")

    p_contains = Pattern("Licensed with .NET Reactor", mode="contains")
    assert p_contains.matches("This software is Licensed with .NET Reactor v6")
    assert not p_contains.matches("Other tool")

    p_regex = Pattern(r"^GClass\d+$", mode="regex")
    assert p_regex.matches("GClass0")
    assert p_regex.matches("GClass123")
    assert not p_regex.matches("GClass")
    assert not p_regex.matches("OtherGClass0")


def test_contains_guard():
    with pytest.raises(ValueError):
        Pattern("short", mode="contains")

    # >= 8 chars should succeed
    p = Pattern("eightchr", mode="contains")
    assert p.matches("something_eightchr_here")


def test_compile_pattern():
    p1 = compile_pattern("TestName", default_mode="exact")
    assert p1.mode == "exact"
    assert p1.matches("testname")

    p2 = compile_pattern({"p": "TestName", "mode": "prefix", "tier": "strong"})
    assert p2.mode == "prefix"
    assert p2.tier == "strong"
    assert p2.matches("TestNameSuffix")
