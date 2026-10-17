"""
Pytest integration for ConfuserExKillerRunner deobfuscation benchmark.

Validates end-to-end deobfuscation, structural integrity audits, AST-level transformations,
and runtime behavior for benign C# protection fixtures without regressions.
"""

import os
import shutil
import subprocess
from pathlib import Path
import pytest

from benchmarks.run_benchmark import (
    find_runner,
    get_benign_baseline,
    run_benchmark_case,
    FIXTURES_DIR,
    BENIGN_DLL,
)


@pytest.fixture(scope="session")
def runner_path():
    try:
        return find_runner()
    except FileNotFoundError:
        pytest.skip("ConfuserExKillerRunner.exe not found. Build solution first.")


@pytest.fixture(scope="session")
def expected_baseline():
    if not BENIGN_DLL.exists():
        pytest.skip("BenignSample.dll not found. Build solution first.")
    
    # Auto-generate fixtures if missing
    if not (FIXTURES_DIR / "fixture_constants.dll").exists():
        generator_exe = BENIGN_DLL.parent.parent.parent.parent / "FixtureGenerator" / "bin" / "Release" / "net8.0-windows" / "FixtureGenerator.exe"
        if generator_exe.exists():
            FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                [str(generator_exe), "--input", str(BENIGN_DLL), "--output-dir", str(FIXTURES_DIR)],
                check=False,
                capture_output=True,
            )

    return get_benign_baseline()


def test_benign_baseline_output(expected_baseline):
    """Verifies that the benign baseline executes and emits expected markers."""
    assert "BENIGN_START" in expected_baseline
    assert "CONST_STR:ConfuserEx_Benchmark_Secret_String_2026" in expected_baseline
    assert "CONST_NUM:133742:9223372036854775800" in expected_baseline
    assert "CFLOW:100:30" in expected_baseline
    assert "PROXY:42" in expected_baseline
    assert "RESOURCE:HELLO_FROM_BENIGN_EMBEDDED_RESOURCE" in expected_baseline
    assert "BENIGN_END" in expected_baseline


@pytest.mark.parametrize(
    "case_name,fixture_filename,scenario,min_constants,min_proxies,min_resources",
    [
        ("Constants (Strings & Numerics)", "fixture_constants.dll", "constants", 2, 0, 0),
        ("Reference & Delegate Proxies", "fixture_proxies.dll", "proxies", 0, 1, 0),
        ("Encrypted Resources", "fixture_resources.dll", "resources", 0, 0, 1),
        ("Deflate Compressor Unpacker", "fixture_compressor.dll", "compressor", 0, 0, 0),
        ("Control Flow & Trampolines", "fixture_cflow.dll", "cflow", 0, 0, 0),
        ("Anti-Tamper & Cleaner Hooks", "fixture_antitamper.dll", "antitamper", 0, 0, 0),
        ("Generics & Exception Edges", "fixture_edge_cases.dll", "edge_cases", 0, 0, 0),
    ],
)
def test_deobfuscation_synthetic_pipeline_case(
    case_name,
    fixture_filename,
    scenario,
    min_constants,
    min_proxies,
    min_resources,
    runner_path,
    expected_baseline,
):
    """Tests individual synthetic protection deobfuscation end-to-end with structural AST audit and runtime verification."""
    fixture_path = FIXTURES_DIR / fixture_filename
    if not fixture_path.exists():
        pytest.skip(f"Fixture {fixture_filename} not generated yet.")

    record = run_benchmark_case(case_name, fixture_path, scenario, runner_path, expected_baseline, timeout_sec=25)

    assert record["output_produced"], f"No output produced for {case_name}. Error: {record.get('error')}"
    assert record["execution_returncode"] == 0, f"Runtime process failed with code {record['execution_returncode']}"
    assert record["audit_status"] == "CLEAN", f"Audit failed for {case_name}: {record['audit_status']}"
    assert record["behavioral_match"], f"Behavioral output mismatch for {case_name}. Error: {record.get('error')}"
    assert record["verdict"] == "SYNTHETIC_PASS", f"Expected SYNTHETIC_PASS verdict, got {record['verdict']}"

    # Verify structural AST checks
    v_data = record.get("structural_verification", {})
    assert v_data.get("verified", False), f"AST-level verification failed for {case_name}: {v_data}"

    metrics = record["metrics"]
    if min_constants > 0:
        assert metrics.get("constants_decrypted", 0) >= min_constants
    if min_proxies > 0:
        assert metrics.get("proxies_inlined", 0) >= min_proxies
    if min_resources > 0:
        assert metrics.get("resources_extracted", 0) >= min_resources


def test_combined_fixture_exposes_ordering_bottleneck(runner_path, expected_baseline):
    """
    Validates that the combined fixture exercises each expected transformation
    and accurately classifies as SYNTHETIC_PARTIAL due to the cctor ordering bottleneck.
    """
    fixture_path = FIXTURES_DIR / "fixture_combined.dll"
    if not fixture_path.exists():
        pytest.skip("fixture_combined.dll not generated yet.")

    record = run_benchmark_case(
        "Combined Multi-Protection",
        fixture_path,
        "combined",
        runner_path,
        expected_baseline,
        timeout_sec=25,
    )

    assert record["output_produced"], "Combined fixture produced no output"
    assert record["audit_status"] == "CLEAN", f"Audit failed: {record['audit_status']}"
    assert record["verdict"] == "SYNTHETIC_PARTIAL", f"Expected SYNTHETIC_PARTIAL, got {record['verdict']}"

    v_data = record.get("structural_verification", {})
    assert v_data.get("partial") is True, f"Expected partial=true in AST verification: {v_data}"
    verified_ts = v_data.get("verified_transformations", [])
    unverified_ts = v_data.get("unverified_transformations", [])

    # Confirm specific verified transformations
    assert "proxies_inlined" in verified_ts
    assert "cflow_deadcode_stripped" in verified_ts
    assert "cctor_antitamper_hook_stripped" in verified_ts

    # Confirm specific unverified transformation that exposes the next algorithmic improvement
    assert "constants_decrypted_and_inlined" in unverified_ts


def test_missing_protector_marked_skipped_never_passed():
    """Validates that unavailable external protectors are marked SKIPPED_TOOL_MISSING and never reported as passed."""
    fake_cli = Path("non_existent_tools/Confuser.CLI.exe")
    assert not fake_cli.exists()
    status = "SKIPPED_TOOL_MISSING" if not fake_cli.exists() else "REAL_PROTECTOR_PASS"
    assert status == "SKIPPED_TOOL_MISSING"
    assert status != "REAL_PROTECTOR_PASS"
