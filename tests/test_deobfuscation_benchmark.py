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
    find_generator,
    get_exec_command,
    get_benign_baseline,
    run_benchmark_case,
    run_all_benchmarks,
    FIXTURES_DIR,
    BENIGN_DLL,
)


@pytest.fixture(scope="session")
def runner_path():
    try:
        return find_runner()
    except FileNotFoundError:
        pytest.fail("ConfuserExKillerRunner binary not found. Build unconfuser.sln first.")


@pytest.fixture(scope="session")
def expected_baseline():
    if not BENIGN_DLL.exists():
        pytest.fail(f"BenignSample.dll not found at {BENIGN_DLL}. Build solution first.")

    # Auto-generate fixtures if missing
    if not (FIXTURES_DIR / "fixture_constants.dll").exists():
        generator = find_generator()
        if not generator or not generator.exists():
            pytest.fail("FixtureGenerator binary not found. Build solution first.")
        FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
        gen_cmd = get_exec_command(generator) + ["--input", str(BENIGN_DLL), "--output-dir", str(FIXTURES_DIR)]
        gen_res = subprocess.run(gen_cmd, capture_output=True, text=True)
        if gen_res.returncode != 0:
            pytest.fail(f"Fixture generation failed with returncode {gen_res.returncode}: {gen_res.stderr}")

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
        ("Constants (Strings & Numerics)", "fixture_constants.dll", "constants", 3, 0, 0),
        ("Reference & Method Call Proxies", "fixture_proxies.dll", "proxies", 0, 1, 0),
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
        pytest.fail(f"Required synthetic fixture {fixture_filename} does not exist at {fixture_path}.")

    record = run_benchmark_case(case_name, fixture_path, scenario, runner_path, expected_baseline, is_synthetic=True, timeout_sec=25)

    assert record["output_produced"], f"No output produced for {case_name}. Error: {record.get('error')}"
    assert record["deobfuscator_returncode"] == 0, f"Deobfuscator process failed with code {record['deobfuscator_returncode']}"
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
        pytest.fail("fixture_combined.dll not found; synthetic fixtures must be generated.")

    record = run_benchmark_case(
        "Combined Multi-Protection",
        fixture_path,
        "combined",
        runner_path,
        expected_baseline,
        is_synthetic=True,
        timeout_sec=25,
    )

    assert record["output_produced"], "Combined fixture produced no output"
    assert record["deobfuscator_returncode"] == 0, f"Deobfuscator failed: {record['deobfuscator_returncode']}"
    assert record["execution_returncode"] == 0, f"Runtime execution failed: {record['execution_returncode']}"
    assert record["behavioral_match"], f"Behavioral output mismatch for combined fixture: {record.get('error')}"
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

    # Confirm specific unverified transformation that exposes the documented limitation
    assert "constants_decrypted_and_inlined" in unverified_ts


def test_real_protector_integration_and_skip_logic(runner_path, expected_baseline):
    """Validates that real protector profile is executed when present, or cleanly skipped as SKIPPED_TOOL_MISSING."""
    summary = run_all_benchmarks(fixtures_dir=FIXTURES_DIR, runner_path=runner_path)
    real_cases = [r for r in summary["results"] if r.get("scenario") == "real_confuserex"]
    assert len(real_cases) == 1, "Expected exactly one real ConfuserEx CLI preset case in benchmark summary"
    real_case = real_cases[0]

    if real_case["verdict"] == "SKIPPED_TOOL_MISSING":
        assert real_case["verdict"] != "REAL_PROTECTOR_PASS"
        assert real_case["verdict"] != "SYNTHETIC_PASS"
        assert "Confuser.CLI.exe (pinned ConfuserEx v1.0.0) not found" in real_case["error"]
        assert summary["skipped_tool_missing"] >= 1
    elif real_case["verdict"] == "REAL_PROTECTOR_PASS":
        assert real_case["output_produced"]
        assert real_case["execution_returncode"] == 0
        assert real_case["behavioral_match"]
    else:
        assert real_case["verdict"] == "REAL_PROTECTOR_FAIL"
