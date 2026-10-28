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
    verify_structural_transformations,
    validate_sha256,
    get_confuserex_pin_configuration,
    FIXTURES_DIR,
    BENIGN_DLL,
    CONFUSEREX_EXPECTED_SHA256,
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
    """Verifies that the benign baseline executes and emits expected markers across all paths."""
    assert "BENIGN_START" in expected_baseline
    assert "CONST_STR:ConfuserEx_Benchmark_Secret_String_2026" in expected_baseline
    assert "CONST_NUM:133742:9223372036854775800" in expected_baseline
    assert "CFLOW:100:30:35:95" in expected_baseline
    assert "PROXY:42" in expected_baseline
    assert "RESOURCE:HELLO_FROM_BENIGN_EMBEDDED_RESOURCE" in expected_baseline
    assert "BENIGN_END" in expected_baseline


# Exact expected recovery counts documented per synthetic fixture
@pytest.mark.parametrize(
    "case_name,fixture_filename,scenario,exp_constants,exp_proxies,exp_resources,exp_junk_pairs,exp_cleaner_hooks",
    [
        # Constants fixture: exactly 3 constants encrypted (1 string, 1 int32, 1 int64)
        ("Constants (Strings & Numerics)", "fixture_constants.dll", "constants", 3, 0, 0, 0, 0),
        # Control flow fixture: exactly 1 dead-code junk pair (ldc.i4 8888 + pop) in ComputeSwitch
        ("Control Flow (Dead Code & Junk Stripping)", "fixture_cflow.dll", "cflow", 0, 0, 0, 1, 0),
        # Proxies fixture: exactly 1 proxy method inlining AddProxyTarget
        ("Reference & Method Call Proxies", "fixture_proxies.dll", "proxies", 0, 1, 0, 0, 0),
        # Resources fixture: exactly 1 encrypted embedded resource (BenignSample.Greeting.txt)
        ("Encrypted Resources", "fixture_resources.dll", "resources", 0, 0, 1, 0, 0),
        # Deflate compressor fixture: uncompressed payload container restored, 0 internal counters
        ("Deflate Compressor Unpacker", "fixture_compressor.dll", "compressor", 0, 0, 0, 0, 0),
        # Anti-tamper fixture: exactly 1 module initializer hook stripped and pruned
        ("Anti-Tamper & Cleaner Hooks", "fixture_antitamper.dll", "antitamper", 0, 0, 0, 0, 1),
        # Generics & exception edges: clean pass-through of generic method and nested handlers; exactly 1 boundary junk pair stripped
        ("Generics & Exception Edges", "fixture_edge_cases.dll", "edge_cases", 0, 0, 0, 1, 0),
    ],
)
def test_deobfuscation_synthetic_pipeline_case(
    case_name,
    fixture_filename,
    scenario,
    exp_constants,
    exp_proxies,
    exp_resources,
    exp_junk_pairs,
    exp_cleaner_hooks,
    runner_path,
    expected_baseline,
):
    """Tests individual synthetic protection deobfuscation end-to-end with structural AST audit and exact metric counts."""
    fixture_path = FIXTURES_DIR / fixture_filename
    if not fixture_path.exists():
        pytest.fail(f"Required synthetic fixture {fixture_filename} does not exist at {fixture_path}.")

    record = run_benchmark_case(
        case_name,
        fixture_path,
        scenario,
        runner_path,
        expected_baseline,
        baseline_dll_path=BENIGN_DLL,
        is_synthetic=True,
        timeout_sec=25,
    )

    assert record["output_produced"], f"No output produced for {case_name}. Error: {record.get('error')}"
    assert record["deobfuscator_returncode"] == 0, f"Deobfuscator process failed with code {record['deobfuscator_returncode']}"
    assert record["execution_returncode"] == 0, f"Runtime process failed with code {record['execution_returncode']}"
    assert record["audit_status"] == "CLEAN", f"Audit failed for {case_name}: {record['audit_status']}"
    assert record["behavioral_match"], f"Behavioral output mismatch for {case_name}. Error: {record.get('error')}"
    assert record["verdict"] == "SYNTHETIC_PASS", f"Expected SYNTHETIC_PASS verdict, got {record['verdict']}"

    # Verify structural AST checks
    v_data = record.get("structural_verification", {})
    assert v_data.get("verified", False), f"AST-level verification failed for {case_name}: {v_data}"

    # Verify exact metric recovery counts (no >= leniency)
    metrics = record["metrics"]
    assert metrics.get("constants_decrypted", 0) == exp_constants, (
        f"Exact constants count mismatch in {case_name}: expected {exp_constants}, got {metrics.get('constants_decrypted', 0)}"
    )
    assert metrics.get("proxies_inlined", 0) == exp_proxies, (
        f"Exact proxies count mismatch in {case_name}: expected {exp_proxies}, got {metrics.get('proxies_inlined', 0)}"
    )
    assert metrics.get("resources_extracted", 0) == exp_resources, (
        f"Exact resources count mismatch in {case_name}: expected {exp_resources}, got {metrics.get('resources_extracted', 0)}"
    )
    assert metrics.get("deadcode_junk_pairs", 0) == exp_junk_pairs, (
        f"Exact deadcode junk pairs mismatch in {case_name}: expected {exp_junk_pairs}, got {metrics.get('deadcode_junk_pairs', 0)}"
    )
    if exp_cleaner_hooks > 0:
        assert metrics.get("cleaner_hooks_stripped", 0) >= 1, (
            f"Expected cleaner hooks stripped in {case_name}, got {metrics.get('cleaner_hooks_stripped', 0)}"
        )
    else:
        assert metrics.get("cleaner_hooks_stripped", 0) == 0, (
            f"Expected 0 cleaner hooks stripped in {case_name}, got {metrics.get('cleaner_hooks_stripped', 0)}"
        )
    if scenario == "compressor":
        assert metrics.get("compressor_unpacked") is True, f"Compressor unpacked flag not True for {case_name}"


def test_combined_fixture_resolves_ordering_bottleneck(runner_path, expected_baseline):
    """
    Validates that the combined multi-protection fixture exercises each expected transformation
    and successfully deobfuscates all 4 layers (proxies, cflow, antitamper hook, AND constants)
    achieving SYNTHETIC_PASS after eliminating the cctor ordering bottleneck.
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
        baseline_dll_path=BENIGN_DLL,
        is_synthetic=True,
        timeout_sec=25,
    )

    assert record["output_produced"], "Combined fixture produced no output"
    assert record["deobfuscator_returncode"] == 0, f"Deobfuscator failed: {record['deobfuscator_returncode']}"
    assert record["execution_returncode"] == 0, f"Runtime execution failed: {record['execution_returncode']}"
    assert record["behavioral_match"], f"Behavioral output mismatch for combined fixture: {record.get('error')}"
    assert record["audit_status"] == "CLEAN", f"Audit failed: {record['audit_status']}"
    assert record["verdict"] == "SYNTHETIC_PASS", f"Expected SYNTHETIC_PASS, got {record['verdict']}"

    v_data = record.get("structural_verification", {})
    assert v_data.get("verified") is True, f"Expected verified=true in AST verification: {v_data}"
    verified_ts = v_data.get("verified_transformations", [])

    # Confirm all 4 multi-protection transformations are verified
    assert "proxies_inlined" in verified_ts
    assert "cflow_deadcode_stripped" in verified_ts
    assert "cctor_antitamper_hook_stripped" in verified_ts
    assert "constants_decrypted_and_inlined" in verified_ts

    # Confirm exact metric recovery counts for combined scenario
    metrics = record["metrics"]
    assert metrics.get("proxies_inlined", 0) == 1
    assert metrics.get("deadcode_junk_pairs", 0) == 1
    assert metrics.get("cleaner_hooks_stripped", 0) >= 1
    assert metrics.get("constants_decrypted", 0) >= 1



def test_real_protector_integration_and_skip_logic(runner_path, expected_baseline):
    """Validates that real protector profile is executed when present, or cleanly skipped as SKIPPED_TOOL_MISSING."""
    summary = run_all_benchmarks(fixtures_dir=FIXTURES_DIR, runner_path=runner_path)
    real_cases = [r for r in summary["results"] if r.get("scenario") == "real_confuserex"]
    assert len(real_cases) == 1, "Expected exactly one real ConfuserEx CLI preset case in benchmark summary"
    real_case = real_cases[0]

    if real_case["verdict"] == "SKIPPED_TOOL_MISSING":
        assert real_case["verdict"] != "REAL_PROTECTOR_PASS"
        assert real_case["verdict"] != "SYNTHETIC_PASS"
        assert "not found" in real_case["error"]
        assert summary["skipped_tool_missing"] >= 1
    elif real_case["verdict"] == "REAL_PROTECTOR_PASS":
        assert real_case["output_produced"]
        assert real_case["execution_returncode"] == 0
        assert real_case["behavioral_match"]
        assert real_case["audit_status"] == "CLEAN"
        v_data = real_case.get("structural_verification", {})
        assert v_data.get("verified") is True, f"Real ConfuserEx structural verification failed: {v_data}"
        verified_ts = v_data.get("verified_transformations", [])
        assert "assembly_identity_preserved" in verified_ts
        assert "types_intact" in verified_ts
        assert "constants_decrypted" in verified_ts
        assert "resources_extracted" in verified_ts
        assert "module_initializer_clean" in verified_ts
    else:
        pytest.fail(f"Real ConfuserEx protector integration failed with verdict {real_case['verdict']}: {real_case.get('error')}")


def test_missing_baseline_fails_closed_and_unverified(tmp_path, runner_path, expected_baseline):
    """
    Validates that missing baseline fails closed, does not leave baselineMatched=true,
    and returns UNVERIFIED with exit code 3.
    """
    clean_path = FIXTURES_DIR / "fixture_edge_cases_clean.dll"
    if not clean_path.exists():
        run_benchmark_case(
            "Generics & Exception Edges",
            FIXTURES_DIR / "fixture_edge_cases.dll",
            "edge_cases",
            runner_path,
            expected_baseline,
            baseline_dll_path=BENIGN_DLL,
        )

    fake_baseline = tmp_path / "non_existent_baseline.dll"
    res = verify_structural_transformations(clean_path, "edge_cases", baseline_path=fake_baseline)
    assert res.get("verified") is False
    assert res.get("status") == "UNVERIFIED"
    assert "baseline_exception_handlers_matched" in res.get("unverified_transformations", [])

    # Also test compressor scenario with missing baseline
    comp_clean = FIXTURES_DIR / "fixture_compressor_clean.dll"
    if not comp_clean.exists():
        run_benchmark_case(
            "Deflate Compressor Unpacker",
            FIXTURES_DIR / "fixture_compressor.dll",
            "compressor",
            runner_path,
            expected_baseline,
            baseline_dll_path=BENIGN_DLL,
        )
    comp_res = verify_structural_transformations(comp_clean, "compressor", baseline_path=fake_baseline)
    assert comp_res.get("verified") is False
    assert comp_res.get("status") == "UNVERIFIED"
    assert "assembly_full_identity_matched_baseline" in comp_res.get("unverified_transformations", [])
    assert "payload_types_entrypoint_and_required_resources_matched_baseline" in comp_res.get("unverified_transformations", [])


def test_altered_exception_handler_ranges_detected(tmp_path, runner_path, expected_baseline):
    """
    Validates that altered exception-handler boundary targets or instruction bodies
    fail verification rather than passing due to superficial range checks.
    """
    generator = find_generator()
    clean_path = FIXTURES_DIR / "fixture_edge_cases_clean.dll"
    if not clean_path.exists():
        run_benchmark_case(
            "Generics & Exception Edges",
            FIXTURES_DIR / "fixture_edge_cases.dll",
            "edge_cases",
            runner_path,
            expected_baseline,
            baseline_dll_path=BENIGN_DLL,
        )

    tampered_dll = tmp_path / "tampered_eh.dll"
    tamper_cmd = get_exec_command(generator) + ["--tamper-eh", str(clean_path), str(tampered_dll)]
    t_res = subprocess.run(tamper_cmd, capture_output=True, text=True)
    assert t_res.returncode == 0, f"Tamper command failed: {t_res.stderr}"

    verify_res = verify_structural_transformations(tampered_dll, "edge_cases", baseline_path=BENIGN_DLL)
    assert verify_res.get("verified") is False
    assert verify_res.get("status") == "FAILED"
    assert "baseline_exception_handlers_matched" in verify_res.get("unverified_transformations", [])


def test_unexpected_extra_resources_detected(tmp_path, runner_path, expected_baseline):
    """
    Validates that unexpected extra resources fail exact resource-manifest equality checks.
    """
    generator = find_generator()
    clean_path = FIXTURES_DIR / "fixture_resources_clean.dll"
    if not clean_path.exists():
        run_benchmark_case(
            "Encrypted Resources",
            FIXTURES_DIR / "fixture_resources.dll",
            "resources",
            runner_path,
            expected_baseline,
            baseline_dll_path=BENIGN_DLL,
        )

    tampered_dll = tmp_path / "tampered_res.dll"
    tamper_cmd = get_exec_command(generator) + ["--tamper-res", str(clean_path), str(tampered_dll)]
    t_res = subprocess.run(tamper_cmd, capture_output=True, text=True)
    assert t_res.returncode == 0, f"Tamper command failed: {t_res.stderr}"

    verify_res = verify_structural_transformations(tampered_dll, "resources", baseline_path=BENIGN_DLL)
    assert verify_res.get("verified") is False
    assert verify_res.get("status") == "FAILED"
    assert "resource_manifest_names_matched" in verify_res.get("unverified_transformations", [])


def test_mismatched_confuserex_checksum_fails(tmp_path, runner_path, monkeypatch):
    """
    Validates that a ConfuserEx CLI with a mismatched SHA-256 fails immediately
    with REAL_PROTECTOR_FAIL and does not run or silently change the pinned release label.
    """
    fake_cli = tmp_path / "Confuser.CLI.exe"
    fake_cli.write_bytes(b"MZ_DUMMY_EXECUTABLE_CONTENT_FOR_HASH_MISMATCH_TEST")

    monkeypatch.setenv("CONFUSEREX_PATH", str(fake_cli))
    summary = run_all_benchmarks(fixtures_dir=FIXTURES_DIR, runner_path=runner_path)

    real_cases = [r for r in summary["results"] if r.get("scenario") == "real_confuserex"]
    assert len(real_cases) == 1
    real_case = real_cases[0]

    assert real_case["verdict"] == "REAL_PROTECTOR_FAIL"
    assert "identity verification failed" in real_case["error"]
    assert str(CONFUSEREX_EXPECTED_SHA256) in real_case["error"]
    assert real_case["output_produced"] is False


def test_branch_target_redirection_to_same_opcode_detected(tmp_path, runner_path, expected_baseline):
    """
    Validates that redirecting a branch instruction to a different target with the same
    OpCode (e.g. redirecting brtrue to another ldstr) is caught by normalized instruction
    mapping rather than falsely matching on OpCode equality alone.
    """
    generator = find_generator()
    clean_path = FIXTURES_DIR / "fixture_edge_cases_clean.dll"
    if not clean_path.exists():
        run_benchmark_case(
            "Generics & Exception Edges",
            FIXTURES_DIR / "fixture_edge_cases.dll",
            "edge_cases",
            runner_path,
            expected_baseline,
            baseline_dll_path=BENIGN_DLL,
        )

    tampered_dll = tmp_path / "tampered_branch_target.dll"
    tamper_cmd = get_exec_command(generator) + ["--tamper-branch-target", str(clean_path), str(tampered_dll)]
    t_res = subprocess.run(tamper_cmd, capture_output=True, text=True)
    assert t_res.returncode == 0, f"Tamper branch command failed: {t_res.stderr}"

    verify_res = verify_structural_transformations(tampered_dll, "edge_cases", baseline_path=BENIGN_DLL)
    assert verify_res.get("verified") is False
    assert verify_res.get("status") == "FAILED"
    assert "baseline_exception_handlers_matched" in verify_res.get("unverified_transformations", [])


def test_exception_handler_boundary_moved_to_same_structural_fingerprint_detected(tmp_path, runner_path, expected_baseline):
    """
    Validates that moving an exception-handler boundary (TryStart) to another instruction
    with the exact same structural fingerprint (same OpCode ldloc.0 and operand) is detected
    via normalized instruction stream index alignment.
    """
    generator = find_generator()
    clean_path = FIXTURES_DIR / "fixture_edge_cases_clean.dll"
    if not clean_path.exists():
        run_benchmark_case(
            "Generics & Exception Edges",
            FIXTURES_DIR / "fixture_edge_cases.dll",
            "edge_cases",
            runner_path,
            expected_baseline,
            baseline_dll_path=BENIGN_DLL,
        )

    tampered_dll = tmp_path / "tampered_eh_fingerprint.dll"
    tamper_cmd = get_exec_command(generator) + ["--tamper-eh-boundary-fingerprint", str(clean_path), str(tampered_dll)]
    t_res = subprocess.run(tamper_cmd, capture_output=True, text=True)
    assert t_res.returncode == 0, f"Tamper EH boundary fingerprint command failed: {t_res.stderr}"

    verify_res = verify_structural_transformations(tampered_dll, "edge_cases", baseline_path=BENIGN_DLL)
    assert verify_res.get("verified") is False
    assert verify_res.get("status") == "FAILED"
    assert "baseline_exception_handlers_matched" in verify_res.get("unverified_transformations", [])


def test_whitespace_and_invalid_confuserex_sha256_fails_immediately(tmp_path, runner_path, monkeypatch):
    """
    Validates that any invalid CONFUSEREX_SHA256 (including whitespace-only strings that would
    strip to empty, wrong-length hex strings, and non-hex characters) fails immediately with
    ValueError and cannot accidentally disable executable checksum verification.
    """
    # 1. Whitespace only: must raise ValueError immediately
    monkeypatch.setenv("CONFUSEREX_SHA256", "   \t  \n  ")
    with pytest.raises(ValueError, match="CONFUSEREX_SHA256 environment variable"):
        get_confuserex_pin_configuration()

    with pytest.raises(ValueError, match="CONFUSEREX_SHA256 environment variable"):
        run_all_benchmarks(fixtures_dir=FIXTURES_DIR, runner_path=runner_path)

    # 2. Too short (e.g. 63 chars): must raise ValueError
    monkeypatch.setenv("CONFUSEREX_SHA256", "a" * 63)
    with pytest.raises(ValueError, match="expected exactly 64 hexadecimal characters"):
        get_confuserex_pin_configuration()

    # 3. Non-hex characters: must raise ValueError
    monkeypatch.setenv("CONFUSEREX_SHA256", "z" * 64)
    with pytest.raises(ValueError, match="expected exactly 64 hexadecimal characters"):
        get_confuserex_pin_configuration()

    # 4. Valid 64-hex override succeeds in configuration resolution
    valid_sha = "a" * 64
    monkeypatch.setenv("CONFUSEREX_SHA256", valid_sha)
    monkeypatch.setenv("CONFUSEREX_BUILD_ID", "CI-Test-Build-42")
    pinned_release, expected_sha = get_confuserex_pin_configuration()
    assert expected_sha == valid_sha
    assert "Custom ConfuserEx Build (CI-Test-Build-42)" in pinned_release

    # 5. Executable whose hash does not match the valid override fails verification
    fake_cli = tmp_path / "Confuser.CLI.exe"
    fake_cli.write_bytes(b"MZ_DUMMY_EXECUTABLE_CONTENT_FOR_HASH_MISMATCH_TEST")
    monkeypatch.setenv("CONFUSEREX_PATH", str(fake_cli))

    summary = run_all_benchmarks(fixtures_dir=FIXTURES_DIR, runner_path=runner_path)
    real_cases = [r for r in summary["results"] if r.get("scenario") == "real_confuserex"]
    assert len(real_cases) == 1
    assert real_cases[0]["verdict"] == "REAL_PROTECTOR_FAIL"
    assert valid_sha in real_cases[0]["error"]


def test_altered_local_variable_type_detected(tmp_path, runner_path, expected_baseline):
    """
    Validates that altering a local variable's type without changing the local count
    (e.g. changing int32 to int64) is caught by baseline metadata comparison and fails verification.
    """
    generator = find_generator()
    clean_path = FIXTURES_DIR / "fixture_edge_cases_clean.dll"
    if not clean_path.exists():
        run_benchmark_case(
            "Generics & Exception Edges",
            FIXTURES_DIR / "fixture_edge_cases.dll",
            "edge_cases",
            runner_path,
            expected_baseline,
            baseline_dll_path=BENIGN_DLL,
        )

    tampered_dll = tmp_path / "tampered_local_type.dll"
    tamper_cmd = get_exec_command(generator) + ["--tamper-local-type", str(clean_path), str(tampered_dll)]
    t_res = subprocess.run(tamper_cmd, capture_output=True, text=True)
    assert t_res.returncode == 0, f"Tamper local type command failed: {t_res.stderr}"

    verify_res = verify_structural_transformations(tampered_dll, "edge_cases", baseline_path=BENIGN_DLL)
    assert verify_res.get("verified") is False
    assert verify_res.get("status") == "FAILED"
    assert "baseline_exception_handlers_matched" in verify_res.get("unverified_transformations", [])


def test_missing_tool_diagnostic_uses_custom_pin_label(runner_path, monkeypatch):
    """
    Validates that when a custom ConfuserEx pin is configured, the SKIPPED_TOOL_MISSING
    diagnostic consistently reports the custom pin label and custom expected SHA-256
    rather than stale module-level official defaults.
    """
    custom_sha = "b" * 64
    custom_build = "Custom-CI-Diagnostic-Test"
    monkeypatch.setenv("CONFUSEREX_SHA256", custom_sha)
    monkeypatch.setenv("CONFUSEREX_BUILD_ID", custom_build)
    monkeypatch.setenv("CONFUSEREX_PATH", "nonexistent/Confuser.CLI.exe")

    summary = run_all_benchmarks(fixtures_dir=FIXTURES_DIR, runner_path=runner_path)
    real_cases = [r for r in summary["results"] if r.get("scenario") == "real_confuserex"]
    assert len(real_cases) == 1
    real_case = real_cases[0]

    assert real_case["verdict"] == "SKIPPED_TOOL_MISSING"
    assert custom_build in real_case["case_name"]
    assert custom_build in real_case["error"]
    assert custom_sha[:16] in real_case["error"]
    assert "yck1509/ConfuserEx" not in real_case["error"]


def test_altered_generic_special_constraint_flag_detected(tmp_path, runner_path, expected_baseline):
    """
    Validates that altering a generic parameter's special constraint flags (e.g. ReferenceTypeConstraint)
    without modifying the explicit constraint collection is caught by baseline metadata comparison and fails verification.
    """
    generator = find_generator()
    clean_path = FIXTURES_DIR / "fixture_edge_cases_clean.dll"
    if not clean_path.exists():
        run_benchmark_case(
            "Generics & Exception Edges",
            FIXTURES_DIR / "fixture_edge_cases.dll",
            "edge_cases",
            runner_path,
            expected_baseline,
            baseline_dll_path=BENIGN_DLL,
        )

    tampered_dll = tmp_path / "tampered_generic_constraint.dll"
    tamper_cmd = get_exec_command(generator) + ["--tamper-generic-constraint", str(clean_path), str(tampered_dll)]
    t_res = subprocess.run(tamper_cmd, capture_output=True, text=True)
    assert t_res.returncode == 0, f"Tamper generic constraint command failed: {t_res.stderr}"

    verify_res = verify_structural_transformations(tampered_dll, "edge_cases", baseline_path=BENIGN_DLL)
    assert verify_res.get("verified") is False
    assert verify_res.get("status") == "FAILED"
    assert "baseline_exception_handlers_matched" in verify_res.get("unverified_transformations", [])




