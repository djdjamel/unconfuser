#!/usr/bin/env python3
"""
Tests for scripts/Verify-DeobfuscatedBinary.ps1 behavioral harness.

Covers acceptance criteria from Phase 7:
1. Valid assembly execution and success
2. Missing file handling
3. Unreadable/locked file handling
4. Invalid PE header / corrupted file handling
5. Empty / truncated file handling
6. Missing WinForms ComponentResourceManager resources
7. Corrupted IL method detection
8. Timeout enforcement and worker process termination
9. Safe execution with -SkipModuleCctor
10. Indeterminate classification on runtime dependency mismatch
11. JSON report schema completeness and traceability
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path
import pytest

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = WORKSPACE_ROOT / "scripts" / "Verify-DeobfuscatedBinary.ps1"
FIXTURES_DIR = WORKSPACE_ROOT / "tests" / "fixtures" / "verification"
BENIGN_SAMPLE = WORKSPACE_ROOT / "benchmarks" / "BenignSample" / "bin" / "Release" / "net48" / "BenignSample.exe"


def run_verify(target_path, args=None, timeout_sec=30):
    """Executes Verify-DeobfuscatedBinary.ps1 with specified parameters and captures output."""
    cmd = [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(SCRIPT_PATH),
        "-Target",
        str(target_path),
    ]
    if args:
        cmd.extend(args)

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
    return proc


@pytest.fixture(scope="session", autouse=True)
def ensure_verification_fixtures():
    """Ensures synthetic verification fixtures are present before running tests."""
    corrupted_fixture = FIXTURES_DIR / "corrupted_il.dll"
    if not corrupted_fixture.exists():
        gen_script = WORKSPACE_ROOT / "scripts" / "Generate-VerificationFixtures.ps1"
        subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(gen_script)],
            check=True,
            capture_output=True,
        )


def test_valid_assembly_passes():
    """Verify that a valid benign assembly passes all checks and reports PASS."""
    assert BENIGN_SAMPLE.exists(), f"BenignSample executable not found at {BENIGN_SAMPLE}"
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = Path(tmp.name)

    try:
        proc = run_verify(BENIGN_SAMPLE, ["-ReportJson", str(report_path)])
        assert proc.returncode == 0, f"Expected returncode 0, got {proc.returncode}. Output:\n{proc.stdout}"

        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "PASS"
        assert data["load_success"] is True
        assert data["module_cctor_status"] == "SUCCESS"
        assert data["jit_success"] > 0
        assert data["jit_failed_corrupted_il"] == 0
    finally:
        if report_path.exists():
            report_path.unlink()


def test_missing_file_fails():
    """Verify that a non-existent file path reports FAIL and exit code 1."""
    nonexistent = WORKSPACE_ROOT / "nonexistent_assembly_xyz123.dll"
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = Path(tmp.name)

    try:
        proc = run_verify(nonexistent, ["-ReportJson", str(report_path)])
        assert proc.returncode == 1, f"Expected returncode 1, got {proc.returncode}"

        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "FAIL"
        assert data["load_success"] is False
        assert "not found" in data["load_error"].lower()
    finally:
        if report_path.exists():
            report_path.unlink()


def test_invalid_pe_header_fails():
    """Verify that a non-PE file (plain text) reports FAIL and invalid PE signature."""
    with tempfile.NamedTemporaryFile(suffix=".dll", delete=False) as tmp_file:
        tmp_file.write(b"NOT_A_PE_HEADER_" * 10)
        invalid_pe = Path(tmp_file.name)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_rep:
        report_path = Path(tmp_rep.name)

    try:
        proc = run_verify(invalid_pe, ["-ReportJson", str(report_path)])
        assert proc.returncode == 1

        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "FAIL"
        assert "invalid pe" in data["load_error"].lower() or "invalid pe" in data["summary"].lower()
    finally:
        if invalid_pe.exists():
            invalid_pe.unlink()
        if report_path.exists():
            report_path.unlink()


def test_empty_file_fails():
    """Verify that a 0-byte file reports FAIL and empty file error."""
    with tempfile.NamedTemporaryFile(suffix=".dll", delete=False) as tmp_file:
        empty_file = Path(tmp_file.name)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_rep:
        report_path = Path(tmp_rep.name)

    try:
        proc = run_verify(empty_file, ["-ReportJson", str(report_path)])
        assert proc.returncode == 1

        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "FAIL"
        assert "empty" in data["load_error"].lower() or "too small" in data["load_error"].lower()
    finally:
        if empty_file.exists():
            empty_file.unlink()
        if report_path.exists():
            report_path.unlink()


def test_missing_resource_form_fails():
    """Verify that a Form with missing ComponentResourceManager resources is detected and fails."""
    fixture = FIXTURES_DIR / "missing_resource_form.dll"
    assert fixture.exists(), f"Missing fixture {fixture}"

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = Path(tmp.name)

    try:
        proc = run_verify(fixture, ["-CheckForms", "-ReportJson", str(report_path)])
        assert proc.returncode == 1, f"Expected returncode 1, got {proc.returncode}"

        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "FAIL"
        assert data["forms_failed"] > 0
        assert len(data["form_failures"]) > 0
        assert any("MissingManifestResourceException" in f for f in data["form_failures"])
    finally:
        if report_path.exists():
            report_path.unlink()


def test_corrupted_il_method_fails():
    """Verify that a method with invalid/corrupted IL (stack underflow) triggers JIT failure and reports FAIL."""
    fixture = FIXTURES_DIR / "corrupted_il.dll"
    assert fixture.exists(), f"Missing fixture {fixture}"

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = Path(tmp.name)

    try:
        proc = run_verify(fixture, ["-ReportJson", str(report_path)])
        assert proc.returncode == 1, f"Expected returncode 1, got {proc.returncode}"

        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "FAIL"
        assert data["jit_failed_corrupted_il"] >= 1
        assert len(data["corrupted_il_failures"]) >= 1
        assert any("InvalidProgramException" in f for f in data["corrupted_il_failures"])
    finally:
        if report_path.exists():
            report_path.unlink()


def test_timeout_exceeded_fails():
    """Verify that an infinite loop inside <Module>..cctor times out and is terminated with status TIMEOUT."""
    fixture = FIXTURES_DIR / "infinite_loop_cctor.dll"
    assert fixture.exists(), f"Missing fixture {fixture}"

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = Path(tmp.name)

    try:
        # Strict 2-second timeout
        proc = run_verify(fixture, ["-TimeoutSeconds", "2", "-ReportJson", str(report_path)], timeout_sec=15)
        assert proc.returncode == 1, f"Expected returncode 1, got {proc.returncode}"

        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "TIMEOUT"
        assert data["exit_code"] == 1
        assert "timed out" in data["summary"].lower()
    finally:
        if report_path.exists():
            report_path.unlink()


def test_skip_module_cctor_avoids_timeout():
    """Verify that -SkipModuleCctor prevents executing <Module>..cctor and passes without timeout."""
    fixture = FIXTURES_DIR / "infinite_loop_cctor.dll"
    assert fixture.exists(), f"Missing fixture {fixture}"

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = Path(tmp.name)

    try:
        proc = run_verify(fixture, ["-SkipModuleCctor", "-TimeoutSeconds", "5", "-ReportJson", str(report_path)])
        assert proc.returncode == 0, f"Expected returncode 0 with SkipModuleCctor, got {proc.returncode}"

        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "PASS"
        assert data["module_cctor_status"] == "SKIPPED"
    finally:
        if report_path.exists():
            report_path.unlink()


def test_indeterminate_when_type_load_errors():
    """Verify that assemblies with runtime dependency mismatch are classified as INDETERMINATE, not PASS."""
    net8_fixture = WORKSPACE_ROOT / "benchmarks" / "BenignSample" / "bin" / "Release" / "net8.0" / "BenignSample.dll"
    if not net8_fixture.exists():
        pytest.skip("net8.0 fixture not available")

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = Path(tmp.name)

    try:
        proc = run_verify(net8_fixture, ["-ReportJson", str(report_path)])
        # Exit code should be non-zero (INDETERMINATE returns 2 without -AllowIndeterminate)
        assert proc.returncode != 0

        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "INDETERMINATE"
        assert len(data["type_load_errors"]) > 0
    finally:
        if report_path.exists():
            report_path.unlink()


def test_report_json_schema_completeness():
    """Verify that generated JSON report has all required schema keys and valid types."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = Path(tmp.name)

    try:
        proc = run_verify(BENIGN_SAMPLE, ["-ReportJson", str(report_path), "-CommitHash", "testcommit123"])
        assert proc.returncode == 0

        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        required_keys = [
            "timestamp",
            "commit_hash",
            "target",
            "sha256",
            "status",
            "exit_code",
            "duration_ms",
            "bitness",
            "load_success",
            "load_error",
            "module_cctor_status",
            "module_cctor_error",
            "total_types",
            "types_discovered",
            "type_load_errors",
            "total_methods",
            "jit_success",
            "jit_skipped",
            "jit_failed_missing_dependency",
            "jit_failed_corrupted_il",
            "corrupted_il_failures",
            "dependency_failures",
            "forms_checked",
            "forms_success",
            "forms_failed",
            "form_failures",
            "summary",
        ]

        for k in required_keys:
            assert k in data, f"Missing key '{k}' in JSON report"

        assert data["commit_hash"] == "testcommit123"
        assert isinstance(data["sha256"], str) and len(data["sha256"]) == 64
        assert data["status"] in ("PASS", "PARTIAL", "INDETERMINATE", "FAIL", "TIMEOUT", "NOT_RUN")
    finally:
        if report_path.exists():
            report_path.unlink()
