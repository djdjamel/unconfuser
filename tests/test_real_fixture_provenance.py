"""
Tests for authentic ConfuserEx fixture provenance and reproducibility verification.

Validates that benchmarks/prepare_real_fixture.py strictly rejects:
  - Missing fixtures
  - Missing manifests
  - Stale fixtures (source module or profile modified)
  - Tampered / unauthenticated PE files (even with valid MZ headers)
and safely reuses only verified fixtures.
"""

import json
import shutil
from pathlib import Path
import pytest

from benchmarks.prepare_real_fixture import (
    create_fixture_manifest,
    save_fixture_manifest,
    verify_fixture_provenance,
    prepare_real_confuserex_fixture,
    get_manifest_path,
    compute_file_sha256,
    compute_source_code_hash,
    EXPECTED_CLI_SHA256,
)


@pytest.fixture
def mock_fixture_env(tmp_path):
    """Sets up a temporary isolated directory with mock source, profile, and toolchain."""
    work_dir = tmp_path / "fixture_test"
    work_dir.mkdir()

    # 1. Mock Confuser.CLI.exe with expected hash (fake binary with padding)
    cli_file = work_dir / "Confuser.CLI.exe"
    cli_file.write_bytes(b"MOCK_CLI_BINARY" * 100)

    # 2. Mock source module (BenignSample.exe)
    source_file = work_dir / "BenignSample.exe"
    source_file.write_bytes(b"MZ" + b"\x00" * 5000 + b"ORIGINAL_SOURCE_CODE")

    # 3. Mock protection profile (.crproj)
    profile_file = work_dir / "test_profile.crproj"
    profile_file.write_text("<project><rule pattern='true'><protection id='constants'/></rule></project>", encoding="utf-8")

    # 4. Mock generated fixture (valid PE with MZ header > 4096 bytes)
    fixture_dir = work_dir / "real_confuserex"
    fixture_dir.mkdir()
    fixture_file = fixture_dir / "BenignSample.exe"
    fixture_file.write_bytes(b"MZ" + b"\x90" * 10000 + b"PROTECTED_PAYLOAD")

    manifest_file = fixture_dir / "fixture_manifest.json"

    return {
        "work_dir": work_dir,
        "cli_file": cli_file,
        "source_file": source_file,
        "profile_file": profile_file,
        "fixture_dir": fixture_dir,
        "fixture_file": fixture_file,
        "manifest_file": manifest_file,
    }


def test_provenance_fails_when_fixture_missing(mock_fixture_env, monkeypatch):
    """Provenance check must fail if the fixture file is missing."""
    env = mock_fixture_env
    mock_cli_sha = compute_file_sha256(env["cli_file"])
    monkeypatch.setattr("benchmarks.prepare_real_fixture.EXPECTED_CLI_SHA256", mock_cli_sha)

    manifest_data = create_fixture_manifest(
        target_output_file=env["fixture_file"],
        source_module=env["source_file"],
        cli_path=env["cli_file"],
        profile_path=env["profile_file"],
    )
    save_fixture_manifest(env["manifest_file"], manifest_data)

    # Delete fixture file
    env["fixture_file"].unlink()

    is_valid, reason = verify_fixture_provenance(
        env["fixture_file"], env["manifest_file"], env["source_file"], env["cli_file"], env["profile_file"]
    )
    assert not is_valid
    assert "not found" in reason.lower()


def test_provenance_fails_when_manifest_missing(mock_fixture_env):
    """Provenance check must fail if the manifest is missing, even with a valid MZ file."""
    env = mock_fixture_env
    assert env["fixture_file"].exists()
    assert not env["manifest_file"].exists()

    is_valid, reason = verify_fixture_provenance(
        env["fixture_file"], env["manifest_file"], env["source_file"], env["cli_file"], env["profile_file"]
    )
    assert not is_valid
    assert "manifest not found" in reason.lower()


def test_provenance_succeeds_when_all_hashes_match(mock_fixture_env, monkeypatch):
    """Provenance check succeeds when fixture, manifest, source, profile, and toolchain match."""
    env = mock_fixture_env

    # Monkeypatch EXPECTED_CLI_SHA256 to match our mock cli
    mock_cli_sha = compute_file_sha256(env["cli_file"])
    monkeypatch.setattr("benchmarks.prepare_real_fixture.EXPECTED_CLI_SHA256", mock_cli_sha)

    manifest_data = create_fixture_manifest(
        target_output_file=env["fixture_file"],
        source_module=env["source_file"],
        cli_path=env["cli_file"],
        profile_path=env["profile_file"],
    )
    save_fixture_manifest(env["manifest_file"], manifest_data)

    is_valid, reason = verify_fixture_provenance(
        env["fixture_file"], env["manifest_file"], env["source_file"], env["cli_file"], env["profile_file"]
    )
    assert is_valid
    assert "verified" in reason.lower()


def test_provenance_fails_when_source_module_stale(mock_fixture_env, monkeypatch):
    """Provenance check fails if the source module was modified after fixture was built."""
    env = mock_fixture_env
    mock_cli_sha = compute_file_sha256(env["cli_file"])
    monkeypatch.setattr("benchmarks.prepare_real_fixture.EXPECTED_CLI_SHA256", mock_cli_sha)

    manifest_data = create_fixture_manifest(
        target_output_file=env["fixture_file"],
        source_module=env["source_file"],
        cli_path=env["cli_file"],
        profile_path=env["profile_file"],
    )
    save_fixture_manifest(env["manifest_file"], manifest_data)

    # Modify source module
    env["source_file"].write_bytes(b"MZ" + b"\x00" * 5000 + b"MODIFIED_SOURCE_CODE")

    is_valid, reason = verify_fixture_provenance(
        env["fixture_file"], env["manifest_file"], env["source_file"], env["cli_file"], env["profile_file"]
    )
    assert not is_valid
    assert "source module hash changed" in reason.lower()


def test_provenance_fails_when_protection_profile_stale(mock_fixture_env, monkeypatch):
    """Provenance check fails if the protection profile (.crproj) was modified."""
    env = mock_fixture_env
    mock_cli_sha = compute_file_sha256(env["cli_file"])
    monkeypatch.setattr("benchmarks.prepare_real_fixture.EXPECTED_CLI_SHA256", mock_cli_sha)

    manifest_data = create_fixture_manifest(
        target_output_file=env["fixture_file"],
        source_module=env["source_file"],
        cli_path=env["cli_file"],
        profile_path=env["profile_file"],
    )
    save_fixture_manifest(env["manifest_file"], manifest_data)

    # Modify profile
    env["profile_file"].write_text("<project><rule pattern='true'><protection id='ctrl flow'/></rule></project>", encoding="utf-8")

    is_valid, reason = verify_fixture_provenance(
        env["fixture_file"], env["manifest_file"], env["source_file"], env["cli_file"], env["profile_file"]
    )
    assert not is_valid
    assert "protection profile hash changed" in reason.lower()


def test_provenance_fails_when_fixture_tampered(mock_fixture_env, monkeypatch):
    """Provenance check fails if the fixture binary itself was modified/tampered."""
    env = mock_fixture_env
    mock_cli_sha = compute_file_sha256(env["cli_file"])
    monkeypatch.setattr("benchmarks.prepare_real_fixture.EXPECTED_CLI_SHA256", mock_cli_sha)

    manifest_data = create_fixture_manifest(
        target_output_file=env["fixture_file"],
        source_module=env["source_file"],
        cli_path=env["cli_file"],
        profile_path=env["profile_file"],
    )
    save_fixture_manifest(env["manifest_file"], manifest_data)

    # Tamper with fixture binary (even keeping MZ header)
    env["fixture_file"].write_bytes(b"MZ" + b"\x90" * 10000 + b"TAMPERED_CONTENT")

    is_valid, reason = verify_fixture_provenance(
        env["fixture_file"], env["manifest_file"], env["source_file"], env["cli_file"], env["profile_file"]
    )
    assert not is_valid
    assert "hash mismatch" in reason.lower()


def test_provenance_fails_when_fixture_too_small_or_not_mz(mock_fixture_env, monkeypatch):
    """Provenance check fails if fixture is truncated or missing MZ header."""
    env = mock_fixture_env
    mock_cli_sha = compute_file_sha256(env["cli_file"])
    monkeypatch.setattr("benchmarks.prepare_real_fixture.EXPECTED_CLI_SHA256", mock_cli_sha)

    # Small file
    env["fixture_file"].write_bytes(b"MZ1234")
    manifest_data = create_fixture_manifest(
        target_output_file=env["fixture_file"],
        source_module=env["source_file"],
        cli_path=env["cli_file"],
        profile_path=env["profile_file"],
    )
    save_fixture_manifest(env["manifest_file"], manifest_data)

    is_valid, reason = verify_fixture_provenance(
        env["fixture_file"], env["manifest_file"], env["source_file"], env["cli_file"], env["profile_file"]
    )
    assert not is_valid
    assert "too small" in reason.lower()


def test_real_fixture_end_to_end_idempotency():
    """Validates that running prepare_real_confuserex_fixture on the real repo fixture is idempotent."""
    # First execution: ensures fixture and manifest exist
    fixture_path = prepare_real_confuserex_fixture(force=False)
    assert fixture_path.exists()
    assert fixture_path.stat().st_size > 4096

    manifest_path = get_manifest_path()
    assert manifest_path.exists()

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    assert manifest["confuserex_toolchain"]["actual_cli_sha256"] == EXPECTED_CLI_SHA256.lower()
    assert manifest["fixture"]["sha256"] == compute_file_sha256(fixture_path).lower()

    # Record timestamp before second call
    mtime_before = fixture_path.stat().st_mtime_ns

    # Second execution: must reuse without rebuilding
    fixture_path_2 = prepare_real_confuserex_fixture(force=False)
    mtime_after = fixture_path_2.stat().st_mtime_ns

    assert fixture_path == fixture_path_2
    assert mtime_before == mtime_after, "Expected fixture to be reused without modification"


def test_provenance_fails_when_source_code_modified(mock_fixture_env, monkeypatch):
    """Provenance check fails if tracked C# source code files were modified."""
    env = mock_fixture_env
    mock_cli_sha = compute_file_sha256(env["cli_file"])
    monkeypatch.setattr("benchmarks.prepare_real_fixture.EXPECTED_CLI_SHA256", mock_cli_sha)

    # Create a mock .csproj and .cs file in the source directory
    proj_file = env["work_dir"] / "BenignSample.csproj"
    proj_file.write_text("<Project></Project>", encoding="utf-8")
    cs_file = env["work_dir"] / "Program.cs"
    cs_file.write_text("class Program {}", encoding="utf-8")

    manifest_data = create_fixture_manifest(
        target_output_file=env["fixture_file"],
        source_module=env["source_file"],
        cli_path=env["cli_file"],
        profile_path=env["profile_file"],
    )
    save_fixture_manifest(env["manifest_file"], manifest_data)

    assert "source_code" in manifest_data

    # Modify the C# source file
    cs_file.write_text("class Program { int x = 42; }", encoding="utf-8")

    is_valid, reason = verify_fixture_provenance(
        env["fixture_file"], env["manifest_file"], env["source_file"], env["cli_file"], env["profile_file"]
    )
    assert not is_valid
    assert "source code modified" in reason.lower()


def test_provenance_fails_when_source_code_cannot_be_computed(mock_fixture_env, monkeypatch):
    """Provenance check must strictly fail if source_code is tracked in manifest but source files/csproj are missing."""
    env = mock_fixture_env
    mock_cli_sha = compute_file_sha256(env["cli_file"])
    monkeypatch.setattr("benchmarks.prepare_real_fixture.EXPECTED_CLI_SHA256", mock_cli_sha)

    # Create mock project files
    proj_file = env["work_dir"] / "BenignSample.csproj"
    proj_file.write_text("<Project></Project>", encoding="utf-8")
    cs_file = env["work_dir"] / "Program.cs"
    cs_file.write_text("class Program {}", encoding="utf-8")

    manifest_data = create_fixture_manifest(
        target_output_file=env["fixture_file"],
        source_module=env["source_file"],
        cli_path=env["cli_file"],
        profile_path=env["profile_file"],
    )
    save_fixture_manifest(env["manifest_file"], manifest_data)
    assert "source_code" in manifest_data

    # Now delete the .csproj so compute_source_code_hash returns None
    proj_file.unlink()
    cs_file.unlink()

    is_valid, reason = verify_fixture_provenance(
        env["fixture_file"], env["manifest_file"], env["source_file"], env["cli_file"], env["profile_file"]
    )
    assert not is_valid
    assert "cannot verify source code provenance" in reason.lower()


def test_source_code_hash_recursive_and_subdirectory_files(mock_fixture_env):
    """Verifies that compute_source_code_hash recursively scans subdirectories and is sensitive to changes therein."""
    env = mock_fixture_env
    proj_file = env["work_dir"] / "BenignSample.csproj"
    proj_file.write_text("<Project></Project>", encoding="utf-8")
    sub_dir = env["work_dir"] / "Services" / "Helpers"
    sub_dir.mkdir(parents=True)
    sub_cs = sub_dir / "MathHelper.cs"
    sub_cs.write_text("class MathHelper {}", encoding="utf-8")

    res = compute_source_code_hash(env["source_file"])
    assert res is not None
    hash1, files1 = res
    assert "Services/Helpers/MathHelper.cs" in files1
    assert "BenignSample.csproj" in files1

    # Modifying the subdirectory file changes the hash
    sub_cs.write_text("class MathHelper { public int Add(int a, int b) => a + b; }", encoding="utf-8")
    res2 = compute_source_code_hash(env["source_file"])
    assert res2 is not None
    hash2, files2 = res2
    assert hash1 != hash2


