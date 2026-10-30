#!/usr/bin/env python3
"""
Dedicated fixture preparation script for authentic ConfuserEx 1.0.0 binaries.
Ensures ConfuserEx toolchain is provisioned and generates:
    benchmarks/fixtures/real_confuserex/BenignSample.exe
along with a cryptographic provenance manifest:
    benchmarks/fixtures/real_confuserex/fixture_manifest.json
verifying input module, protection profile, ConfuserEx binary, and output fixture hashes.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
BENCHMARKS_DIR = WORKSPACE_ROOT / "benchmarks"
FIXTURES_DIR = BENCHMARKS_DIR / "fixtures"
REAL_CONFUSEREX_DIR = FIXTURES_DIR / "real_confuserex"
PROFILE_CRPROJ = BENCHMARKS_DIR / "ConfuserExProfile" / "confuserex_v1.0.0.crproj"
MANIFEST_NAME = "fixture_manifest.json"

# Add benchmarks directory to sys.path to import provision_confuserex
sys.path.insert(0, str(BENCHMARKS_DIR))
try:
    from provision_confuserex import provision_confuserex, EXPECTED_CLI_SHA256, compute_file_sha256
except ImportError:
    from benchmarks.provision_confuserex import provision_confuserex, EXPECTED_CLI_SHA256, compute_file_sha256


def get_confuser_cli_path() -> Path:
    env_path = os.environ.get("CONFUSEREX_PATH")
    if env_path:
        p = Path(env_path)
        if p.exists():
            return p
    return WORKSPACE_ROOT / "tools" / "ConfuserEx" / "Confuser.CLI.exe"


def compute_source_code_hash(source_module: Path) -> Optional[Tuple[str, List[str]]]:
    """Computes a deterministic composite hash of all C# source and project files for the module project."""
    curr = source_module.parent
    proj_dir = None
    for _ in range(4):
        if list(curr.glob("*.csproj")):
            proj_dir = curr
            break
        curr = curr.parent

    if not proj_dir:
        return None

    sources = []
    for ext in ("*.cs", "*.csproj", "*.txt"):
        for f in proj_dir.rglob(ext):
            if f.is_file():
                parts = f.relative_to(proj_dir).parts
                if "bin" in parts or "obj" in parts:
                    continue
                sources.append(f)

    if not sources:
        return None

    sources.sort(key=lambda p: p.relative_to(proj_dir).as_posix())
    hasher = hashlib.sha256()
    relative_names = []
    for s in sources:
        rel_posix = s.relative_to(proj_dir).as_posix()
        relative_names.append(rel_posix)
        hasher.update(rel_posix.encode("utf-8"))
        hasher.update(s.read_bytes())

    return hasher.hexdigest(), relative_names


def ensure_benign_sample(force_rebuild: bool = False) -> Path:
    """Finds or builds the target module to be protected, ensuring it is fresh with respect to C# sources."""
    benign_dir = BENCHMARKS_DIR / "BenignSample"
    net48_exe = benign_dir / "bin" / "Release" / "net48" / "BenignSample.exe"
    net8_dll = benign_dir / "bin" / "Release" / "net8.0" / "BenignSample.dll"

    target_bin = net48_exe if net48_exe.exists() else (net8_dll if net8_dll.exists() else net48_exe)

    needs_build = force_rebuild or not target_bin.exists()
    if not needs_build and target_bin.exists():
        bin_mtime = target_bin.stat().st_mtime
        for ext in ("*.cs", "*.csproj", "*.txt"):
            for s in benign_dir.rglob(ext):
                parts = s.relative_to(benign_dir).parts
                if "bin" in parts or "obj" in parts:
                    continue
                if s.stat().st_mtime > bin_mtime:
                    print(f"[*] Source file {s.name} is newer than binary {target_bin.name}. Rebuilding...")
                    needs_build = True
                    break
            if needs_build:
                break

    if needs_build:
        print("[*] Building BenignSample from sources...")
        proj_path = benign_dir / "BenignSample.csproj"
        res = subprocess.run(
            ["dotnet", "build", str(proj_path), "-c", "Release"],
            capture_output=True,
            text=True
        )
        if res.returncode != 0:
            raise RuntimeError(f"Failed to build BenignSample: {res.stderr}\n{res.stdout}")

    if net48_exe.exists():
        return net48_exe
    if net8_dll.exists():
        return net8_dll
    raise FileNotFoundError("Could not find BenignSample binary after build.")


def get_manifest_path(target_dir: Optional[Path] = None) -> Path:
    base_dir = target_dir or REAL_CONFUSEREX_DIR
    return base_dir / MANIFEST_NAME


def create_fixture_manifest(
    target_output_file: Path,
    source_module: Path,
    cli_path: Path,
    profile_path: Path,
) -> Dict[str, Any]:
    """Builds a structured provenance manifest dictionary."""
    cli_sha = compute_file_sha256(cli_path)
    source_sha = compute_file_sha256(source_module)
    profile_sha = compute_file_sha256(profile_path)
    fixture_sha = compute_file_sha256(target_output_file)

    manifest = {
        "manifest_version": "1.0.0",
        "generator": "benchmarks/prepare_real_fixture.py",
        "confuserex_toolchain": {
            "release": "v1.0.0",
            "commit": "3c9c29d9daf2f1259edf69054c5693d5d225a980",
            "cli_filename": cli_path.name,
            "expected_cli_sha256": EXPECTED_CLI_SHA256.lower(),
            "actual_cli_sha256": cli_sha.lower(),
        },
        "source_module": {
            "name": source_module.name,
            "sha256": source_sha.lower(),
            "size_bytes": source_module.stat().st_size,
        },
        "protection_profile": {
            "filename": profile_path.name,
            "sha256": profile_sha.lower(),
            "size_bytes": profile_path.stat().st_size,
        },
        "fixture": {
            "filename": target_output_file.name,
            "sha256": fixture_sha.lower(),
            "size_bytes": target_output_file.stat().st_size,
        },
    }

    src_code_info = compute_source_code_hash(source_module)
    if src_code_info:
        sources_sha, source_files = src_code_info
        manifest["source_code"] = {
            "source_files": source_files,
            "sources_sha256": sources_sha.lower(),
        }

    return manifest


def save_fixture_manifest(manifest_path: Path, manifest_data: Dict[str, Any]) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = manifest_path.with_suffix(".tmp")
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2)
    temp_path.replace(manifest_path)


def verify_fixture_provenance(
    target_output_file: Path,
    manifest_path: Path,
    source_module: Path,
    cli_path: Path,
    profile_path: Path,
) -> Tuple[bool, str]:
    """
    Verifies that target_output_file matches the cryptographic provenance in manifest_path.
    Returns (True, "Provenance verified") or (False, <failure_reason>).
    """
    if not target_output_file.exists():
        return False, f"Fixture file not found at {target_output_file}"

    if not manifest_path.exists():
        return False, f"Provenance manifest not found at {manifest_path}"

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception as ex:
        return False, f"Failed to parse provenance manifest: {ex}"

    # 1. Validate manifest structure
    if "confuserex_toolchain" not in manifest or "source_module" not in manifest or "fixture" not in manifest or "protection_profile" not in manifest:
        return False, "Provenance manifest is missing required sections"

    # 2. Validate toolchain hash
    if not cli_path.exists():
        return False, f"Confuser.CLI.exe not found at {cli_path}"

    actual_cli_sha = compute_file_sha256(cli_path).lower()
    manifest_cli_sha = str(manifest["confuserex_toolchain"].get("actual_cli_sha256", "")).lower()
    if actual_cli_sha != EXPECTED_CLI_SHA256.lower():
        return False, f"Confuser.CLI.exe hash {actual_cli_sha} does not match expected {EXPECTED_CLI_SHA256.lower()}"
    if manifest_cli_sha != actual_cli_sha:
        return False, f"Manifest toolchain hash {manifest_cli_sha} does not match current CLI hash {actual_cli_sha}"

    # 3. Validate source module binary hash
    if not source_module.exists():
        return False, f"Source module not found at {source_module}"

    actual_source_sha = compute_file_sha256(source_module).lower()
    manifest_source_sha = str(manifest["source_module"].get("sha256", "")).lower()
    if actual_source_sha != manifest_source_sha:
        return False, f"Source module hash changed (current: {actual_source_sha}, manifest: {manifest_source_sha})"

    # 3.5 Validate source code hash if tracked in manifest
    if "source_code" in manifest:
        src_code_info = compute_source_code_hash(source_module)
        if not src_code_info:
            return False, "Cannot verify source code provenance: project directory or sources missing"
        current_sources_sha, _ = src_code_info
        manifest_sources_sha = str(manifest["source_code"].get("sources_sha256", "")).lower()
        if current_sources_sha != manifest_sources_sha:
            return False, f"Source code modified (current: {current_sources_sha}, manifest: {manifest_sources_sha})"

    # 4. Validate protection profile hash
    if not profile_path.exists():
        return False, f"Protection profile not found at {profile_path}"

    actual_profile_sha = compute_file_sha256(profile_path).lower()
    manifest_profile_sha = str(manifest["protection_profile"].get("sha256", "")).lower()
    if actual_profile_sha != manifest_profile_sha:
        return False, f"Protection profile hash changed (current: {actual_profile_sha}, manifest: {manifest_profile_sha})"

    # 5. Validate output fixture hash and basic PE sanity
    if target_output_file.stat().st_size <= 4096:
        return False, f"Fixture size is too small ({target_output_file.stat().st_size} bytes)"

    with open(target_output_file, "rb") as f:
        header = f.read(2)
    if header != b"MZ":
        return False, "Fixture missing MZ executable header"

    actual_fixture_sha = compute_file_sha256(target_output_file).lower()
    manifest_fixture_sha = str(manifest["fixture"].get("sha256", "")).lower()
    if actual_fixture_sha != manifest_fixture_sha:
        return False, f"Fixture hash mismatch (current: {actual_fixture_sha}, manifest: {manifest_fixture_sha})"

    manifest_fixture_size = manifest["fixture"].get("size_bytes")
    if target_output_file.stat().st_size != manifest_fixture_size:
        return False, f"Fixture size mismatch (current: {target_output_file.stat().st_size}, manifest: {manifest_fixture_size})"

    return True, "Provenance verified"


def prepare_real_confuserex_fixture(
    force: bool = False,
    target_dir: Optional[Path] = None,
    source_module: Optional[Path] = None,
    cli_path: Optional[Path] = None,
    profile_path: Optional[Path] = None,
) -> Path:
    """
    Provisions Confuser.CLI.exe if needed, generates the authentic fixture,
    and produces a cryptographic provenance manifest. If an existing fixture
    has verified provenance matching current source and profile, it is safely reused.
    """
    base_dir = target_dir or REAL_CONFUSEREX_DIR
    base_dir.mkdir(parents=True, exist_ok=True)
    target_output_file = base_dir / "BenignSample.exe"
    manifest_path = get_manifest_path(base_dir)

    # Resolve dependencies
    resolved_cli = cli_path or get_confuser_cli_path()
    resolved_source = source_module or ensure_benign_sample()
    resolved_profile = profile_path or PROFILE_CRPROJ

    # Check existing fixture provenance
    if target_output_file.exists() and not force:
        if resolved_cli.exists() and resolved_source.exists() and resolved_profile.exists():
            is_valid, reason = verify_fixture_provenance(
                target_output_file, manifest_path, resolved_source, resolved_cli, resolved_profile
            )
            if is_valid:
                print(f"[+] Authentic ConfuserEx fixture with verified provenance present at: {target_output_file}")
                return target_output_file
            print(f"[*] Fixture provenance check failed ({reason}). Re-generating fixture...")
        else:
            print("[*] Required toolchain or source files missing for provenance check. Re-generating...")

    print("[*] Preparing authentic ConfuserEx fixture...")

    # 1. Ensure Confuser.CLI.exe is provisioned
    if not resolved_cli.exists():
        print("[*] Provisioning Confuser.CLI.exe...")
        resolved_cli = provision_confuserex()

    actual_sha = compute_file_sha256(resolved_cli)
    if actual_sha.lower() != EXPECTED_CLI_SHA256.lower():
        raise ValueError(
            f"Confuser.CLI.exe checksum mismatch! Expected: {EXPECTED_CLI_SHA256}, Got: {actual_sha}"
        )

    # 2. Ensure BenignSample binary is built
    print(f"[*] Target source module: {resolved_source}")
    print(f"[*] Protection profile:   {resolved_profile}")

    # 3. Clean target directory for clean run
    if base_dir.exists():
        for item in list(base_dir.iterdir()):
            if item.is_file():
                try:
                    item.unlink()
                except Exception:
                    pass

    # 4. Generate .crproj instance
    crproj_template = resolved_profile.read_text(encoding="utf-8")
    try:
        rel_output_dir = os.path.relpath(base_dir, resolved_source.parent)
        rel_base_dir = os.path.relpath(resolved_source.parent, base_dir)
        rel_module_path = resolved_source.name
    except ValueError:
        rel_output_dir = str(base_dir)
        rel_base_dir = str(resolved_source.parent)
        rel_module_path = str(resolved_source)

    crproj_content = crproj_template.format(
        output_dir=rel_output_dir,
        base_dir=rel_base_dir,
        module_path=rel_module_path,
    )
    instance_crproj_path = base_dir / "confuser_run.crproj"
    instance_crproj_path.write_text(crproj_content, encoding="utf-8")

    # 5. Run Confuser.CLI.exe
    print(f"[*] Running Confuser.CLI.exe with {instance_crproj_path}...")
    proc = subprocess.run(
        [str(resolved_cli), "-n", str(instance_crproj_path)],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )

    if proc.returncode != 0:
        err = proc.stderr.strip() or proc.stdout.strip()
        raise RuntimeError(f"Confuser.CLI.exe failed (code {proc.returncode}): {err}")

    # The output file has the same name as resolved_source
    produced_file = base_dir / resolved_source.name
    if not produced_file.exists():
        raise FileNotFoundError(f"Confuser.CLI.exe did not produce expected output at {produced_file}")

    # Ensure final fixture is named BenignSample.exe
    if produced_file.resolve() != target_output_file.resolve():
        shutil.copy2(produced_file, target_output_file)

    # Validate output file
    if target_output_file.stat().st_size <= 4096:
        raise ValueError(f"Produced fixture is too small ({target_output_file.stat().st_size} bytes)")

    with open(target_output_file, "rb") as f:
        if f.read(2) != b"MZ":
            raise ValueError("Produced fixture does not start with MZ header")

    # 6. Generate and save cryptographic provenance manifest
    manifest_data = create_fixture_manifest(
        target_output_file, resolved_source, resolved_cli, resolved_profile
    )
    save_fixture_manifest(manifest_path, manifest_data)

    # 7. Post-generation verification
    is_valid, reason = verify_fixture_provenance(
        target_output_file, manifest_path, resolved_source, resolved_cli, resolved_profile
    )
    if not is_valid:
        raise RuntimeError(f"Post-generation provenance verification failed: {reason}")

    sha = compute_file_sha256(target_output_file)
    print(f"[+] Successfully generated authentic ConfuserEx fixture with verified provenance:")
    print(f"    Path:     {target_output_file}")
    print(f"    Manifest: {manifest_path}")
    print(f"    Size:     {target_output_file.stat().st_size:,} bytes")
    print(f"    SHA-256:  {sha}")

    return target_output_file


def main():
    parser = argparse.ArgumentParser(description="Prepare authentic ConfuserEx fixture with provenance manifest")
    parser.add_argument("--force", action="store_true", help="Force regeneration of fixture")
    args = parser.parse_args()

    try:
        fixture_path = prepare_real_confuserex_fixture(force=args.force)
        print(f"[+] Ready: {fixture_path}")
        return 0
    except Exception as ex:
        print(f"[!] Error preparing fixture: {ex}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
