#!/usr/bin/env python3
"""
Dedicated fixture preparation script for authentic ConfuserEx 1.0.0 binaries.
Provisions the ConfuserEx toolchain and generates:
    benchmarks/fixtures/real_confuserex/BenignSample.exe
using the deterministic profile at benchmarks/ConfuserExProfile/confuserex_v1.0.0.crproj.
"""

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
BENCHMARKS_DIR = WORKSPACE_ROOT / "benchmarks"
FIXTURES_DIR = BENCHMARKS_DIR / "fixtures"
REAL_CONFUSEREX_DIR = FIXTURES_DIR / "real_confuserex"
PROFILE_CRPROJ = BENCHMARKS_DIR / "ConfuserExProfile" / "confuserex_v1.0.0.crproj"

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


def ensure_benign_sample() -> Path:
    """Finds or builds the target module to be protected."""
    net48_exe = BENCHMARKS_DIR / "BenignSample" / "bin" / "Release" / "net48" / "BenignSample.exe"
    net8_dll = BENCHMARKS_DIR / "BenignSample" / "bin" / "Release" / "net8.0" / "BenignSample.dll"

    if net48_exe.exists():
        return net48_exe
    if net8_dll.exists():
        return net8_dll

    print("[*] BenignSample binary not found. Building BenignSample...")
    proj_path = BENCHMARKS_DIR / "BenignSample" / "BenignSample.csproj"
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


def prepare_real_confuserex_fixture(force: bool = False) -> Path:
    """
    Provisions Confuser.CLI.exe if needed, generates benchmarks/fixtures/real_confuserex/BenignSample.exe,
    and validates the resulting protected PE.
    """
    REAL_CONFUSEREX_DIR.mkdir(parents=True, exist_ok=True)
    target_output_file = REAL_CONFUSEREX_DIR / "BenignSample.exe"

    if target_output_file.exists() and not force:
        if target_output_file.stat().st_size > 4096:
            with open(target_output_file, "rb") as f:
                header = f.read(2)
            if header == b"MZ":
                print(f"[+] Authentic ConfuserEx fixture already present at: {target_output_file}")
                return target_output_file

    print("[*] Preparing authentic ConfuserEx fixture...")

    # 1. Ensure Confuser.CLI.exe is provisioned
    cli_path = get_confuser_cli_path()
    if not cli_path.exists():
        print("[*] Provisioning Confuser.CLI.exe...")
        cli_path = provision_confuserex()

    actual_sha = compute_file_sha256(cli_path)
    if actual_sha.lower() != EXPECTED_CLI_SHA256.lower():
        raise ValueError(
            f"Confuser.CLI.exe checksum mismatch! Expected: {EXPECTED_CLI_SHA256}, Got: {actual_sha}"
        )

    # 2. Ensure BenignSample binary is built
    target_module = ensure_benign_sample()
    print(f"[*] Target source module: {target_module}")

    # 3. Clean target directory for clean run
    if REAL_CONFUSEREX_DIR.exists():
        for item in list(REAL_CONFUSEREX_DIR.iterdir()):
            if item.is_file():
                try:
                    item.unlink()
                except Exception:
                    pass

    # 4. Generate .crproj instance
    crproj_template = PROFILE_CRPROJ.read_text(encoding="utf-8")
    crproj_content = crproj_template.format(
        output_dir=str(REAL_CONFUSEREX_DIR),
        base_dir=str(target_module.parent),
        module_path=str(target_module),
    )
    instance_crproj_path = REAL_CONFUSEREX_DIR / "confuser_run.crproj"
    instance_crproj_path.write_text(crproj_content, encoding="utf-8")

    # 5. Run Confuser.CLI.exe
    print(f"[*] Running Confuser.CLI.exe with {instance_crproj_path}...")
    proc = subprocess.run(
        [str(cli_path), "-n", str(instance_crproj_path)],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )

    if proc.returncode != 0:
        err = proc.stderr.strip() or proc.stdout.strip()
        raise RuntimeError(f"Confuser.CLI.exe failed (code {proc.returncode}): {err}")

    # The output file has the same name as target_module
    produced_file = REAL_CONFUSEREX_DIR / target_module.name
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

    sha = compute_file_sha256(target_output_file)
    print(f"[+] Successfully generated authentic ConfuserEx fixture:")
    print(f"    Path:    {target_output_file}")
    print(f"    Size:    {target_output_file.stat().st_size:,} bytes")
    print(f"    SHA-256: {sha}")

    return target_output_file


def main():
    parser = argparse.ArgumentParser(description="Prepare authentic ConfuserEx fixture")
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
