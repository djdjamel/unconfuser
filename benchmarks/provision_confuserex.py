#!/usr/bin/env python3
"""
Official ConfuserEx Toolchain Provisioner
Downloads and immutably verifies ConfuserEx v1.0.0 release binaries from upstream:
https://github.com/yck1509/ConfuserEx/releases/tag/v1.0.0
"""

import argparse
import hashlib
import io
import sys
import urllib.request
import zipfile
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = WORKSPACE_ROOT / "tools" / "ConfuserEx"

CONFUSEREX_RELEASE_URL = (
    "https://github.com/yck1509/ConfuserEx/releases/download/v1.0.0/ConfuserEx_bin.zip"
)
EXPECTED_ZIP_SHA256 = (
    "7810adc7b8650ae4590190798da35f6a4cb491bd2c71e122ee2f2468f8eb1374"
)
EXPECTED_CLI_SHA256 = (
    "2b3e5cb7f96589e5377700a5f7f25e9fc6a14539e85256e6ac6e85c07f769f61"
)


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_file_sha256(file_path: Path) -> str:
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def provision_confuserex(dest_dir: Path = TOOLS_DIR, force: bool = False) -> Path:
    cli_path = dest_dir / "Confuser.CLI.exe"

    if cli_path.exists() and not force:
        actual_sha = compute_file_sha256(cli_path)
        if actual_sha.lower() == EXPECTED_CLI_SHA256.lower():
            print(f"[+] Confuser.CLI.exe already provisioned and verified at {cli_path}")
            print(f"    SHA-256: {actual_sha}")
            return cli_path
        print(f"[!] Existing Confuser.CLI.exe hash mismatch ({actual_sha}). Re-provisioning...")

    print(f"[*] Downloading official ConfuserEx release archive from {CONFUSEREX_RELEASE_URL}...")
    dest_dir.mkdir(parents=True, exist_ok=True)

    req = urllib.request.Request(
        CONFUSEREX_RELEASE_URL,
        headers={"User-Agent": "Unconfuser-Benchmark-Provisioner/1.0"},
    )
    with urllib.request.urlopen(req) as response:
        zip_bytes = response.read()

    print(f"[*] Downloaded {len(zip_bytes):,} bytes. Verifying archive checksum...")
    actual_zip_sha = compute_sha256(zip_bytes)
    if actual_zip_sha.lower() != EXPECTED_ZIP_SHA256.lower():
        raise ValueError(
            f"ConfuserEx archive checksum verification failed!\n"
            f"Expected: {EXPECTED_ZIP_SHA256}\n"
            f"Actual:   {actual_zip_sha}"
        )
    print(f"[+] Archive SHA-256 verified: {actual_zip_sha}")

    print(f"[*] Extracting archive into {dest_dir}...")
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        zf.extractall(dest_dir)

    if not cli_path.exists():
        raise FileNotFoundError(f"Confuser.CLI.exe not found in extracted archive at {cli_path}")

    actual_cli_sha = compute_file_sha256(cli_path)
    if actual_cli_sha.lower() != EXPECTED_CLI_SHA256.lower():
        raise ValueError(
            f"Confuser.CLI.exe checksum verification failed!\n"
            f"Expected: {EXPECTED_CLI_SHA256}\n"
            f"Actual:   {actual_cli_sha}"
        )

    print(f"[+] Confuser.CLI.exe successfully verified and ready.")
    print(f"    Path:    {cli_path}")
    print(f"    SHA-256: {actual_cli_sha}")
    return cli_path


def main():
    parser = argparse.ArgumentParser(description="Provision official ConfuserEx v1.0.0 toolchain")
    parser.add_argument(
        "--dest-dir",
        type=Path,
        default=TOOLS_DIR,
        help="Destination directory for ConfuserEx toolchain",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-download even if already provisioned",
    )
    args = parser.parse_args()

    try:
        provision_confuserex(dest_dir=args.dest_dir, force=args.force)
    except Exception as ex:
        print(f"[ERROR] Failed to provision ConfuserEx: {ex}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
