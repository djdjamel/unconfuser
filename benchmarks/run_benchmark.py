#!/usr/bin/env python3
"""
Reproducible End-to-End Deobfuscation Benchmark for ConfuserExKillerRunner.

Tests deobfuscation performance against a suite of controlled benign C# fixtures
covering synthetic protection patterns and identified ConfuserEx profiles.

Note: Subprocess timeouts (30s runner, 5s runtime) serve as operational execution limits,
not an operating-system-level security sandbox. Runtime testing must only be performed
on verified, controlled benign fixtures.
"""

import os
import sys
import json
import shutil
import hashlib
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
BENCHMARKS_DIR = WORKSPACE_ROOT / "benchmarks"
FIXTURES_DIR = BENCHMARKS_DIR / "fixtures"
BENIGN_DIR = BENCHMARKS_DIR / "BenignSample"
BENIGN_DLL = BENIGN_DIR / "bin" / "Release" / "net8.0" / "BenignSample.dll"
BENIGN_CONFIG = BENIGN_DIR / "bin" / "Release" / "net8.0" / "BenignSample.runtimeconfig.json"
PROFILE_CRPROJ = BENCHMARKS_DIR / "ConfuserExProfile" / "confuserex_v1.0.0.crproj"

# Pinned ConfuserEx toolchain identity and immutable verification
CONFUSEREX_PINNED_RELEASE = "v1.0.0 (Release 36eb45d)"
CONFUSEREX_EXPECTED_SHA256 = os.environ.get(
    "CONFUSEREX_SHA256",
    # Official Release v1.0.0 Confuser.CLI.exe SHA-256
    "3810c9d7496ef9f244199baee6a666e85eefb9db2f3ba9e89d6b2cba1608be92",
)

# Candidate runner paths prioritized by platform compatibility (.dll and .exe)
RUNNER_CANDIDATES = [
    WORKSPACE_ROOT / "ConfuserExKillerRunner" / "bin" / "Release" / "net8.0-windows" / "ConfuserExKillerRunner.dll",
    WORKSPACE_ROOT / "ConfuserExKillerRunner" / "bin" / "Release" / "net8.0-windows" / "ConfuserExKillerRunner.exe",
    WORKSPACE_ROOT / "ConfuserExKillerRunner" / "bin" / "Release" / "net48" / "ConfuserExKillerRunner.exe",
    WORKSPACE_ROOT / "ConfuserExKillerRunner" / "bin" / "Debug" / "net8.0-windows" / "ConfuserExKillerRunner.dll",
    WORKSPACE_ROOT / "ConfuserExKillerRunner" / "bin" / "Debug" / "net8.0-windows" / "ConfuserExKillerRunner.exe",
]

GENERATOR_CANDIDATES = [
    BENCHMARKS_DIR / "FixtureGenerator" / "bin" / "Release" / "net8.0-windows" / "FixtureGenerator.dll",
    BENCHMARKS_DIR / "FixtureGenerator" / "bin" / "Release" / "net8.0-windows" / "FixtureGenerator.exe",
]


def find_runner() -> Path:
    for candidate in RUNNER_CANDIDATES:
        if candidate.exists():
            return candidate
    raise FileNotFoundError("ConfuserExKillerRunner (.dll or .exe) not found in Release/Debug outputs.")


def find_generator() -> Optional[Path]:
    for candidate in GENERATOR_CANDIDATES:
        if candidate.exists():
            return candidate
    return None


def get_exec_command(target_path: Path) -> List[str]:
    """Returns the command list to invoke a .NET binary via dotnet CLI or direct execution."""
    if target_path.suffix.lower() == ".dll":
        return ["dotnet", str(target_path)]
    elif target_path.suffix.lower() == ".exe":
        dll_sibling = target_path.with_suffix(".dll")
        if dll_sibling.exists():
            return ["dotnet", str(dll_sibling)]
        return [str(target_path)]
    return [str(target_path)]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def get_benign_baseline() -> str:
    """Executes the benign baseline in a restricted process to capture expected output."""
    if not BENIGN_DLL.exists():
        raise FileNotFoundError(f"BenignSample.dll not found at {BENIGN_DLL}. Run dotnet build first.")

    res = subprocess.run(
        ["dotnet", str(BENIGN_DLL), "test"],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
        cwd=str(BENIGN_DIR),
    )
    if res.returncode != 0:
        raise RuntimeError(f"BenignSample baseline failed with returncode {res.returncode}:\n{res.stderr}")
    return res.stdout.strip()


def parse_runner_metrics(stdout: str) -> Dict[str, Any]:
    metrics = {
        "constants_decrypted": 0,
        "proxies_inlined": 0,
        "switches_resolved": 0,
        "deadcode_optimized_methods": 0,
        "deadcode_junk_pairs": 0,
        "resources_extracted": 0,
        "compressor_unpacked": False,
        "cleaner_hooks_stripped": 0,
        "audit_status": "NONE",
        "invalid_instructions": 0,
        "unresolved_call_sites": 0,
        "obfuscation_reduction_delta": 0,
    }

    for line in stdout.splitlines():
        line_clean = line.strip()
        if "[+] ConstantKiller:" in line_clean:
            parts = line_clean.split("[+] ConstantKiller:")[-1].strip().split()
            if parts and parts[0].isdigit():
                metrics["constants_decrypted"] = int(parts[0])
        elif "[+] ProxyKiller:" in line_clean:
            parts = line_clean.split("[+] ProxyKiller:")[-1].strip().split()
            if parts and parts[0].isdigit():
                metrics["proxies_inlined"] = int(parts[0])
        elif "SwitchKiller:" in line_clean and "switches resolved" in line_clean:
            parts = line_clean.split("SwitchKiller:")[-1].strip().split()
            if parts and parts[0].isdigit():
                metrics["switches_resolved"] = int(parts[0])
        elif line_clean.startswith("[+] DeadCodeStripper") and "Optimized" in line_clean:
            try:
                opt_part = line_clean.split("Optimized")[-1].strip().split()[0]
                metrics["deadcode_optimized_methods"] += int(opt_part)
                if "stripped" in line_clean:
                    junk_part = line_clean.split("stripped")[-1].strip().split()[0]
                    metrics["deadcode_junk_pairs"] += int(junk_part)
            except Exception:
                pass
        elif "[+] ResourceKiller: Extracted & re-embedded" in line_clean:
            parts = line_clean.split("Extracted & re-embedded")[-1].strip().split()
            if parts and parts[0].isdigit():
                metrics["resources_extracted"] = int(parts[0])
        elif "[+] CompressorUnpacker: Successfully unpacked" in line_clean:
            metrics["compressor_unpacked"] = True
        elif "[+] CleanerKiller: Stripped" in line_clean:
            parts = line_clean.split("Stripped")[-1].strip().split()
            if parts and parts[0].isdigit():
                metrics["cleaner_hooks_stripped"] = int(parts[0])
        elif "[*] Status:" in line_clean and "[" in line_clean:
            if "CLEAN" in line_clean:
                metrics["audit_status"] = "CLEAN"
            elif "WARNING" in line_clean:
                metrics["audit_status"] = "WARNINGS"
            elif "FAILED" in line_clean:
                metrics["audit_status"] = "FAILED"
        elif "[*] Invalid Instructions:" in line_clean:
            parts = line_clean.split(":")[-1].strip()
            if parts.isdigit():
                metrics["invalid_instructions"] = int(parts)
        elif "[*] Unresolved Call Sites:" in line_clean:
            parts = line_clean.split(":")[-1].strip()
            if parts.isdigit():
                metrics["unresolved_call_sites"] = int(parts)
        elif "[*] Score Delta:" in line_clean:
            try:
                delta_str = line_clean.split(":")[-1].strip().split()[0]
                metrics["obfuscation_reduction_delta"] = int(delta_str)
            except Exception:
                pass

    return metrics


def verify_structural_transformations(
    clean_path: Path, scenario: str, baseline_path: Optional[Path] = None
) -> Dict[str, Any]:
    """Uses FixtureGenerator --verify to check AST-level IL and metadata transformations."""
    generator = find_generator()
    if not generator or not generator.exists():
        return {
            "verified": False,
            "partial": False,
            "status": "UNVERIFIED",
            "error": "FixtureGenerator binary unavailable for structural verification",
            "verified_transformations": [],
            "unverified_transformations": [],
            "notes": "Structural verification skipped because FixtureGenerator was not built.",
        }

    cmd = get_exec_command(generator) + ["--verify", str(clean_path), "--scenario", scenario]
    if baseline_path and baseline_path.exists():
        cmd.extend(["--baseline", str(baseline_path)])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
        if proc.returncode not in (0, 2):
            return {
                "verified": False,
                "partial": False,
                "status": "FAILED",
                "verifier_returncode": proc.returncode,
                "error": f"Structural verifier exited with code {proc.returncode}: {proc.stderr.strip()}",
                "verified_transformations": [],
                "unverified_transformations": [],
            }

        parsed = json.loads(proc.stdout.strip())
        parsed["verifier_returncode"] = proc.returncode
        parsed["status"] = "VERIFIED" if parsed.get("verified") else ("PARTIAL" if parsed.get("partial") else "FAILED")
        return parsed
    except Exception as ex:
        return {
            "verified": False,
            "partial": False,
            "status": "FAILED",
            "error": f"Verification execution exception: {str(ex)}",
            "verified_transformations": [],
            "unverified_transformations": [],
        }


def run_benchmark_case(
    case_name: str,
    fixture_path: Path,
    scenario: str,
    runner_path: Path,
    expected_baseline: str,
    baseline_dll_path: Optional[Path] = None,
    is_synthetic: bool = True,
    timeout_sec: int = 30,
) -> Dict[str, Any]:
    fail_verdict = "SYNTHETIC_FAIL" if is_synthetic else "REAL_PROTECTOR_FAIL"
    pass_verdict = "SYNTHETIC_PASS" if is_synthetic else "REAL_PROTECTOR_PASS"

    if baseline_dll_path is None:
        baseline_dll_path = BENIGN_DLL

    record: Dict[str, Any] = {
        "case_name": case_name,
        "fixture_name": fixture_path.name,
        "scenario": scenario,
        "is_synthetic": is_synthetic,
        "input_sha256": sha256_file(fixture_path),
        "output_produced": False,
        "output_sha256": None,
        "deobfuscator_returncode": None,
        "metrics": {},
        "audit_status": "NONE",
        "behavioral_match": False,
        "execution_returncode": None,
        "structural_verification": {},
        "error": None,
        "verdict": fail_verdict,
    }

    clean_output = fixture_path.parent / f"{fixture_path.stem}_clean.dll"
    if clean_output.exists():
        try:
            clean_output.unlink()
        except Exception:
            pass

    cmd = get_exec_command(runner_path) + [
        str(fixture_path),
        "-o",
        str(clean_output),
        "--allow-execution",
        "--no-de4dot",
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
        )
        record["deobfuscator_returncode"] = proc.returncode
        runner_stdout = proc.stdout
        runner_stderr = proc.stderr
        record["metrics"] = parse_runner_metrics(runner_stdout)
        record["audit_status"] = record["metrics"].get("audit_status", "NONE")

        if proc.returncode != 0:
            record["error"] = f"Deobfuscator exited with error code {proc.returncode}: {runner_stderr.strip()[:200]}"
            record["verdict"] = fail_verdict
            if clean_output.exists():
                try:
                    clean_output.unlink()
                except Exception:
                    pass
            return record

    except subprocess.TimeoutExpired:
        record["error"] = f"Deobfuscation timed out after {timeout_sec}s execution limit"
        record["verdict"] = fail_verdict
        return record
    except Exception as ex:
        record["error"] = f"Execution failed: {str(ex)}"
        record["verdict"] = fail_verdict
        return record

    if clean_output.exists() and clean_output.stat().st_size > 0:
        record["output_produced"] = True
        record["output_sha256"] = sha256_file(clean_output)

        # 1. Deep Structural Verification (AST / IL / Metadata inspection)
        record["structural_verification"] = verify_structural_transformations(
            clean_output, scenario, baseline_path=baseline_dll_path
        )

        # 2. Behavioral verification in separate process with 5s execution limit
        runtime_config_dest = fixture_path.parent / f"{clean_output.stem}.runtimeconfig.json"
        if BENIGN_CONFIG.exists():
            shutil.copy2(BENIGN_CONFIG, runtime_config_dest)

        try:
            exec_proc = subprocess.run(
                ["dotnet", str(clean_output), "test"],
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
            )
            record["execution_returncode"] = exec_proc.returncode
            clean_stdout = exec_proc.stdout.strip()
            record["behavioral_match"] = (exec_proc.returncode == 0) and (clean_stdout == expected_baseline)
            if not record["behavioral_match"]:
                if exec_proc.returncode != 0:
                    record["error"] = f"Runtime exit code {exec_proc.returncode}: {exec_proc.stderr.strip()[:200]}"
                else:
                    record["error"] = "Behavioral output mismatch against baseline."
        except subprocess.TimeoutExpired:
            record["behavioral_match"] = False
            record["error"] = "Behavioral execution timed out after 5s limit"
        except Exception as ex:
            record["behavioral_match"] = False
            record["error"] = f"Behavioral test exception: {str(ex)}"
        finally:
            if runtime_config_dest.exists():
                try:
                    runtime_config_dest.unlink()
                except Exception:
                    pass

    # Verdict evaluation: strict, no-bypass decision matrix
    v_data = record.get("structural_verification", {})
    verified = v_data.get("verified", False)
    partial = v_data.get("partial", False)
    verifier_status = v_data.get("status", "FAILED")
    is_audit_clean = (record["audit_status"] == "CLEAN")
    is_deobf_success = (record.get("deobfuscator_returncode") == 0)
    is_runtime_success = (record.get("execution_returncode") == 0 and record["behavioral_match"])

    if not record["output_produced"] or not is_deobf_success:
        record["verdict"] = fail_verdict
    elif verifier_status == "UNVERIFIED":
        record["verdict"] = "UNVERIFIED"
    elif not is_audit_clean:
        record["verdict"] = fail_verdict
    elif verified and is_runtime_success:
        record["verdict"] = pass_verdict
    elif is_synthetic and partial and is_runtime_success:
        # Strict validation: Only allow SYNTHETIC_PARTIAL if the limitation matches the explicitly documented limitation
        unverified_ts = v_data.get("unverified_transformations", [])
        if unverified_ts == ["constants_decrypted_and_inlined"]:
            record["verdict"] = "SYNTHETIC_PARTIAL"
        else:
            record["verdict"] = "SYNTHETIC_FAIL"
    else:
        record["verdict"] = fail_verdict

    return record


def run_all_benchmarks(
    fixtures_dir: Path = FIXTURES_DIR,
    runner_path: Optional[Path] = None,
    output_report_path: Optional[Path] = None,
) -> Dict[str, Any]:
    if runner_path is None:
        runner_path = find_runner()

    # Auto-generate fixtures if missing and generator is available
    if not (fixtures_dir / "fixture_constants.dll").exists():
        generator = find_generator()
        if generator and BENIGN_DLL.exists():
            fixtures_dir.mkdir(parents=True, exist_ok=True)
            gen_cmd = get_exec_command(generator) + ["--input", str(BENIGN_DLL), "--output-dir", str(fixtures_dir)]
            subprocess.run(gen_cmd, check=False, capture_output=True)

    expected_baseline = get_benign_baseline()

    # Defined deterministic benchmark cases (8 synthetic patterns)
    cases = [
        ("Constants (Strings & Numerics)", fixtures_dir / "fixture_constants.dll", "constants"),
        ("Control Flow (Dead Code & Junk Stripping)", fixtures_dir / "fixture_cflow.dll", "cflow"),
        ("Reference & Method Call Proxies", fixtures_dir / "fixture_proxies.dll", "proxies"),
        ("Encrypted Resources", fixtures_dir / "fixture_resources.dll", "resources"),
        ("Deflate Compressor Unpacker", fixtures_dir / "fixture_compressor.dll", "compressor"),
        ("Anti-Tamper & Cleaner Hooks", fixtures_dir / "fixture_antitamper.dll", "antitamper"),
        ("Combined Multi-Protection", fixtures_dir / "fixture_combined.dll", "combined"),
        ("Generics & Exception Edges", fixtures_dir / "fixture_edge_cases.dll", "edge_cases"),
    ]

    results: List[Dict[str, Any]] = []

    for case_name, fixture_path, scenario in cases:
        if not fixture_path.exists():
            # Missing synthetic fixtures are setup errors, not optional skips!
            results.append({
                "case_name": case_name,
                "fixture_name": fixture_path.name,
                "scenario": scenario,
                "is_synthetic": True,
                "input_sha256": "N/A",
                "output_produced": False,
                "output_sha256": None,
                "deobfuscator_returncode": None,
                "metrics": {},
                "audit_status": "SETUP_ERROR",
                "behavioral_match": False,
                "execution_returncode": None,
                "structural_verification": {"verified": False, "status": "FAILED"},
                "error": "Required synthetic fixture file not found. Run FixtureGenerator before benchmarking.",
                "verdict": "SYNTHETIC_FAIL",
            })
            continue

        res = run_benchmark_case(
            case_name,
            fixture_path,
            scenario,
            runner_path,
            expected_baseline,
            baseline_dll_path=BENIGN_DLL,
            is_synthetic=True,
        )
        results.append(res)

    # 9. Real ConfuserEx CLI Preset: Always included in results, whether tool is present or missing
    confuser_cli_env = os.environ.get("CONFUSEREX_PATH")
    confuser_cli_path = Path(confuser_cli_env) if confuser_cli_env else WORKSPACE_ROOT / "tools" / "ConfuserEx" / "Confuser.CLI.exe"
    real_case_name = f"ConfuserEx {CONFUSEREX_PINNED_RELEASE} (Constants, Ctrl Flow, Ref Proxy, Resources)"

    if confuser_cli_path.exists():
        # Verify immutable identity before execution
        cli_sha = sha256_file(confuser_cli_path)
        if CONFUSEREX_EXPECTED_SHA256 and cli_sha.lower() != CONFUSEREX_EXPECTED_SHA256.lower():
            results.append({
                "case_name": real_case_name,
                "fixture_name": "BenignSample.dll",
                "scenario": "real_confuserex",
                "is_synthetic": False,
                "input_sha256": cli_sha,
                "output_produced": False,
                "output_sha256": None,
                "deobfuscator_returncode": None,
                "metrics": {},
                "audit_status": "FAILED",
                "behavioral_match": False,
                "execution_returncode": None,
                "structural_verification": {},
                "error": f"Confuser.CLI.exe SHA-256 identity verification failed. Expected {CONFUSEREX_EXPECTED_SHA256}, got {cli_sha}.",
                "verdict": "REAL_PROTECTOR_FAIL",
            })
        else:
            # Clean output directory for each run to prevent stale protected outputs from being reused
            cli_fixture_dir = fixtures_dir / "real_confuserex"
            if cli_fixture_dir.exists():
                shutil.rmtree(cli_fixture_dir, ignore_errors=True)
            cli_fixture_dir.mkdir(parents=True, exist_ok=True)
            cli_output_file = cli_fixture_dir / "BenignSample.dll"

            # Generate config project from template
            crproj_content = PROFILE_CRPROJ.read_text(encoding="utf-8")
            crproj_instance = crproj_content.format(
                output_dir=str(cli_fixture_dir),
                base_dir=str(BENIGN_DIR / "bin" / "Release" / "net8.0"),
                module_path=str(BENIGN_DLL),
            )
            instance_crproj_path = cli_fixture_dir / "confuser_run.crproj"
            instance_crproj_path.write_text(crproj_instance, encoding="utf-8")

            try:
                prot_proc = subprocess.run(
                    [str(confuser_cli_path), "-n", str(instance_crproj_path)],
                    capture_output=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=60,
                )
                if prot_proc.returncode == 0 and cli_output_file.exists():
                    res = run_benchmark_case(
                        real_case_name,
                        cli_output_file,
                        "real_confuserex",
                        runner_path,
                        expected_baseline,
                        baseline_dll_path=BENIGN_DLL,
                        is_synthetic=False,
                    )
                    results.append(res)
                else:
                    results.append({
                        "case_name": real_case_name,
                        "fixture_name": "BenignSample.dll",
                        "scenario": "real_confuserex",
                        "is_synthetic": False,
                        "input_sha256": "N/A",
                        "output_produced": False,
                        "output_sha256": None,
                        "deobfuscator_returncode": None,
                        "metrics": {},
                        "audit_status": "FAILED",
                        "behavioral_match": False,
                        "execution_returncode": None,
                        "structural_verification": {},
                        "error": f"Confuser.CLI.exe protection failed: {prot_proc.stderr.strip()[:200]}",
                        "verdict": "REAL_PROTECTOR_FAIL",
                    })
            except Exception as ex:
                results.append({
                    "case_name": real_case_name,
                    "fixture_name": "BenignSample.dll",
                    "scenario": "real_confuserex",
                    "is_synthetic": False,
                    "input_sha256": "N/A",
                    "output_produced": False,
                    "output_sha256": None,
                    "deobfuscator_returncode": None,
                    "metrics": {},
                    "audit_status": "FAILED",
                    "behavioral_match": False,
                    "execution_returncode": None,
                    "structural_verification": {},
                    "error": f"Confuser.CLI.exe execution exception: {str(ex)}",
                    "verdict": "REAL_PROTECTOR_FAIL",
                })
    else:
        # Tool is not provisioned: explicitly record SKIPPED_TOOL_MISSING with clear reason
        results.append({
            "case_name": real_case_name,
            "fixture_name": "BenignSample.dll",
            "scenario": "real_confuserex",
            "is_synthetic": False,
            "input_sha256": "N/A",
            "output_produced": False,
            "output_sha256": None,
            "deobfuscator_returncode": None,
            "metrics": {},
            "audit_status": "SKIPPED",
            "behavioral_match": False,
            "execution_returncode": None,
            "structural_verification": {},
            "error": f"Confuser.CLI.exe ({CONFUSEREX_PINNED_RELEASE}, expected SHA-256: {CONFUSEREX_EXPECTED_SHA256[:16]}...) not found in tools/ConfuserEx or CONFUSEREX_PATH.",
            "verdict": "SKIPPED_TOOL_MISSING",
        })

    summary = {
        "total_cases": len(results),
        "synthetic_pass": sum(1 for r in results if r["verdict"] == "SYNTHETIC_PASS"),
        "synthetic_partial": sum(1 for r in results if r["verdict"] == "SYNTHETIC_PARTIAL"),
        "synthetic_fail": sum(1 for r in results if r["verdict"] == "SYNTHETIC_FAIL"),
        "unverified": sum(1 for r in results if r["verdict"] == "UNVERIFIED"),
        "real_protector_pass": sum(1 for r in results if r["verdict"] == "REAL_PROTECTOR_PASS"),
        "real_protector_fail": sum(1 for r in results if r["verdict"] == "REAL_PROTECTOR_FAIL"),
        "skipped_tool_missing": sum(1 for r in results if r["verdict"] == "SKIPPED_TOOL_MISSING"),
        "results": results,
    }

    if output_report_path:
        generate_markdown_report(summary, output_report_path)

    return summary


def generate_markdown_report(summary: Dict[str, Any], report_path: Path):
    lines = []
    lines.append("# End-to-End Deobfuscation Benchmark Report")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append("> [!IMPORTANT]")
    lines.append("> **Terminology & Validation Scope:**")
    lines.append("> - `SYNTHETIC_PASS`: ConfuserExKillerRunner recognizes and deobfuscates specific synthetic IL and metadata patterns generated via dnlib.")
    lines.append("> - `SYNTHETIC_PARTIAL`: Output produced, execution succeeded with exit code 0 matching expected baseline, and audit clean, but specific documented transformations were unrecovered due to known ordering dependencies.")
    lines.append("> - `SYNTHETIC_FAIL`: Deobfuscator crashed, structural verification explicitly failed, runtime failed, or output mismatched.")
    lines.append("> - `UNVERIFIED`: Structural verification tool was unavailable; output produced but unverifiable at AST level.")
    lines.append("> - `REAL_PROTECTOR_PASS`: Reserved exclusively for fixtures produced by a pinned, identified build of the ConfuserEx toolchain that have passed structural, audit, and runtime tests.")
    lines.append("> - `REAL_PROTECTOR_FAIL`: Protection or deobfuscation failed on a fixture produced by the pinned ConfuserEx toolchain.")
    lines.append("> - `SKIPPED_TOOL_MISSING`: Specific external protector CLI was not provisioned; explicitly skipped and never counted as passed.")
    lines.append("> - **Execution Limits:** Process timeouts (30s deobfuscation, 5s runtime) serve as operational limits, not an operating-system-level sandbox.")
    lines.append("")
    lines.append(f"- **Total Benchmark Cases:** {summary['total_cases']}")
    lines.append(f"- **Synthetic Pattern Pass (`SYNTHETIC_PASS`):** {summary['synthetic_pass']}")
    lines.append(f"- **Synthetic Pattern Partial (`SYNTHETIC_PARTIAL`):** {summary['synthetic_partial']}")
    lines.append(f"- **Synthetic Pattern Fail (`SYNTHETIC_FAIL`):** {summary['synthetic_fail']}")
    lines.append(f"- **Unverified Cases (`UNVERIFIED`):** {summary['unverified']}")
    lines.append(f"- **Real Protector Confirmed (`REAL_PROTECTOR_PASS`):** {summary['real_protector_pass']}")
    lines.append(f"- **Real Protector Failed (`REAL_PROTECTOR_FAIL`):** {summary['real_protector_fail']}")
    lines.append(f"- **Skipped (Protector Missing):** {summary['skipped_tool_missing']}")
    lines.append("")
    lines.append("## Per-Case Benchmark Results")
    lines.append("")
    lines.append("| Case / Protection Family | Input SHA256 | Output | Runner Exit | Runtime Exit | Audit | Behavior | Structural Assertions | Verdict |")
    lines.append("|---|---|---|---|---|---|---|---|---|")

    for r in summary["results"]:
        in_sha = r["input_sha256"][:8] if r["input_sha256"] != "N/A" else "N/A"
        out_prod = "Yes" if r["output_produced"] else "No"
        runner_ret = str(r["deobfuscator_returncode"]) if r["deobfuscator_returncode"] is not None else "-"
        ret_code = str(r["execution_returncode"]) if r["execution_returncode"] is not None else "-"
        audit = r["audit_status"]
        beh = "Exact Match" if r["behavioral_match"] else ("Skipped" if "SKIPPED" in r["verdict"] else "Mismatch")

        v_data = r.get("structural_verification", {})
        verified_ts = v_data.get("verified_transformations", [])
        unverified_ts = v_data.get("unverified_transformations", [])

        assertions_summary = []
        if verified_ts:
            assertions_summary.append(f"Passed: {', '.join(verified_ts)}")
        if unverified_ts:
            assertions_summary.append(f"Unverified: {', '.join(unverified_ts)}")

        ast_str = "<br>".join(assertions_summary) if assertions_summary else (r.get("error") or "None")
        v_badge = f"**`{r['verdict']}`**"
        lines.append(f"| {r['case_name']} | `{in_sha}` | {out_prod} | {runner_ret} | {ret_code} | {audit} | {beh} | {ast_str} | {v_badge} |")

    lines.append("")
    lines.append("## Detailed Structural Assertions & Findings")
    lines.append("")

    for idx, r in enumerate(summary["results"], 1):
        lines.append(f"### {idx}. {r['case_name']} (`{r['verdict']}`)")
        beh_desc = "Exact Match" if r["behavioral_match"] else ("Skipped" if "SKIPPED" in r["verdict"] else "Mismatch / Failed")
        lines.append(f"- **Verdict:** `{r['verdict']}` | **Audit Status:** `{r['audit_status']}` | **Runtime Behavior:** `{beh_desc}`")

        v_data = r.get("structural_verification", {})
        verified_ts = v_data.get("verified_transformations", [])
        unverified_ts = v_data.get("unverified_transformations", [])
        notes = v_data.get("notes")

        if verified_ts:
            lines.append(f"- **Verified Structural Transformations:** {', '.join(verified_ts)}")
        if unverified_ts:
            lines.append(f"- **Unverified Transformations:** {', '.join(unverified_ts)}")
        if notes:
            lines.append(f"- **Verification Notes:** {notes}")
        if r.get("error"):
            lines.append(f"- **Diagnostic / Failure Information:** {r['error']}")
        lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")


def print_console_summary(summary: Dict[str, Any]):
    print("\n" + "=" * 102)
    print(f"{'DEOBFUSCATION BENCHMARK RESULTS SUMMARY':^102}")
    print("=" * 102)
    print(f"Total: {summary['total_cases']} | Synthetic Pass: {summary['synthetic_pass']} | Partial: {summary['synthetic_partial']} | Fail: {summary['synthetic_fail']} | Unverified: {summary['unverified']} | Real: {summary['real_protector_pass']} | Skipped: {summary['skipped_tool_missing']}")
    print("-" * 102)
    header = f"{'Test Case':<36} {'Output':<8} {'RunExit':<8} {'ExeExit':<8} {'Audit':<10} {'Behavior':<12} {'Verdict':<18}"
    print(header)
    print("-" * 102)
    for r in summary["results"]:
        out_str = "Yes" if r["output_produced"] else "No"
        run_ret = str(r["deobfuscator_returncode"]) if r["deobfuscator_returncode"] is not None else "-"
        exe_ret = str(r["execution_returncode"]) if r["execution_returncode"] is not None else "-"
        beh_str = "Exact" if r["behavioral_match"] else ("Skip" if "SKIPPED" in r["verdict"] else "Mismatch")
        print(f"{r['case_name']:<36} {out_str:<8} {run_ret:<8} {exe_ret:<8} {r['audit_status']:<10} {beh_str:<12} {r['verdict']:<18}")
    print("=" * 102 + "\n")


if __name__ == "__main__":
    report_file = BENCHMARKS_DIR / "benchmark_report.md"
    summary = run_all_benchmarks(output_report_path=report_file)
    print_console_summary(summary)
    print(f"[+] Detailed Markdown report generated at: {report_file}")
    sys.exit(0 if summary["synthetic_fail"] == 0 and summary["real_protector_fail"] == 0 and summary["unverified"] == 0 else 1)

