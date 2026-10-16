"""
False-positive benchmark for NetDetect (Phase 7).

Scans clean, trusted .NET assemblies (Framework, GAC, shared runtime, plus any
user-supplied directories) and reports how often the detector wrongly flags them.

Usage:
    python tests/fp_benchmark.py                       # default corpora, 300 files
    python tests/fp_benchmark.py --limit 100 --json out.json
    python tests/fp_benchmark.py --extra-dir C:\\my\\clean\\apps
    python tests/fp_benchmark.py --baseline tests/fp_baseline.json
    python tests/fp_benchmark.py --write-baseline tests/fp_baseline.json

Exit code is non-zero when a gate (--max-named-fp / --max-verdict-fp) is exceeded.
"""

import argparse
import collections
import glob
import json
import logging
import os
import random
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
logging.disable(logging.CRITICAL)  # dnfile is very chatty on odd heaps

from netdetect.analyzer import BinaryAnalyzer  # noqa: E402
from netdetect.detector import ObfuscatorDetector  # noqa: E402

DEFAULT_ROOTS = [
    r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319",
    r"C:\Windows\Microsoft.NET\Framework\v4.0.30319",
    r"C:\Windows\Microsoft.NET\assembly\GAC_MSIL",
    r"C:\Windows\Microsoft.NET\assembly\GAC_32",
    r"C:\Windows\Microsoft.NET\assembly\GAC_64",
    r"C:\Program Files\dotnet\shared",
    r"C:\Program Files (x86)\dotnet\shared",
]

NAMED_LEVELS = {"MEDIUM", "HIGH"}


def discover(roots, max_size):
    files = []
    for r in roots:
        if not os.path.isdir(r):
            continue
        for ext in ("*.dll", "*.exe"):
            files += glob.glob(os.path.join(r, "**", ext), recursive=True)
    files = sorted({f for f in files if os.path.getsize(f) <= max_size})
    return files


def run(files):
    stats = {
        "scanned": 0,
        "dotnet": 0,
        "errors": 0,
        "named_fp_files": 0,
        "verdict_fp_files": 0,
        "elapsed_s": 0.0,
        "protector_hits": collections.Counter(),
        "technique_hits": collections.Counter(),
        "primary": collections.Counter(),
    }
    examples = {}
    t0 = time.time()
    for f in files:
        stats["scanned"] += 1
        try:
            a = BinaryAnalyzer(f).analyze()
            if not a.get("is_dotnet"):
                continue
            stats["dotnet"] += 1
            r = ObfuscatorDetector(a).detect()
        except Exception as e:  # noqa: BLE001
            stats["errors"] += 1
            examples.setdefault("<error>", []).append(f"{os.path.basename(f)}: {type(e).__name__}: {e}")
            continue

        named = [p for p in r.get("protectors", []) if p.get("confidence") in NAMED_LEVELS]
        if named:
            stats["named_fp_files"] += 1
        if r.get("confidence", "NONE") != "NONE":
            stats["verdict_fp_files"] += 1
        stats["primary"][str(r.get("primary_detector"))] += 1
        for p in r.get("protectors", []):
            key = f"{p['name']} [{p['confidence']}]"
            stats["protector_hits"][key] += 1
            examples.setdefault(key, (os.path.basename(f), p.get("evidence", [])[:2]))
        for t in r.get("generic_techniques", []):
            stats["technique_hits"][t["technique"]] += 1
            examples.setdefault("T:" + t["technique"], (os.path.basename(f), t.get("details", "")[:100]))
    stats["elapsed_s"] = round(time.time() - t0, 2)
    return stats, examples


def pct(n, d):
    return round(100.0 * n / d, 2) if d else 0.0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--limit", type=int, default=300)
    ap.add_argument("--max-size", type=int, default=3_000_000, help="skip files larger than N bytes")
    ap.add_argument("--extra-dir", action="append", default=[])
    ap.add_argument("--seed", type=int, default=1337, help="sampling seed (deterministic)")
    ap.add_argument("--json", help="write full results JSON here")
    ap.add_argument("--baseline", help="compare against a baseline JSON")
    ap.add_argument("--write-baseline", help="write current summary as baseline JSON")
    ap.add_argument("--max-named-fp", type=float, default=1.0, help="gate: named FP %% (default 1.0)")
    ap.add_argument("--max-verdict-fp", type=float, default=5.0, help="gate: verdict FP %% (default 5.0)")
    ap.add_argument("--no-gate", action="store_true", help="report only; never fail")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    files = discover(DEFAULT_ROOTS + args.extra_dir, args.max_size)
    if not files:
        print("No corpus files found.")
        return 2
    random.Random(args.seed).shuffle(files)
    files = files[: args.limit]

    stats, examples = run(files)
    dn = stats["dotnet"]
    named_pct = pct(stats["named_fp_files"], dn)
    verdict_pct = pct(stats["verdict_fp_files"], dn)
    avg = round(stats["elapsed_s"] / max(stats["scanned"], 1), 3)

    summary = {
        "scanned": stats["scanned"],
        "dotnet_assemblies": dn,
        "errors": stats["errors"],
        "named_fp_pct": named_pct,
        "verdict_fp_pct": verdict_pct,
        "avg_seconds_per_file": avg,
    }

    if not args.quiet:
        print(f"Scanned {stats['scanned']} files ({dn} .NET) in {stats['elapsed_s']}s  "
              f"(avg {avg}s/file, {stats['errors']} errors)")
        print(f"  Named-protector FP (MEDIUM+) : {stats['named_fp_files']}/{dn} = {named_pct}%")
        print(f"  Verdict FP (confidence!=NONE): {stats['verdict_fp_files']}/{dn} = {verdict_pct}%")
        if stats["protector_hits"]:
            print("\nProtector findings on clean files:")
            for k, v in stats["protector_hits"].most_common(25):
                ex = examples.get(k)
                print(f"  {v:4}  {k}   e.g. {ex}")
        if stats["technique_hits"]:
            print("\nGeneric techniques on clean files:")
            for k, v in stats["technique_hits"].most_common(25):
                print(f"  {v:4}  {k}")
        if examples.get("<error>"):
            print("\nErrors (first 5):")
            for e in examples["<error>"][:5]:
                print("  ", e)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({
                "summary": summary,
                "protector_hits": stats["protector_hits"],
                "technique_hits": stats["technique_hits"],
                "primary": stats["primary"],
                "examples": {k: v for k, v in examples.items()},
            }, fh, indent=2, default=str)
    if args.write_baseline:
        with open(args.write_baseline, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)
        print(f"\nBaseline written to {args.write_baseline}")

    if args.baseline and os.path.isfile(args.baseline):
        with open(args.baseline, encoding="utf-8") as fh:
            base = json.load(fh)
        print(f"\nvs baseline: named {base['named_fp_pct']}% -> {named_pct}% ; "
              f"verdict {base['verdict_fp_pct']}% -> {verdict_pct}%")

    if args.no_gate:
        return 0
    failed = []
    if named_pct > args.max_named_fp:
        failed.append(f"named FP {named_pct}% > {args.max_named_fp}%")
    if verdict_pct > args.max_verdict_fp:
        failed.append(f"verdict FP {verdict_pct}% > {args.max_verdict_fp}%")
    if failed:
        print("\nGATE FAILED: " + "; ".join(failed))
        return 1
    print("\nGATE PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
