"""
NetDetect CLI - All-in-One .NET Obfuscator and Packer Detection Tool.
"""

import sys
import os
import argparse
from colorama import init, Fore, Style

from netdetect import BinaryAnalyzer, ObfuscatorDetector, DetectionReporter

init(autoreset=True)


def scan_single_file(
    file_path: str,
    json_out: str | None = None,
    verbose: bool = False,
    explain: bool = False,
    skip_il: bool = False,
    rules_path: str | None = None,
):
    if not os.path.exists(file_path):
        print(f"{Fore.RED}[!] Error: File does not exist: {file_path}{Style.RESET_ALL}")
        return

    analyzer = BinaryAnalyzer(file_path, skip_il=skip_il)
    analysis_res = analyzer.analyze()

    detector = ObfuscatorDetector(analysis_res)
    detection_res = detector.detect()

    # YARA integration (Phase 15)
    if rules_path:
        from netdetect.yara_engine import YaraScanner
        scanner = YaraScanner([rules_path])
        if scanner.available:
            yara_matches = scanner.scan_file(file_path)
            for ym in yara_matches:
                detection_res.setdefault("protectors", []).append({
                    "name": ym["tool"],
                    "layer": ym["layer"],
                    "version": ym.get("version"),
                    "score": 85 if ym["tier"] == "definitive" else 60,
                    "confidence": "HIGH" if ym["tier"] == "definitive" else "MEDIUM",
                    "tier_hits": {ym["tier"]: 1},
                    "evidence": [f"YARA rule match: '{ym['rule']}'"],
                    "characteristics": ["External YARA signature match"],
                })
        elif scanner.error:
            analysis_res.setdefault("errors", []).append(scanner.error)

    DetectionReporter.print_terminal_report(analysis_res, detection_res, verbose=verbose, explain=explain)

    if json_out:
        DetectionReporter.save_json_report(analysis_res, detection_res, json_out)


def scan_directory(
    dir_path: str,
    json_out: str | None = None,
    verbose: bool = False,
    explain: bool = False,
    skip_il: bool = False,
    rules_path: str | None = None,
):
    if not os.path.isdir(dir_path):
        print(f"{Fore.RED}[!] Error: Directory does not exist: {dir_path}{Style.RESET_ALL}")
        return

    targets = []
    for root, _, files in os.walk(dir_path):
        for f in files:
            if f.lower().endswith((".exe", ".dll")):
                targets.append(os.path.join(root, f))

    if not targets:
        print(f"{Fore.YELLOW}[!] No .exe or .dll binaries found in {dir_path}{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[*] Found {len(targets)} executable(s) to scan in: {dir_path}{Style.RESET_ALL}\n")

    summary_results = []
    for target in targets:
        analyzer = BinaryAnalyzer(target, skip_il=skip_il)
        analysis_res = analyzer.analyze()
        detector = ObfuscatorDetector(analysis_res)
        detection_res = detector.detect()

        DetectionReporter.print_terminal_report(analysis_res, detection_res, verbose=verbose, explain=explain)
        summary_results.append({
            "file": target,
            "analysis": analysis_res,
            "detection": detection_res,
        })

    if json_out:
        import json
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(summary_results, f, indent=2, ensure_ascii=False)
        print(f"{Fore.GREEN}[+] Batch scan report saved to: {json_out}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description="NetDetect - All-in-One .NET Obfuscator, Protector, and Packer Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python netdetect_cli.py sample.exe
  python netdetect_cli.py sample.exe -v
  python netdetect_cli.py sample.exe --explain
  python netdetect_cli.py sample.exe --no-il
  python netdetect_cli.py sample.exe --rules rules/
  python netdetect_cli.py --dir C:\\malware_samples\\
        """
    )
    parser.add_argument("file", nargs="?", help="Target .NET executable or DLL file to scan")
    parser.add_argument("-d", "--dir", help="Scan all .exe and .dll files within a directory")
    parser.add_argument("-j", "--json", help="Save detection findings to a JSON file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print detailed metadata dump")
    parser.add_argument("--explain", action="store_true", help="Explain detection reasoning, tier counts, and weights")
    parser.add_argument("--no-il", action="store_true", help="Skip IL method body disassembly for faster scans")
    parser.add_argument("--rules", help="Directory or file path of custom YARA rules")

    args = parser.parse_args()

    if not args.file and not args.dir:
        parser.print_help()
        sys.exit(1)

    if args.dir:
        scan_directory(
            args.dir,
            args.json,
            verbose=args.verbose,
            explain=args.explain,
            skip_il=args.no_il,
            rules_path=args.rules,
        )
    elif args.file:
        scan_single_file(
            args.file,
            args.json,
            verbose=args.verbose,
            explain=args.explain,
            skip_il=args.no_il,
            rules_path=args.rules,
        )


if __name__ == "__main__":
    main()
