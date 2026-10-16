"""
Console and JSON reporting module with colorized terminal formatting.
"""

import json
from typing import Dict, Any
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)


class DetectionReporter:
    """
    Renders detection results into human-readable colored terminal output or JSON.
    """

    @staticmethod
    def print_terminal_report(
        analysis: Dict[str, Any],
        detection: Dict[str, Any],
        verbose: bool = False,
        explain: bool = False,
    ):
        """
        Prints a structured, colored report to the console.
        """
        print("\n" + "=" * 70)
        print(f"{Fore.CYAN}{Style.BRIGHT}   .NET OBFUSCATION & PACKER DETECTION REPORT")
        print("=" * 70)

        # File Overview
        print(f"\n{Fore.YELLOW}[*] Target Information:{Style.RESET_ALL}")
        print(f"  [>] Path:         {analysis.get('file_path')}")
        file_sz_kb = round(analysis.get('file_size', 0) / 1024, 2)
        print(f"  [>] File Size:    {file_sz_kb} KB")
        print(f"  [>] PE Valid:     {analysis.get('is_valid_pe')}")
        print(f"  [>] .NET Managed: {analysis.get('is_dotnet')}")

        dotnet_info = analysis.get("dotnet_info", {})
        if analysis.get("is_dotnet"):
            asm_name = dotnet_info.get("assembly_name", "Unknown")
            asm_ver = dotnet_info.get("assembly_version", "Unknown")
            runtime_ver = dotnet_info.get("runtime_version", "Unknown")
            print(f"  [>] Assembly:     {asm_name} (v{asm_ver})")
            print(f"  [>] Target CLR:   {runtime_ver}")

            flags = dotnet_info.get("flags", {})
            il_type = "Pure IL (Managed)" if flags.get("ILOnly") else "Mixed-Mode / Native Stub"
            print(f"  [>] Execution:    {il_type}")

        # Verdict Header
        print("\n" + "-" * 70)
        primary = detection.get("primary_detector", "None")
        confidence = detection.get("confidence", "NONE")
        score = detection.get("verdict_score", 0)

        if confidence == "HIGH":
            badge = f"{Fore.RED}{Style.BRIGHT}[ DETECTED - HIGH CONFIDENCE ]"
            title_color = Fore.RED
        elif confidence == "MEDIUM":
            badge = f"{Fore.YELLOW}{Style.BRIGHT}[ PROBABLE - MEDIUM CONFIDENCE ]"
            title_color = Fore.YELLOW
        elif confidence == "LOW":
            badge = f"{Fore.MAGENTA}{Style.BRIGHT}[ SUSPECTED - LOW CONFIDENCE ]"
            title_color = Fore.MAGENTA
        else:
            badge = f"{Fore.GREEN}{Style.BRIGHT}[ CLEAN / UNOBFUSCATED ]"
            title_color = Fore.GREEN

        print(f" Verdict: {badge}")
        print(f" Primary: {title_color}{Style.BRIGHT}{primary}{Style.RESET_ALL} (Score: {score})")

        layers = detection.get("layers", [])
        if layers:
            layer_str = " -> ".join(f"{l['layer'].capitalize()}: {l['name']}" for l in layers)
            print(f" Layers:  {Fore.CYAN}{layer_str}{Style.RESET_ALL}")

        print(f" Summary: {detection.get('summary')}")
        print("-" * 70)

        # Matched Protectors & Signatures
        protectors = detection.get("protectors", [])
        if protectors:
            print(f"\n{Fore.CYAN}[+] Identified Protectors & Signatures:{Style.RESET_ALL}")
            for p in protectors:
                conf_color = Fore.RED if p['confidence'] == 'HIGH' else (Fore.YELLOW if p['confidence'] == 'MEDIUM' else Fore.MAGENTA)
                ver_str = f" {Fore.CYAN}v{p['version']}{Style.RESET_ALL}" if p.get("version") else ""
                layer_lbl = f" [{p.get('layer', 'protector').upper()}]"
                print(f"\n  [!] {Fore.WHITE}{Style.BRIGHT}{p['name']}{Style.RESET_ALL}{ver_str}{Fore.LIGHTBLACK_EX}{layer_lbl}{Style.RESET_ALL} {conf_color}({p['confidence']} - Score: {p['score']}/100){Style.RESET_ALL}")

                if explain:
                    th = p.get("tier_hits", {})
                    print(f"      {Fore.BLUE}[*] Tiers: Definitive: {th.get('definitive', 0)}, Strong: {th.get('strong', 0)}, Weak: {th.get('weak', 0)}{Style.RESET_ALL}")

                # Evidence
                for ev in p.get("evidence", []):
                    print(f"      {Fore.GREEN}[+] Evidence:{Style.RESET_ALL} {ev}")

                # Characteristics
                chars = p.get("characteristics", [])
                if chars:
                    print(f"      {Fore.LIGHTBLACK_EX}Features: {', '.join(chars)}{Style.RESET_ALL}")

        # Generic Obfuscation Techniques
        techniques = detection.get("generic_techniques", [])
        if techniques:
            print(f"\n{Fore.YELLOW}[!] Generic Obfuscation Techniques Detected:{Style.RESET_ALL}")
            for t in techniques:
                sev_color = Fore.RED if t["severity"] == "HIGH" else Fore.YELLOW
                explain_str = f" {Fore.LIGHTBLACK_EX}(Weight: {t.get('weight', 0)}, Kind: {t.get('kind', 'unknown')}){Style.RESET_ALL}" if explain else ""
                print(f"  [>] {sev_color}[{t['severity']}]{Style.RESET_ALL} {Style.BRIGHT}{t['technique']}{Style.RESET_ALL}{explain_str}")
                print(f"      |-> {t['details']}")

        # PE Sections & Entropy
        sections = analysis.get("pe_sections", [])
        if sections:
            print(f"\n{Fore.CYAN}[#] PE Section Structure & Entropy:{Style.RESET_ALL}")
            for sec in sections:
                ent = sec["entropy"]
                ent_color = Fore.RED if ent >= 7.2 else (Fore.YELLOW if ent >= 6.5 else Fore.GREEN)
                flag = f"{Fore.RED}[HIGH ENTROPY]{Style.RESET_ALL}" if ent >= 7.2 else ""
                print(f"  [>] {sec['name']:<10} VirtualSize: {sec['virtual_size']:<8} RawSize: {sec['raw_size']:<8} Entropy: {ent_color}{ent:.4f}{Style.RESET_ALL} {flag}")

        # High Entropy Resources
        high_res = dotnet_info.get("high_entropy_resources", [])
        if high_res:
            print(f"\n{Fore.MAGENTA}[#] High Entropy Resources (Encrypted/Compressed):{Style.RESET_ALL}")
            for r in high_res:
                print(f"  [>] {r['name']:<30} Size: {r['size']} bytes   Entropy: {r['entropy']:.4f}")

        # Identifier Metrics
        metrics = dotnet_info.get("identifier_metrics", {})
        if metrics.get("total_count", 0) > 0:
            print(f"\n{Fore.CYAN}[#] Identifier Metric Breakdown:{Style.RESET_ALL}")
            print(f"  [>] Total Identifiers:           {metrics.get('total_count')}")
            print(f"  [>] Short Renamed (<=3 ch):      {metrics.get('short_count')} ({round(metrics.get('short_ratio', 0) * 100, 1)}%)")
            print(f"  [>] Zero-Width / Invisible:      {metrics.get('invisible_count')} ({round(metrics.get('invisible_ratio', 0) * 100, 1)}%)")
            print(f"  [>] Non-ASCII / Scrambled:       {metrics.get('non_ascii_count')} ({round(metrics.get('non_ascii_ratio', 0) * 100, 1)}%)")
            if metrics.get("high_entropy_name_count", 0) > 0:
                print(f"  [>] High-Entropy / Unwordlike:   {metrics.get('high_entropy_name_count')} ({round(metrics.get('high_entropy_name_ratio', 0) * 100, 1)}%)")
            if metrics.get("keyword_name_count", 0) > 0:
                print(f"  [>] C# Reserved Keyword Names:   {metrics.get('keyword_name_count')}")
            if metrics.get("cjk_confusable_count", 0) > 0:
                print(f"  [>] CJK / Confusable Characters: {metrics.get('cjk_confusable_count')} ({round(metrics.get('cjk_confusable_ratio', 0) * 100, 1)}%)")

        # Verbose Deep Inspection Dump
        if verbose:
            print(f"\n{Fore.MAGENTA}{Style.BRIGHT}[*] VERBOSE DEEP METADATA DUMP:{Style.RESET_ALL}")

            # Packaging formats
            pkgs = analysis.get("packaging_formats", [])
            if pkgs:
                print(f"\n  {Fore.YELLOW}Packaging Formats & Runtimes:{Style.RESET_ALL}")
                for pf in pkgs:
                    print(f"    - {pf.get('format')}: {pf.get('details')}")

            # Overlay
            if analysis.get("has_overlay"):
                print(f"\n  {Fore.YELLOW}PE Overlay Detected:{Style.RESET_ALL}")
                print(f"    - Size:    {analysis.get('overlay_size')} bytes ({round(analysis.get('overlay_ratio', 0) * 100, 1)}% of total file)")
                print(f"    - Entropy: {analysis.get('overlay_entropy')}")
                for ov in analysis.get("overlay_indicators", []):
                    print(f"    - Content: {ov.get('type')} ({ov.get('details')})")

            # Native Entry Point match
            if analysis.get("ep_signature_match"):
                epm = analysis.get("ep_signature_match")
                print(f"\n  {Fore.YELLOW}Native Entry Point Match:{Style.RESET_ALL}")
                print(f"    - Packer: {epm.get('name')}")
                print(f"    - Pattern: {epm.get('description')}")

            # IL Analysis
            ilm = dotnet_info.get("il_metrics", {})
            if ilm:
                print(f"\n  {Fore.YELLOW}IL Method Disassembly Metrics:{Style.RESET_ALL}")
                print(f"    - Methods Analyzed:  {ilm.get('methods_analyzed', 0)}")
                print(f"    - Flattened Loops:   {ilm.get('cff_count', 0)} ({round(ilm.get('cff_ratio', 0) * 100, 1)}%)")
                print(f"    - Max Switch Cases:  {ilm.get('max_switch_cases', 0)}")
                print(f"    - Empty Stub Bodies: {ilm.get('empty_stub_count', 0)}")

            # P/Invoke Imports
            pinvs = dotnet_info.get("pinvoke_imports", [])
            if pinvs:
                print(f"\n  {Fore.YELLOW}P/Invoke Native Imports ({len(pinvs)} total):{Style.RESET_ALL}")
                for pi in pinvs[:15]:
                    print(f"    - {pi.get('dll')}!{pi.get('name')}")

            # CLR Streams
            streams = dotnet_info.get("clr_streams", [])
            if streams:
                print(f"\n  {Fore.YELLOW}CLR Metadata Streams:{Style.RESET_ALL}")
                for st in streams:
                    print(f"    - {st.get('name'):<12} Size: {st.get('size')} B")

            # Referenced Assemblies
            asm_refs = dotnet_info.get("assembly_refs", [])
            print(f"\n  {Fore.YELLOW}Referenced Assemblies ({len(asm_refs)} total):{Style.RESET_ALL}")
            for r in asm_refs:
                print(f"    - {r}")

            # Custom Attributes
            cas = dotnet_info.get("custom_attributes", [])
            print(f"\n  {Fore.YELLOW}Custom Attributes ({len(cas)} total):{Style.RESET_ALL}")
            for ca in cas[:20]:
                print(f"    - {ca.get('full_name')}")

            # Declared Namespaces
            nss = dotnet_info.get("namespaces", [])
            print(f"\n  {Fore.YELLOW}Declared Namespaces ({len(nss)} total):{Style.RESET_ALL}")
            for ns in nss:
                print(f"    - '{ns}'")

            # Resources
            ress = dotnet_info.get("resources", [])
            print(f"\n  {Fore.YELLOW}Manifest Resources ({len(ress)} total):{Style.RESET_ALL}")
            for res in ress:
                print(f"    - {res.get('name')} (Size: {res.get('size')} B, Entropy: {res.get('entropy')})")

            # Sample Types
            types = dotnet_info.get("type_names", [])
            print(f"\n  {Fore.YELLOW}Sample Types (First 15 of {len(types)}):{Style.RESET_ALL}")
            for t in types[:15]:
                print(f"    - {t}")

        print("\n" + "=" * 70 + "\n")

    @staticmethod
    def save_json_report(analysis: Dict[str, Any], detection: Dict[str, Any], output_path: str):
        """
        Saves full scan data to a JSON file.
        """
        payload = {
            "analysis": analysis,
            "detection": detection,
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        print(f"{Fore.GREEN}[+] Full scan report saved to: {output_path}{Style.RESET_ALL}")
