"""
Detection and Scoring Engine for identifying .NET Obfuscators, Protectors, and Packers.
Phase 8: Tier-weighted evidence scoring, token-aware pattern matching, trusted publisher suppression.
Phase 10: Recalibrated heuristic thresholds to eliminate false positives on clean assemblies.
"""

import re
from typing import Dict, Any, List, Optional
from .signatures import (
    OBFUSCATOR_SIGNATURES,
    SECTION_NAME_TO_TOOL,
    KNOWN_PACKER_IMPORTS,
    MICROSOFT_PUBLIC_KEY_TOKENS,
    FINDING_ALIASES,
)
from .matching import compile_pattern
from .api_indicators import evaluate_api_indicators


class ObfuscatorDetector:
    """
    Evaluates metadata extracted from a PE/.NET binary against known signatures and heuristics.
    """

    def __init__(self, analysis_result: Dict[str, Any]):
        self.raw_data = analysis_result
        self.is_dotnet = analysis_result.get("is_dotnet", False)
        self.dotnet_info = analysis_result.get("dotnet_info", {})
        self.pe_sections = analysis_result.get("pe_sections", [])
        self.high_entropy_sections = analysis_result.get("high_entropy_sections", [])

    def detect(self) -> Dict[str, Any]:
        """
        Runs signature matching and heuristic scoring.
        """
        findings: List[Dict[str, Any]] = []
        generic_techniques: List[Dict[str, Any]] = []

        if not self.raw_data.get("is_valid_pe", False):
            return {
                "detected": False,
                "primary_detector": None,
                "confidence": "NONE",
                "verdict_score": 0,
                "protectors": [],
                "generic_techniques": [],
                "summary": "Not a valid Windows PE executable.",
            }

        if not self.is_dotnet:
            # Native PE - check for native packers/crypters
            native_findings = self._check_section_tool_mapping()
            native_findings += self._check_import_table_indicators()

            ep_m = self.raw_data.get("ep_signature_match")
            if ep_m:
                native_findings.append({
                    "name": ep_m["name"],
                    "layer": "packer",
                    "score": 90,
                    "confidence": "HIGH",
                    "tier_hits": {"definitive": 1, "strong": 0, "weak": 0},
                    "evidence": [f"Native entry point byte pattern: {ep_m['description']}"],
                    "characteristics": ["Native packer/crypter entry point stub"],
                })

            pe_heuristics = self._evaluate_pe_heuristics()
            pe_heuristics += self._check_pe_header_anomalies(is_native=True)

            primary = native_findings[0] if native_findings else None
            return {
                "detected": len(native_findings) > 0,
                "is_dotnet": False,
                "primary_detector": primary["name"] if primary else None,
                "confidence": primary["confidence"] if primary else "NONE",
                "verdict_score": sum(t.get("weight", 1) for t in pe_heuristics),
                "protectors": native_findings,
                "generic_techniques": pe_heuristics,
                "summary": "Native (non-.NET) executable." + (
                    f" Potential packer detected: {primary['name']}." if primary else ""
                ),
            }

        # ---- .NET path ----

        # 1. Match against known .NET Obfuscator Signatures
        for name, sig in OBFUSCATOR_SIGNATURES.items():
            match_info = self._match_single_signature(name, sig)
            if match_info:
                findings.append(match_info)

        # 2. Check for Confuser/MindLated zero-width characters heuristic
        confuser_heuristic = self._check_confuser_heuristics()
        if confuser_heuristic:
            heuristic_name = confuser_heuristic["name"]
            existing = next(
                (f for f in findings if "Confuser" in f["name"] or "MindLated" in f["name"]),
                None,
            )
            if existing:
                existing["score"] = min(existing["score"] + confuser_heuristic.get("score_boost", 0), 100)
                existing["evidence"].extend(confuser_heuristic.get("evidence", []))
                existing["confidence"] = confuser_heuristic["confidence"]
                existing["tier_hits"] = confuser_heuristic.get("tier_hits", existing.get("tier_hits", {}))
                if "MindLated" in heuristic_name and "MindLated" not in existing["name"]:
                    existing["name"] = heuristic_name
            else:
                findings.append(confuser_heuristic)

        # 3. Check for Costura Resource signatures
        costura_match = self._check_costura_resources()
        if costura_match:
            existing = next((f for f in findings if "Costura" in f["name"]), None)
            if existing:
                existing["evidence"].extend(costura_match["evidence"])
            else:
                findings.append(costura_match)

        # 4. Import table indicators (native wrapper detection)
        for finding in self._check_import_table_indicators():
            findings.append(finding)

        # 5. Custom CLR stream detection
        claimed_streams: set = set()
        for f in findings:
            for ev in f.get("evidence", []):
                if "CLR stream marker:" in ev:
                    claimed_streams.add(ev.split("'")[1] if "'" in ev else "")

        for stream_finding in self._check_clr_streams(claimed_streams):
            findings.append(stream_finding)

        # 6. Section tool mapping (for .NET packed with native packer)
        for finding in self._check_section_tool_mapping():
            existing = next((f for f in findings if f["name"] == finding["name"]), None)
            if not existing:
                findings.append(finding)

        # 7. Check native EP signature match (for native packer over .NET)
        ep_m = self.raw_data.get("ep_signature_match")
        if ep_m:
            findings.append({
                "name": ep_m["name"],
                "layer": "packer",
                "score": 90,
                "confidence": "HIGH",
                "tier_hits": {"definitive": 1, "strong": 0, "weak": 0},
                "evidence": [f"Native entry point byte pattern: {ep_m['description']}"],
                "characteristics": ["Native packer/crypter entry point stub"],
            })

        # 8. Check packaging formats (Single-File AppHost bundles)
        for fmt in self.raw_data.get("packaging_formats", []):
            fmt_name = fmt.get("format", "")
            if "Single-File" in fmt_name:
                findings.append({
                    "name": ".NET Single-File Bundle",
                    "layer": "bundler",
                    "score": 85,
                    "confidence": "HIGH",
                    "tier_hits": {"definitive": 1, "strong": 0, "weak": 0},
                    "evidence": ["Microsoft .NET Single-File AppHost bundle signature present"],
                    "characteristics": ["Self-contained single-file deployment"],
                })

        # 9. Check overlay indicators
        for ov in self.raw_data.get("overlay_indicators", []):
            if ov.get("magic") == "EVB/BoxedApp":
                findings.append({
                    "name": "Enigma Virtual Box / BoxedApp",
                    "layer": "packer",
                    "score": 90,
                    "confidence": "HIGH",
                    "tier_hits": {"definitive": 1, "strong": 0, "weak": 0},
                    "evidence": [ov.get("details", "")],
                    "characteristics": ["Virtual file system container"],
                })

        # 7. Normalize aliases and merge duplicate findings
        findings = self._normalize_and_dedup_findings(findings)

        # 8. Filter low-confidence findings on trusted publishers (Microsoft, BCL)
        if self._is_trusted_publisher():
            findings = [f for f in findings if f.get("confidence") in ("HIGH", "MEDIUM") and f.get("tier_hits", {}).get("weak", 0) < 2]

        # 9. Evaluate Generic Obfuscation Techniques
        generic_techniques = self._evaluate_generic_techniques()
        generic_techniques.extend(self._check_pe_header_anomalies(is_native=False))

        cctor_tech = self._check_cctor_density()
        if cctor_tech:
            generic_techniques.append(cctor_tech)

        # Promote findings based on attribution hints from structural techniques
        for t in generic_techniques:
            hint = t.get("hint")
            if hint:
                for f in findings:
                    if hint.lower() in f["name"].lower():
                        f["score"] = min(f.get("score", 0) + 25, 100)
                        if f["confidence"] == "LOW":
                            f["confidence"] = "MEDIUM"
                        f.setdefault("evidence", []).append(f"Structural heuristic hint: {t['technique']}")

        # 10. Verdict calculation
        verdict_score = sum(t.get("weight", 0) for t in generic_techniques)
        has_structural = any(t.get("kind") == "structural" for t in generic_techniques)
        distinct_kinds = len(set(t.get("kind") for t in generic_techniques if t.get("weight", 0) > 0))

        metrics = self.dotnet_info.get("identifier_metrics", {})
        has_strong_naming = any(
            t["technique"] == "Invisible Unicode Character Mangling"
            or ("Symbol Renaming" in t["technique"] and metrics.get("short_ratio", 0) >= 0.60)
            for t in generic_techniques
        )

        # Build Layered finding stack (Phase 15: layered verdict)
        layer_order = ["packer", "bundler", "virtualizer", "protector", "obfuscator", "licensing", "info"]
        layer_map: Dict[str, Dict[str, Any]] = {}
        for f in findings:
            if f["confidence"] in ("HIGH", "MEDIUM"):
                l = f.get("layer", "protector")
                if l not in layer_map or f.get("score", 0) > layer_map[l].get("score", 0):
                    layer_map[l] = f
        layers = [
            {"layer": l, "name": layer_map[l]["name"], "confidence": layer_map[l]["confidence"]}
            for l in layer_order
            if l in layer_map
        ]

        strong_candidates = [f for f in findings if f["confidence"] in ("HIGH", "MEDIUM")]
        primary = strong_candidates[0] if strong_candidates else None

        if primary:
            # Outermost layer primary candidate if layers exist
            if layers:
                primary_name = layers[0]["name"]
                confidence = layers[0]["confidence"]
            else:
                primary_name = primary["name"]
                confidence = primary["confidence"]
            detected = True
        elif not self._is_trusted_publisher() and ((verdict_score >= 6 and has_structural and distinct_kinds >= 2) or has_strong_naming):
            primary_name = "Generic / Custom Obfuscation"
            confidence = "HIGH" if verdict_score >= 8 else "MEDIUM"
            detected = True
        else:
            primary_name = "None Detected"
            confidence = "NONE"
            detected = False

        return {
            "detected": detected,
            "is_dotnet": True,
            "primary_detector": primary_name,
            "confidence": confidence,
            "verdict_score": verdict_score,
            "protectors": findings,
            "layers": layers,
            "generic_techniques": generic_techniques,
            "summary": self._generate_summary(primary, generic_techniques, detected, layers=layers),
        }

    # ------------------------------------------------------------------
    # Publisher Trust Check
    # ------------------------------------------------------------------

    def _is_trusted_publisher(self) -> bool:
        """
        Detects if assembly is from trusted Microsoft / runtime BCL sources.
        """
        # 1. Public key token check
        pkt = self.dotnet_info.get("public_key_token", "").lower()
        if pkt in MICROSOFT_PUBLIC_KEY_TOKENS:
            return True

        # 2. Namespace inspection
        nss = self.dotnet_info.get("namespaces", [])
        if nss:
            is_all_ms = all(
                ns.startswith("System")
                or ns.startswith("Microsoft")
                or ns.startswith("Windows")
                or ns.startswith("Accessibility")
                for ns in nss
            )
            if is_all_ms and len(nss) >= 2:
                return True

        # 3. Assembly name check
        asm_name = (self.dotnet_info.get("assembly_name") or "").lower()
        if asm_name.startswith("system.") or asm_name.startswith("microsoft.") or asm_name in ("mscorlib", "windowsbase"):
            return True

        return False

    # ------------------------------------------------------------------
    # Signature matching (Phase 8: Tier-weighted, token-aware)
    # ------------------------------------------------------------------

    def _match_single_signature(
        self, name: str, sig: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        score = 0
        evidence: List[str] = []
        tier_hits: Dict[str, int] = {"definitive": 0, "strong": 0, "weak": 0}
        categories_hit: set = set()

        custom_attrs = self.dotnet_info.get("custom_attributes", [])
        type_names   = self.dotnet_info.get("type_names", [])
        namespaces   = self.dotnet_info.get("namespaces", [])
        user_strings = self.dotnet_info.get("user_strings", [])
        meta_strings = self.dotnet_info.get("metadata_strings", [])
        member_refs  = self.dotnet_info.get("member_refs", [])
        resources    = self.dotnet_info.get("resources", [])
        import_dlls  = self.raw_data.get("import_dlls", [])
        clr_streams  = self.dotnet_info.get("clr_stream_names", [])
        asm_refs     = self.dotnet_info.get("assembly_refs", [])

        # 1. CLR Stream Markers (DEFINITIVE: +70)
        for s_spec in sig.get("clr_stream_markers", []):
            pat = compile_pattern(s_spec, default_mode="exact")
            for st in clr_streams:
                if pat.matches(st):
                    tier_hits["definitive"] += 1
                    categories_hit.add("clr_stream")
                    score += 70
                    evidence.append(f"CLR stream marker: '{st}'")
                    break

        # 2. Custom Attributes (DEFINITIVE: +70, or STRONG: +35)
        for ca_spec in sig.get("attributes", []):
            pat = compile_pattern(ca_spec, default_mode="token")
            matched = False
            for ca in custom_attrs:
                ca_name = ca.get("name", "")
                ca_full = ca.get("full_name", "")
                if pat.matches(ca_name) or pat.matches(ca_full):
                    tier = pat.tier or "definitive"
                    tier_hits[tier] += 1
                    categories_hit.add("attribute")
                    score += 70 if tier == "definitive" else 35
                    evidence.append(f"CustomAttribute match: '{ca_full or ca_name}'")
                    matched = True
                    break
            if matched:
                break

        # 3. IAT Native Imports (STRONG / DEFINITIVE: +35 / +70)
        for imp_spec in sig.get("import_names", []):
            pat = compile_pattern(imp_spec, default_mode="token")
            for dll in import_dlls:
                if pat.matches(dll):
                    tier = pat.tier or "strong"
                    tier_hits[tier] += 1
                    categories_hit.add("iat_import")
                    score += 60 if tier == "definitive" else 35
                    evidence.append(f"IAT import match: '{dll}'")
                    break

        # 4. Assembly References (STRONG: +35)
        for ref_spec in sig.get("assembly_refs", []):
            pat = compile_pattern(ref_spec, default_mode="exact")
            for r in asm_refs:
                if pat.matches(r):
                    tier_hits["strong"] += 1
                    categories_hit.add("assembly_ref")
                    score += 35
                    evidence.append(f"Referenced protection assembly: '{r}'")
                    break

        # 5. Type Names (STRONG: +35, max 2 counted)
        type_hits = 0
        for t_spec in sig.get("type_names", []):
            pat = compile_pattern(t_spec, default_mode="token")
            for t in type_names:
                if pat.matches(t):
                    type_hits += 1
                    tier_hits["strong"] += 1
                    categories_hit.add("type_name")
                    score += 35
                    evidence.append(f"Type signature match: '{t}'")
                    break
            if type_hits >= 2:
                break

        # 6. Namespaces (STRONG: +30)
        for ns_spec in sig.get("namespaces", []):
            pat = compile_pattern(ns_spec, default_mode="token")
            for ns in namespaces:
                if pat.matches(ns):
                    tier_hits["strong"] += 1
                    categories_hit.add("namespace")
                    score += 30
                    evidence.append(f"Namespace signature match: '{ns}'")
                    break

        # 7. Resource Names (STRONG: +35)
        for rn_spec in sig.get("resource_names", []):
            pat = compile_pattern(rn_spec, default_mode="prefix")
            for res in resources:
                rname = res.get("name", "")
                if pat.matches(rname):
                    tier_hits["strong"] += 1
                    categories_hit.add("resource_name")
                    score += 35
                    evidence.append(f"Resource name match: '{rname}'")
                    break

        # 8. Resource Magic (STRONG: +30)
        for rm_spec in sig.get("resource_magic", []):
            pat = compile_pattern(rm_spec, default_mode="prefix")
            for res in resources:
                rmagic = res.get("magic_bytes", "")
                if pat.matches(rmagic):
                    tier_hits["strong"] += 1
                    categories_hit.add("resource_magic")
                    score += 30
                    evidence.append(f"Resource magic-byte match: '{res.get('name')}' starts with 0x{rmagic.upper()}")
                    break

        # 9. Strings (STRONG if prominent watermark >= 12 chars, else WEAK)
        str_hits = 0
        all_strings = user_strings + meta_strings
        for s_spec in sig.get("strings", []):
            def_mode = "contains" if (isinstance(s_spec, str) and len(s_spec) >= 8) else "token"
            pat = compile_pattern(s_spec, default_mode=def_mode)
            for s in all_strings:
                if pat.matches(s):
                    str_hits += 1
                    tier = pat.tier or ("strong" if len(pat.raw) >= 12 else "weak")
                    tier_hits[tier] += 1
                    categories_hit.add("string")
                    score += 35 if tier == "strong" else 12
                    if str_hits <= 3:
                        evidence.append(f"Embedded string marker: '{s[:60]}'")
                    break
            if str_hits >= 2:
                break

        # 10. MemberRefs (WEAK: +12)
        for mr_spec in sig.get("namespaces", []) + sig.get("type_names", []):
            pat = compile_pattern(mr_spec, default_mode="token")
            for mr in member_refs:
                parent = mr.get("parent", "")
                if parent and pat.matches(parent):
                    tier_hits["weak"] += 1
                    categories_hit.add("member_ref")
                    score += 12
                    evidence.append(f"MemberRef parent match: '{parent}'")
                    break

        if score == 0:
            return None

        # Determine Confidence
        confidence = "LOW"
        if tier_hits["definitive"] >= 1 or (tier_hits["strong"] >= 2 and len(categories_hit) >= 2):
            confidence = "HIGH"
        elif tier_hits["strong"] >= 1 and (len(categories_hit) >= 2 or score >= 40):
            confidence = "MEDIUM"

        cap = sig.get("confidence_cap")
        if cap == "LOW":
            confidence = "LOW"
        elif cap == "MEDIUM" and confidence == "HIGH":
            confidence = "MEDIUM"

        # Extract version if version_regex specified
        version_str = None
        v_regex = sig.get("version_regex")
        if v_regex:
            v_pat = re.compile(v_regex, re.IGNORECASE)
            for s in all_strings:
                m = v_pat.search(s)
                if m:
                    version_str = m.group(1) if m.groups() else m.group(0)
                    evidence.append(f"Version identified: {version_str}")
                    break

        return {
            "name": name,
            "layer": sig.get("layer", "protector"),
            "version": version_str,
            "score": min(score, 100),
            "confidence": confidence,
            "tier_hits": tier_hits,
            "evidence": list(set(evidence)),
            "characteristics": sig.get("characteristics", []),
        }

    # ------------------------------------------------------------------
    # Heuristics checks
    # ------------------------------------------------------------------

    def _check_confuser_heuristics(self) -> Optional[Dict[str, Any]]:
        metrics = self.dotnet_info.get("identifier_metrics", {})
        invisible_count = metrics.get("invisible_count", 0)
        invisible_detected = metrics.get("invisible_detected", [])

        if invisible_count <= 0:
            return None

        all_strings = (
            self.dotnet_info.get("metadata_strings", [])
            + self.dotnet_info.get("user_strings", [])
        )
        if any("mindlated" in s.lower() for s in all_strings):
            tool_name = "MindLated (ConfuserEx Fork)"
        else:
            tool_name = "ConfuserEx (Heuristic Match)"

        evidence = [
            f"Detected {invisible_count} identifiers with zero-width/invisible characters: "
            f"{', '.join(invisible_detected)}"
        ]
        if self.dotnet_info.get("has_module_cctor", False):
            evidence.append(
                "<Module> static constructor (.cctor) present "
                "(typical ConfuserEx/MindLated decryptor stub)"
            )

        return {
            "name": tool_name,
            "layer": "obfuscator",
            "score": 85 if self.dotnet_info.get("has_module_cctor") else 70,
            "score_boost": 40,
            "confidence": "HIGH" if invisible_count >= 5 else "MEDIUM",
            "tier_hits": {"definitive": 1, "strong": 1, "weak": 0},
            "evidence": evidence,
            "characteristics": [
                "Unicode zero-width character identifier mangling",
                "Dynamic module initialization via <Module>..cctor",
            ],
        }

    def _check_costura_resources(self) -> Optional[Dict[str, Any]]:
        resources = self.dotnet_info.get("resources", [])
        costura_res = [r["name"] for r in resources if r["name"].lower().startswith("costura.")]
        if costura_res:
            return {
                "name": "Costura (Fody Assembly Embedder)",
                "layer": "bundler",
                "score": 90,
                "confidence": "HIGH",
                "tier_hits": {"definitive": 0, "strong": 2, "weak": 0},
                "evidence": [f"Embedded Costura resource: '{r}'" for r in costura_res[:3]],
                "characteristics": [
                    "Embedded assemblies packed/compressed into resources",
                    "Dynamic runtime assembly resolution via Costura.AssemblyLoader",
                ],
            }
        return None

    def _check_section_tool_mapping(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        seen: set = set()
        for sec in self.raw_data.get("suspicious_sections", []):
            sec_name = sec["name"]
            sec_name_lower = sec_name.lower()
            tool = (
                SECTION_NAME_TO_TOOL.get(sec_name_lower)
                or SECTION_NAME_TO_TOOL.get(sec_name)
            )
            display = tool if tool else f"Unknown Packer ({sec_name})"
            if display in seen:
                continue
            seen.add(display)
            findings.append({
                "name": display,
                "layer": "packer",
                "score": 80,
                "confidence": "HIGH" if tool else "MEDIUM",
                "tier_hits": {"definitive": 0, "strong": 2, "weak": 0},
                "evidence": [
                    f"PE section '{sec_name}' (entropy {sec['entropy']}) matches known packer signature"
                ],
                "characteristics": [
                    f"Packed binary — section name '{sec_name}' is a {display} signature"
                ],
            })
        return findings

    def _check_import_table_indicators(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        seen: set = set()
        import_dlls = self.raw_data.get("import_dlls", [])
        for dll in import_dlls:
            dll_lower = dll.lower()
            for key, tool in KNOWN_PACKER_IMPORTS.items():
                if key in dll_lower and tool not in seen:
                    seen.add(tool)
                    findings.append({
                        "name": tool,
                        "layer": "packer",
                        "score": 75,
                        "confidence": "HIGH",
                        "tier_hits": {"definitive": 1, "strong": 1, "weak": 0},
                        "evidence": [f"Native IAT import '{dll}' matches known protector DLL"],
                        "characteristics": [f"IAT-level native protector wrapper: {tool}"],
                    })
        return findings

    def _check_clr_streams(self, claimed_streams: set) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        standard = {"#~", "#-", "#Strings", "#US", "#GUID", "#Blob"}
        streams = self.dotnet_info.get("clr_stream_names", [])
        for stream in streams:
            if stream not in standard and stream not in claimed_streams:
                findings.append({
                    "name": f"Custom CLR Stream ({stream})",
                    "layer": "protector",
                    "score": 70,
                    "confidence": "HIGH",
                    "tier_hits": {"definitive": 1, "strong": 0, "weak": 0},
                    "evidence": [f"Non-standard CLR metadata stream '{stream}' present"],
                    "characteristics": ["Custom protector-injected CLR metadata stream"],
                })
        return findings

    def _normalize_and_dedup_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # 1. Apply aliases
        for f in findings:
            if f["name"] in FINDING_ALIASES:
                f["name"] = FINDING_ALIASES[f["name"]]

        # 2. Sort by score descending and deduplicate by name
        seen: set = set()
        deduped: List[Dict[str, Any]] = []
        for f in sorted(findings, key=lambda x: x["score"], reverse=True):
            if f["name"] not in seen:
                seen.add(f["name"])
                deduped.append(f)
        return deduped

    # ------------------------------------------------------------------
    # Generic obfuscation techniques (Phase 10: Recalibrated)
    # ------------------------------------------------------------------

    def _evaluate_generic_techniques(self) -> List[Dict[str, Any]]:
        techniques: List[Dict[str, Any]] = []
        metrics = self.dotnet_info.get("identifier_metrics", {})

        # 1. Identifier Renaming (short / alphabetic)
        short_ratio = metrics.get("short_ratio", 0.0)
        short_count = metrics.get("short_count", 0)
        if short_ratio >= 0.35 and short_count >= 10:
            techniques.append({
                "technique": "Symbol Renaming (Short / Alphabetic)",
                "severity": "MEDIUM",
                "weight": 3,
                "kind": "naming",
                "details": (
                    f"{round(short_ratio * 100, 1)}% of identifiers "
                    f"({short_count} total) have been shortened (e.g. 'a', 'b', 'c0')."
                ),
            })

        # 2. Invisible / Unicode Mangling
        invisible_count = metrics.get("invisible_count", 0)
        if invisible_count > 0:
            techniques.append({
                "technique": "Invisible Unicode Character Mangling",
                "severity": "HIGH",
                "weight": 5,
                "kind": "naming",
                "details": (
                    f"{invisible_count} identifiers utilize zero-width "
                    "or unprintable formatting characters."
                ),
            })

        # 3. High-Entropy Identifier Names (hash-based renaming)
        high_ent_ratio = metrics.get("high_entropy_name_ratio", 0.0)
        high_ent_count = metrics.get("high_entropy_name_count", 0)
        if high_ent_ratio >= 0.30 and high_ent_count >= 10:
            techniques.append({
                "technique": "High-Entropy Identifier Names (Hash-Based Renaming)",
                "severity": "MEDIUM",
                "weight": 3,
                "kind": "naming",
                "details": (
                    f"{round(high_ent_ratio * 100, 1)}% of identifiers "
                    f"({high_ent_count} total) have high character-entropy/unwordlike patterns."
                ),
            })

        # 4. High Entropy Resources
        high_ent_res = self.dotnet_info.get("high_entropy_resources", [])
        if high_ent_res:
            techniques.append({
                "technique": "Encrypted / Packed Resources",
                "severity": "HIGH",
                "weight": 4,
                "kind": "structural",
                "details": (
                    f"{len(high_ent_res)} resource(s) have entropy >= 7.2 "
                    f"(e.g. '{high_ent_res[0]['name']}' with entropy {high_ent_res[0]['entropy']})."
                ),
            })

        # 5. Module Initializer (.cctor) Runtime Decryptor
        if self.dotnet_info.get("has_module_cctor", False):
            techniques.append({
                "technique": "<Module> Static Constructor Decryptor",
                "severity": "HIGH",
                "weight": 4,
                "kind": "structural",
                "details": (
                    "Global <Module> class contains a .cctor static constructor, "
                    "commonly used to dynamically decrypt strings/resources or enforce anti-tampering."
                ),
            })

        # 6. String Encryption Indicator
        user_strings = self.dotnet_info.get("user_strings", [])
        type_count = len(self.dotnet_info.get("type_names", []))
        if type_count > 30 and len(user_strings) == 0:
            techniques.append({
                "technique": "Suspected String Encryption",
                "severity": "MEDIUM",
                "weight": 2,
                "kind": "structural",
                "details": (
                    f"Binary has {type_count} declared types but 0 user strings in the #US heap."
                ),
            })

        # 7. Anti-Metadata Analysis (via dotnetfile)
        anti_md = self.dotnet_info.get("anti_metadata", {})
        flagged_anti = [k for k, v in anti_md.items() if v]
        if flagged_anti:
            techniques.append({
                "technique": "Anti-Decompilation Metadata Tampering",
                "severity": "HIGH",
                "weight": 5,
                "kind": "structural",
                "details": f"Manipulated metadata structures detected: {', '.join(flagged_anti)}",
            })

        # 8. Mixed-Mode / Native Stub
        if self.dotnet_info.get("is_mixed_assembly", False):
            techniques.append({
                "technique": "Mixed-Mode / Native Code Integration",
                "severity": "HIGH",
                "weight": 4,
                "kind": "structural",
                "details": "Assembly contains both managed IL and unmanaged native code.",
            })

        # 9. High Entropy PE Sections
        if self.high_entropy_sections:
            sec = self.high_entropy_sections[0]
            techniques.append({
                "technique": "High Entropy PE Section (Packed Code)",
                "severity": "HIGH",
                "weight": 4,
                "kind": "structural",
                "details": f"Section '{sec['name']}' has high entropy ({sec['entropy']}).",
            })

        # 10. Stripped Method Bodies (Virtualization Hook)
        empty_rva = self.dotnet_info.get("empty_rva_methods_count", 0)
        total_methods = len(self.dotnet_info.get("method_names", []))
        if empty_rva >= 10 and (empty_rva / max(total_methods, 1)) >= 0.05:
            techniques.append({
                "technique": "Stripped / Dynamic Method Bodies (Virtualization Hook)",
                "severity": "HIGH",
                "weight": 5,
                "kind": "structural",
                "details": (
                    f"{empty_rva} implemented method(s) ({round(empty_rva / max(total_methods, 1) * 100, 1)}%) "
                    "have RVA == 0 without abstract/pinvoke flags."
                ),
            })

        # 11. Large Overlay
        if (
            self.raw_data.get("has_overlay", False)
            and self.raw_data.get("overlay_size", 0) > 102400
        ):
            sz_mb = round(self.raw_data.get("overlay_size", 0) / (1024 * 1024), 2)
            ratio = self.raw_data.get("overlay_ratio", 0.0)
            if ratio >= 0.20:
                techniques.append({
                    "technique": "Large Embedded Overlay Payload",
                    "severity": "HIGH",
                    "weight": 4,
                    "kind": "structural",
                    "details": (
                        f"PE Overlay contains {sz_mb} MB ({round(ratio * 100, 1)}% of file size) "
                        f"with entropy {self.raw_data.get('overlay_entropy', 0)}."
                    ),
                })

        # 12. API Indicators (Phase 12)
        api_techs = evaluate_api_indicators(
            self.dotnet_info.get("member_refs", []),
            self.dotnet_info.get("pinvoke_imports", []),
        )
        techniques.extend(api_techs)

        # 13. Duplicate CLR metadata streams (Phase 12)
        dup_streams = self.dotnet_info.get("duplicate_streams", [])
        if dup_streams:
            techniques.append({
                "technique": "Duplicate Metadata Stream Names (Anti-Dump)",
                "severity": "HIGH",
                "weight": 5,
                "kind": "structural",
                "hint": "ConfuserEx",
                "details": f"Duplicate CLR metadata streams detected: {', '.join(dup_streams)}",
            })

        # 14. Encrypted Field Initial Values (Phase 12)
        field_blobs = self.dotnet_info.get("field_rva_blobs", [])
        enc_blobs = [b for b in field_blobs if b.get("size", 0) >= 4096 and b.get("entropy", 0.0) >= 7.2]
        if enc_blobs:
            techniques.append({
                "technique": "Encrypted Field Initial Values (Static Constant Array)",
                "severity": "HIGH",
                "weight": 4,
                "kind": "structural",
                "hint": "ConfuserEx",
                "details": f"{len(enc_blobs)} FieldRVA blob(s) >= 4KB have high entropy >= 7.2 (constants/compressor payload).",
            })

        # 15. High-Entropy Metadata Heap (Phase 12)
        heap_ent = self.dotnet_info.get("heap_entropy", {})
        high_heaps = [k for k, v in heap_ent.items() if v >= 7.0]
        if high_heaps:
            techniques.append({
                "technique": "High-Entropy Metadata Heap",
                "severity": "HIGH",
                "weight": 3,
                "kind": "structural",
                "details": f"CLR heaps with high entropy >= 7.0: {', '.join(high_heaps)}",
            })

        # 16. Suspicious Entry Point Section (Phase 12)
        flags = self.dotnet_info.get("flags", {})
        is_ilonly = flags.get("ILOnly", False)
        ep_sec = self.raw_data.get("ep_section", "")
        if is_ilonly and ep_sec and ep_sec.lower() not in (".text", "code", "text"):
            techniques.append({
                "technique": "Suspicious Entry Point Section",
                "severity": "HIGH",
                "weight": 3,
                "kind": "structural",
                "details": f"Managed ILOnly assembly has native entry point in non-code section '{ep_sec}'.",
            })

        # 17. Reserved-Keyword Names (Phase 12)
        kw_count = metrics.get("keyword_name_count", 0)
        if kw_count >= 10:
            techniques.append({
                "technique": "Reserved-Keyword Symbol Renaming",
                "severity": "MEDIUM",
                "weight": 2,
                "kind": "naming",
                "details": f"{kw_count} identifiers are named after C# reserved keywords to break decompilers.",
            })

        # 18. Unicode Lookalike / CJK Confusable Renaming (Phase 12)
        cjk_count = metrics.get("cjk_confusable_count", 0)
        cjk_ratio = metrics.get("cjk_confusable_ratio", 0.0)
        if cjk_count >= 5 and cjk_ratio >= 0.20:
            techniques.append({
                "technique": "Unicode Lookalike / CJK Symbol Renaming",
                "severity": "HIGH",
                "weight": 3,
                "kind": "naming",
                "hint": "Babel",
                "details": f"{cjk_count} identifiers ({round(cjk_ratio*100, 1)}%) utilize CJK/confusable characters.",
            })

        # 19. IL Heuristics (Phase 13)
        il_m = self.dotnet_info.get("il_metrics", {})
        if il_m:
            if il_m.get("cff_ratio", 0.0) >= 0.15 and il_m.get("cff_count", 0) >= 3:
                techniques.append({
                    "technique": "Control Flow Flattening (CFF)",
                    "severity": "HIGH",
                    "weight": 4,
                    "kind": "structural",
                    "hint": "ConfuserEx",
                    "details": f"{il_m.get('cff_count')} method(s) ({round(il_m.get('cff_ratio', 0)*100, 1)}%) contain switch-state dispatch loops with arithmetic flattening.",
                })
            if il_m.get("max_switch_cases", 0) >= 100 and (
                self.dotnet_info.get("has_module_cctor")
                or metrics.get("short_ratio", 0) >= 0.20
                or il_m.get("cff_count", 0) >= 2
            ):
                techniques.append({
                    "technique": "Virtual Machine Interpreter Dispatch Loop",
                    "severity": "HIGH",
                    "weight": 5,
                    "kind": "structural",
                    "hint": "KoiVM",
                    "details": f"Method contains massive dispatcher switch with {il_m.get('max_switch_cases')} opcode handlers (VM virtualizer loop).",
                })
            empty_il = il_m.get("empty_stub_count", 0)
            analyzed_il = il_m.get("methods_analyzed", 0)
            if analyzed_il >= 20 and empty_il >= 15 and (empty_il / analyzed_il) >= 0.25:
                techniques.append({
                    "technique": "Stripped IL Method Stubs (Dynamic Body Decryptor)",
                    "severity": "HIGH",
                    "weight": 4,
                    "kind": "structural",
                    "hint": "ILProtector",
                    "details": f"{empty_il} method(s) ({round(empty_il/analyzed_il*100, 1)}%) contain only stub return/throw instructions (runtime method restoration).",
                })
            if il_m.get("decryptor_target") and (self.dotnet_info.get("has_module_cctor") or metrics.get("short_ratio", 0) >= 0.25):
                tok, hits = il_m.get("decryptor_target")
                techniques.append({
                    "technique": "Centralized Dynamic String Decryptor Calls",
                    "severity": "HIGH",
                    "weight": 3,
                    "kind": "structural",
                    "details": f"Method token 0x{tok:08X} is called {hits} times with preceding load-constant arguments.",
                })

        return techniques

    def _check_pe_header_anomalies(self, is_native: bool) -> List[Dict[str, Any]]:
        techniques: List[Dict[str, Any]] = []

        ts = self.raw_data.get("pe_timestamp", -1)
        if ts == 0:
            techniques.append({
                "technique": "Zeroed PE TimeDateStamp",
                "severity": "MEDIUM",
                "weight": 2,
                "kind": "environmental",
                "details": "PE header TimeDateStamp is 0.",
            })

        # Missing Rich Header is ONLY an anomaly for native binaries (Roslyn/managed compilers never emit it)
        if is_native and not self.raw_data.get("has_rich_header", True):
            techniques.append({
                "technique": "Missing Rich Header",
                "severity": "LOW",
                "weight": 1,
                "kind": "environmental",
                "details": "Rich Header absent or zeroed in native binary.",
            })

        if is_native and not self.raw_data.get("has_import_table", True):
            techniques.append({
                "technique": "Empty Import Table (IAT Zeroed)",
                "severity": "HIGH",
                "weight": 4,
                "kind": "structural",
                "details": "No imports in IAT for a native executable.",
            })

        return techniques

    def _check_cctor_density(self) -> Optional[Dict[str, Any]]:
        cctor_count = self.dotnet_info.get("cctor_count", 0)
        type_count  = len(self.dotnet_info.get("type_names", []))
        if type_count >= 20 and cctor_count >= 15 and (cctor_count / type_count) >= 0.28:
            return {
                "technique": "Abnormal .cctor Density (Virtualizer Indicator)",
                "severity": "HIGH",
                "weight": 4,
                "kind": "structural",
                "details": (
                    f"{cctor_count} static constructors across {type_count} types "
                    f"({round(cctor_count / type_count * 100)}%)."
                ),
            }
        return None

    def _evaluate_pe_heuristics(self) -> List[Dict[str, Any]]:
        heuristics: List[Dict[str, Any]] = []
        if self.high_entropy_sections:
            sec = self.high_entropy_sections[0]
            heuristics.append({
                "technique": "Packed / Compressed Native Section",
                "severity": "HIGH",
                "weight": 4,
                "kind": "structural",
                "details": f"Section '{sec['name']}' has high entropy ({sec['entropy']}).",
            })
        return heuristics

    def _generate_summary(
        self,
        primary: Optional[Dict[str, Any]],
        techniques: List[Dict[str, Any]],
        detected: bool,
        layers: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        if layers and len(layers) > 1:
            layer_str = " -> ".join(l["name"] for l in layers)
            return f"Layered protection detected: {layer_str}."

        if primary and primary["confidence"] == "HIGH":
            return (
                f"High confidence detection of '{primary['name']}'. "
                "Matched signature and structural indicators."
            )
        elif primary and primary["confidence"] == "MEDIUM":
            return (
                f"Probable match for '{primary['name']}' "
                "based on multiple heuristic markers."
            )
        elif detected:
            return (
                f"Generic/Custom obfuscation detected. "
                f"Identified {len(techniques)} distinct obfuscation techniques."
            )
        else:
            return (
                "No obvious obfuscator or packer detected. "
                "Assembly appears to be clean or unobfuscated."
            )
