"""
YARA scanning engine for NetDetect (Phase 15).
Provides optional YARA pattern matching integration for custom and external rules.
Degrades gracefully when 'yara' is not installed.
"""

import os
from typing import List, Dict, Any, Optional

try:
    import yara
    _YARA_AVAILABLE = True
except ImportError:
    yara = None
    _YARA_AVAILABLE = False


class YaraScanner:
    """
    Loads and compiles YARA rule sets, scans files, and maps matches into detection evidence.
    """

    def __init__(self, rule_paths: Optional[List[str]] = None):
        self.available = _YARA_AVAILABLE
        self.rules = None
        self.error: Optional[str] = None

        if not self.available:
            self.error = "yara-python is not installed (optional dependency)."
            return

        compiled_sources = {}
        if rule_paths:
            for p in rule_paths:
                if os.path.isfile(p):
                    compiled_sources[os.path.basename(p)] = p
                elif os.path.isdir(p):
                    for fname in os.listdir(p):
                        if fname.endswith((".yar", ".yara")):
                            full = os.path.join(p, fname)
                            compiled_sources[fname] = full

        if compiled_sources:
            try:
                self.rules = yara.compile(filepaths=compiled_sources)
            except Exception as e:
                self.error = f"YARA compilation error: {e}"

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Scans a file with loaded YARA rules and returns normalized finding descriptors.
        """
        if not self.available or not self.rules:
            return []

        findings: List[Dict[str, Any]] = []
        try:
            matches = self.rules.match(file_path)
            for m in matches:
                meta = m.meta or {}
                tool_name = meta.get("tool", m.rule)
                layer = meta.get("layer", "protector")
                tier = meta.get("tier", "strong").lower()
                version = meta.get("version")

                findings.append({
                    "rule": m.rule,
                    "tool": tool_name,
                    "layer": layer,
                    "tier": tier,
                    "version": version,
                    "tags": m.tags,
                    "strings": [s[2].decode("utf-8", errors="ignore") if isinstance(s[2], bytes) else str(s[2]) for s in m.strings[:5]],
                })
        except Exception as e:
            self.error = f"YARA match error: {e}"

        return findings
