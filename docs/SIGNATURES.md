# NetDetect Signature Schema V2 Reference & Authoring Guide

## Overview

NetDetect uses **Schema v2** for defining signatures of .NET Obfuscators, Protectors, Packers, Virtualizers, and Bundlers. Each signature entry is registered in `netdetect/signatures.py` under the dictionary `OBFUSCATOR_SIGNATURES`.

Every pattern in Schema v2 is validated by `validate_signatures()` at import time and during test runs.

---

## Signature Structure

```python
"Tool Name": {
    "layer": "obfuscator",                # Required: layer category
    "verified": True,                     # Required: True if verified on sample, False if speculative
    "confidence_cap": None,               # Optional: "LOW" or "MEDIUM" cap for unverified signatures
    "attributes": [                       # CustomAttribute TypeDef or TypeRef markers
        "ObfuscatedByAttribute",          # Exact or token mode by default
    ],
    "type_names": [                       # Declared type names or token patterns
        {"p": "ObfuscatedClass", "mode": "token"},
    ],
    "namespaces": [                       # Declared namespaces
        "ToolNamespace",
    ],
    "assembly_refs": [                    # Referenced assemblies
        {"p": "Tool.Runtime", "mode": "exact"},
    ],
    "strings": [                          # User or metadata strings
        {"p": "Tool Watermark String", "mode": "contains"},
    ],
    "resource_names": [                   # Manifest resource names
        {"p": "tool.payload.", "mode": "prefix"},
    ],
    "resource_magic": [                   # First bytes of manifest resources
        {"p": "1f8b", "mode": "prefix"},
    ],
    "import_names": [                     # P/Invoke or native DLL imports
        "toolhelper",
    ],
    "clr_stream_markers": [               # Custom CLR metadata stream names
        "#ToolStream",
    ],
    "version_regex": r"Tool\s+v?([\d.]+)", # Optional: regex to extract version
    "characteristics": [                  # High-level descriptions for reporting
        "String and constant encryption",
        "Control flow obfuscation",
    ],
}
```

---

## Layers

The `layer` attribute determines the execution role of the tool and enables NetDetect's **Layered Protection Stack**:

| Layer | Description | Examples |
|---|---|---|
| `packer` | Compresses, encrypts, or unpacks executable at native entry | UPX, MPRESS, ASPack, Enigma, BoxedApp |
| `bundler` | Packs assemblies, dependencies, or runtime into single file | Costura, Fody, ILMerge, ILRepack, .NET Single-File |
| `virtualizer` | Converts CIL instructions into custom bytecode interpreted by VM | KoiVM, EzirizVM, Agile.NET VM, Babel VM, Eazfuscator VM |
| `protector` | Native or heavy managed envelope, anti-tamper, and dynamic restore | ConfuserEx, .NET Reactor, Themida, VMProtect, ILProtector |
| `obfuscator` | Renaming, control flow flattening, string/constant encryption | Obfuscar, Dotfuscator, Eazfuscator.NET, Babel, CodeWall |
| `licensing` | Commercial license enforcement and hardware dongle protection | CryptoLicensing, Thales Sentinel HASP, Wibu CodeMeter |
| `info` | Post-processing, deobfuscator traces, or informational output | de4dot (Deobfuscated Output) |

---

## Pattern Matching Modes

Patterns can be specified as a string (which uses the field's default mode) or as a dictionary: `{"p": "<pattern>", "mode": "<mode>"}`.

| Mode | Semantics | Used for |
|---|---|---|
| `exact` | Case-insensitive equality (`text.lower() == pat.lower()`) | CLR stream names, attributes, assembly refs |
| `prefix` | Case-insensitive prefix match (`text.lower().startswith(pat.lower())`) | Resource names, version prefixes |
| `token` | Word-boundary matching using camelCase, dots, underscores, and digit boundaries | Type names, namespaces |
| `contains` | Substring match. **Guard Rule:** Pattern must be at least 8 characters long (`MIN_CONTAINS_LEN = 8`) to prevent false positive substring collisions. | Long watermarks and branding strings |
| `regex` | Compiled regular expression | Complex naming schemes, version extraction |

---

## Evidence Tiers & Confidence

When matching against binaries, evidence is weighted across three tiers:

- **DEFINITIVE (+70):** CLR stream marker, exact attribute TypeDef/TypeRef, exact IAT DLL, YARA definitive rule.
- **STRONG (+35):** Type name token, assembly ref, resource prefix/magic, section name.
- **WEAK (+12):** User/metadata string watermark, MemberRef parent.

### Confidence Rules:
- **HIGH:** At least 1 DEFINITIVE, or at least 2 STRONG from distinct categories.
- **MEDIUM:** At least 1 STRONG plus at least 1 other category, or total score ≥ 40.
- **LOW:** WEAK evidence only. LOW findings are reported but never chosen as primary detector.

---

## Authoring a New Signature Checklist

1. Verify tool behavior on real samples or decompiled binaries.
2. If verified on real binary, set `"verified": True`. If hypothetical or based on documentation only, set `"verified": False` and `"confidence_cap": "LOW"`.
3. Avoid generic short strings (e.g. `UPX0`, `netz`, `VM_`). Use `token` mode or exact prefixes.
4. Run validation:
   ```bash
   python -c "from netdetect.signatures import validate_signatures; validate_signatures()"
   ```
5. Run the False Positive benchmark gate to ensure clean BCL assemblies are not impacted:
   ```bash
   python tests/fp_benchmark.py --limit 150 --baseline tests/fp_baseline.json
   ```
