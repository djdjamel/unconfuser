# ConfuserEx Protection Coverage & Evidence-Based Support Matrix

This document provides a detailed, evidence-based breakdown of ConfuserEx 1.0.0 (and common forks) protection mechanisms, their support status in **ConfuserExKillerRunner** (`unconfuser`), operational requirements (static vs. dynamic execution), exact fixture provenance, and verified validation results.

**Guiding Principle**: Unconfuser never claims `SUCCESS` or full verification without concrete structural and runtime proof. If a protection is unverified, indeterminate, or partial, the engine reports this truthfully.

---

## 1. Formal Status Definitions

Every ConfuserEx protection is classified under one of the following formal statuses:

| Status | Definition | CLI & Report Indicator |
| :--- | :--- | :--- |
| **Not Detected** | Protection markers, signatures, or IL patterns were not found in the target assembly. | `NotDetected` (`N/A`) |
| **Supported (Static)** | The protection is completely reversed statically using ECMA-335 / PE analysis without executing target code. | `SupportedStatic` |
| **Requires Dynamic Execution** | Reversing this protection requires running isolated decrypter routines (`--allow-execution`). In static mode, hooks are preserved. | `RequiresDynamicExecution` |
| **Verified on Real Fixture** | The protection was reversed, transformed, and validated against authentic ConfuserEx 1.0.0 binaries with structural and runtime tests. | `VerifiedOnRealFixture` |
| **Partially Processed** | Only a subset of references or patterns could be safely resolved. Unresolved elements are preserved to avoid corrupting IL semantics. | `PartiallyProcessed` |
| **Unsupported** | The protection technique (e.g. native x86 machine code or JIT compiler hooking) cannot be executed or reversed safely. The assembly is left untouched. | `Unsupported` |

---

## 2. Evidence-Based Protection Support Matrix

| Protection & Variant | Detection | Transformation | Mode | Fixture & Manifest | Structural Validation | Runtime Validation | Known Limitations | Evidence Level |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Anti-Tamper** (Normal Mode: Section Encryption) | Tested | Tested | Dynamic (`--allow-execution`) | `real_confuserex_antitamper`<br>([manifest](../benchmarks/fixtures/real_confuserex_antitamper/fixture_manifest.json)) | PASSED (Clean PE headers, decrypted `.text` methods) | PASSED (JIT verified via `Verify-DeobfuscatedBinary.ps1`) | Requires isolated worker execution; static mode skips with exit code 2. | Real Fixture + CI |
| **Anti-Tamper** (JIT Mode: `compileMethod` Hook) | Tested | Not Tested (Detection Only) | Static | `fixture_antitamper_jit.dll`<br>(Synthetic) | Preserved | N/A (Preserved) | Native CLR runtime hook patching cannot be undone safely. Preserved fail-safe. | Synthetic Unit Test |
| **Anti-Dump** (PE/CLR Header Scrubbing) | Tested | Tested | Static | Synthetic + Corrupt PE stubs<br>(`Cor20RepairTests`) | PASSED (COR20 header size 72, MetaData RVA, BSJB magic restored) | PASSED (Loadable via dnlib & CLR) | Heavily truncated memory dumps missing metadata stream tables require manual reconstruction. | Unit + Integration |
| **Anti-Debug** (Managed Watchdog & Win32 P/Invoke) | Tested | Tested | Static | `CleanerKillerTests`<br>(91 unit tests) | PASSED (Hook calls & dead pop sequences stripped) | PASSED (Benign diagnostics strictly preserved) | Only positive ConfuserEx crash patterns stripped; application logging preserved. | Unit Test |
| **Anti-ILDasm** (`SuppressIldasmAttribute`) | Tested | Tested | Static | Clean assembly stubs | PASSED (Attribute stripped from assembly metadata) | PASSED | None. Standard ECMA-335 custom attribute removal. | Unit Test |
| **Invalid Metadata** (Stream & Table Mangling) | Tested | Tested | Static | `PEParsingAndRobustnessTests` | PASSED (Normalized during dnlib stream serialization) | PASSED (PEVerify clean) | Irrecoverably truncated metadata streams cannot be reconstructed. | Unit Test |
| **Constants** (Normal Mode: Static Buffers) | Tested | Tested | Static | `real_confuserex`<br>([manifest](../benchmarks/fixtures/real_confuserex/fixture_manifest.json)) | PASSED (25/25 constants decrypted, buffers pruned) | PASSED (Exact string & numeric runtime match) | Emulates 11 primitive array types and string decrypters. | Real Fixture + CI |
| **Constants** (Dynamic Mode: Runtime Mutation) | Tested | Tested | Dynamic (`--allow-execution`) | `real_confuserex_antitamper_constants`<br>([manifest](../benchmarks/fixtures/real_confuserex_antitamper_constants/fixture_manifest.json)) | PASSED (Dynamic constant decrypter calls inlined) | PASSED (Exact runtime output match) | Requires isolated worker execution. | Real Fixture + CI |
| **Constants** (x86 Mode: Native Machine Code) | Tested | Not Tested | N/A | Detection heuristics | Preserved without corruption | N/A | Native x86 machine-code stubs are not emulated. | Static Detection |
| **Control Flow** (Switch / State Machine) | Tested | Tested | Static | `real_confuserex`<br>([manifest](../benchmarks/fixtures/real_confuserex/fixture_manifest.json)) | PASSED (334/334 switches resolved, linear blocks restored) | PASSED (Exact runtime algorithm output) | Complex non-deterministic state machines with external predicates are preserved. | Real Fixture + CI |
| **Control Flow** (Jump Mangler & Junk Code) | Tested | Tested | Static | `real_confuserex_proxy_cflow`<br>([manifest](../benchmarks/fixtures/real_confuserex_proxy_cflow/fixture_manifest.json)) | PASSED (Dead code pairs, trampolines, and junk stripped) | PASSED (Exact runtime behavior) | Opaque predicates requiring external symbolic solving are left intact. | Real Fixture + CI |
| **Control Flow** (x86 Native Thunks) | Tested | Not Tested | N/A | Detection heuristics | Preserved without corruption | N/A | Native x86 control-flow thunks not supported. | Static Detection |
| **Reference Proxies** (Mild Mode: Direct Call) | Tested | Tested | Static | `real_confuserex`<br>([manifest](../benchmarks/fixtures/real_confuserex/fixture_manifest.json)) | PASSED (Direct proxy call stubs inlined, delegates pruned) | PASSED (Exact call-site semantics) | Unreferenced delegates pruned automatically. | Real Fixture + CI |
| **Reference Proxies** (Strong Mode: Dynamic Invocation) | Tested | Tested | Static | `real_confuserex_proxy_cflow`<br>([manifest](../benchmarks/fixtures/real_confuserex_proxy_cflow/fixture_manifest.json)) | PASSED (Dynamic delegates resolved to target methods) | PASSED (Exact call-site semantics) | Proxies containing complex exception handling or branch targets in proxy body are preserved. | Real Fixture + CI |
| **Resources** (Normal & Dynamic Encrypted Mode) | Tested | Tested | Dynamic (`--allow-execution`) | `real_confuserex`<br>([manifest](../benchmarks/fixtures/real_confuserex/fixture_manifest.json)) | PASSED (Encrypted resources extracted, cleartext embedded) | PASSED (Resource stream resolution verified) | Requires isolated worker execution; static mode skips with exit code 2. | Real Fixture + CI |
| **Compressor** (Deflate Packer / Stub) | Tested | Tested | Static / Dynamic | `real_confuserex_compressor`<br>([manifest](../benchmarks/fixtures/real_confuserex_compressor/fixture_manifest.json)) | PASSED (Payload extracted, entry point restored, valid PE) | PASSED (Unpacked binary verified via JIT) | Outer packaging stripped; inner assembly then passed to deobfuscation pipeline. | Real Fixture + CI |
| **Name Protection** (Unicode & Control Characters) | Tested | Tested | Static | `SemanticRenamerTests`<br>(Unit tests C10_16-17) | PASSED (Zero-width and control characters detected and normalized) | PASSED (Valid ECMA-335 identifiers emitted) | Original names irreversibly destroyed by ConfuserEx. | Unit Test |
| **Name Protection** (ASCII Punctuation & Scrambled Symbols) | Tested | Tested | Static | `SemanticRenamerTests`<br>(Unit tests C10_05, C10_16) | PASSED (Punctuation and scrambled symbols detected and normalized) | PASSED (Valid ECMA-335 identifiers emitted) | Original names irreversibly destroyed by ConfuserEx. | Unit Test |
| **Name Protection** (Decodable & Sequential Modes) | Tested | Tested | Static | `SemanticRenamerTests`<br>(Unit test C10_23) | PASSED (Decodable patterns e.g. `_0001` detected and normalized) | PASSED (Clean semantic names applied) | Handled by de4dot pass and SemanticRenamer. | Unit Test |
| **Name Protection** (Letters & High-Entropy ASCII) | Tested | Tested | Static | `SemanticRenamerTests`<br>(Unit tests C10_21, C10_24, C10_25, C10_26) | PASSED (Consonant clusters and alternating case detected with Shannon entropy; legitimate code, technical compound acronyms e.g. SctpRtpRtcpProcessor, SmtpTlsHandler, and network/crypto patterns strictly preserved) | PASSED (Clean semantic names applied) | Full restoration of non-Forms/non-Resources symbols is mathematically non-reversible without oracles or PDBs. | Unit Test |
| **Name Protection** (MD5 Hash Mode) | Tested | Tested | Static | `SemanticRenamerTests`<br>(Unit test C10_22) | PASSED (32-character hexadecimal MD5 hashes detected and normalized) | PASSED (Clean semantic names applied) | Original names irreversibly hashed without salt/dictionary oracle. | Unit Test |
| **Semantic Renaming** (WinForms Controls & Forms) | Tested | Tested | Static | `SemanticRenamerTests`<br>(38 unit tests) | PASSED (Forms recovered via `set_Name` and ComponentResourceManager) | PASSED (No MissingManifestResourceException) | Controls without explicit `Name` property in `InitializeComponent` receive generic semantic names. | Unit + Real Sample |
| **Semantic Renaming** (Reflection & API Protection) | Tested | Tested | Static | `SemanticRenamerTests`<br>(C10_11-15, C10_20) | PASSED (Compiler-generated symbols, P/Invoke, and Reflection preserved) | PASSED (No TypeLoadException / MissingMethodException) | Ambiguous reflection lookups preserved with `Ambiguous` decision. | Unit + Real Sample |

---

## 3. Real Fixtures Inventory & Manifest Verification

All authentic ConfuserEx fixtures are generated from benign C# test applications using official pinned releases of ConfuserEx. Every fixture is accompanied by an immutable cryptographic manifest (`fixture_manifest.json`):

| Fixture Name | Path | Profile (`.crproj`) | Target Protections | Toolchain Version & Commit |
| :--- | :--- | :--- | :--- | :--- |
| `real_confuserex` | `benchmarks/fixtures/real_confuserex/` | `confuserex_v1.0.0.crproj` | Constants, Control Flow, Reference Proxy, Resources | ConfuserEx v1.0.0 (`3c9c29d`) |
| `real_confuserex_antitamper` | `benchmarks/fixtures/real_confuserex_antitamper/` | `confuser_antitamper.crproj` | Anti-Tamper (Normal Mode) | ConfuserEx v1.0.0 (`3c9c29d`) |
| `real_confuserex_antitamper_constants` | `benchmarks/fixtures/real_confuserex_antitamper_constants/` | `confuser_at_const.crproj` | Anti-Tamper + Constants | ConfuserEx v1.0.0 (`3c9c29d`) |
| `real_confuserex_compressor` | `benchmarks/fixtures/real_confuserex_compressor/` | `confuser_compressor.crproj` | Deflate Compressor Packer | ConfuserEx v1.0.0 (`3c9c29d`) |
| `real_confuserex_proxy_cflow` | `benchmarks/fixtures/real_confuserex_proxy_cflow/` | `confuser_proxy_cflow.crproj` | Reference Proxy + Control Flow | ConfuserEx v1.0.0 (`3c9c29d`) |

All fixture manifests verify:
1. Toolchain executable SHA-256 (`2b3e5cb7f96589e5377700a5f7f25e9fc6a14539e85256e6ac6e85c07f769f61`).
2. Input source binary SHA-256 and size.
3. Protection profile `.crproj` SHA-256 and size.
4. Composite SHA-256 hash of all C# source files (`.cs`, `.csproj`).
5. Output fixture SHA-256 and size.

---

## 4. Evidence Hierarchy & Proof Levels

To ensure scientific honesty and complete auditability, all claims in Unconfuser are backed by one of four tiers of proof:

1. **Unit Test Level**: Isolated component unit tests in `ConfuserExKillerRunner.Tests/` validating algorithms on synthesized ASTs or instruction sequences (e.g. `CleanerKillerTests`, `PredicateEvaluationTests`, `JobObjectTests`).
2. **Synthetic Fixture Level**: Full PE binaries generated by `benchmarks/FixtureGenerator/` targeting individual isolated protection patterns (e.g. `fixture_constants.dll`, `fixture_cflow.dll`, `fixture_edge_cases.dll`).
3. **Real Protector Fixture Level**: Full PE binaries compiled from clean C# source code and protected by authentic `Confuser.CLI.exe` v1.0.0 under verified profiles with cryptographic manifests.
4. **CI Automated Level**: Continuous integration in GitHub Actions (`.github/workflows/ci.yml`) executing all unit tests, benchmark scenarios, PowerShell verification harnesses, and pytest suites on clean Windows runners.
