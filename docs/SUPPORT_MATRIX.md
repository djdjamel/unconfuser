# ConfuserEx Protection Coverage & Support Matrix

This document provides a detailed, authoritative breakdown of ConfuserEx 1.0.0 (and common forks) protection mechanisms, their support status within **ConfuserExKillerRunner** (`unconfuser`), operational requirements (static vs. dynamic execution), and behavior when encountering unsupported or partially processed variants.

---

## 1. Support Status Definitions

Every ConfuserEx protection is classified under one of the following formal statuses:

| Status | Definition | CLI / Report Indicator |
| :--- | :--- | :--- |
| **Not Detected** | The protection markers, signatures, or IL patterns were not found in the target assembly. | `N/A` |
| **Supported (Static)** | The protection can be completely reversed statically using ECMA-335 / PE analysis without executing any target code. | `Clean / Normalized / Stripped` |
| **Requires Dynamic Execution** | Reversing this protection requires running the assembly's isolated decrypter routines (`--allow-execution`). In static mode, hooks are preserved. | `Skipped (Static Mode)` |
| **Verified on Real Fixture** | The protection was reversed, transformed, and validated against authentic ConfuserEx 1.0.0 binaries and dnlib structural integrity checks. | `Resolved / Decrypted / Repaired` |
| **Partially Processed** | Only a subset of references or patterns could be safely resolved. Unresolved elements are kept untouched to prevent corrupting IL semantics. | `Partial / Retained` |
| **Unsupported** | The protection technique (e.g. native x86 machine code or JIT compiler hooking) cannot be executed or reversed safely. The assembly is left untouched. | `Unsupported (Preserved)` |

---

## 2. Comprehensive Protection Support Matrix

| Protection Family | Mode / Variant | Static Mode (`default`) | Dynamic Mode (`--allow-execution`) | Responsible Engine Component | Notes & Limitations |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Anti-Tamper** | Normal Mode (Section Encryption) | `RequiresDynamicExecution` | `VerifiedOnRealFixture` | `AntiTamperKiller` / Isolated Worker | Section diffing against memory image. Requires `--allow-execution` to decrypt `.text` methods. |
| **Anti-Tamper** | JIT Mode (`compileMethod` Hook) | `Unsupported` | `Unsupported` | `AntiTamperKiller` (Detection Only) | Detected with warning; non-destructive fallback preserves original assembly. |
| **Anti-Dump** | PE Header Scrubbing & BSJB Erasure | `VerifiedOnRealFixture` | `VerifiedOnRealFixture` | `Cor20Repair` / `PEUtils` | Reconstructs COR20 header size (72), MetaData RVA, and BSJB magic from intact on-disk PE reference. |
| **Anti-Debug** | Managed Watchdog & Win32 P/Invoke | `SupportedStatic` | `SupportedStatic` | `CleanerKiller` | Strips `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, and startup kill loops from `<Module>..cctor`. |
| **Anti-ILDasm** | `SuppressIldasmAttribute` | `SupportedStatic` | `SupportedStatic` | `CleanerKiller` / dnlib Writer | Strips assembly attribute suppressing disassemblers. |
| **Invalid Metadata** | Mangled Tables & Stream Headers | `SupportedStatic` | `SupportedStatic` | `PEInfo` / dnlib Writer | Metadata tables and stream schemas normalized during dnlib reconstruction. |
| **Constants** | Normal Mode (Encrypted String / Array Buffer) | `VerifiedOnRealFixture` | `VerifiedOnRealFixture` | `ConstantKiller` / `KeyEvaluation` | Static evaluation with stack emulation for 11 primitive array types and string decrypters. |
| **Constants** | Dynamic Mode (Runtime Key Mutation) | `RequiresDynamicExecution` | `VerifiedOnRealFixture` | `ConstantKiller` / Isolated Worker | Resolves dynamic constant decryptor calls via isolated subprocess execution. |
| **Constants** | x86 Mode (Native Machine Code Decryptor) | `Unsupported` | `Unsupported` | `ConstantKiller` (Detection Only) | Native x86 machine-code stubs are not emulated. Preserved without corruption. |
| **Control Flow** | Switch Flattening (State Machine) | `VerifiedOnRealFixture` | `VerifiedOnRealFixture` | `SwitchKillerImpl` | Resolves arithmetic dispatcher loops, restoring linear control-flow blocks. |
| **Control Flow** | Jump Mangler & Junk Code (Dead Branches) | `VerifiedOnRealFixture` | `VerifiedOnRealFixture` | `PredicateKiller` / `DeadCodeStripper` | Folds algebraic identities, collapses jump trampolines, and removes dead code pairs. |
| **Control Flow** | x86 Mode (Native Control Thunks) | `Unsupported` | `Unsupported` | `SwitchKiller` (Detection Only) | Native x86 dispatcher thunks are not supported. Preserved without corruption. |
| **Reference Proxies** | Mild Mode (Direct Call Indirection) | `VerifiedOnRealFixture` | `VerifiedOnRealFixture` | `ProxyKillerImpl` | Inlines direct static proxy call stubs to target methods. |
| **Reference Proxies** | Strong Mode (Dynamic Delegates & Indirect Dispatches) | `VerifiedOnRealFixture` | `VerifiedOnRealFixture` | `ProxyKillerImpl` | Resolves delegate invoke targets and replaces proxy dispatch with target member references. |
| **Resources** | Normal & Dynamic Mode | `RequiresDynamicExecution` | `VerifiedOnRealFixture` | `ResourceKiller` / Isolated Worker | Extracts encrypted resources, re-embeds into cleartext manifest, and strips runtime `ResourceResolve` hooks. |
| **Compressor** | Deflate Packer / Embedded Assemblies | `VerifiedOnRealFixture` | `VerifiedOnRealFixture` | `CompressorUnpacker` | Detects packaging stub, decrypts and deflates embedded payload, and validates output PE. |
| **Static Constructors** | `<Module>..cctor` Sanitization | `SupportedStatic` | `VerifiedOnRealFixture` | `CleanerKiller` | Atomic hook removal with rollback on structural audit failure; preserves application logic. |
| **WinForms Resources** | ComponentResourceManager Compatibility | `SupportedStatic` | `VerifiedOnRealFixture` | `QualityAuditor` / `SemanticRenamer` | Validates resource streams against `ComponentResourceManager` call sites; bidirectional disambiguation. |
| **Semantic Renaming** | Reflection-Preserving Symbol Renaming | `SupportedStatic` | `SupportedStatic` | `SemanticRenamer` | Protects public API, string literals, reflection targets, and resource-linked names with confidence scoring. |

---

## 3. Detailed Category Breakdown

### 3.1 Constants Protection
- **Transformations Handled:** Static constant array extraction, string decryption routines, stack-evaluated arithmetic keys, and dynamic worker key execution.
- **Prerequisites:** Clean PE metadata; unencrypted IL body or decrypted Anti-Tamper payload; for dynamic mode, valid isolated worker environment.
- **Known Limitations:** Native x86 decryption thunks embedded in unmanaged sections cannot be emulated; multi-protection hook ordering bottlenecks are eliminated via pre-cleaning passes on module initializers.
- **Regression Tests:** `ConstantKillerTests.cs`, `tests/test_deobfuscation_benchmark.py::test_deobfuscation_synthetic_pipeline_case[Constants]`.
- **Fixtures Used:** `fixture_constants.dll`, `benchmarks/fixtures/real_confuserex/BenignSample.exe`.
- **Verified Result:** 25/25 constants decrypted on real ConfuserEx fixture; 3/3 decrypted on synthetic fixture.
- **Unsupported Cases:** Native x86 thunks.

### 3.2 Control Flow Protection
- **Transformations Handled:** State machine flattening (`SwitchKiller`), dead unconditional jump chains, trampolines, algebraic constant folding (`PredicateKiller`), and dead code pair stripping.
- **Prerequisites:** Valid exception handler boundaries (`TryStart`, `TryEnd`, `HandlerStart`, `HandlerEnd`).
- **Known Limitations:** Complex state machines with non-deterministic external predicates or native x86 dispatch loops are left intact.
- **Regression Tests:** `SwitchKillerTests.cs`, `DeadCodeStripperTests.cs`, `tests/test_deobfuscation_benchmark.py::test_deobfuscation_synthetic_pipeline_case[Control Flow]`.
- **Fixtures Used:** `fixture_cflow.dll`, `benchmarks/fixtures/real_confuserex/BenignSample.exe`.
- **Verified Result:** 334/334 switches resolved on real ConfuserEx fixture; dead code pairs eliminated.
- **Unsupported Cases:** Native x86 control flow dispatchers.

### 3.3 Reference Proxies
- **Transformations Handled:** Mild static proxies (direct method calls), strong dynamic delegates (`newobj` + invoke), and multi-argument proxy forwarding.
- **Prerequisites:** Proxy call sites must match candidate signature; target method must be resolvable.
- **Known Limitations:** Proxies targeting variadic methods or complex generic constraints with unresolved type parameters are preserved to avoid invalid IL.
- **Regression Tests:** `ProxyKillerTests.cs` (13 tests including unsupported signature tests), `tests/test_deobfuscation_benchmark.py::test_deobfuscation_synthetic_pipeline_case[Reference & Method Call Proxies]`.
- **Fixtures Used:** `fixture_proxies.dll`, `benchmarks/fixtures/real_confuserex/BenignSample.exe`.
- **Verified Result:** 15/15 proxies inlined on real ConfuserEx fixture; 1/1 on synthetic fixture.
- **Unsupported Cases:** Proxies containing branching or exception handling within proxy body.

### 3.4 Anti-Dump Protection
- **Transformations Handled:** Restoration of CLR COR20 header size (72 bytes), MetaData RVA normalization, and BSJB metadata header recovery from intact on-disk PE image.
- **Prerequisites:** Target binary must have a readable DOS and NT PE header structure.
- **Known Limitations:** In-memory dumps where PE headers have been completely zeroed without any recoverable metadata stream references require manual offset reconstruction.
- **Regression Tests:** `Cor20RepairTests.cs`, `PEUtilsTests.cs`.
- **Fixtures Used:** Real ConfuserEx Anti-Dump samples.
- **Verified Result:** Header reconstructed and validated by dnlib `ModuleDefMD.Load`.

### 3.5 Anti-Tamper Protection
- **Transformations Handled:** Section encryption recovery via isolated memory dump comparison; module initializer hook removal from `<Module>..cctor`.
- **Prerequisites:** Dynamic execution permitted (`--allow-execution`) for normal section decryption.
- **Known Limitations:** JIT Mode (`compileMethod` native CLR hook) is detected and reported as unsupported; original assembly is preserved without modification.
- **Regression Tests:** `AntiTamperKillerTests.cs`, `tests/test_deobfuscation_benchmark.py::test_deobfuscation_synthetic_pipeline_case[Anti-Tamper & Cleaner Hooks]`.
- **Fixtures Used:** `fixture_antitamper.dll`, real ConfuserEx Anti-Tamper samples.
- **Verified Result:** Initializer hooks stripped; JIT mode correctly detected and flagged.

### 3.6 Anti-Debug Protection
- **Transformations Handled:** Neutralization of Win32 `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`, and watchdog thread loops terminating via `FailFast`, `ExitProcess`, or `Kill`.
- **Prerequisites:** Hook method must have 0 parameters, return void, contain no pointer writes or cipher arithmetic, and exhibit positive proof of termination or watchdog creation.
- **Known Limitations:** Application diagnostics (logging methods checking `Debugger.IsAttached` without crashing) are retained as non-protector application logic.
- **Regression Tests:** `CleanerKillerTests.cs` (91 unit tests covering positive detection and false-positive protection).
- **Fixtures Used:** Real ConfuserEx Anti-Debug binaries, synthetic diagnostic stubs.
- **Verified Result:** ConfuserEx termination hooks stripped; application diagnostic methods strictly preserved.

### 3.7 Static Constructors (`<Module>..cctor`)
- **Transformations Handled:** Identification and removal of protector initialization calls; NOPing of consumer `pop` instructions; validation of structural integrity with atomic rollback on failure.
- **Prerequisites:** Valid CIL body in `<Module>..cctor`.
- **Known Limitations:** Unresolved module initializer calls or ambiguous P/Invoke calls without positive protector proof are preserved.
- **Regression Tests:** `CleanerKillerTests.cs`, `SanitizerModuleConstructorTests.cs`.
- **Fixtures Used:** Synthetic cctor fixtures, `benchmarks/fixtures/real_confuserex/BenignSample.exe`.
- **Verified Result:** All protector initializers safely stripped with structural audit confirmation.

### 3.8 WinForms Resources
- **Transformations Handled:** Detection of `ComponentResourceManager(typeof(T))` and `ResourceManager(string)` patterns; validation of manifest `.resources` stream integrity; two-way disambiguation to prevent corrupting Form resource bindings.
- **Prerequisites:** Embedded resource streams with valid `0xBEEFCACE` headers.
- **Known Limitations:** Intentionally empty resources (0 entries) are recognized as valid; corrupt or missing streams prevent candidate promotion.
- **Regression Tests:** `QualityAuditorTests.cs`, `SemanticRenamerTests.cs`, `tests/test_verify_deobfuscated_binary.py`.
- **Fixtures Used:** Real WinForms application assemblies (`WinFormsSample.dll`), `missing_resource_form.dll`.
- **Verified Result:** Missing resource streams detected; valid resources bound without `MissingManifestResourceException`.

### 3.9 Semantic Renaming
- **Transformations Handled:** Heuristic symbol recovery for Form controls and models; reflection reference mapping protecting public API, `Type.GetType`, `GetMethod`, and string literal reflection lookups; confidence scoring (`StrongReference`, `HighConfidence`, `Heuristic`, `Ambiguous`).
- **Prerequisites:** Symbol references must be unambiguous.
- **Known Limitations:** Ambiguous symbols with equal-scoring candidates are preserved with their original names to prevent runtime reflection breakage.
- **Regression Tests:** `SemanticRenamerTests.cs` (all 52 tests passing).
- **Fixtures Used:** Real deobfuscated assemblies, synthetic reflection fixtures.
- **Verified Result:** Form fields, event handlers, and models renamed without breaking dynamic reflection calls.

---

## 4. Hierarchy of Evidence & Verification Levels

To ensure complete transparency and prevent misleading claims, all verification findings are categorized by their formal level of proof:

1. **Level 1 — Static Code Inspection:** Algorithmic verification of code paths, bounds, and preconditions.
2. **Level 2 — Local Unit Tests:** Deterministic unit tests targeting individual components (`CleanerKillerTests`, `ProxyKillerTests`, `SemanticRenamerTests`, `QualityAuditorTests`).
3. **Level 3 — Local Integration Tests:** End-to-end deobfuscation and verification of synthetic and real fixtures (`run_benchmark.py`, `Verify-DeobfuscatedBinary.ps1`).
4. **Level 4 — Confirmed CI (GitHub Actions):** Execution within the automated workflow on clean virtual machine runners (`.github/workflows/ci.yml`).
5. **Level 5 — Authentic Protectors Fixture:** Verification against authentic ConfuserEx 1.0.0 binaries provisioned via pinned cryptographic SHA-256 (`prepare_real_fixture.py`).
6. **Level 6 — Real-World Application Assemblies:** Validation against real-world obfuscated application assemblies.

> [!NOTE]
> CI workflows run on benign, source-built fixtures and authentic ConfuserEx binaries generated during the run. Commercial/proprietary application assemblies are validated locally and are never embedded into public CI runs without licensing authorization.
