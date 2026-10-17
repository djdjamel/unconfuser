# End-to-End Deobfuscation Benchmark Report

## Executive Summary

> [!IMPORTANT]
> **Terminology & Validation Scope:**
> - `SYNTHETIC_PASS`: ConfuserExKillerRunner recognizes and deobfuscates specific synthetic IL and metadata patterns generated via dnlib.
> - `SYNTHETIC_PARTIAL`: Output produced, execution succeeded with exit code 0 matching expected baseline, and audit clean, but specific documented transformations were unrecovered due to known ordering dependencies.
> - `SYNTHETIC_FAIL`: Deobfuscator crashed, structural verification explicitly failed, runtime failed, or output mismatched.
> - `UNVERIFIED`: Structural verification tool was unavailable; output produced but unverifiable at AST level.
> - `REAL_PROTECTOR_PASS`: Reserved exclusively for fixtures produced by a pinned, identified build of the ConfuserEx toolchain.
> - `SKIPPED_TOOL_MISSING`: Specific external protector CLI was not provisioned; explicitly skipped and never counted as passed.
> - **Execution Limits:** Process timeouts (30s deobfuscation, 5s runtime) serve as operational limits, not an operating-system-level sandbox.

- **Total Benchmark Cases:** 9
- **Synthetic Pattern Pass (`SYNTHETIC_PASS`):** 7
- **Synthetic Pattern Partial (`SYNTHETIC_PARTIAL`):** 1
- **Synthetic Pattern Fail (`SYNTHETIC_FAIL`):** 0
- **Unverified Cases (`UNVERIFIED`):** 0
- **Real Protector Confirmed (`REAL_PROTECTOR_PASS`):** 0
- **Real Protector Failed (`REAL_PROTECTOR_FAIL`):** 0
- **Skipped (Protector Missing):** 1

## Per-Case Benchmark Results

| Case / Protection Family | Input SHA256 | Output | Runner Exit | Runtime Exit | Audit | Behavior | Structural Assertions | Verdict |
|---|---|---|---|---|---|---|---|---|
| Constants (Strings & Numerics) | `1909f045` | Yes | 0 | 0 | CLEAN | Exact Match | Passed: string_constant_inlined(System.String), numeric_constant_inlined(System.Int32), numeric_constant_inlined(System.Int64), decrypter_calls_removed | **`SYNTHETIC_PASS`** |
| Control Flow & Trampolines | `6855a063` | Yes | 0 | 0 | CLEAN | Exact Match | Passed: deadcode_junk_pair_stripped, control_flow_structure_preserved | **`SYNTHETIC_PASS`** |
| Reference & Method Call Proxies | `6436e19e` | Yes | 0 | 0 | CLEAN | Exact Match | Passed: proxy_call_rewritten_to_target, intermediate_proxy_call_removed, proxy_method_definition_pruned | **`SYNTHETIC_PASS`** |
| Encrypted Resources | `309b93ca` | Yes | 0 | 0 | CLEAN | Exact Match | Passed: resource_manifest_names_matched, resource_byte_for_byte_exact_match | **`SYNTHETIC_PASS`** |
| Deflate Compressor Unpacker | `f973c252` | Yes | 0 | 0 | CLEAN | Exact Match | Passed: assembly_identity_restored_to_payload, all_payload_types_present, payload_embedded_resources_restored | **`SYNTHETIC_PASS`** |
| Anti-Tamper & Cleaner Hooks | `e83328d6` | Yes | 0 | 0 | CLEAN | Exact Match | Passed: cctor_hook_removed, protector_method_pruned | **`SYNTHETIC_PASS`** |
| Combined Multi-Protection | `965cf44c` | Yes | 0 | 0 | CLEAN | Exact Match | Passed: proxies_inlined, cflow_deadcode_stripped, cctor_antitamper_hook_stripped<br>Unverified: constants_decrypted_and_inlined | **`SYNTHETIC_PARTIAL`** |
| Generics & Exception Edges | `9f188ac3` | Yes | 0 | 0 | CLEAN | Exact Match | Passed: generic_method_signature_intact, local_variables_structure_preserved, exception_handlers_structure_preserved | **`SYNTHETIC_PASS`** |
| Full ConfuserEx CLI Preset (v1.0.0 Pinned) | `N/A` | No | - | - | SKIPPED | Skipped | Confuser.CLI.exe (pinned ConfuserEx v1.0.0) not found in tools/ConfuserEx or CONFUSEREX_PATH. | **`SKIPPED_TOOL_MISSING`** |

## Detailed Structural Assertions & Findings

### 1. Constants (Strings & Numerics) (`SYNTHETIC_PASS`)
- **Coverage:** `System.String`, `System.Int32`, `System.Int64`.
- **Assertions:** `GetStringConstant` contains exact string; `GetNumericConstant1` contains exact int32 (133742); `GetNumericConstant2` contains exact int64 (9223372036854775800L); exactly 3 constants decrypted; call sites to `<Module>.Decrypter<T>` eliminated.
- **Status:** Fully verified at AST level and runtime behavior.

### 2. Control Flow & Trampolines (`SYNTHETIC_PASS`)
- **Assertions:** Dummy stack-neutral junk pairs (`ldc.i4 8888` + `pop`) stripped from `ComputeSwitch`; branch evaluation preserved.
- **Status:** Fully verified at AST level and runtime behavior.

### 3. Reference & Method Call Proxies (`SYNTHETIC_PASS`)
- **Assertions:** `ExecuteProxy` rewritten to directly call `AddProxyTarget`; intermediate `PrivateScope` proxy call eliminated; proxy method definition pruned.
- **Status:** Fully verified at AST level and runtime behavior.

### 4. Encrypted Resources (`SYNTHETIC_PASS`)
- **Assertions:** Decrypted resource module extracted; manifest resource names match exactly; `BenignSample.Greeting.txt` re-embedded with exact byte-for-byte comparison (no `.Trim()`).
- **Status:** Fully verified at AST level and runtime behavior.

### 5. Deflate Compressor Unpacker (`SYNTHETIC_PASS`)
- **Assertions:** Container stub unwrapped; target assembly identity restored from `CompressorStubAsm` back to `BenignSample`; full type set and embedded resources verified against known payload assembly.
- **Status:** Fully verified at AST level and runtime behavior.

### 6. Anti-Tamper & Cleaner Hooks (`SYNTHETIC_PASS`)
- **Assertions:** Module initializer hook removed from `<Module>.cctor`; unused `ConfuserAntiTamper` method pruned by `CleanerKiller`.
- **Scope Clarification:** Verifies `CleanerKiller` initializer stripping and method pruning. Does not simulate or claim raw native PE section decryption of ConfuserEx native anti-tamper runtime.

### 7. Combined Multi-Protection (`SYNTHETIC_PARTIAL`)
- **Verified Transformations:** Proxies inlined, deadcode stripped, anti-tamper hook stripped from `<Module>.cctor`.
- **Unverified Transformation:** Constant decryption was **NOT** completed.
- **Documented Limitation:** In this synthetic fixture, the module initializer hook causes `TypeInitializationException` when loaded into Reflection by `ConstantKiller`. This blocks constant decryption even though proxy inlining, dead code stripping, and hook removal succeed. Runtime execution exits with code 0 and matches baseline.

### 8. Generics & Exception Edges (`SYNTHETIC_PASS`)
- **Assertions:** Generic method signature `Process<U>`, local variables (3+), and nested `try-catch-finally` exception handlers structure verified against known baseline.
- **Status:** Fully verified at AST level and runtime behavior.

### 9. Real ConfuserEx CLI Integration (`SKIPPED_TOOL_MISSING`)
- **Status:** Explicitly tracked as `SKIPPED_TOOL_MISSING` when `Confuser.CLI.exe` (pinned ConfuserEx v1.0.0) is not provisioned in `tools/ConfuserEx/` or `CONFUSEREX_PATH`.
