# End-to-End Deobfuscation Benchmark Report

## Executive Summary

> [!IMPORTANT]
> **Terminology & Validation Scope:**
> - `SYNTHETIC_PASS`: ConfuserExKillerRunner recognizes and deobfuscates specific synthetic IL and metadata patterns generated via dnlib.
> - `SYNTHETIC_PARTIAL`: Output produced, execution succeeded with exit code 0 matching expected baseline, and audit clean, but specific documented transformations were unrecovered due to known ordering dependencies.
> - `SYNTHETIC_FAIL`: Deobfuscator crashed, structural verification explicitly failed, runtime failed, or output mismatched.
> - `UNVERIFIED`: Structural verification tool or required baseline was unavailable; output produced but unverified.
> - `REAL_PROTECTOR_PASS`: Reserved exclusively for fixtures produced by a pinned, identified build of the ConfuserEx toolchain that have passed structural, audit, and runtime tests.
> - `REAL_PROTECTOR_FAIL`: Protection or deobfuscation failed on a fixture produced by the pinned ConfuserEx toolchain.
> - `SKIPPED_TOOL_MISSING`: Pinned external protector CLI was not provisioned; explicitly skipped and never counted as passed.
> - **Execution Limits:** Process timeouts (30s deobfuscation, 5s runtime) serve as operational limits, not an operating-system-level sandbox.

- **Total Benchmark Cases:** 9
- **Synthetic Pattern Pass (`SYNTHETIC_PASS`):** 7
- **Synthetic Pattern Partial (`SYNTHETIC_PARTIAL`):** 1
- **Synthetic Pattern Fail (`SYNTHETIC_FAIL`):** 0
- **Unverified Cases (`UNVERIFIED`):** 0
- **Real Protector Confirmed (`REAL_PROTECTOR_PASS`):** 1
- **Real Protector Failed (`REAL_PROTECTOR_FAIL`):** 0
- **Skipped (Protector Missing):** 0

## Per-Case Benchmark Results

| Case / Protection Family | Input SHA256 | Output | Runner Exit | Runtime Exit | Audit | Behavior | Structural Assertions | Verdict |
|---|---|---|---|---|---|---|---|---|
| Constants (Strings & Numerics) | `382a453a` | Yes | 0 | 0 | CLEAN | Exact Match | Passed: string_constant_inlined(System.String), numeric_constant_inlined(System.Int32), numeric_constant_inlined(System.Int64), decrypter_calls_removed | **`SYNTHETIC_PASS`** |
| Control Flow (Dead Code & Junk Stripping) | `13076d4f` | Yes | 0 | 0 | CLEAN | Exact Match | Passed: deadcode_junk_pair_stripped, switch_dispatch_structure_preserved | **`SYNTHETIC_PASS`** |
| Reference & Method Call Proxies | `9a14f787` | Yes | 0 | 0 | CLEAN | Exact Match | Passed: proxy_call_rewritten_to_target, intermediate_proxy_call_removed, proxy_method_definition_pruned | **`SYNTHETIC_PASS`** |
| Encrypted Resources | `a6afaae0` | Yes | 0 | 0 | CLEAN | Exact Match | Passed: resource_manifest_names_matched, resource_byte_for_byte_exact_match | **`SYNTHETIC_PASS`** |
| Deflate Compressor Unpacker | `e3be7e23` | Yes | 0 | 0 | CLEAN | Exact Match | Passed: assembly_full_identity_matched_baseline, payload_types_entrypoint_and_required_resources_matched_baseline, assembly_simple_name_restored, all_payload_types_present, payload_embedded_resources_restored | **`SYNTHETIC_PASS`** |
| Anti-Tamper & Cleaner Hooks | `aba42f14` | Yes | 0 | 0 | CLEAN | Exact Match | Passed: cctor_hook_removed, protector_method_pruned | **`SYNTHETIC_PASS`** |
| Combined Multi-Protection | `d8f0de14` | Yes | 0 | 0 | CLEAN | Exact Match | Passed: proxies_inlined, cflow_deadcode_stripped, cctor_antitamper_hook_stripped<br>Unverified: constants_decrypted_and_inlined | **`SYNTHETIC_PARTIAL`** |
| Generics & Exception Edges | `a919c594` | Yes | 0 | 0 | CLEAN | Exact Match | Passed: generic_method_signature_intact, local_variables_structure_preserved, exception_handlers_try_and_handler_ranges_verified, baseline_exception_handlers_matched | **`SYNTHETIC_PASS`** |
| ConfuserEx yck1509/ConfuserEx v1.0.0 (commit 3c9c29d9daf2f1259edf69054c5693d5d225a980) (Constants, Ctrl Flow, Ref Proxy, Resources) | `fd8f0c53` | Yes | 0 | 0 | CLEAN | Exact Match | Passed: assembly_identity_preserved, types_intact, constants_decrypted, resources_extracted, module_initializer_clean | **`REAL_PROTECTOR_PASS`** |

## Detailed Structural Assertions & Findings

### 1. Constants (Strings & Numerics) (`SYNTHETIC_PASS`)
- **Verdict:** `SYNTHETIC_PASS` | **Audit Status:** `CLEAN` | **Runtime Behavior:** `Exact Match`
- **Verified Structural Transformations:** string_constant_inlined(System.String), numeric_constant_inlined(System.Int32), numeric_constant_inlined(System.Int64), decrypter_calls_removed
- **Verification Notes:** Exact string (System.String), integer (System.Int32), and long (System.Int64) constants recovered and inlined; exactly 3 constants decrypted.

### 2. Control Flow (Dead Code & Junk Stripping) (`SYNTHETIC_PASS`)
- **Verdict:** `SYNTHETIC_PASS` | **Audit Status:** `CLEAN` | **Runtime Behavior:** `Exact Match`
- **Verified Structural Transformations:** deadcode_junk_pair_stripped, switch_dispatch_structure_preserved
- **Verification Notes:** Dead-code junk pairs (ldc.i4 8888 + pop) stripped and switch dispatch structure preserved across all 4 switch cases.

### 3. Reference & Method Call Proxies (`SYNTHETIC_PASS`)
- **Verdict:** `SYNTHETIC_PASS` | **Audit Status:** `CLEAN` | **Runtime Behavior:** `Exact Match`
- **Verified Structural Transformations:** proxy_call_rewritten_to_target, intermediate_proxy_call_removed, proxy_method_definition_pruned
- **Verification Notes:** PrivateScope reference proxy method inlined, call site rewritten directly to target, and proxy definition pruned.

### 4. Encrypted Resources (`SYNTHETIC_PASS`)
- **Verdict:** `SYNTHETIC_PASS` | **Audit Status:** `CLEAN` | **Runtime Behavior:** `Exact Match`
- **Verified Structural Transformations:** resource_manifest_names_matched, resource_byte_for_byte_exact_match
- **Verification Notes:** Resource extracted from encrypted payload and re-embedded with exact byte-for-byte payload match and correct manifest name set.

### 5. Deflate Compressor Unpacker (`SYNTHETIC_PASS`)
- **Verdict:** `SYNTHETIC_PASS` | **Audit Status:** `CLEAN` | **Runtime Behavior:** `Exact Match`
- **Verified Structural Transformations:** assembly_full_identity_matched_baseline, payload_types_entrypoint_and_required_resources_matched_baseline, assembly_simple_name_restored, all_payload_types_present, payload_embedded_resources_restored
- **Verification Notes:** Deflate container unwrapped and verified against reference BenignSample.dll: 4-part assembly identity (Name, Version, Culture, PublicKeyToken), top-level type set (7 types), entry point, and required embedded resource byte-for-byte match.

### 6. Anti-Tamper & Cleaner Hooks (`SYNTHETIC_PASS`)
- **Verdict:** `SYNTHETIC_PASS` | **Audit Status:** `CLEAN` | **Runtime Behavior:** `Exact Match`
- **Verified Structural Transformations:** cctor_hook_removed, protector_method_pruned
- **Verification Notes:** CleanerKiller stripped module initializer hook from <Module>.cctor and pruned unused ConfuserAntiTamper method. (Tests module initializer cleanup; does not simulate native PE section decryption).

### 7. Combined Multi-Protection (`SYNTHETIC_PARTIAL`)
- **Verdict:** `SYNTHETIC_PARTIAL` | **Audit Status:** `CLEAN` | **Runtime Behavior:** `Exact Match`
- **Verified Structural Transformations:** proxies_inlined, cflow_deadcode_stripped, cctor_antitamper_hook_stripped
- **Unverified Transformations:** constants_decrypted_and_inlined
- **Verification Notes:** Partially transformed: Proxies, deadcode, and anti-tamper hooks stripped, but constant decryption was blocked by TypeInitializationException during Reflection module load prior to hook removal.

### 8. Generics & Exception Edges (`SYNTHETIC_PASS`)
- **Verdict:** `SYNTHETIC_PASS` | **Audit Status:** `CLEAN` | **Runtime Behavior:** `Exact Match`
- **Verified Structural Transformations:** generic_method_signature_intact, local_variables_structure_preserved, exception_handlers_try_and_handler_ranges_verified, baseline_exception_handlers_matched
- **Verification Notes:** Generic method signature (parameters, return type, generic constraints & special flags), local variables (count and types), and exception-handler try/handler ranges (including semantic TryStart/TryEnd, HandlerStart/HandlerEnd targets, and instruction bodies) verified against baseline assembly.

### 9. ConfuserEx yck1509/ConfuserEx v1.0.0 (commit 3c9c29d9daf2f1259edf69054c5693d5d225a980) (Constants, Ctrl Flow, Ref Proxy, Resources) (`REAL_PROTECTOR_PASS`)
- **Verdict:** `REAL_PROTECTOR_PASS` | **Audit Status:** `CLEAN` | **Runtime Behavior:** `Exact Match`
- **Verified Structural Transformations:** assembly_identity_preserved, types_intact, constants_decrypted, resources_extracted, module_initializer_clean
- **Verification Notes:** Real ConfuserEx CLI output verified for identity, types, decrypted constants, extracted resources, and clean module initializer.
