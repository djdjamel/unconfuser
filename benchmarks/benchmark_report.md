# End-to-End Deobfuscation Benchmark Report

## Executive Summary

> [!IMPORTANT]
> **Terminology & Validation Scope:**
> - `SYNTHETIC_PASS`: Demonstrates that ConfuserExKillerRunner recognizes and deobfuscates specific synthetic IL and metadata patterns generated via dnlib.
> - `SYNTHETIC_PARTIAL`: Output produced and clean audit, but specific transformations were unrecovered or blocked by ordering dependencies.
> - `REAL_PROTECTOR_PASS`: Reserved exclusively for fixtures produced by a pinned, identified build of the ConfuserEx toolchain.
> - `SKIPPED_TOOL_MISSING`: Specific external protector CLI was not provisioned; explicitly skipped and never counted as passed.
> - **Execution Limits:** Process timeouts (30s deobfuscation, 5s runtime) serve as operational limits, not an operating-system-level sandbox.

- **Total Benchmark Cases:** 9
- **Synthetic Pattern Pass (`SYNTHETIC_PASS`):** 7
- **Synthetic Pattern Partial (`SYNTHETIC_PARTIAL`):** 1
- **Synthetic Pattern Fail (`SYNTHETIC_FAIL`):** 0
- **Real Protector Confirmed (`REAL_PROTECTOR_PASS`):** 0
- **Skipped (Protector Missing):** 1

## Per-Case Benchmark Results

| Case / Protection Family | Input SHA256 | Output | Exit Code | Audit | Behavior | Structural Assertions | Verdict |
|---|---|---|---|---|---|---|---|
| Constants (Strings & Numerics) | `cdc4431c` | Yes | 0 | CLEAN | Exact Match | Passed: string_constant_inlined, numeric_constant_inlined, decrypter_calls_removed | **`SYNTHETIC_PASS`** |
| Control Flow & Trampolines | `a1600389` | Yes | 0 | CLEAN | Exact Match | Passed: deadcode_junk_pair_stripped | **`SYNTHETIC_PASS`** |
| Reference & Delegate Proxies | `f05717ad` | Yes | 0 | CLEAN | Exact Match | Passed: proxy_call_rewritten_to_target, intermediate_proxy_call_removed | **`SYNTHETIC_PASS`** |
| Encrypted Resources | `33d980c8` | Yes | 0 | CLEAN | Exact Match | Passed: resource_re_embedded_exact_bytes_match | **`SYNTHETIC_PASS`** |
| Deflate Compressor Unpacker | `f7cd7061` | Yes | 0 | CLEAN | Exact Match | Passed: deflate_container_unwrapped_to_payload | **`SYNTHETIC_PASS`** |
| Anti-Tamper & Cleaner Hooks | `b88b1f9c` | Yes | 0 | CLEAN | Exact Match | Passed: cctor_hook_removed, protector_method_pruned | **`SYNTHETIC_PASS`** |
| Combined Multi-Protection | `e11ee806` | Yes | 0 | CLEAN | Exact Match | Passed: proxies_inlined, cflow_deadcode_stripped, cctor_antitamper_hook_stripped<br>Unverified: constants_decrypted_and_inlined | **`SYNTHETIC_PARTIAL`** |
| Generics & Exception Edges | `c2003b93` | Yes | 0 | CLEAN | Exact Match | Passed: exception_handlers_preserved, local_variables_preserved | **`SYNTHETIC_PASS`** |
| Full ConfuserEx CLI Preset (v1.0.0 Pinned) | `N/A` | No | - | SKIPPED | Skipped | Confuser.CLI.exe protector unavailable in environment (SKIPPED) | **`SKIPPED_TOOL_MISSING`** |

## Detailed Structural Assertions & Findings

### 1. Constants (Strings & Numerics) (`SYNTHETIC_PASS`)
- **Assertions:** `GetStringConstant` contains `ldstr` with exact expected secret string; `GetNumericConstant1` contains `ldc.i4` with integer 133742; call sites to `<Module>.Decrypter<T>` completely eliminated.
- **Status:** Fully verified at AST level and runtime behavior.

### 2. Control Flow & Trampolines (`SYNTHETIC_PASS`)
- **Assertions:** Dummy stack-neutral junk pairs (`ldc.i4 8888` + `pop`) stripped from `ComputeSwitch`; branch evaluation preserved.
- **Status:** Fully verified at AST level and runtime behavior.

### 3. Reference & Delegate Proxies (`SYNTHETIC_PASS`)
- **Assertions:** `ExecuteProxy` rewritten to directly call `AddProxyTarget`; intermediate `PrivateScope` proxy call eliminated.
- **Status:** Fully verified at AST level and runtime behavior.

### 4. Encrypted Resources (`SYNTHETIC_PASS`)
- **Assertions:** Decrypted resource module extracted; `BenignSample.Greeting.txt` re-embedded into manifest; exact byte comparison matches original UTF-8 payload.
- **Status:** Fully verified at AST level and runtime behavior.

### 5. Deflate Compressor Unpacker (`SYNTHETIC_PASS`)
- **Assertions:** Container stub unwrapped; target assembly identity restored from `CompressorStubAsm` back to `BenignSample`; types intact.
- **Status:** Fully verified at AST level and runtime behavior.

### 6. Anti-Tamper & Cleaner Hooks (`SYNTHETIC_PASS`)
- **Assertions:** Hook invocation removed from `<Module>.cctor`; protector method unreferenced.
- **Classification Note:** Confirmed at hook-stripping level. Does not claim raw encrypted PE section decryption.

### 7. Combined Multi-Protection (`SYNTHETIC_PARTIAL`)
- **Verified Transformations:** Proxies inlined, deadcode stripped, anti-tamper hook stripped from `<Module>.cctor`.
- **Unverified Transformation:** Constant decryption was **NOT** completed.
- **Root Cause Discovered by Benchmark:** When Anti-Tamper installs an unmanaged hook into `<Module>.cctor`, loading the module into Reflection causes `<Module>.cctor` to fault with `TypeInitializationException`. This fault prevents downstream `ConstantKiller` from executing `<Module>.Decrypter<T>`, leaving constant calls unrewritten. This explicitly exposes the ordering dependency bottleneck.

### 8. Generics & Exception Edges (`SYNTHETIC_PASS`)
- **Assertions:** Generic parameters, local variables, and nested `try-catch-finally` exception handlers preserved without corruption.
- **Status:** Fully verified at AST level and runtime behavior.

### 9. Real ConfuserEx CLI Integration (`SKIPPED_TOOL_MISSING`)
- **Status:** Skipped because `Confuser.CLI.exe` was not provisioned in `tools/ConfuserEx/` or `CONFUSEREX_PATH`. Never falsely claimed as passed.
