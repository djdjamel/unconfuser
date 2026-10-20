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
| **Anti-Debug** | Win32 API & Managed Checks | `SupportedStatic` | `SupportedStatic` | `CleanerKiller` | Strips `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, and startup kill loops from `<Module>..cctor`. |
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
| **Name Protection** | Symbol Renaming | `PartiallyProcessed` | `PartiallyProcessed` | `de4dot-cex` / dnlib | Irreversible without original symbol mapping; unprintable Unicode identifiers normalized. |

---

## 3. Operational Modes & Safety Architecture

### 3.1 Static-Only Mode (Default)
When invoked without `--allow-execution`:
- Purely analyzes PE structures, ECMA-335 metadata, and CIL bytecode.
- Never executes any byte of target code.
- Protections requiring dynamic evaluation (Anti-Tamper section decryption, dynamic resource decryption, dynamic constants) are skipped.
- Protector hooks and decrypters are safely preserved to avoid producing broken or non-functional assemblies.
- The output assembly will be flagged as:
  ```
  Overall Verdict: PARTIALLY DEOBFUSCATED (Dynamic Execution Required)
  ```

### 3.2 Dynamic Execution Mode (`--allow-execution`)
When invoked with `--allow-execution`:
- Protections requiring runtime resolution are delegated to isolated child worker processes (`WorkerHost`).
- Strict security controls:
  - Timeouts (enforced via child process monitoring).
  - Isolated memory space (preventing host process poisoning or crashes from hostile protector traps).
  - Structural audit validation before any candidate assembly is promoted to the final destination.

### 3.3 Handling of Unsupported Modes
ConfuserEx includes several native x86 machine-code protections and JIT compile-time hooks:
- **Anti-Tamper JIT Mode:** Hooks `compileMethod` inside `clr.dll` / `mscorwks.dll`.
- **x86 Constants:** Uses native machine-code thunks embedded in unmanaged PE sections.
- **x86 Control Flow:** Embeds native machine code transitions.

**Unconfuser Guarantees:**
1. Detection and explicit warning in the console output and matrix report.
2. The assembly is not corrupted; unsupported methods and hooks are retained.
3. The overall verdict accurately reflects partial completion (`PARTIALLY DEOBFUSCATED (Unsupported Modes Detected)`).
