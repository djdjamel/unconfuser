# Real-Target Re-Evaluation Procedure

This document specifies the standard operating procedure for re-evaluating the real-world protected assembly `H:\Xpert.Common.BLL.dll` (or any equivalent commercial ConfuserEx protected target) using `ConfuserExKillerRunner`.

---

## 1. Background & Target Profile

- **Target Binary**: `H:\Xpert.Common.BLL.dll` (or local test clone)
- **Observed Protections**:
  - ConfuserEx Anti-Tamper (Normal Mode with section encryption)
  - Anti-Dump (corrupted COR20 header sizes and BSJB signatures)
  - Resources Protection (encrypted container stream resolved via runtime hook)
  - Constants Protection (dynamic decryption helpers and byte array initializers)
  - Control Flow Protection (mangled switch dispatch blocks and dead code)
  - Reference Proxy Protection (indirect delegate dispatch)
- **Previous Anomalies Observed & Resolved**:
  1. *Dynamic Execution Warning*: Spurious warning about fallback to static analysis when running with `--allow-execution`. (Fixed via isolated worker client pipeline).
  2. *Protection Matrix Status Priority*: Code protections (`Constants`, `Reference Proxy`) displaying `PartiallyProcessed` even when successfully resolved, or masking failure priority over `RequiresDynamic`. (Fixed via strict precedence ordering).
  3. *PEVerify Internal Crash `0x8013129d`*: External PEVerify crashing with internal CLR error `0x8013129d` or French locale equivalent (`Erreur interne fatale`), previously failing the pipeline or overwriting final outputs. (Fixed by mapping internal verifier errors to `INDETERMINATE`, writing `.unverified_candidate.dll`, never overwriting verified final files, and exiting with code `2`).
  4. *NetDetect Heuristic Score Shift*: Post-deobfuscation scan showing an indicator score increase (+5 / +55.6%). (Clarified: unpacking Anti-Tamper sections unpacks thousands of previously hidden method bodies, revealing internal ConfuserEx heuristic patterns to static scanners, not an engine regression).
  5. *Preserved Hooks in `<Module>.cctor`*: Ambiguous runtime hooks preserved for safety without explanation. (Fixed by tracking and documenting exact hook signatures in report warnings and limitations).

---

## 2. Prerequisites

1. **Operating System & Tooling**:
   - Windows 10/11 or Windows Server (x64).
   - .NET 8.0 SDK / Runtime installed.
   - .NET Framework 4.8 Developer Pack (for PEVerify toolchain access).
   - Python 3.8+ (for NetDetect pre/post triage scans).
2. **Environment Configuration**:
   - Set `NETDETECT_CLI_PATH` if `netdetect_cli.py` is outside repository root.
   - Optional: set `DE4DOT_PATH` to explicitly point to `de4dot-cex.exe`.

---

## 3. Execution Commands

### 3.1 Standard Automated Deobfuscation Run
To execute the complete deobfuscation pipeline with isolated dynamic execution and JSON audit generation:

```powershell
dotnet run --project ConfuserExKillerRunner/ConfuserExKillerRunner.csproj -c Release -f net8.0-windows -- `
  "H:\Xpert.Common.BLL.dll" `
  --allow-execution `
  --allow-target-deps `
  --worker-timeout 45000 `
  --report-json "H:\Xpert.Common.BLL_audit.json"
```

### 3.2 Safe Static Triage Run (Without Execution)
To perform pure static analysis, COR20 header repair, and triage inspection without executing target code:

```powershell
dotnet run --project ConfuserExKillerRunner/ConfuserExKillerRunner.csproj -c Release -f net8.0-windows -- `
  "H:\Xpert.Common.BLL.dll" `
  --report-json "H:\Xpert.Common.BLL_static_audit.json"
```

---

## 4. Verification & Validation Steps

Following pipeline execution, verify the output against the following criteria:

### 4.1 Exit Code Interpretation
- **Exit Code `0` (`SUCCESS`)**:
  - All protections resolved.
  - Structural audit PASSED.
  - External IL verification PASSED.
  - Candidate assembly promoted to `H:\Xpert.Common.BLL_final.dll`.
- **Exit Code `2` (`PARTIAL_SUCCESS` or `INDETERMINATE`)**:
  - `INDETERMINATE`: External IL verifier produced an internal tool failure (e.g., `0x8013129d` or timeout).
    - **Crucial Rule**: The candidate assembly is saved as `H:\Xpert.Common.BLL.unverified_candidate.dll`.
    - Any existing, previously verified `H:\Xpert.Common.BLL_final.dll` is **PRESERVED AND NEVER OVERWRITTEN**.
  - `PARTIAL_SUCCESS`: Candidate promoted, but some unsupported or partially evaluated protections remain (e.g. JIT hooks or partial constants).
- **Exit Code `1` (`FAILED`)**:
  - Structural defect detected (e.g., broken branches, invalid opcodes, stack underflow).
  - Candidate discarded; no corrupt binary written.

### 4.2 NetDetect Triage Inspection
Examine the console output and `report.NetDetect` in the JSON report:
- Pre-Scan Obfuscation Score: typically ~9 (primary detector: ConfuserEx).
- Post-Scan Obfuscation Score: typically ~14 (+5 / +55.6%).
- Confirm the interpretation note:
  > `"Heuristic score increase (+5) reflects internal signatures newly exposed after unpacking outer protection layers (e.g. Anti-Tamper/Compressor), not an engine regression."`
- Confirm that `ResolvedSignatures` lists the stripped outer protectors (e.g., `Anti-Tamper`, `Compressor`).

### 4.3 Protection Matrix Validation
Examine the `ConfuserEx Protection Coverage & Support Matrix`:
- **Anti-Tamper**: `RESOLVED` (Normal Mode decrypted via isolated worker).
- **Anti-Dump**: `RESOLVED` (COR20 header cb normalized to 72, MetaData RVA and BSJB restored).
- **Constants**: `RESOLVED` or `PARTIALLY_PROCESSED` (with exact count of decrypted constants and unresolved references).
- **Resources**: `RESOLVED` (Decrypted resource container extracted and re-embedded into manifest).
- **Control Flow**: `RESOLVED` (Switch statements flattened, dead code removed).
- **Reference Proxy**: `RESOLVED` (Proxy delegates inlined).

### 4.4 Preserved Hooks in `<Module>.cctor`
Examine the `[*] Preserved Hooks in <Module>.cctor` console section and `report.KnownLimitations` in the JSON report:
- Verify that any remaining initializer calls are documented with reasons (e.g., non-void argument consumer, user class initializer, or unconfirmed Anti-Tamper hook).
- Ensure no unresolved decrypter hooks were removed prematurely, preventing runtime `NullReferenceException` or `TypeInitializationException`.

### 4.5 Execution Timing Reconciliation
Review the `PIPELINE STAGE TIMINGS` table:
- Verify that every stage (`Stage0_Compressor`, `Stage1_AntiTamper_HeaderRepair`, `Stage2_Constants_Resources_Proxies`, `Stage3_CleanerHooks`, `Stage4_ControlFlow_DeadCode`, `Stage5_ExternalDeobfuscator`, `Stage6_FinalCleanup`, `Stage7_QualityAudit`, `PostScan_NetDetect`) has a single, unique line with non-zero elapsed milliseconds.
- Verify that `Total Pipeline Elapsed` accurately reflects the entire execution duration.
