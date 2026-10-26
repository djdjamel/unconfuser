# NetDetect: Advanced .NET Obfuscator, Protector, Packer & Virtualizer Detection Engine

**NetDetect** is an enterprise-grade static analysis, triage, and detection engine designed for reverse engineers, malware analysts, and security researchers. It combines deep PE header analysis, ECMA-335 metadata parsing, CIL instruction disassembly, behavioral API pattern detection, bigram wordlikeness analysis, and a 3-tier weighted signature engine into a unified tool.

---

## Key Capabilities & Features

### 1. Multi-Layer Protection Architecture
NetDetect identifies tools across distinct functional layers, computing an execution stack:
```
Packer (e.g., UPX / Enigma) -> Bundler (e.g., Costura / Single-File) -> Virtualizer (e.g., KoiVM / EzirizVM) -> Protector (e.g., ConfuserEx) -> Obfuscator (e.g., Obfuscar) -> Licensing (e.g., Sentinel)
```

### 2. Comprehensive Tool Coverage (68 Signatures)
- **Protectors & Forks:** ConfuserEx, ConfuserEx 2 (mkaring), Neo-ConfuserEx, ModPhuserEx, Beds-Protector, AsStrongAsFuck, Krawk, .NET Reactor, SmartAssembly, ILProtector, Themida/WinLicense, VMProtect, Enigma Protector, SafeEngine Shielden, NetShrink.
- **Virtualizers:** KoiVM, EzirizVM, Agile.NET VM, Babel VM, Eazfuscator VM.
- **Obfuscators:** Obfuscar, Dotfuscator, Eazfuscator.NET, Babel .NET, Agile.NET (CliSecure), Crypto Obfuscator, CodeWall, CodeFort, Rummage, Spices.Net, DeepSea, Goliath, Yano, Skater, Macrobject, Dotnet Patcher, Salamander (Remotesoft), de4dot output detection.
- **Packers:** UPX, MPRESS, ASPack/ASProtect, Petite, FSG, Sixxpack, RPX, Netz.
- **Bundlers & Embedders:** Costura.Fody, Fody Generic, ILMerge, ILRepack, .NET Single-File AppHost Bundles.
- **Licensing Envelopes:** Thales Sentinel / HASP, Wibu CodeMeter AxProtector, CryptoLicensing, Siticone/Kimasoft.

### 3. CIL Method Disassembly & IL Heuristics (Phase 13)
- **Control Flow Flattening (CFF):** Detects state dispatch switch loops with non-trivial arithmetic selectors and backward branches.
- **Virtual Machine Interpreter Loops:** Identifies massive opcode dispatch switches (>= 100 cases) characteristic of VM bytecode interpreters.
- **Empty Method Stubs:** Detects assemblies where method bodies have been stripped (`RVA == 0` or stub `ret`/`throw`) for runtime method restoration.
- **Centralized String Decryptor Call Density:** Clusters calls to static decryptor methods called repeatedly with constant arguments.

### 4. Behavioral API Indicators (Phase 12)
- **Anti-Debugging:** Evaluates combinations of `Debugger.IsAttached`, `Debugger.IsLogging`, `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`.
- **Memory Protection & Anti-Tamper:** Identifies imports of `VirtualProtect`, `VirtualAlloc`, `WriteProcessMemory`, `Marshal.GetHINSTANCE`.
- **Dynamic Assembly Loading:** Identifies combinations of `Assembly.Load(byte[])`, `AppDomain.AssemblyResolve`, and manifest resource streaming.
- **Runtime JIT Hooking:** Detects usage of `DynamicMethod`, `ILGenerator.Emit`, `Module.ResolveMethod`, `RuntimeHelpers.PrepareMethod`.

### 5. Packaging & Container Detectors (Phase 14)
- **.NET Single-File AppHost Bundles:** Scans for the 32-byte Microsoft bundle marker and manifest header.
- **Native AOT:** Identifies ahead-of-time compiled binaries without CLR metadata headers.
- **ReadyToRun (R2R):** Detects crossgen composite images containing precompiled machine code.
- **PE Overlay Analysis:** Detects appended ZIP, 7-Zip, RAR, embedded MZ executables, and Enigma Virtual Box containers.
- **Native Entry Point Byte Matching:** PEiD-style pattern matching with wildcards at the native entry point.

### 6. Zero False Positive Precision (Phase 7–10)
- **Tier-Weighted Scoring:** Evidence is categorized into DEFINITIVE (+70), STRONG (+35), and WEAK (+12).
- **Pattern Match Modes:** Replaces error-prone substrings with `exact`, `prefix`, `token` (camelCase-aware), `contains` (guarded with length >= 8), and `regex`.
- **Bigram Wordlikeness Analysis:** Employs an embedded English and programming bigram model to distinguish normal identifier variety (`GetEnumerator`) from genuine high-entropy random hashes (`xKqR7pVw`).
- **Benchmark Gate:** Verified **0.0% False Positive rate** across clean Microsoft runtime and Framework BCL assemblies.

---

## Installation & Requirements

NetDetect requires Python 3.10+ and standard static analysis libraries:
```bash
pip install -r requirements.txt
```
*(Optional: `yara-python` for custom YARA rule integration.)*

---

## Usage

### 1. Basic Scan
```bash
python netdetect_cli.py target.exe
```

### 2. Explain Detection Scoring & Weights
```bash
python netdetect_cli.py target.exe --explain
```

### 3. Verbose Deep Inspection Dump
```bash
python netdetect_cli.py target.exe -v
```

### 4. Fast Scan (Skip IL Disassembly)
```bash
python netdetect_cli.py target.exe --no-il
```

### 5. Scan with Custom YARA Rules
```bash
python netdetect_cli.py target.exe --rules path/to/rules/
```

### 6. Export Results to JSON
```bash
python netdetect_cli.py target.exe --json scan_report.json
```

### 7. Batch Directory Scan
```bash
python netdetect_cli.py --dir C:\samples\ --json batch_report.json
```

---

## ConfuserExKillerRunner (Unconfuser Deobfuscation Engine)

**ConfuserExKillerRunner** is an advanced, multi-targeted (`net48`, `net6.0-windows`, `net8.0-windows`) .NET deobfuscation and unpacking suite specifically engineered to reverse modern, hardened ConfuserEx protections and forks.

### Pipeline Stages & Capabilities:
1. **Anti-Tamper Killer:** In-memory diffing and section decryption (`.text`, dynamic section unscrambling).
2. **Anti-Dump & Header Repair:** Bound-checked COR20 metadata RVA and header size restoration.
3. **Field RVA Restoration:** Unmaps memory-backed static field initializers and restores decrypted payload buffers.
4. **Resource Killer:** In-memory method rewriting with isolated assembly execution, extracting encrypted assembly resources (`.resources`) and transplanting them into cleartext manifest storage.
5. **Proxy Killer:** Recursively inlines proxy calls, delegates, and dynamic method dispatches.
6. **Constant Killer:** Stack-evaluating arithmetic engine with open-generic reflection invocation for 11 primitive array types and strings.
7. **Cleaner Killer:** Strips protector hooks, anti-tamper P/Invokes (`VirtualProtect`), and module constructor initializers.
8. **Predicate Killer & Dead Code Stripper:** Folds algebraic identities, evaluates constant conditional jumps, collapses jump-to-jump chains, and prunes dead trampolines.
9. **Switch Killer:** Resolves control-flow flattening state machines and restores linear IL.
10. **Quality Auditor:** Automated IL verification ensuring 0 invalid instructions and 0 unresolved call sites.

For a full matrix of supported ConfuserEx 1.0.0 protections, static vs. dynamic modes, and unsupported edge cases, see the [ConfuserEx Support Matrix](docs/SUPPORT_MATRIX.md).

### Usage:
```bash
# Build the runner
dotnet build ConfuserExKillerRunner/ConfuserExKillerRunner.csproj -c Release

# Execute deobfuscation (targeting net48 for x86 32-bit targets)
dotnet run --project ConfuserExKillerRunner/ConfuserExKillerRunner.csproj -f net48 -c Release -- "path/to/target.dll" --allow-execution --json-report report.json

# CLI Options:
#   --allow-execution       Allow target module execution via isolated worker process
#   --worker-timeout <ms>   Timeout in milliseconds for isolated worker process (default: 30000)
#   --allow-target-deps     Permit worker to resolve dependencies from target assembly directory
#   --dep-dir <path>        Add explicitly authorized directory for dependency resolution
#   -o, --output <path>     Specify custom destination path for final cleaned assembly
#   -d, --de4dot <path>     Specify explicit path to de4dot-cex executable
#   --no-de4dot             Skip de4dot external process pass
#   --no-netdetect          Skip NetDetect pre/post obfuscation audit
#   --json-report <path>    Generate structured versioned JSON audit report
#   --strict-exit-codes     Return exit code 2 on any partial deobfuscation
#   --restore-names         Restore semantic symbol names (Forms, Controls, Handlers, Resources)
#   --force-promote         Promote candidate to output path even if external dependencies cause indeterminate status
#   --verbose               Enable verbose console output

# Exit Codes:
#   0: Success - all requested protections resolved or fully clean output
#   1: Fatal Error - corrupt assembly, structural audit failed, or unhandled exception
#   2: Partial Result - candidate promoted with known limitations (dynamic required, unsupported)
```

---

## Verification & Testing

Run all .NET unit tests:
```bash
dotnet test unconfuser.sln -c Release
```

Run the Deobfuscation Benchmark Suite (including authentic ConfuserEx binaries):
```bash
python benchmarks/run_benchmark.py
```

Run Python test suites:
```bash
python -m pytest
```

Run the False Positive Benchmark Gate:
```bash
python tests/fp_benchmark.py --limit 150 --baseline tests/fp_baseline.json
```

---

## Licenses & Attributions

This project incorporates and links with `de4dot.blocks.dll` (GPLv3) and `dnlib.dll` (MIT). For detailed licensing analysis, third-party attributions, .NET framework support lifecycle, and security guidance, see [docs/LICENSES.md](docs/LICENSES.md).
