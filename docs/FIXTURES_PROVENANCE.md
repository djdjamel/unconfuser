# Fixtures Provenance and Transformations Documentation

This document describes the provenance, generation methodologies, cryptographic signatures, and architectural characteristics of all test fixtures utilized in the `ConfuserExKillerRunner` test and benchmarking suite.

---

## 1. Real ConfuserEx Protected Fixtures

Real ConfuserEx fixtures are produced directly using official, untampered ConfuserEx toolchain binaries targeting compiled test assemblies.

### 1.1 Full Protection Profile Fixture (`BenignSample.exe`)
- **Directory**: `benchmarks/fixtures/real_confuserex/`
- **Source Module**: `benchmarks/BenignSample/` (.NET Framework 4.8 / .NET 8.0)
  - Features: Multiple control-flow branches, nested try/catch blocks, string constants, embedded text resource (`Greeting.txt`), delegate invocations.
  - Source SHA256: `3de2f377e34ebd98fd7b612f05406724c09ea4a80fe23cfc394f6edc2cc312b0`
- **ConfuserEx Toolchain**:
  - Release: `ConfuserEx v1.0.0`
  - Upstream Commit: `3c9c29d9daf2f1259edf69054c5693d5d225a980`
  - Toolchain SHA256 (`Confuser.CLI.exe`): `2b3e5cb7f96589e5377700a5f7f25e9fc6a14539e85256e6ac6e85c07f769f61`
- **Protection Profile (`confuser_run.crproj`)**:
  - `constants` (mode: normal, string/number encryption)
  - `ctrl flow` (predicate & switch mangling)
  - `ref proxy` (delegate indirection)
  - `resources` (embedded resource encryption)
  - `anti tamper` (JIT / PE section encryption)
- **Output Artifact**: `BenignSample.exe`
  - Size: 43,520 bytes
  - SHA256: `4fdd2cbca60d2ac54be34d92a9026d9ad0de6251364b7537461aef7aa2c9448f`
  - Verified Output: `BenignSample_clean.exe` (29,696 bytes)

### 1.2 Isolated Anti-Tamper Fixture
- **Directory**: `benchmarks/fixtures/real_confuserex_antitamper/`
- **Protection Profile (`confuser_antitamper.crproj`)**:
  - Rule: `<protection id="anti tamper" />`
  - Target: `BenignSample.exe`
- **Output Artifact**: `BenignSample.exe`
  - Size: 10,240 bytes
  - Behavior: Method bodies encrypted inside dedicated PE section (`.text` encrypted or custom section), decrypted dynamically during module static initialization `<Module>.cctor`.

---

## 2. Synthetic Test Fixtures (`benchmarks/FixtureGenerator`)

Synthetic fixtures are programmatically generated using `dnlib` in `benchmarks/FixtureGenerator/` to provide deterministic, isolated regression testing for each individual deobfuscation stage.

| Fixture Name | Primary Protected Technique | Intended Deobfuscation Stage | Verification Criteria |
|---|---|---|---|
| `fixture_constants.dll` | Constant encryption helper methods and stack-evaluated buffers | `ConstantKiller` | All encrypted strings and numerical constants restored in-place; decrypter methods removed. |
| `fixture_cflow.dll` | Obfuscated switch statements with state variable dispatchers | `SwitchKiller` | Switch dispatch state machines collapsed into linear IL blocks; dummy variables stripped. |
| `fixture_proxies.dll` | Method reference proxies, delegate indirection | `ProxyKiller` | Proxy calls replaced with direct target `Call`/`Callvirt` opcodes; proxy definitions deleted. |
| `fixture_resources.dll` | Encrypted manifest resource streams | `ResourceKiller` | Decrypted resource stream extracted and re-embedded into module resources table. |
| `fixture_antitamper.dll` | Synthetic section encryption hook simulation | `AntiTamperKiller` | Section differences identified and method headers unpacked. |
| `fixture_compressor.dll` | ConfuserEx compressor stub wrapping payload | `CompressorUnpacker` | Inner payload decrypted and extracted to `.unwrapped.dll`. |
| `fixture_edge_cases.dll` | Mixed nested handlers, short branches, non-standard opcodes | Full Pipeline | No stack underflows or invalid branches introduced by any transform pass. |
| `fixture_combined.dll` | Multi-layered combination of all synthetic techniques | Full Pipeline | End-to-end multi-pass resolution without stage interference. |

### Limitations of Synthetic Fixtures:
Synthetic fixtures model exact opcode patterns and AST constructs, but do not necessarily reflect the full non-deterministic metadata layout, compiler variations, or obfuscator packer wrappers present in real-world commercial binaries.

---

## 3. Negative and Regression Fixtures (`NegativeFixtureTests`)

Negative testing ensures that `ConfuserExKillerRunner` acts with absolute safety: it must never corrupt or incorrectly alter assemblies that are clean, non-obfuscated, or protected by foreign tools.

### 3.1 Benign Clean Assembly Sample
- **Purpose**: Verifies that standard C# assemblies (classes, interfaces, async/await state machines, LINQ, generics, exception handlers) pass through the pipeline with zero modifications, zero regressions, and exit code `0`.
- **Validation**:
  - Methods inspected and verified.
  - Zero constants, zero switches, zero hooks modified.
  - Final output byte-identical or structurally isomorphic with no IL regressions.

### 3.2 Foreign Protector Sample
- **Purpose**: Verifies behavior against assemblies protected by foreign tools (e.g., .NET Reactor, Agile.NET, Babel.NET).
- **Validation**:
  - Foreign protector indicators must not trigger ConfuserEx killers.
  - Anti-tamper, constant decrypters, and switch solvers must gracefully decline to process unverified structures.
  - Matrix classifies techniques as unsupported or non-confuserex without failing with uncontrolled crashes.

---

## 4. In-Memory Assembly Fixtures and `AssemblyDefUser` Manifest Requirement

During unit and integration tests (such as `NegativeFixtureTests.cs` and `QualityAuditorTests.cs`), in-memory test assemblies are constructed using dnlib.

### The Assembly Manifest Requirement:
- In the ECMA-335 .NET metadata standard, a standalone executable or library must contain an **Assembly Manifest** (the `Assembly` metadata table `0x20`).
- If an in-memory module is initialized only as `new ModuleDefUser("Test.dll")` and written to disk, it creates a raw `.netmodule` lacking an assembly manifest.
- When Microsoft's `PEVerify.exe` analyzes a `.netmodule` without an assembly manifest, it aborts with exit code `1`:
  ```
  The module was expected to contain an assembly manifest.
  (French: Le module était censé contenir un manifeste de l'assembly.)
  ```
- **Solution implemented**:
  All programmatic fixture generation wraps modules within an explicit `AssemblyDefUser`:
  ```csharp
  var asm = new AssemblyDefUser(new AssemblyNameInfo("FixtureAssembly", new Version(1, 0, 0, 0)));
  asm.Modules.Add(mod);
  asm.Write(path, writerOptions);
  ```
  This guarantees that external IL verification engines (`PEVerify` and `ILVerify`) validate the actual bytecode and control-flow integrity rather than failing on missing container headers.
