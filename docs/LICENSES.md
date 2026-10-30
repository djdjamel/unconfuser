# Third-Party Licenses & Dependency Attributions

## 1. Project Licensing Analysis & Recommendation

`Unconfuser` (`ConfuserExKillerRunner`) directly links against and incorporates functionality from `de4dot.blocks.dll`, which is derived from `de4dot`.

- **`de4dot` and `de4dot.blocks`** are licensed under the **GNU General Public License v3.0 (GPLv3)**.
- Under the terms of the GNU GPLv3, any work that statically or dynamically links with GPLv3 code, or constitutes a derived work thereof, must be licensed under the GNU GPLv3 (or a compatible license) when distributed.
- **`dnlib`** is licensed under the **MIT License** (permissive, GPLv3-compatible).
- **`ConfuserEx`** is licensed under the **MIT License** (permissive, GPLv3-compatible).

**Recommendation:**
To maintain legal compliance with upstream copyleft obligations, all distributed binaries and derivative codebases of `Unconfuser` incorporating `de4dot.blocks` must be licensed under the **GNU General Public License v3.0 (GPL-3.0-or-later)**.

---

## 2. Dependency Licenses

### de4dot.blocks.dll
- **Author:** 0xd4d
- **Source:** https://github.com/de4dot/de4dot
- **License:** GNU General Public License v3.0 (GPLv3)
- **Notice:**
  > This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
  > This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

### dnlib.dll
- **Author:** 0xd4d
- **Source:** https://github.com/0xd4d/dnlib
- **License:** MIT License
- **Notice:**
  > Copyright (C) 2012-2019 de4dot@gmail.com
  > Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
  > The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

### ConfuserEx (Pin v1.0.0 official tooling)
- **Author:** Ki
- **Source:** https://github.com/yck1509/ConfuserEx
- **License:** MIT License
- **Notice:**
  > Copyright (c) 2014-2016 Ki
  > Permission is hereby granted, free of charge, to any person obtaining a copy of this software...

---

## 3. Target Frameworks & Support Lifecycle

The `ConfuserExKillerRunner` engine is configured with multi-target framework support in `ConfuserExKillerRunner.csproj`:

| Target Framework | Platform Target | Support Status | Rationale |
| :--- | :--- | :--- | :--- |
| **`net48`** (.NET Framework 4.8) | `x86` (32-bit required) | **Active (Component of Windows 10/11)** | Required for full compatibility with historical 32-bit ConfuserEx protected targets, runtime `AppDomain`/`Assembly.Load` reflection execution, mixed-mode C++/CLI, and anti-tamper P/Invoke hooks that rely on native 32-bit memory layouts. Supported natively as part of Windows OS lifecycle. |
| **`net6.0-windows`** (.NET 6.0) | `AnyCPU` | **Déprécié (EOL Nov 2024)** | Maintenu pour compatibilité transitoire; voir [Plan d'Obsolescence](DEPRECATION_NET6.md) pour le calendrier de retrait. |
| **`net8.0-windows`** (.NET 8.0) | `AnyCPU` | **Active Modern LTS (Supported until Nov 2026)** | Modern high-performance JIT runtime target for 64-bit and portable static analysis execution. |

### Build Reproducibility & Binary Assemblies:
Currently, `dnlib.dll` and `de4dot.blocks.dll` are referenced as pre-compiled assemblies within `ConfuserExKillerRunner/`. Because modern NuGet packages for `de4dot.blocks` are not officially maintained by upstream on public NuGet feeds without fork drift, keeping pinned, verified local assemblies preserves reproducible builds across all three target frameworks (`net48`, `net6.0-windows`, `net8.0-windows`) without breaking historical builds.

---

## 4. Security Sandbox Notice & Dynamic Mode Restrictions

- **Default Mode:** Pure static analysis. Untrusted module constructors (`<Module>.cctor`) are never executed.
- **Dynamic Mode (`--allow-execution`):** Executes target reflection code within the host CLR to decrypt anti-tamper and runtime constant tables.
- **CRITICAL WARNING:** A separate .NET process or separate AppDomain does **NOT** constitute a security sandbox. Untrusted or malicious binaries must always be analyzed in an isolated virtual machine (VM) with network connectivity disabled.
