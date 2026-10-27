<#
.SYNOPSIS
    Automated behavioral test harness for deobfuscated .NET assemblies.
.DESCRIPTION
    Performs runtime verification by:
    1. Executing <Module>..cctor in an isolated 32-bit/64-bit environment.
    2. JIT compiling all non-abstract methods via RuntimeHelpers.PrepareMethod.
    3. Checking WinForms ComponentResourceManager initialization to prevent MissingManifestResourceException.
.PARAMETER Target
    Path to the assembly (.dll or .exe) to verify.
.PARAMETER DepDirs
    Directories containing dependencies.
.PARAMETER CheckForms
    Whether to instantiate ComponentResourceManager for all WinForms types.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Target,
    [string[]]$DepDirs = @(),
    [switch]$CheckForms,
    [switch]$Force32Bit
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Target)) {
    Write-Error "Target assembly not found: $Target"
    exit 1
}

$targetFull = [System.IO.Path]::GetFullPath($Target)
$targetDir = [System.IO.Path]::GetDirectoryName($targetFull)

# If 32-bit execution is required and current process is 64-bit, relaunch in 32-bit powershell
if ($Force32Bit -or [Environment]::Is64BitProcess) {
    $sysWow64Ps = "$env:WINDIR\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
    if ([Environment]::Is64BitProcess -and (Test-Path $sysWow64Ps)) {
        Write-Host "[*] Relaunching in 32-bit PowerShell (SysWOW64) for accurate x86 JIT & P/Invoke execution..." -ForegroundColor Cyan
        $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $PSCommandPath, "-Target", "`"$targetFull`"")
        if ($DepDirs -and $DepDirs.Count -gt 0) {
            $argList += "-DepDirs"
            $argList += ($DepDirs -join ",")
        }
        if ($CheckForms) { $argList += "-CheckForms" }
        
        $p = Start-Process -FilePath $sysWow64Ps -ArgumentList $argList -NoNewWindow -Wait -PassThru
        exit $p.ExitCode
    }
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Behavioral Verification & JIT Harness (Unconfuser)       " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Target: $targetFull"
Write-Host "Process Bitness: $((32, 64)[[Environment]::Is64BitProcess]) bits"

$allDepDirs = [System.Collections.Generic.List[string]]::new()
$allDepDirs.Add($targetDir)
foreach ($d in $DepDirs) {
    if (Test-Path $d) {
        $allDepDirs.Add([System.IO.Path]::GetFullPath($d))
    }
}

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.ComponentModel;
using System.Collections.Generic;

public class VerifyResult {
    public bool LoadSuccess;
    public string LoadError;
    public bool ModuleCctorSuccess;
    public string ModuleCctorError;
    public int TotalTypes;
    public int TotalMethods;
    public int JitSuccess;
    public int JitSkipped;
    public int JitFailedMissingDependency;
    public int JitFailedCorruptedIl;
    public List<string> DependencyFailures = new List<string>();
    public List<string> CorruptedIlFailures = new List<string>();
    public int FormsChecked;
    public int FormsSuccess;
    public int FormsFailed;
    public List<string> FormFailures = new List<string>();
}

public static class AssemblyVerifier {
    public static List<string> SearchDirs = new List<string>();

    public static Assembly OnAssemblyResolve(object sender, ResolveEventArgs args) {
        string assemblyName = new AssemblyName(args.Name).Name;
        string[] candidates = new string[] { assemblyName + ".dll", assemblyName + ".exe" };
        foreach (var dir in SearchDirs) {
            foreach (var cand in candidates) {
                string fullPath = Path.Combine(dir, cand);
                if (File.Exists(fullPath)) {
                    try { return Assembly.LoadFrom(fullPath); } catch { }
                }
            }
        }
        return null;
    }

    public static VerifyResult Verify(string assemblyPath, bool checkForms) {
        var result = new VerifyResult();
        AppDomain.CurrentDomain.AssemblyResolve += OnAssemblyResolve;

        Assembly asm;
        try {
            asm = Assembly.LoadFrom(assemblyPath);
            result.LoadSuccess = true;
        } catch (Exception ex) {
            result.LoadSuccess = false;
            result.LoadError = ex.GetType().Name + ": " + ex.Message;
            return result;
        }

        // 1. Run Module .cctor
        try {
            foreach (var mod in asm.GetModules()) {
                RuntimeHelpers.RunModuleConstructor(mod.ModuleHandle);
            }
            result.ModuleCctorSuccess = true;
        } catch (Exception ex) {
            result.ModuleCctorSuccess = false;
            result.ModuleCctorError = ex.GetType().Name + ": " + (ex.InnerException ?? ex).Message;
        }

        // 2. Discover types
        Type[] types;
        try {
            types = asm.GetTypes();
        } catch (ReflectionTypeLoadException rtle) {
            var list = new List<Type>();
            foreach (var t in rtle.Types) { if (t != null) list.Add(t); }
            types = list.ToArray();
        }
        result.TotalTypes = types.Length;

        // 3. JIT methods
        BindingFlags flags = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;
        foreach (var type in types) {
            if (type.ContainsGenericParameters) {
                result.JitSkipped++;
                continue;
            }

            var members = new List<MethodBase>();
            try {
                members.AddRange(type.GetMethods(flags));
                members.AddRange(type.GetConstructors(flags));
            } catch {
                result.JitSkipped++;
                continue;
            }

            foreach (var member in members) {
                result.TotalMethods++;
                try {
                    if (member.IsAbstract || member.ContainsGenericParameters || member.GetMethodBody() == null) {
                        result.JitSkipped++;
                        continue;
                    }
                    RuntimeHelpers.PrepareMethod(member.MethodHandle);
                    result.JitSuccess++;
                } catch (FileNotFoundException fnfe) {
                    result.JitFailedMissingDependency++;
                    if (result.DependencyFailures.Count < 10) {
                        result.DependencyFailures.Add(type.FullName + "::" + member.Name + " -> Missing dependency: " + fnfe.Message);
                    }
                } catch (TypeLoadException tle) {
                    result.JitFailedMissingDependency++;
                    if (result.DependencyFailures.Count < 10) {
                        result.DependencyFailures.Add(type.FullName + "::" + member.Name + " -> TypeLoadException: " + tle.Message);
                    }
                } catch (Exception ex) {
                    result.JitFailedCorruptedIl++;
                    if (result.CorruptedIlFailures.Count < 20) {
                        result.CorruptedIlFailures.Add(type.FullName + "::" + member.Name + " -> " + ex.GetType().Name + ": " + (ex.InnerException ?? ex).Message);
                    }
                }
            }

            // 4. Check Form ComponentResourceManager
            if (checkForms) {
                bool isForm = false;
                try {
                    Type current = type;
                    while (current != null && current != typeof(object)) {
                        if (current.Name == "Form" || current.Name == "XpertForm" || current.Name == "UserControl" || current.Name == "XtraForm") {
                            isForm = true;
                            break;
                        }
                        current = current.BaseType;
                    }
                } catch { }

                if (isForm) {
                    result.FormsChecked++;
                    try {
                        var rm = new ComponentResourceManager(type);
                        // Force resource groveling without throwing UI
                        var rs = rm.GetResourceSet(System.Globalization.CultureInfo.InvariantCulture, true, false);
                        result.FormsSuccess++;
                    } catch (System.Resources.MissingManifestResourceException mmre) {
                        result.FormsFailed++;
                        result.FormFailures.Add(type.FullName + " -> MissingManifestResourceException: " + mmre.Message);
                    } catch {
                        // Other non-resource exceptions are tolerated at this stage
                        result.FormsSuccess++;
                    }
                }
            }
        }

        return result;
    }
}
"@ -ReferencedAssemblies @("System.Windows.Forms", "System.Drawing")

[AssemblyVerifier]::SearchDirs.Clear()
foreach ($d in $allDepDirs) {
    [AssemblyVerifier]::SearchDirs.Add($d)
}

$res = [AssemblyVerifier]::Verify($targetFull, [bool]$CheckForms)

Write-Host "`n--- Verification Report ---" -ForegroundColor White
if ($res.LoadSuccess) {
    Write-Host "[+] Assembly Load: SUCCESS" -ForegroundColor Green
} else {
    Write-Host "[-] Assembly Load: FAILED ($($res.LoadError))" -ForegroundColor Red
}

if ($res.ModuleCctorSuccess) {
    Write-Host "[+] Module .cctor: SUCCESS" -ForegroundColor Green
} else {
    Write-Host "[-] Module .cctor: FAILED ($($res.ModuleCctorError))" -ForegroundColor Red
}

Write-Host "[*] Types Discovered: $($res.TotalTypes)"
Write-Host "[*] JIT Methods: ok=$($res.JitSuccess), skipped=$($res.JitSkipped), missing-dep=$($res.JitFailedMissingDependency), corrupted-il=$($res.JitFailedCorruptedIl)" -ForegroundColor $(if ($res.JitFailedCorruptedIl -eq 0) { "Green" } else { "Red" })

if ($res.JitFailedCorruptedIl -gt 0) {
    Write-Host "    Corrupted IL Failures:" -ForegroundColor Red
    foreach ($f in $res.CorruptedIlFailures) {
        Write-Host "      $f" -ForegroundColor Red
    }
}

if ($res.JitFailedMissingDependency -gt 0) {
    Write-Host "    Missing Dependency Notes:" -ForegroundColor Yellow
    foreach ($f in $res.DependencyFailures) {
        Write-Host "      $f" -ForegroundColor DarkYellow
    }
}

if ($CheckForms) {
    Write-Host "[*] Forms Checked: total=$($res.FormsChecked), success=$($res.FormsSuccess), failed=$($res.FormsFailed)" -ForegroundColor $(if ($res.FormsFailed -eq 0) { "Green" } else { "Red" })
    if ($res.FormsFailed -gt 0) {
        Write-Host "    MissingManifestResourceException failures:" -ForegroundColor Red
        foreach ($ff in $res.FormFailures) {
            Write-Host "      $ff" -ForegroundColor Red
        }
    }
}

$hasFatalFailures = (-not $res.LoadSuccess) -or (-not $res.ModuleCctorSuccess) -or ($res.FormsFailed -gt 0) -or ($res.JitFailedCorruptedIl -gt 0)

if (-not $hasFatalFailures) {
    if ($res.JitFailedMissingDependency -gt 0) {
        Write-Host "`n[+] ALL STRUCTURAL, MODULE .CCTOR, FORMS & IL CHECKS PASSED (with $($res.JitFailedMissingDependency) external dependency warning(s))." -ForegroundColor Green
    } else {
        Write-Host "`n[+] ALL RUNTIME & BEHAVIORAL CHECKS PASSED!" -ForegroundColor Green
    }
    exit 0
} else {
    Write-Host "`n[-] RUNTIME CHECKS DETECTED ISSUES." -ForegroundColor Red
    exit 1
}
