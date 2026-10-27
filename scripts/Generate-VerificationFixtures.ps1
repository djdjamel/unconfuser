param(
    [string]$OutputDir = "$PSScriptRoot\..\tests\fixtures\verification"
)

$ErrorActionPreference = "Stop"

$dnlibPath = "$PSScriptRoot\..\ConfuserExKillerRunner\dnlib.dll"
if (-not (Test-Path $dnlibPath)) {
    $dnlibPath = "$PSScriptRoot\..\benchmarks\FixtureGenerator\bin\Release\net8.0-windows\dnlib.dll"
}

if (-not (Test-Path $dnlibPath)) {
    throw "dnlib.dll not found at $dnlibPath"
}

$dnlibFull = (Resolve-Path $dnlibPath).Path
if (-not (Test-Path $OutputDir)) {
    [System.IO.Directory]::CreateDirectory($OutputDir) | Out-Null
}
$outFull = [System.IO.Path]::GetFullPath($OutputDir)

$cp = [System.CodeDom.Compiler.CompilerParameters]::new()
$cp.ReferencedAssemblies.Add($dnlibFull) | Out-Null
$cp.TreatWarningsAsErrors = $false
$cp.WarningLevel = 0

Add-Type -CompilerParameters $cp -TypeDefinition @"
using System;
using System.IO;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

public static class VerificationFixtureBuilder {
    public static void GenerateAll(string outputDir) {
        Directory.CreateDirectory(outputDir);

        // 1. Corrupted IL Assembly (causes InvalidProgramException on JIT)
        var mod1 = new ModuleDefUser("CorruptedIlFixture", Guid.NewGuid());
        mod1.Kind = ModuleKind.Dll;
        var asm1 = new AssemblyDefUser("CorruptedIlFixture", new Version(1, 0, 0, 0));
        asm1.Modules.Add(mod1);

        var type1 = new TypeDefUser("CorruptedNamespace", "CorruptedClass", mod1.CorLibTypes.Object.TypeDefOrRef);
        type1.Attributes = TypeAttributes.Public | TypeAttributes.Class;
        mod1.Types.Add(type1);

        var meth1 = new MethodDefUser(
            "CorruptedMethod",
            MethodSig.CreateStatic(mod1.CorLibTypes.Void),
            MethodImplAttributes.IL,
            MethodAttributes.Public | MethodAttributes.Static
        );
        meth1.Body = new CilBody();
        meth1.Body.KeepOldMaxStack = true;
        meth1.Body.MaxStack = 2;
        // Stack underflow: Add with no operands
        meth1.Body.Instructions.Add(OpCodes.Add.ToInstruction());
        meth1.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        type1.Methods.Add(meth1);

        string corruptedPath = Path.Combine(outputDir, "corrupted_il.dll");
        mod1.Write(corruptedPath);

        // 2. Missing Resource Form Assembly
        var mod2 = new ModuleDefUser("MissingResourceFixture", Guid.NewGuid());
        mod2.Kind = ModuleKind.Dll;
        var asm2 = new AssemblyDefUser("MissingResourceFixture", new Version(1, 0, 0, 0));
        asm2.Modules.Add(mod2);

        var formBase = new TypeDefUser("System.Windows.Forms", "Form", mod2.CorLibTypes.Object.TypeDefOrRef);
        formBase.Attributes = TypeAttributes.Public | TypeAttributes.Class;
        mod2.Types.Add(formBase);

        var formSub = new TypeDefUser("TestApp", "MissingResourceForm", formBase);
        formSub.Attributes = TypeAttributes.Public | TypeAttributes.Class;
        mod2.Types.Add(formSub);

        var formMeth = new MethodDefUser(
            "Init",
            MethodSig.CreateInstance(mod2.CorLibTypes.Void),
            MethodImplAttributes.IL,
            MethodAttributes.Public
        );
        formMeth.Body = new CilBody();
        formMeth.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        formSub.Methods.Add(formMeth);

        string missingResPath = Path.Combine(outputDir, "missing_resource_form.dll");
        mod2.Write(missingResPath);

        // 3. Infinite Loop .cctor Assembly (causes timeout)
        var mod3 = new ModuleDefUser("InfiniteLoopFixture", Guid.NewGuid());
        mod3.Kind = ModuleKind.Dll;
        var asm3 = new AssemblyDefUser("InfiniteLoopFixture", new Version(1, 0, 0, 0));
        asm3.Modules.Add(mod3);

        var globalType = mod3.GlobalType;
        var cctor = globalType.FindOrCreateStaticConstructor();
        cctor.Body = new CilBody();
        var loopTarget = OpCodes.Nop.ToInstruction();
        cctor.Body.Instructions.Add(loopTarget);
        cctor.Body.Instructions.Add(OpCodes.Br_S.ToInstruction(loopTarget));

        string loopPath = Path.Combine(outputDir, "infinite_loop_cctor.dll");
        mod3.Write(loopPath);

        // 4. Zero Methods / Interface Only (causes INDETERMINATE status)
        var mod4 = new ModuleDefUser("ZeroMethodsFixture", Guid.NewGuid());
        mod4.Kind = ModuleKind.Dll;
        var asm4 = new AssemblyDefUser("ZeroMethodsFixture", new Version(1, 0, 0, 0));
        asm4.Modules.Add(mod4);

        var iface = new TypeDefUser("TestApp", "IEmptyInterface", null);
        iface.Attributes = TypeAttributes.Public | TypeAttributes.Interface | TypeAttributes.Abstract;
        mod4.Types.Add(iface);

        string zeroMethodsPath = Path.Combine(outputDir, "zero_methods.dll");
        mod4.Write(zeroMethodsPath);
    }
}
"@

[System.AppDomain]::CurrentDomain.add_AssemblyResolve({
    param($s, $e)
    if ($e.Name -like "dnlib*") {
        return [System.Reflection.Assembly]::LoadFrom($dnlibFull)
    }
    return $null
})

[VerificationFixtureBuilder]::GenerateAll($outFull)
Write-Host "[+] All verification test fixtures successfully generated in $outFull"
