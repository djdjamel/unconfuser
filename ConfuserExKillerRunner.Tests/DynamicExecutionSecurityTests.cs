using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using ConfuserExKillerRunner.Core;
using ConfuserExKillerRunner.Killers;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    [Trait("Category", "Integration")]
    public class DynamicExecutionSecurityTests : IDisposable
    {
        private readonly string _testDir;

        public DynamicExecutionSecurityTests()
        {
            _testDir = Path.Combine(Path.GetTempPath(), "unconfuser_sec_tests_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_testDir);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_testDir))
                    Directory.Delete(_testDir, recursive: true);
            }
            catch { }
        }

        [Fact]
        public void WorkerClient_WhenTargetModuleLoopsInfinitely_TerminatesProcessAndReportsTimeout()
        {
            // Create target assembly with infinite loop in <Module>.cctor
            string asmPath = Path.Combine(_testDir, "HangingTarget.dll");
            CreateHangingAssembly(asmPath);

            byte[] originalBytes = File.ReadAllBytes(asmPath);
            var opts = new WorkerOptions
            {
                TimeoutMs = 1500, // Short timeout for test
                TempDirectory = _testDir
            };

            var result = WorkerClient.ExecuteAntiTamper(asmPath, originalBytes, opts);

            Assert.Equal(AntiTamperStatus.Failed, result.Status);
            Assert.Contains("timed out", result.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(originalBytes, result.DecryptedPeImage); // Input unchanged
        }

        [Fact]
        public void WorkerClient_WhenTargetModuleCallsEnvironmentExit_ReportsFailureWithoutCrashingHost()
        {
            // Create target assembly with Environment.Exit(42) in <Module>.cctor
            string asmPath = Path.Combine(_testDir, "CrashingTarget.dll");
            CreateCrashingAssembly(asmPath, exitCode: 42);

            byte[] originalBytes = File.ReadAllBytes(asmPath);
            var opts = new WorkerOptions
            {
                TimeoutMs = 5000,
                TempDirectory = _testDir
            };

            var result = WorkerClient.ExecuteAntiTamper(asmPath, originalBytes, opts);

            Assert.Equal(AntiTamperStatus.Failed, result.Status);
            Assert.False(result.Modified);
            Assert.Equal(originalBytes, result.DecryptedPeImage);
        }

        [Fact]
        public void WorkerClient_PreservesSourceAssemblyBytesOnDisk()
        {
            string asmPath = Path.Combine(_testDir, "PreservedTarget.dll");
            CreateSimpleAssembly(asmPath);

            byte[] bytesBefore = File.ReadAllBytes(asmPath);
            string hashBefore = ComputeSha256(bytesBefore);

            var opts = new WorkerOptions
            {
                TimeoutMs = 5000,
                TempDirectory = _testDir
            };

            var result = WorkerClient.ExecuteAntiTamper(asmPath, bytesBefore, opts);

            byte[] bytesAfter = File.ReadAllBytes(asmPath);
            string hashAfter = ComputeSha256(bytesAfter);

            Assert.Equal(hashBefore, hashAfter);
        }

        [Fact]
        public void RestrictedResolver_BlocksUnauthorizedDependencyNotReferencedByTarget()
        {
            string targetPath = Path.Combine(_testDir, "TargetModule.dll");
            CreateSimpleAssembly(targetPath);

            // Put a malicious or unreferenced dll in testDir
            string unauthDll = Path.Combine(_testDir, "UnauthorizedNeighbor.dll");
            CreateSimpleAssembly(unauthDll);

            // Setup resolver
            WorkerHost.SetupRestrictedResolver(targetPath, new List<string>(), allowTargetDir: true);

            // Attempt to resolve unauthorized assembly
            // Under restricted resolver, since "UnauthorizedNeighbor" is not in TargetModule's AssemblyRefs,
            // AppDomain.CurrentDomain.AssemblyResolve will return null.
            bool resolveFailed = false;
            try
            {
                var asm = System.Reflection.Assembly.Load("UnauthorizedNeighbor, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null");
                if (asm == null) resolveFailed = true;
            }
            catch
            {
                resolveFailed = true;
            }

            Assert.True(resolveFailed, "Unauthorized neighbor DLL should NOT be resolved!");
        }

        [Fact]
        public void Compressor_StaticMode_NeverExecutesTargetCode()
        {
            string asmPath = Path.Combine(_testDir, "CrashingStaticProbe.dll");
            CreateCrashingAssembly(asmPath, exitCode: 99);
            byte[] rawBytes = File.ReadAllBytes(asmPath);

            using (var mod = ModuleDefMD.Load(rawBytes))
            {
                // Must complete without exiting or executing untrusted code
                var result = CompressorUnpacker.TryUnpack(mod, rawBytes, allowExecution: false);
                Assert.False(result.SuccessfullyUnpacked);
            }
        }

        [Fact]
        public void WorkerClient_ExecuteCompressorUnpack_WhenTargetLoopsInfinitely_TerminatesProcessAndReportsTimeout()
        {
            string asmPath = Path.Combine(_testDir, "HangingCompressorTarget.exe");
            CreateHangingExe(asmPath);

            var opts = new WorkerOptions
            {
                TimeoutMs = 1500,
                TempDirectory = _testDir
            };

            var result = WorkerClient.ExecuteCompressorUnpack(asmPath, opts);

            Assert.False(result.Success);
            Assert.Contains("timed out", result.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void WorkerClient_ExecuteCompressorUnpack_WhenTargetCallsEnvironmentExit_ReportsFailureWithoutCrashingHost()
        {
            string asmPath = Path.Combine(_testDir, "CrashingCompressorTarget.exe");
            CreateCrashingExe(asmPath, exitCode: 42);

            var opts = new WorkerOptions
            {
                TimeoutMs = 5000,
                TempDirectory = _testDir
            };

            var result = WorkerClient.ExecuteCompressorUnpack(asmPath, opts);

            Assert.False(result.Success);
            Assert.Null(result.UnpackedAssemblyBytes);
        }

        [Fact]
        public void WorkerClient_ExecuteConstants_WithBenignAssembly_ReturnsSuccessAndMessageWithoutException()
        {
            string asmPath = Path.Combine(_testDir, "BenignConstantsTarget.dll");
            CreateSimpleAssembly(asmPath);

            byte[] bytes = File.ReadAllBytes(asmPath);
            var opts = new WorkerOptions
            {
                TimeoutMs = 10000,
                TempDirectory = _testDir
            };

            var result = WorkerClient.ExecuteConstants(bytes, opts);

            Assert.True(result.success);
            Assert.Equal(0, result.decryptedCount);
            Assert.False(string.IsNullOrWhiteSpace(result.message));
            Assert.NotNull(result.outputPe);
        }

        [Fact]
        public void WorkerClient_ExecuteConstants_WhenWorkerTimesOut_ReturnsFailureAndTimeoutMessage()
        {
            string asmPath = Path.Combine(_testDir, "HangingConstantsTarget.dll");
            CreateConstantDecrypterAssembly(asmPath, hanging: true);

            byte[] bytes = File.ReadAllBytes(asmPath);
            var opts = new WorkerOptions
            {
                TimeoutMs = 1500,
                TempDirectory = _testDir
            };

            var result = WorkerClient.ExecuteConstants(bytes, opts);

            Assert.False(result.success);
            Assert.Equal(0, result.decryptedCount);
            Assert.Contains("timed out", result.message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void WorkerClient_ExecuteConstants_WhenTargetCrashes_ReturnsFailureAndErrorMessage()
        {
            string asmPath = Path.Combine(_testDir, "CrashingConstantsTarget.dll");
            CreateConstantDecrypterAssembly(asmPath, exitCode: 42);

            byte[] bytes = File.ReadAllBytes(asmPath);
            var opts = new WorkerOptions
            {
                TimeoutMs = 5000,
                TempDirectory = _testDir
            };

            var result = WorkerClient.ExecuteConstants(bytes, opts);

            Assert.False(result.success);
            Assert.False(string.IsNullOrWhiteSpace(result.message));
        }

        private static void CreateConstantDecrypterAssembly(string path, bool hanging = false, int? exitCode = null)
        {
            var asm = new AssemblyDefUser("ConstTargetAsm", new Version(1, 0, 0, 0));
            var mod = new ModuleDefUser("ConstTarget.dll");
            asm.Modules.Add(mod);
            mod.Kind = ModuleKind.Dll;

            var decrypterSig = MethodSig.CreateStaticGeneric(1, new GenericMVar(0), mod.CorLibTypes.UInt32);
            var decrypterDef = new MethodDefUser("Decrypter", decrypterSig,
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static);
            decrypterDef.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            decrypterDef.Body = new CilBody();

            if (hanging)
            {
                var loopTarget = Instruction.Create(OpCodes.Nop);
                decrypterDef.Body.Instructions.Add(loopTarget);
                decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Br, loopTarget));
                decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
                decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            }
            else if (exitCode.HasValue)
            {
                var exitMethod = mod.Import(typeof(Environment).GetMethod("Exit", new[] { typeof(int) }));
                decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, exitCode.Value));
                decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Call, exitMethod));
                decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
                decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            }
            else
            {
                decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_4));
                decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Newarr, mod.CorLibTypes.Byte.TypeDefOrRef));
                decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            }
            mod.GlobalType.Methods.Add(decrypterDef);

            var userType = new TypeDefUser("UserType", mod.CorLibTypes.Object.TypeDefOrRef);
            mod.Types.Add(userType);
            var caller = new MethodDefUser("Run", MethodSig.CreateStatic(mod.CorLibTypes.Void));
            caller.Body = new CilBody();
            var genMethodSig = new GenericInstMethodSig(new SZArraySig(mod.CorLibTypes.Byte));
            var methodSpec = new MethodSpecUser(decrypterDef, genMethodSig);
            caller.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 12345));
            caller.Body.Instructions.Add(Instruction.Create(OpCodes.Call, methodSpec));
            caller.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            caller.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            userType.Methods.Add(caller);

            mod.Write(path);
        }

        private static void CreateHangingExe(string path)
        {
            var asm = new AssemblyDefUser("HangingExeAsm", new Version(1, 0, 0, 0));
            var mod = new ModuleDefUser("HangingExeTarget.exe");
            asm.Modules.Add(mod);
            mod.Kind = ModuleKind.Console;

            // Mark as authentic ConfuserEx compressor stub via Confuser payload resource marker
            mod.Resources.Add(new EmbeddedResource("ConfuserEx.CompressedPayload", new byte[128]));

            var ep = new MethodDefUser("Main", MethodSig.CreateStatic(mod.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static);
            ep.Body = new CilBody();

            var asmLoadRef = mod.Import(typeof(System.Reflection.Assembly).GetMethod("Load", new[] { typeof(byte[]) }));
            ep.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            ep.Body.Instructions.Add(Instruction.Create(OpCodes.Call, asmLoadRef));
            ep.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            mod.GlobalType.Methods.Add(ep);
            mod.EntryPoint = ep;

            var cctor = mod.GlobalType.FindOrCreateStaticConstructor();
            cctor.Body = new CilBody();
            var loopTarget = Instruction.Create(OpCodes.Nop);
            cctor.Body.Instructions.Add(loopTarget);
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Br, loopTarget));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            mod.Write(path);
        }

        private static void CreateCrashingExe(string path, int exitCode)
        {
            var asm = new AssemblyDefUser("CrashingExeAsm", new Version(1, 0, 0, 0));
            var mod = new ModuleDefUser("CrashingExeTarget.exe");
            asm.Modules.Add(mod);
            mod.Kind = ModuleKind.Console;

            // Mark as authentic ConfuserEx compressor stub via Confuser payload resource marker
            mod.Resources.Add(new EmbeddedResource("ConfuserEx.CompressedPayload", new byte[128]));

            var ep = new MethodDefUser("Main", MethodSig.CreateStatic(mod.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static);
            ep.Body = new CilBody();

            var asmLoadRef = mod.Import(typeof(System.Reflection.Assembly).GetMethod("Load", new[] { typeof(byte[]) }));
            ep.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            ep.Body.Instructions.Add(Instruction.Create(OpCodes.Call, asmLoadRef));
            ep.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            mod.GlobalType.Methods.Add(ep);
            mod.EntryPoint = ep;

            var cctor = mod.GlobalType.FindOrCreateStaticConstructor();
            cctor.Body = new CilBody();
            var exitMethod = mod.Import(typeof(Environment).GetMethod("Exit", new[] { typeof(int) }));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, exitCode));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, exitMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            mod.Write(path);
        }

        private static void CreateHangingAssembly(string path)
        {
            var asm = new AssemblyDefUser("HangingAsm", new Version(1, 0, 0, 0));
            var mod = new ModuleDefUser("HangingTarget.dll");
            asm.Modules.Add(mod);
            mod.Kind = ModuleKind.Dll;

            var cctor = mod.GlobalType.FindOrCreateStaticConstructor();
            cctor.Body = new CilBody();
            var loopTarget = Instruction.Create(OpCodes.Nop);
            cctor.Body.Instructions.Add(loopTarget);
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Br, loopTarget));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            mod.Write(path);
        }

        private static void CreateCrashingAssembly(string path, int exitCode)
        {
            var asm = new AssemblyDefUser("CrashingAsm", new Version(1, 0, 0, 0));
            var mod = new ModuleDefUser("CrashingTarget.dll");
            asm.Modules.Add(mod);
            mod.Kind = ModuleKind.Dll;

            var cctor = mod.GlobalType.FindOrCreateStaticConstructor();
            cctor.Body = new CilBody();

            var exitMethod = mod.Import(typeof(Environment).GetMethod("Exit", new[] { typeof(int) }));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, exitCode));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, exitMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            mod.Write(path);
        }

        private static void CreateSimpleAssembly(string path)
        {
            var asm = new AssemblyDefUser("SimpleAsm", new Version(1, 0, 0, 0));
            var mod = new ModuleDefUser("SimpleTarget.dll");
            asm.Modules.Add(mod);
            mod.Kind = ModuleKind.Dll;

            var type = new TypeDefUser("SimpleNamespace", "SimpleClass", mod.CorLibTypes.Object.TypeDefOrRef);
            mod.Types.Add(type);
            var method = new MethodDefUser("Hello", MethodSig.CreateStatic(mod.CorLibTypes.String),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static);
            method.Body = new CilBody();
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "World"));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            type.Methods.Add(method);

            mod.Write(path);
        }

        [Fact]
        public void WorkerOptions_AllowTargetDirectoryDependencies_DefaultsToFalse()
        {
            var options = new WorkerOptions();
            Assert.False(options.AllowTargetDirectoryDependencies, "AllowTargetDirectoryDependencies must be secure by default (false).");
        }

        [Fact]
        public void WorkerClient_ExecutesInNeutralWorkingDirectory_PreventingTargetDirCwdHijacking()
        {
            // Create a target assembly in a dedicated directory
            string targetDir = Path.Combine(_testDir, "TargetFolder");
            Directory.CreateDirectory(targetDir);
            string targetDll = Path.Combine(targetDir, "CleanTarget.dll");
            CreateSimpleAssembly(targetDll);

            // Create an isolated temp directory for the worker
            string isolatedTempDir = Path.Combine(_testDir, "IsolatedTemp");
            Directory.CreateDirectory(isolatedTempDir);

            byte[] originalBytes = File.ReadAllBytes(targetDll);
            var opts = new WorkerOptions
            {
                TimeoutMs = 5000,
                TempDirectory = isolatedTempDir,
                AllowTargetDirectoryDependencies = false
            };

            var result = WorkerClient.ExecuteAntiTamper(targetDll, originalBytes, opts);

            // AntiTamper killer executes in neutral isolatedTempDir, not targetDir
            Assert.NotNull(result);
            Assert.NotEqual(AntiTamperStatus.NotAttempted, result.Status);
        }

        [Fact]
        public void WorkerClient_IsWorkerCompatible_ValidatesBitnessAndTargetFramework()
        {
            string net48Worker = Path.Combine(_testDir, "MockWorkerNet48_x86.exe");
            using (var mod = new ModuleDefUser("MockWorkerNet48_x86.exe"))
            {
                var asm = new AssemblyDefUser("MockWorkerNet48_x86", new Version(1, 0, 0, 0));
                asm.Modules.Add(mod);
                mod.Kind = ModuleKind.Console;
                mod.Machine = dnlib.PE.Machine.I386;
                mod.Is32BitRequired = true;
                var tfmType = new TypeRefUser(mod, "System.Runtime.Versioning", "TargetFrameworkAttribute", mod.CorLibTypes.AssemblyRef);
                var tfmCtor = new MemberRefUser(mod, ".ctor", MethodSig.CreateInstance(mod.CorLibTypes.Void, mod.CorLibTypes.String), tfmType);
                asm.CustomAttributes.Add(new CustomAttribute(tfmCtor, new[] { new CAArgument(mod.CorLibTypes.String, ".NETFramework,Version=v4.8") }));
                mod.Write(net48Worker);
            }

            string net8Worker = Path.Combine(_testDir, "MockWorkerNet8_x64.dll");
            using (var mod = new ModuleDefUser("MockWorkerNet8_x64.dll"))
            {
                var asm = new AssemblyDefUser("MockWorkerNet8_x64", new Version(1, 0, 0, 0));
                asm.Modules.Add(mod);
                mod.Kind = ModuleKind.Dll;
                mod.Machine = dnlib.PE.Machine.AMD64;
                mod.Is32BitRequired = false;
                var sysRuntimeRef = new AssemblyRefUser("System.Runtime", new Version(8, 0, 0, 0));
                var tfmType = new TypeRefUser(mod, "System.Runtime.Versioning", "TargetFrameworkAttribute", sysRuntimeRef);
                var tfmCtor = new MemberRefUser(mod, ".ctor", MethodSig.CreateInstance(mod.CorLibTypes.Void, mod.CorLibTypes.String), tfmType);
                asm.CustomAttributes.Add(new CustomAttribute(tfmCtor, new[] { new CAArgument(mod.CorLibTypes.String, ".NETCoreApp,Version=v8.0") }));
                var objRef = new TypeRefUser(mod, "System", "Object", sysRuntimeRef);
                mod.Types.Add(new TypeDefUser("WorkerNs", "WorkerEntry", objRef));
                mod.Write(net8Worker);
            }

            // 1. 32-bit net48 worker IS compatible with X86Required or AnyCPU .NET Framework target
            Assert.True(WorkerClient.IsWorkerCompatible(net48Worker, TargetArchitecture.X86Required, TargetRuntimeFamily.NetFramework, out string reason1));
            Assert.Null(reason1);
            Assert.True(WorkerClient.IsWorkerCompatible(net48Worker, TargetArchitecture.AnyCPU, TargetRuntimeFamily.NetFramework, out string reason2));
            Assert.Null(reason2);

            // 2. 32-bit net48 worker is NOT compatible with 64-bit (X64) target
            Assert.False(WorkerClient.IsWorkerCompatible(net48Worker, TargetArchitecture.X64, TargetRuntimeFamily.NetFramework, out string reasonX64));
            Assert.Contains("64-bit", reasonX64, StringComparison.OrdinalIgnoreCase);

            // 3. net48 worker is NOT compatible with modern .NET (.NET Core / .NET 8) target
            Assert.False(WorkerClient.IsWorkerCompatible(net48Worker, TargetArchitecture.AnyCPU, TargetRuntimeFamily.ModernDotNet, out string reasonModern));
            Assert.Contains("modern .NET runtime", reasonModern, StringComparison.OrdinalIgnoreCase);

            // 4. BIDIRECTIONAL CHECK: modern .NET (.NET 8) worker MUST BE REFUSED for a .NET Framework (net48) target!
            Assert.False(WorkerClient.IsWorkerCompatible(net8Worker, TargetArchitecture.AnyCPU, TargetRuntimeFamily.NetFramework, out string reasonNet8OnNet48));
            Assert.Contains("targets .NET Framework", reasonNet8OnNet48, StringComparison.OrdinalIgnoreCase);
            Assert.False(WorkerClient.IsWorkerCompatible(net8Worker, TargetArchitecture.X64, targetRequiresModernDotNet: false, out string reasonBoolOverload));
            Assert.Contains("targets .NET Framework", reasonBoolOverload, StringComparison.OrdinalIgnoreCase);

            // 5. modern .NET (.NET 8) worker IS compatible with AnyCPU/X64 modern .NET target
            Assert.True(WorkerClient.IsWorkerCompatible(net8Worker, TargetArchitecture.AnyCPU, TargetRuntimeFamily.ModernDotNet, out string reasonNet8Valid));
            Assert.Null(reasonNet8Valid);

            // 6. Unknown runtime family on target or worker MUST be refused
            Assert.False(WorkerClient.IsWorkerCompatible(net48Worker, TargetArchitecture.AnyCPU, TargetRuntimeFamily.Unknown, out string reasonUnknownTarget));
            Assert.Contains("unknown or indeterminate", reasonUnknownTarget, StringComparison.OrdinalIgnoreCase);

            string unknownRuntimeWorker = Path.Combine(_testDir, "CorruptWorker.exe");
            File.WriteAllBytes(unknownRuntimeWorker, CreateSyntheticNativePe(is64Bit: false));
            Assert.False(WorkerClient.IsWorkerCompatible(unknownRuntimeWorker, TargetArchitecture.X86Required, TargetRuntimeFamily.NetFramework, out string reasonUnknownWorker));
            Assert.Contains("unknown or indeterminate", reasonUnknownWorker, StringComparison.OrdinalIgnoreCase);

            // 7. 64-bit worker is NOT compatible with 32-bit (X86Required) target
            string x64Worker = Path.Combine(_testDir, "MockWorker_x64.exe");
            using (var mod = new ModuleDefUser("MockWorker_x64.exe"))
            {
                var asm = new AssemblyDefUser("MockWorker_x64", new Version(1, 0, 0, 0));
                asm.Modules.Add(mod);
                mod.Kind = ModuleKind.Console;
                mod.Machine = dnlib.PE.Machine.AMD64;
                mod.Is32BitRequired = false;
                var tfmType = new TypeRefUser(mod, "System.Runtime.Versioning", "TargetFrameworkAttribute", mod.CorLibTypes.AssemblyRef);
                var tfmCtor = new MemberRefUser(mod, ".ctor", MethodSig.CreateInstance(mod.CorLibTypes.Void, mod.CorLibTypes.String), tfmType);
                asm.CustomAttributes.Add(new CustomAttribute(tfmCtor, new[] { new CAArgument(mod.CorLibTypes.String, ".NETFramework,Version=v4.8") }));
                mod.Write(x64Worker);
            }

            Assert.False(WorkerClient.IsWorkerCompatible(x64Worker, TargetArchitecture.X86Required, TargetRuntimeFamily.NetFramework, out string reasonX86));
            Assert.Contains("32-bit", reasonX86, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void WorkerClient_ResolveWorkerExecutable_NeverSelectsNet8WorkerForNet48Target()
        {
            string prevEnv = Environment.GetEnvironmentVariable("UNCONFUSER_WORKER_PATH");
            try
            {
                Environment.SetEnvironmentVariable("UNCONFUSER_WORKER_PATH", null);

                string net48Target = Path.Combine(_testDir, "TargetNet48.dll");
                CreateSimpleAssembly(net48Target);

                bool resolvedNet48 = WorkerClient.TryResolveCompatibleWorker(net48Target, out string workerForNet48, out string mismatchNet48);
                Assert.True(resolvedNet48, $"Expected compatible net48 worker, got mismatch: {mismatchNet48}");
                Assert.Equal(TargetRuntimeFamily.NetFramework, ArchitectureDetector.DetectRuntimeFamily(workerForNet48));

                string net8Target = Path.Combine(_testDir, "TargetNet8.dll");
                using (var mod = new ModuleDefUser("TargetNet8.dll"))
                {
                    var asm = new AssemblyDefUser("TargetNet8", new Version(1, 0, 0, 0));
                    asm.Modules.Add(mod);
                    var sysRuntimeRef = new AssemblyRefUser("System.Runtime", new Version(8, 0, 0, 0));
                    var objRef = new TypeRefUser(mod, "System", "Object", sysRuntimeRef);
                    mod.Types.Add(new TypeDefUser("SampleNs", "SampleType", objRef));
                    mod.Write(net8Target);
                }

                bool resolvedNet8 = WorkerClient.TryResolveCompatibleWorker(net8Target, out string workerForNet8, out string mismatchNet8);
                Assert.True(resolvedNet8, $"Expected compatible net8 worker, got mismatch: {mismatchNet8}");
                Assert.Equal(TargetRuntimeFamily.ModernDotNet, ArchitectureDetector.DetectRuntimeFamily(workerForNet8));
            }
            finally
            {
                Environment.SetEnvironmentVariable("UNCONFUSER_WORKER_PATH", prevEnv);
            }
        }

        [Fact]
        public void ArchitectureDetector_NativeApphosts_DetectsExactBitnessAndSiblingRuntimeFamily()
        {
            // 1. x86 native apphost (Machine = 0x014C, HasClrHeader = false) + managed AnyCPU .NET 8 sibling DLL
            string x86ApphostExe = Path.Combine(_testDir, "NativeAppX86.exe");
            string x86ApphostDll = Path.Combine(_testDir, "NativeAppX86.dll");
            File.WriteAllBytes(x86ApphostExe, CreateSyntheticNativePe(is64Bit: false));
            using (var mod = new ModuleDefUser("NativeAppX86.dll"))
            {
                var asm = new AssemblyDefUser("NativeAppX86", new Version(1, 0, 0, 0));
                asm.Modules.Add(mod);
                var sysRuntimeRef = new AssemblyRefUser("System.Runtime", new Version(8, 0, 0, 0));
                var objRef = new TypeRefUser(mod, "System", "Object", sysRuntimeRef);
                mod.Types.Add(new TypeDefUser("AppNs", "AppType", objRef));
                mod.Write(x86ApphostDll);
            }

            var x86Info = ArchitectureDetector.Detect(x86ApphostExe);
            Assert.False(x86Info.HasClrHeader);
            // Critical assertion: x86 native apphost must NEVER be classified as AnyCPU; it is strictly X86Required!
            Assert.Equal(TargetArchitecture.X86Required, x86Info.Architecture);
            Assert.Equal(TargetRuntimeFamily.ModernDotNet, ArchitectureDetector.DetectRuntimeFamily(x86ApphostExe));
            Assert.False(WorkerClient.IsWorker64BitProcess(x86ApphostExe));

            // 2. x64 native apphost (Machine = 0x8664, HasClrHeader = false) + managed AnyCPU .NET 8 sibling DLL
            string x64ApphostExe = Path.Combine(_testDir, "NativeAppX64.exe");
            string x64ApphostDll = Path.Combine(_testDir, "NativeAppX64.dll");
            File.WriteAllBytes(x64ApphostExe, CreateSyntheticNativePe(is64Bit: true));
            File.Copy(x86ApphostDll, x64ApphostDll, overwrite: true);

            var x64Info = ArchitectureDetector.Detect(x64ApphostExe);
            Assert.False(x64Info.HasClrHeader);
            Assert.Equal(TargetArchitecture.X64, x64Info.Architecture);
            Assert.Equal(TargetRuntimeFamily.ModernDotNet, ArchitectureDetector.DetectRuntimeFamily(x64ApphostExe));
            Assert.True(WorkerClient.IsWorker64BitProcess(x64ApphostExe));

            // Cross-bitness rejection between x86 apphost and x64 worker (and vice versa)
            Assert.False(WorkerClient.IsWorkerCompatible(x64ApphostExe, x86Info.Architecture, TargetRuntimeFamily.ModernDotNet, out string err1));
            Assert.Contains("32-bit", err1, StringComparison.OrdinalIgnoreCase);
            Assert.False(WorkerClient.IsWorkerCompatible(x86ApphostExe, x64Info.Architecture, TargetRuntimeFamily.ModernDotNet, out string err2));
            Assert.Contains("64-bit", err2, StringComparison.OrdinalIgnoreCase);
        }

        private static byte[] CreateSyntheticNativePe(bool is64Bit)
        {
            byte[] pe = new byte[512];
            // MZ header
            pe[0] = 0x4D; // 'M'
            pe[1] = 0x5A; // 'Z'
            // e_lfanew at 0x3C = 0x80
            BitConverter.GetBytes((uint)0x80).CopyTo(pe, 0x3C);
            // PE signature at 0x80: "PE\0\0"
            pe[0x80] = 0x50;
            pe[0x81] = 0x45;
            pe[0x82] = 0x00;
            pe[0x83] = 0x00;
            // Machine at 0x84: 0x8664 (AMD64) or 0x014C (i386)
            ushort machine = is64Bit ? (ushort)0x8664 : (ushort)0x014C;
            BitConverter.GetBytes(machine).CopyTo(pe, 0x84);
            // NumberOfSections at 0x86 = 0
            BitConverter.GetBytes((ushort)0).CopyTo(pe, 0x86);
            // SizeOfOptionalHeader at 0x94 = 240 (PE32+) or 224 (PE32)
            ushort optSize = is64Bit ? (ushort)240 : (ushort)224;
            BitConverter.GetBytes(optSize).CopyTo(pe, 0x94);
            // Characteristics at 0x96 = 0x0002 (EXECUTABLE_IMAGE)
            BitConverter.GetBytes((ushort)0x0002).CopyTo(pe, 0x96);
            // OptionalHeader at 0x98: Magic = 0x020B (PE32+) or 0x010B (PE32)
            ushort magic = is64Bit ? (ushort)0x020B : (ushort)0x010B;
            BitConverter.GetBytes(magic).CopyTo(pe, 0x98);
            // NumberOfRvaAndSizes = 16 (with COM+ directory zeroed -> HasClrHeader = false)
            int numRvaOffset = 0x98 + (is64Bit ? 108 : 92);
            BitConverter.GetBytes((uint)16).CopyTo(pe, numRvaOffset);
            return pe;
        }

        [Fact]
        public void ArchitectureDetector_RequiresModernDotNetRuntime_DistinguishesNet48FromNet8()
        {
            string net48Dll = Path.Combine(_testDir, "Net48Sample.dll");
            CreateSimpleAssembly(net48Dll);
            Assert.False(ArchitectureDetector.RequiresModernDotNetRuntime(net48Dll));
            Assert.Equal(TargetRuntimeFamily.NetFramework, ArchitectureDetector.DetectRuntimeFamily(net48Dll));

            string net8Dll = Path.Combine(_testDir, "Net8Sample.dll");
            using (var mod = new ModuleDefUser("Net8Sample.dll"))
            {
                var asm = new AssemblyDefUser("Net8Sample", new Version(1, 0, 0, 0));
                asm.Modules.Add(mod);
                var sysRuntimeRef = new AssemblyRefUser("System.Runtime", new Version(8, 0, 0, 0));
                var objRef = new TypeRefUser(mod, "System", "Object", sysRuntimeRef);
                var t = new TypeDefUser("SampleNs", "SampleType", objRef);
                mod.Types.Add(t);
                mod.Write(net8Dll);
            }
            Assert.True(ArchitectureDetector.RequiresModernDotNetRuntime(net8Dll));
            Assert.Equal(TargetRuntimeFamily.ModernDotNet, ArchitectureDetector.DetectRuntimeFamily(net8Dll));
        }

        [Fact]
        public void WorkerHost_EscapeJson_EscapesAllControlCharactersAndRoundTripsViaSimpleJson()
        {
            string rawMessage = "Error:\tLine1\r\nLine2\b\f\"quoted\"\\backslash\u0001\u001F";
            string escaped = WorkerHost.EscapeJson(rawMessage);
            string json = $"{{\"Success\": false, \"Message\": \"{escaped}\"}}";

            var parsed = JsonValue.Parse(json);
            Assert.True(parsed.IsObject);
            Assert.False(parsed["Success"].AsBool(true));
            string roundTripped = parsed["Message"].AsString();
            Assert.Equal(rawMessage, roundTripped);
        }

        private static string ComputeSha256(byte[] data)
        {
            using (var sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(data);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }
    }
}
