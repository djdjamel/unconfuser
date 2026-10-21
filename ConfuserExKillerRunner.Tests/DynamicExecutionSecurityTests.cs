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
