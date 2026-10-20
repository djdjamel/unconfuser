using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using ConfuserExKillerRunner.Analysis;
using ConfuserExKillerRunner.Core;
using ConfuserExKillerRunner.Killers;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public class NegativeFixtureTests : IDisposable
    {
        private readonly string _testDir;

        public NegativeFixtureTests()
        {
            _testDir = Path.Combine(Path.GetTempPath(), "neg_tests_" + Guid.NewGuid().ToString("N"));
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

        private static string GetBenignSamplePath()
        {
            string root = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", ".."));
            string net8Dll = Path.Combine(root, "benchmarks", "BenignSample", "bin", "Release", "net8.0", "BenignSample.dll");
            if (File.Exists(net8Dll)) return net8Dll;

            string net48Exe = Path.Combine(root, "benchmarks", "BenignSample", "bin", "Release", "net48", "BenignSample.exe");
            if (File.Exists(net48Exe)) return net48Exe;

            throw new FileNotFoundException("BenignSample binary not found in release outputs.");
        }

        [Fact]
        public void BenignUnprotectedAssembly_PipelineProducesCleanOutput_PreservesAllElements()
        {
            string benignPath = GetBenignSamplePath();
            string outPath = Path.Combine(_testDir, "benign_deobf.dll");

            int exitCode = Program.Main(new[]
            {
                benignPath,
                "-o", outPath,
                "--no-de4dot",
                "--no-netdetect",
                "--strict-exit-codes"
            });

            Assert.Equal(0, exitCode);
            Assert.True(File.Exists(outPath));

            // Verify with QualityAuditor
            var audit = QualityAuditor.Audit(outPath, runExternalVerifier: false);
            Assert.True(audit.CanLoad);
            Assert.True(audit.StructuralAuditPassed);
            Assert.Equal(0, audit.InvalidInstructionsCount);
            Assert.Equal(0, audit.StackUnderflowCount);

            string srcRuntimeConfig = Path.ChangeExtension(benignPath, ".runtimeconfig.json");
            if (File.Exists(srcRuntimeConfig))
            {
                File.Copy(srcRuntimeConfig, Path.ChangeExtension(outPath, ".runtimeconfig.json"), overwrite: true);
            }

            // Execute output and verify behavior
            var psi = new ProcessStartInfo
            {
                FileName = outPath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? "dotnet" : outPath,
                Arguments = outPath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? $"\"{outPath}\" test" : "test",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            Assert.NotNull(proc);
            string stdout = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(10000);

            Assert.Equal(0, proc.ExitCode);
            Assert.Contains("BENIGN_START", stdout);
            Assert.Contains("CONST_STR:ConfuserEx_Benchmark_Secret_String_2026", stdout);
            Assert.Contains("BENIGN_END", stdout);
        }

        [Fact]
        public void EmbeddedResourcesAndDependencies_ResourcesAreNotStrippedOrCorrupted()
        {
            string modPath = Path.Combine(_testDir, "ResourceSample.dll");
            byte[] customBytes = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x42, 0x13, 0x37 };
            string customText = "ApplicationConfiguration_Data_Token_9988";

            using (var mod = new ModuleDefUser("ResourceSample", Guid.NewGuid()))
            {
                mod.Kind = ModuleKind.Dll;
                var type = new TypeDefUser("ResourceSample", "ConfigHolder", mod.CorLibTypes.Object.TypeDefOrRef);
                mod.Types.Add(type);

                // Add benign embedded resources
                mod.Resources.Add(new EmbeddedResource("appsettings.json", System.Text.Encoding.UTF8.GetBytes(customText)));
                mod.Resources.Add(new EmbeddedResource("binary_payload.dat", customBytes));

                mod.Write(modPath);
            }

            string outPath = Path.Combine(_testDir, "ResourceSample_out.dll");
            int exitCode = Program.Main(new[]
            {
                modPath,
                "-o", outPath,
                "--no-de4dot",
                "--no-netdetect"
            });

            Assert.Equal(0, exitCode);
            Assert.True(File.Exists(outPath));

            using (var readMod = ModuleDefMD.Load(outPath))
            {
                Assert.Equal(2, readMod.Resources.Count);

                var rText = readMod.Resources.Find("appsettings.json") as EmbeddedResource;
                Assert.NotNull(rText);
                string textContent = System.Text.Encoding.UTF8.GetString(rText.GetResourceData());
                Assert.Equal(customText, textContent);

                var rBin = readMod.Resources.Find("binary_payload.dat") as EmbeddedResource;
                Assert.NotNull(rBin);
                Assert.Equal(customBytes, rBin.GetResourceData());
            }
        }

        [Fact]
        public void CosturaPackagingLookalike_AssemblyResolveHook_IsNotClassifiedAsProtectorHook()
        {
            var mod = new ModuleDefUser("CosturaSample", Guid.NewGuid());
            mod.Kind = ModuleKind.Dll;

            var globalType = mod.GlobalType;
            var cctor = new MethodDefUser(".cctor",
                MethodSig.CreateStatic(mod.CorLibTypes.Void),
                dnlib.DotNet.MethodImplAttributes.IL,
                dnlib.DotNet.MethodAttributes.Private | dnlib.DotNet.MethodAttributes.Static | dnlib.DotNet.MethodAttributes.SpecialName | dnlib.DotNet.MethodAttributes.RTSpecialName);
            globalType.Methods.Add(cctor);

            // Create a benign Costura-like assembly loader method
            var costuraLoader = new MethodDefUser("AttachAppDomainResolve",
                MethodSig.CreateStatic(mod.CorLibTypes.Void),
                dnlib.DotNet.MethodImplAttributes.IL,
                dnlib.DotNet.MethodAttributes.Public | dnlib.DotNet.MethodAttributes.Static);
            globalType.Methods.Add(costuraLoader);

            var loaderBody = new CilBody();
            loaderBody.Instructions.Add(Instruction.Create(OpCodes.Nop));
            loaderBody.Instructions.Add(Instruction.Create(OpCodes.Ret));
            costuraLoader.Body = loaderBody;

            // .cctor calls costuraLoader
            var cctorBody = new CilBody();
            cctorBody.Instructions.Add(Instruction.Create(OpCodes.Call, costuraLoader));
            cctorBody.Instructions.Add(Instruction.Create(OpCodes.Ret));
            cctor.Body = cctorBody;

            // Run CleanerKiller
            var cleanResult = CleanerKiller.StripProtectorHooks(mod, resourcesDecrypted: false, constantsDecrypted: false, antiTamperDecrypted: false);

            // Assert benign Costura-like resolver is NOT stripped
            Assert.Equal(0, cleanResult.StrippedHooksCount);
            Assert.Contains(costuraLoader, globalType.Methods);
            Assert.Contains(cctorBody.Instructions, i => i.Operand == costuraLoader);
        }

        [Fact]
        public void BenignHookLookalike_DiagnosticPInvokeMethods_AreNotStripped()
        {
            var mod = new ModuleDefUser("DiagnosticSample", Guid.NewGuid());
            mod.Kind = ModuleKind.Dll;

            var diagType = new TypeDefUser("Diagnostics", "NativeDiagnosticReporter", mod.CorLibTypes.Object.TypeDefOrRef);
            mod.Types.Add(diagType);

            // P/Invoke method for VirtualProtect in benign diagnostic class
            var vpMethod = new MethodDefUser("VirtualProtect",
                MethodSig.CreateStatic(mod.CorLibTypes.Boolean, mod.CorLibTypes.IntPtr, mod.CorLibTypes.UInt32, mod.CorLibTypes.UInt32, mod.CorLibTypes.UInt32.ToByRefSig()),
                dnlib.DotNet.MethodImplAttributes.IL,
                dnlib.DotNet.MethodAttributes.PinvokeImpl | dnlib.DotNet.MethodAttributes.Public | dnlib.DotNet.MethodAttributes.Static);
            vpMethod.ImplMap = new ImplMapUser(new ModuleRefUser(mod, "kernel32.dll"), "VirtualProtect", PInvokeAttributes.CallConvWinapi);
            diagType.Methods.Add(vpMethod);

            // P/Invoke method for IsDebuggerPresent in benign diagnostic class
            var dbgMethod = new MethodDefUser("IsDebuggerPresent",
                MethodSig.CreateStatic(mod.CorLibTypes.Boolean),
                dnlib.DotNet.MethodImplAttributes.IL,
                dnlib.DotNet.MethodAttributes.PinvokeImpl | dnlib.DotNet.MethodAttributes.Public | dnlib.DotNet.MethodAttributes.Static);
            dbgMethod.ImplMap = new ImplMapUser(new ModuleRefUser(mod, "kernel32.dll"), "IsDebuggerPresent", PInvokeAttributes.CallConvWinapi);
            diagType.Methods.Add(dbgMethod);

            // Diagnostic caller method
            var reportMethod = new MethodDefUser("CheckSystemIntegrity",
                MethodSig.CreateStatic(mod.CorLibTypes.Boolean),
                dnlib.DotNet.MethodImplAttributes.IL,
                dnlib.DotNet.MethodAttributes.Public | dnlib.DotNet.MethodAttributes.Static);
            var b = new CilBody();
            b.Instructions.Add(Instruction.Create(OpCodes.Call, dbgMethod));
            b.Instructions.Add(Instruction.Create(OpCodes.Ret));
            reportMethod.Body = b;
            diagType.Methods.Add(reportMethod);

            // Run CleanerKiller
            var cleanResult = CleanerKiller.StripProtectorHooks(mod, resourcesDecrypted: false, constantsDecrypted: false, antiTamperDecrypted: false);

            Assert.Equal(0, cleanResult.StrippedHooksCount);
            Assert.Contains(vpMethod, diagType.Methods);
            Assert.Contains(dbgMethod, diagType.Methods);
            Assert.Contains(reportMethod, diagType.Methods);
        }

        [Fact]
        public void ZeroByteFile_GracefullyHandled_ReturnsExitCode1()
        {
            string emptyFile = Path.Combine(_testDir, "empty.dll");
            File.WriteAllBytes(emptyFile, Array.Empty<byte>());

            string outPath = Path.Combine(_testDir, "empty_out.dll");
            int exitCode = Program.Main(new[] { emptyFile, "-o", outPath });

            Assert.Equal(1, exitCode);
            Assert.False(File.Exists(outPath));
        }

        [Fact]
        public void TruncatedPEFile_GracefullyHandled_ReturnsExitCode1()
        {
            string truncFile = Path.Combine(_testDir, "truncated.exe");
            // Only 16 bytes: "MZ" with incomplete header
            byte[] truncated = new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00 };
            File.WriteAllBytes(truncFile, truncated);

            string outPath = Path.Combine(_testDir, "truncated_out.exe");
            int exitCode = Program.Main(new[] { truncFile, "-o", outPath });

            Assert.Equal(1, exitCode);
            Assert.False(File.Exists(outPath));
        }

        [Fact]
        public void ForeignProtectorMarkers_DoesNotCorruptAssembly()
        {
            string foreignPath = Path.Combine(_testDir, "ForeignSample.dll");
            using (var mod = new ModuleDefUser("ForeignSample", Guid.NewGuid()))
            {
                mod.Kind = ModuleKind.Dll;
                var type = new TypeDefUser("Sample", "BusinessLogic", mod.CorLibTypes.Object.TypeDefOrRef);
                mod.Types.Add(type);

                // Add foreign protector attribute
                var attrType = new TypeDefUser("DotfuscatorAttribute", mod.CorLibTypes.Object.TypeDefOrRef);
                mod.Types.Add(attrType);

                var calcMethod = new MethodDefUser("Add",
                    MethodSig.CreateStatic(mod.CorLibTypes.Int32, mod.CorLibTypes.Int32, mod.CorLibTypes.Int32),
                    dnlib.DotNet.MethodImplAttributes.IL,
                    dnlib.DotNet.MethodAttributes.Public | dnlib.DotNet.MethodAttributes.Static);
                var body = new CilBody();
                body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
                body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1));
                body.Instructions.Add(Instruction.Create(OpCodes.Add));
                body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                calcMethod.Body = body;
                type.Methods.Add(calcMethod);

                mod.Write(foreignPath);
            }

            string outPath = Path.Combine(_testDir, "ForeignSample_out.dll");
            int exitCode = Program.Main(new[]
            {
                foreignPath,
                "-o", outPath,
                "--no-de4dot",
                "--no-netdetect"
            });

            Assert.True(exitCode == 0 || exitCode == 2);
            Assert.True(File.Exists(outPath));

            var audit = QualityAuditor.Audit(outPath, runExternalVerifier: false);
            Assert.True(audit.StructuralAuditPassed);
            Assert.Equal(0, audit.InvalidInstructionsCount);
        }

        [Fact]
        public void UnusualMethods_ComplexExceptionHandlers_PreservesExactStructure()
        {
            var mod = new ModuleDefUser("ComplexEHMod", Guid.NewGuid());
            mod.Kind = ModuleKind.Dll;
            var type = new TypeDefUser("TestType", mod.CorLibTypes.Object.TypeDefOrRef);
            mod.Types.Add(type);

            var method = new MethodDefUser("ComplexMethod",
                MethodSig.CreateStatic(mod.CorLibTypes.Int32, mod.CorLibTypes.Int32),
                dnlib.DotNet.MethodImplAttributes.IL,
                dnlib.DotNet.MethodAttributes.Public | dnlib.DotNet.MethodAttributes.Static);
            type.Methods.Add(method);

            var body = new CilBody { InitLocals = true };
            body.Variables.Add(new Local(mod.CorLibTypes.Int32));
            method.Body = body;

            // IL structure:
            // try1:
            //   try2:
            //     ldarg.0, stloc.0
            //     leave to try1_end
            //   catch Exception:
            //     pop
            //     ldc.i4 -1, stloc.0
            //     leave to try1_end
            // finally:
            //     endfinally
            // ret: ldloc.0, ret
            var try2_start = Instruction.Create(OpCodes.Ldarg_0);
            var stloc0 = Instruction.Create(OpCodes.Stloc_0);
            var leave_try1 = Instruction.Create(OpCodes.Leave_S, (Instruction)null);

            var catch_pop = Instruction.Create(OpCodes.Pop);
            var ldc_m1 = Instruction.Create(OpCodes.Ldc_I4_M1);
            var stloc0_catch = Instruction.Create(OpCodes.Stloc_0);
            var leave_catch = Instruction.Create(OpCodes.Leave_S, (Instruction)null);

            var try1_end = Instruction.Create(OpCodes.Nop);
            var fin_start = Instruction.Create(OpCodes.Nop);
            var endfinally = Instruction.Create(OpCodes.Endfinally);

            var ldloc0 = Instruction.Create(OpCodes.Ldloc_0);
            var ret = Instruction.Create(OpCodes.Ret);

            leave_try1.Operand = ldloc0;
            leave_catch.Operand = ldloc0;

            body.Instructions.Add(try2_start);
            body.Instructions.Add(stloc0);
            body.Instructions.Add(leave_try1);

            body.Instructions.Add(catch_pop);
            body.Instructions.Add(ldc_m1);
            body.Instructions.Add(stloc0_catch);
            body.Instructions.Add(leave_catch);

            body.Instructions.Add(fin_start);
            body.Instructions.Add(endfinally);

            body.Instructions.Add(ldloc0);
            body.Instructions.Add(ret);

            // Handler 1: catch Exception
            var ehCatch = new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                CatchType = mod.CorLibTypes.GetTypeRef("System", "Exception"),
                TryStart = try2_start,
                TryEnd = catch_pop,
                HandlerStart = catch_pop,
                HandlerEnd = fin_start
            };
            body.ExceptionHandlers.Add(ehCatch);

            // Handler 2: finally enclosing outer
            var ehFinally = new ExceptionHandler(ExceptionHandlerType.Finally)
            {
                TryStart = try2_start,
                TryEnd = fin_start,
                HandlerStart = fin_start,
                HandlerEnd = ldloc0
            };
            body.ExceptionHandlers.Add(ehFinally);

            var audit = new AuditReport { CanLoad = true };
            QualityAuditor.AuditMethod(method, audit);

            Assert.True(audit.StructuralAuditPassed);
            Assert.Equal(0, audit.InvalidInstructionsCount);
            Assert.Equal(0, audit.InvalidEHCount);
            Assert.Equal(0, audit.StackUnderflowCount);
        }
    }
}
