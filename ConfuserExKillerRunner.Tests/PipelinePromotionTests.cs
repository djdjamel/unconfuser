using System;
using System.IO;
using ConfuserExKillerRunner.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    [Trait("Category", "Unit")]
    public class PipelinePromotionTests : IDisposable
    {
        private readonly string _testDir;

        public PipelinePromotionTests()
        {
            _testDir = Path.Combine(Path.GetTempPath(), "unconfuser_promo_tests_" + Guid.NewGuid().ToString("N"));
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

        private string CreateTestAssembly(string name, Action<ModuleDefUser> customize)
        {
            string path = Path.Combine(_testDir, name + ".dll");
            var module = new ModuleDefUser(name);
            module.Kind = ModuleKind.Dll;
            module.Characteristics = dnlib.PE.Characteristics.Dll;
            var asm = new AssemblyDefUser(name, new Version(1, 0, 0, 0));
            asm.Modules.Add(module);

            var type = new TypeDefUser("TestNamespace", "TestClass", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            customize?.Invoke(module);

            var options = new dnlib.DotNet.Writer.ModuleWriterOptions(module);
            options.MetaDataOptions.Flags |= dnlib.DotNet.Writer.MetaDataFlags.KeepOldMaxStack;
            options.Logger = DummyLogger.NoThrowInstance;
            module.Write(path, options);
            return path;
        }

        private static string GetBenignSamplePath()
        {
            return TestPathHelper.GetBenignSampleExe();
        }

        [Fact]
        public void Promotion_StructurallyValidCandidate_IsPromotedWithSuccess()
        {
            // Case 1: Structurally valid candidate is promoted
            string inPath = Path.Combine(_testDir, "BenignSample_valid.exe");
            File.Copy(GetBenignSamplePath(), inPath, overwrite: true);

            string outPath = Path.Combine(_testDir, "valid_out.dll");
            string reportPath = Path.Combine(_testDir, "valid_report.json");
            int exitCode = Program.Main(new[] { inPath, "-o", outPath, "--no-de4dot", "--no-netdetect", "--json-report", reportPath });

            Assert.True(exitCode == 0, $"Expected 0, got {exitCode}. Report: {File.ReadAllText(reportPath)}");
            Assert.True(File.Exists(outPath));

            var audit = QualityAuditor.Audit(outPath, runExternalVerifier: false);
            Assert.Equal("CLEAN", audit.Status);
            Assert.True(audit.StructuralAuditPassed);
        }

        [Fact]
        public void Promotion_MissingRequiredOperand_IsRejected()
        {
            // Case 2: Candidate with instruction missing required operand is rejected
            string inPath = CreateTestAssembly("MissingOperandAssembly", mod =>
            {
                var type = mod.Types[1];
                var method = new MethodDefUser("TestMethod", MethodSig.CreateStatic(mod.CorLibTypes.Void));
                method.Body = new CilBody();
                // Call with null operand
                method.Body.Instructions.Add(new Instruction(OpCodes.Call, null));
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                type.Methods.Add(method);
            });

            string outPath = Path.Combine(_testDir, "missing_op_out.dll");
            int exitCode = Program.Main(new[] { inPath, "-o", outPath, "--no-de4dot", "--no-netdetect" });

            Assert.Equal(1, exitCode);
            Assert.False(File.Exists(outPath));
        }

        [Fact]
        public void Promotion_InvalidInstructionOrStackUnderflow_IsRejected()
        {
            // Case 3: Candidate with invalid instruction (stack underflow) is rejected
            string inPath = CreateTestAssembly("StackUnderflowAssembly", mod =>
            {
                var type = mod.Types[1];
                var method = new MethodDefUser("TestMethod", MethodSig.CreateStatic(mod.CorLibTypes.Void));
                method.Body = new CilBody();
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Pop)); // Underflow at IL_0000
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                type.Methods.Add(method);
            });

            string outPath = Path.Combine(_testDir, "stack_underflow_out.dll");
            int exitCode = Program.Main(new[] { inPath, "-o", outPath, "--no-de4dot", "--no-netdetect" });

            Assert.Equal(1, exitCode);
            Assert.False(File.Exists(outPath));
        }

        [Fact]
        public void Promotion_ValidationFailure_PreservesOriginalInput()
        {
            // Case 4: Validation failure preserves original input file intact
            string inPath = CreateTestAssembly("PreserveOriginalAssembly", mod =>
            {
                var type = mod.Types[1];
                var method = new MethodDefUser("TestMethod", MethodSig.CreateStatic(mod.CorLibTypes.Void));
                method.Body = new CilBody();
                method.Body.Instructions.Add(new Instruction(OpCodes.Call, null));
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                type.Methods.Add(method);
            });

            byte[] originalBytes = File.ReadAllBytes(inPath);
            string outPath = Path.Combine(_testDir, "preserve_orig_out.dll");

            int exitCode = Program.Main(new[] { inPath, "-o", outPath, "--no-de4dot", "--no-netdetect" });

            Assert.Equal(1, exitCode);
            Assert.True(File.Exists(inPath));
            byte[] afterBytes = File.ReadAllBytes(inPath);
            Assert.Equal(originalBytes, afterBytes);
        }

        [Fact]
        public void Promotion_ValidationFailure_DoesNotOverwritePreexistingOutput()
        {
            // Case 5: Validation failure never replaces pre-existing valid output
            string inPath = CreateTestAssembly("BadAssembly", mod =>
            {
                var type = mod.Types[1];
                var method = new MethodDefUser("TestMethod", MethodSig.CreateStatic(mod.CorLibTypes.Void));
                method.Body = new CilBody();
                method.Body.Instructions.Add(new Instruction(OpCodes.Call, null));
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                type.Methods.Add(method);
            });

            string outPath = Path.Combine(_testDir, "preexisting_out.dll");
            byte[] existingContent = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04 };
            File.WriteAllBytes(outPath, existingContent);

            int exitCode = Program.Main(new[] { inPath, "-o", outPath, "--no-de4dot", "--no-netdetect" });

            Assert.Equal(1, exitCode);
            Assert.True(File.Exists(outPath));
            byte[] actualContent = File.ReadAllBytes(outPath);
            Assert.Equal(existingContent, actualContent);
        }

        [Fact]
        public void Promotion_JsonStatusAndExitCode_AreStrictlyConsistentOnFailure()
        {
            // Case 9: JSON report status and exitCode are strictly consistent
            string inPath = CreateTestAssembly("JsonStatusAssembly", mod =>
            {
                var type = mod.Types[1];
                var method = new MethodDefUser("TestMethod", MethodSig.CreateStatic(mod.CorLibTypes.Void));
                method.Body = new CilBody();
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Pop)); // Underflow
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                type.Methods.Add(method);
            });

            string outPath = Path.Combine(_testDir, "json_status_out.dll");
            string reportPath = Path.Combine(_testDir, "json_status_report.json");

            int exitCode = Program.Main(new[]
            {
                inPath,
                "-o", outPath,
                "--no-de4dot",
                "--no-netdetect",
                "--json-report", reportPath
            });

            Assert.Equal(1, exitCode);
            Assert.False(File.Exists(outPath));
            Assert.True(File.Exists(reportPath));

            string json = File.ReadAllText(reportPath);
            Assert.Contains("\"finalStatus\": \"FAILED\"", json);
            Assert.Contains("\"exitCode\": 1", json);
            Assert.Contains("Candidate Assembly Rejected by QualityAuditor", json);
        }

        [Fact]
        public void Promotion_CoherentSyntheticAntiTamper_IsPromoted()
        {
            // Case 7: Synthetic Anti-Tamper with valid method bodies is promoted
            string inPath = Path.Combine(_testDir, "BenignSample_at.exe");
            using (var mod = ModuleDefMD.Load(GetBenignSamplePath()))
            {
                var modType = mod.GlobalType;
                var vpMethod = new MethodDefUser("VirtualProtect",
                    MethodSig.CreateStatic(mod.CorLibTypes.Boolean, mod.CorLibTypes.IntPtr, mod.CorLibTypes.UIntPtr, mod.CorLibTypes.UInt32, mod.CorLibTypes.UInt32),
                    MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.PinvokeImpl);
                vpMethod.ImplMap = new ImplMapUser(new ModuleRefUser(mod, "kernel32.dll"), "VirtualProtect", PInvokeAttributes.CallConvWinapi);
                modType.Methods.Add(vpMethod);

                mod.Write(inPath);
            }

            string outPath = Path.Combine(_testDir, "synthetic_at_out.dll");
            int exitCode = Program.Main(new[]
            {
                inPath,
                "-o", outPath,
                "--no-de4dot",
                "--no-netdetect"
            });

            // In static mode without --allow-execution, Anti-Tamper dynamic decryption is skipped:
            // ExitCode is 2 (PARTIAL_SUCCESS), but candidate is structurally coherent so it IS promoted!
            Assert.Equal(2, exitCode);
            Assert.True(File.Exists(outPath));

            var audit = QualityAuditor.Audit(outPath, runExternalVerifier: false);
            Assert.True(audit.StructuralAuditPassed);
        }
    }
}
