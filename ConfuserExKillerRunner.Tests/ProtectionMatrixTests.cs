using System;
using System.Linq;
using ConfuserExKillerRunner.Analysis;
using dnlib.DotNet;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public class ProtectionMatrixTests
    {
        private ModuleDef CreateEmptyModule()
        {
            var mod = new ModuleDefUser("TestModule.dll");
            var asm = new AssemblyDefUser("TestAssembly");
            asm.Modules.Add(mod);
            return mod;
        }

        [Fact]
        public void Evaluate_All15Protections_ArePresentInMatrix()
        {
            var module = CreateEmptyModule();
            var matrix = ProtectionMatrix.Evaluate(
                module,
                allowExecution: false,
                antiTamperDecrypted: false,
                jitModeDetected: false,
                cor20Repaired: false,
                constantsDecryptedCount: 0,
                allConstantsResolved: true,
                resourcesExtractedCount: 0,
                proxiesInlinedCount: 0,
                switchesResolvedCount: 0,
                junkInstructionsStrippedCount: 0,
                cleanerHooksStrippedCount: 0);

            Assert.Equal(15, matrix.Items.Count);
            Assert.Contains(matrix.Items, i => i.Name == "Anti-Tamper" && i.Mode == "Normal");
            Assert.Contains(matrix.Items, i => i.Name == "Anti-Tamper" && i.Mode == "JIT");
            Assert.Contains(matrix.Items, i => i.Name == "Anti-Dump");
            Assert.Contains(matrix.Items, i => i.Name == "Anti-Debug");
            Assert.Contains(matrix.Items, i => i.Name == "Anti-ILDasm");
            Assert.Contains(matrix.Items, i => i.Name == "Invalid Metadata");
            Assert.Contains(matrix.Items, i => i.Name == "Constants" && i.Mode.Contains("Normal"));
            Assert.Contains(matrix.Items, i => i.Name == "Constants" && i.Mode.Contains("x86"));
            Assert.Contains(matrix.Items, i => i.Name == "Control Flow" && i.Mode.Contains("Switch"));
            Assert.Contains(matrix.Items, i => i.Name == "Control Flow" && i.Mode.Contains("Junk"));
            Assert.Contains(matrix.Items, i => i.Name == "Control Flow" && i.Mode.Contains("x86"));
            Assert.Contains(matrix.Items, i => i.Name == "Reference Proxies");
            Assert.Contains(matrix.Items, i => i.Name == "Resources");
            Assert.Contains(matrix.Items, i => i.Name == "Compressor");
            Assert.Contains(matrix.Items, i => i.Name == "Name Protection");
        }

        [Fact]
        public void Evaluate_BenignModule_NothingDetected_VerdictFullyDeobfuscated()
        {
            var module = CreateEmptyModule();
            var matrix = ProtectionMatrix.Evaluate(
                module,
                allowExecution: false,
                antiTamperDecrypted: false,
                jitModeDetected: false,
                cor20Repaired: false,
                constantsDecryptedCount: 0,
                allConstantsResolved: true,
                resourcesExtractedCount: 0,
                proxiesInlinedCount: 0,
                switchesResolvedCount: 0,
                junkInstructionsStrippedCount: 0,
                cleanerHooksStrippedCount: 0);

            Assert.True(matrix.IsComplete);
            Assert.False(matrix.HasPartiallyProcessed);
            Assert.False(matrix.HasUnsupported);
            Assert.False(matrix.HasRequiresDynamicSkipped);
            Assert.Equal("FULLY DEOBFUSCATED", matrix.OverallVerdict);
        }

        [Fact]
        public void Evaluate_AntiTamperWithoutAllowExecution_RequiresDynamicExecution()
        {
            var module = CreateEmptyModule();
            // Simulate Anti-Tamper hook in <Module>..cctor
            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL, MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName);
            cctor.Body = new dnlib.DotNet.Emit.CilBody();
            cctor.Body.Instructions.Add(new dnlib.DotNet.Emit.Instruction(dnlib.DotNet.Emit.OpCodes.Call, new MemberRefUser(module, "VirtualProtect", MethodSig.CreateStatic(module.CorLibTypes.Boolean))));
            cctor.Body.Instructions.Add(new dnlib.DotNet.Emit.Instruction(dnlib.DotNet.Emit.OpCodes.Ret));
            module.GlobalType.Methods.Add(cctor);

            var matrix = ProtectionMatrix.Evaluate(
                module,
                allowExecution: false,
                antiTamperDecrypted: false,
                jitModeDetected: false,
                cor20Repaired: false,
                constantsDecryptedCount: 0,
                allConstantsResolved: true,
                resourcesExtractedCount: 0,
                proxiesInlinedCount: 0,
                switchesResolvedCount: 0,
                junkInstructionsStrippedCount: 0,
                cleanerHooksStrippedCount: 0);

            var at = matrix.Items.First(i => i.Name == "Anti-Tamper" && i.Mode == "Normal");
            Assert.True(at.Detected);
            Assert.Equal(ProtectionSupportStatus.RequiresDynamicExecution, at.Status);
            Assert.True(matrix.HasRequiresDynamicSkipped);
            Assert.False(matrix.IsComplete);
            Assert.Contains("Dynamic Execution Required", matrix.OverallVerdict);
        }

        [Fact]
        public void Evaluate_AntiTamperDecrypted_VerifiedOnRealFixture()
        {
            var module = CreateEmptyModule();
            var matrix = ProtectionMatrix.Evaluate(
                module,
                allowExecution: true,
                antiTamperDecrypted: true,
                jitModeDetected: false,
                cor20Repaired: false,
                constantsDecryptedCount: 0,
                allConstantsResolved: true,
                resourcesExtractedCount: 0,
                proxiesInlinedCount: 0,
                switchesResolvedCount: 0,
                junkInstructionsStrippedCount: 0,
                cleanerHooksStrippedCount: 0);

            var at = matrix.Items.First(i => i.Name == "Anti-Tamper" && i.Mode == "Normal");
            Assert.True(at.Detected);
            Assert.Equal(ProtectionSupportStatus.VerifiedOnRealFixture, at.Status);
            Assert.True(matrix.IsComplete);
            Assert.Equal("FULLY DEOBFUSCATED", matrix.OverallVerdict);
        }

        [Fact]
        public void Evaluate_JitModeDetected_FlagsUnsupported()
        {
            var module = CreateEmptyModule();
            var matrix = ProtectionMatrix.Evaluate(
                module,
                allowExecution: true,
                antiTamperDecrypted: false,
                jitModeDetected: true,
                cor20Repaired: false,
                constantsDecryptedCount: 0,
                allConstantsResolved: true,
                resourcesExtractedCount: 0,
                proxiesInlinedCount: 0,
                switchesResolvedCount: 0,
                junkInstructionsStrippedCount: 0,
                cleanerHooksStrippedCount: 0);

            var atJit = matrix.Items.First(i => i.Name == "Anti-Tamper" && i.Mode == "JIT");
            Assert.True(atJit.Detected);
            Assert.Equal(ProtectionSupportStatus.Unsupported, atJit.Status);
            Assert.True(matrix.HasUnsupported);
            Assert.False(matrix.IsComplete);
            Assert.Contains("Unsupported Modes Detected", matrix.OverallVerdict);
        }

        [Fact]
        public void Evaluate_PartialConstants_FlagsPartiallyProcessed()
        {
            var module = CreateEmptyModule();
            var matrix = ProtectionMatrix.Evaluate(
                module,
                allowExecution: true,
                antiTamperDecrypted: false,
                jitModeDetected: false,
                cor20Repaired: false,
                constantsDecryptedCount: 5,
                allConstantsResolved: false,
                resourcesExtractedCount: 0,
                proxiesInlinedCount: 0,
                switchesResolvedCount: 0,
                junkInstructionsStrippedCount: 0,
                cleanerHooksStrippedCount: 0);

            var c = matrix.Items.First(i => i.Name == "Constants" && i.Mode.Contains("Normal"));
            Assert.True(c.Detected);
            Assert.Equal(ProtectionSupportStatus.PartiallyProcessed, c.Status);
            Assert.True(matrix.HasPartiallyProcessed);
            Assert.False(matrix.IsComplete);
            Assert.Contains("Incomplete Transformations", matrix.OverallVerdict);
        }

        [Fact]
        public void Evaluate_AntiDumpRepaired_FlagsVerifiedOnRealFixture()
        {
            var module = CreateEmptyModule();
            var matrix = ProtectionMatrix.Evaluate(
                module,
                allowExecution: false,
                antiTamperDecrypted: false,
                jitModeDetected: false,
                cor20Repaired: true,
                constantsDecryptedCount: 0,
                allConstantsResolved: true,
                resourcesExtractedCount: 0,
                proxiesInlinedCount: 0,
                switchesResolvedCount: 0,
                junkInstructionsStrippedCount: 0,
                cleanerHooksStrippedCount: 0);

            var ad = matrix.Items.First(i => i.Name == "Anti-Dump");
            Assert.True(ad.Detected);
            Assert.Equal(ProtectionSupportStatus.VerifiedOnRealFixture, ad.Status);
            Assert.True(matrix.IsComplete);
        }

        [Fact]
        public void Evaluate_FormatReport_GeneratesReadableTableAndVerdict()
        {
            var module = CreateEmptyModule();
            var matrix = ProtectionMatrix.Evaluate(
                module,
                allowExecution: false,
                antiTamperDecrypted: false,
                jitModeDetected: true,
                cor20Repaired: false,
                constantsDecryptedCount: 0,
                allConstantsResolved: true,
                resourcesExtractedCount: 0,
                proxiesInlinedCount: 0,
                switchesResolvedCount: 0,
                junkInstructionsStrippedCount: 0,
                cleanerHooksStrippedCount: 0);

            string report = ProtectionMatrix.FormatReport(matrix);

            Assert.NotNull(report);
            Assert.Contains("CONFUSEREX PROTECTION COVERAGE & SUPPORT MATRIX", report);
            Assert.Contains("Anti-Tamper", report);
            Assert.Contains("Overall Verdict:", report);
            Assert.Contains("Unsupported Modes Detected", report);
        }
    }
}
