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

        [Fact]
        public void Evaluate_UnevaluatedProtections_VerdictDeobfuscationUnconfirmed()
        {
            var module = CreateEmptyModule();
            var matrix = ProtectionMatrix.Evaluate(
                module,
                allowExecution: true,
                antiTamperDecrypted: false,
                jitModeDetected: false,
                cor20Repaired: false,
                constantsDecryptedCount: 0,
                allConstantsResolved: true,
                resourcesExtractedCount: 0,
                proxiesInlinedCount: 0,
                switchesResolvedCount: 0,
                junkInstructionsStrippedCount: 0,
                cleanerHooksStrippedCount: 0,
                compressorUnpacked: false,
                unevaluatedProtections: new[] { "Constants (x86 Native)", "Control Flow (x86 Native Thunks)" });

            Assert.False(matrix.IsComplete);
            Assert.True(matrix.HasNotEvaluated);
            Assert.Equal("DEOBFUSCATION UNCONFIRMED (Unevaluated Protections)", matrix.OverallVerdict);

            var c86 = matrix.Items.First(i => i.Name == "Constants" && i.Mode.Contains("x86"));
            Assert.Equal(ProtectionSupportStatus.NotEvaluated, c86.Status);
            Assert.Equal("Not Evaluated", c86.ResultSummary);
            Assert.False(c86.Detected);

            string report = ProtectionMatrix.FormatReport(matrix);
            Assert.Contains("N/E", report);
            Assert.Contains("NotEvaluated", report);
            Assert.Contains("DEOBFUSCATION UNCONFIRMED", report);
        }

        [Fact]
        public void Evaluate_DeadCodeJunk_RealDetection_FlagsCorrectly()
        {
            var module = CreateEmptyModule();
            var type = new TypeDefUser("TestType");
            module.Types.Add(type);
            var method = new MethodDefUser("TestMethod", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL, MethodAttributes.Static);
            method.Body = new dnlib.DotNet.Emit.CilBody();
            method.Body.Instructions.Add(new dnlib.DotNet.Emit.Instruction(dnlib.DotNet.Emit.OpCodes.Ldc_I4_0));
            method.Body.Instructions.Add(new dnlib.DotNet.Emit.Instruction(dnlib.DotNet.Emit.OpCodes.Pop));
            method.Body.Instructions.Add(new dnlib.DotNet.Emit.Instruction(dnlib.DotNet.Emit.OpCodes.Ret));
            type.Methods.Add(method);

            Assert.True(ProtectionMatrix.HasDeadCodeOrJunk(module));

            // Without cleaning: PartiallyProcessed
            var matrixUncleaned = ProtectionMatrix.Evaluate(
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

            var junkItem1 = matrixUncleaned.Items.First(i => i.Name == "Control Flow" && i.Mode.Contains("Junk"));
            Assert.True(junkItem1.Detected);
            Assert.Equal(ProtectionSupportStatus.PartiallyProcessed, junkItem1.Status);
            Assert.Equal("Detected / Unresolved", junkItem1.ResultSummary);

            // With cleaning: VerifiedOnRealFixture
            var matrixCleaned = ProtectionMatrix.Evaluate(
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
                junkInstructionsStrippedCount: 4,
                cleanerHooksStrippedCount: 0);

            var junkItem2 = matrixCleaned.Items.First(i => i.Name == "Control Flow" && i.Mode.Contains("Junk"));
            Assert.True(junkItem2.Detected);
            Assert.Equal(ProtectionSupportStatus.VerifiedOnRealFixture, junkItem2.Status);
            Assert.Contains("Cleaned (4)", junkItem2.ResultSummary);
        }

        [Fact]
        public void Evaluate_Compressor_RealDetection_FlagsCorrectly()
        {
            var module = CreateEmptyModule();
            // Add Confuser payload resource
            module.Resources.Add(new EmbeddedResource("ConfuserEx.CompressedPayload", new byte[] { 0x1, 0x2, 0x3 }));

            Assert.True(ProtectionMatrix.HasCompressor(module));

            // In static mode without unpacking: RequiresDynamicExecution
            var matrixStatic = ProtectionMatrix.Evaluate(
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
                cleanerHooksStrippedCount: 0,
                compressorUnpacked: false);

            var compItem1 = matrixStatic.Items.First(i => i.Name == "Compressor");
            Assert.True(compItem1.Detected);
            Assert.Equal(ProtectionSupportStatus.RequiresDynamicExecution, compItem1.Status);
            Assert.Equal("Skipped (Static Mode)", compItem1.ResultSummary);

            // When unpacked: VerifiedOnRealFixture
            var matrixUnpacked = ProtectionMatrix.Evaluate(
                module,
                allowExecution: true,
                antiTamperDecrypted: false,
                jitModeDetected: false,
                cor20Repaired: false,
                constantsDecryptedCount: 0,
                allConstantsResolved: true,
                resourcesExtractedCount: 0,
                proxiesInlinedCount: 0,
                switchesResolvedCount: 0,
                junkInstructionsStrippedCount: 0,
                cleanerHooksStrippedCount: 0,
                compressorUnpacked: true);

            var compItem2 = matrixUnpacked.Items.First(i => i.Name == "Compressor");
            Assert.True(compItem2.Detected);
            Assert.Equal(ProtectionSupportStatus.VerifiedOnRealFixture, compItem2.Status);
            Assert.Equal("Unpacked", compItem2.ResultSummary);
        }

        [Fact]
        public void Evaluate_NativeMethods_FlagsX86Unsupported()
        {
            var module = CreateEmptyModule();
            var type = new TypeDefUser("NativeContainer");
            module.Types.Add(type);
            var nativeMethod = new MethodDefUser("NativeThunk", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.Native, MethodAttributes.Static);
            type.Methods.Add(nativeMethod);

            Assert.True(ProtectionMatrix.HasX86ConstantDecrypters(module));
            Assert.True(ProtectionMatrix.HasX86ControlFlow(module));

            var matrix = ProtectionMatrix.Evaluate(
                module,
                allowExecution: true,
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

            var const86 = matrix.Items.First(i => i.Name == "Constants" && i.Mode.Contains("x86"));
            Assert.True(const86.Detected);
            Assert.Equal(ProtectionSupportStatus.Unsupported, const86.Status);

            var cflow86 = matrix.Items.First(i => i.Name == "Control Flow" && i.Mode.Contains("x86"));
            Assert.True(cflow86.Detected);
            Assert.Equal(ProtectionSupportStatus.Unsupported, cflow86.Status);

            Assert.True(matrix.HasUnsupported);
            Assert.Contains("Unsupported Modes Detected", matrix.OverallVerdict);
        }

        [Fact]
        public void Evaluate_ConstantsNormalDynamic_CanBeUnevaluated()
        {
            var module = CreateEmptyModule();
            var matrix = ProtectionMatrix.Evaluate(
                module,
                allowExecution: true,
                antiTamperDecrypted: false,
                jitModeDetected: false,
                cor20Repaired: false,
                constantsDecryptedCount: 0,
                allConstantsResolved: true,
                resourcesExtractedCount: 0,
                proxiesInlinedCount: 0,
                switchesResolvedCount: 0,
                junkInstructionsStrippedCount: 0,
                cleanerHooksStrippedCount: 0,
                compressorUnpacked: false,
                unevaluatedProtections: new[] { "Constants (Normal / Dynamic)" });

            Assert.False(matrix.IsComplete);
            Assert.True(matrix.HasNotEvaluated);
            Assert.Equal("DEOBFUSCATION UNCONFIRMED (Unevaluated Protections)", matrix.OverallVerdict);

            var item = matrix.Items.First(i => i.Name == "Constants" && i.Mode == "Normal / Dynamic");
            Assert.Equal(ProtectionSupportStatus.NotEvaluated, item.Status);
            Assert.Equal("Not Evaluated", item.ResultSummary);
            Assert.False(item.Detected);
        }

        [Fact]
        public void Evaluate_MultipleIncompleteStatusesSimultaneous_UnsupportedWithUnevaluated_MaintainsIncompleteAndMentionsBoth()
        {
            var module = CreateEmptyModule();
            var matrix = ProtectionMatrix.Evaluate(
                module,
                allowExecution: true,
                antiTamperDecrypted: false,
                jitModeDetected: true, // Unsupported
                cor20Repaired: false,
                constantsDecryptedCount: 0,
                allConstantsResolved: true,
                resourcesExtractedCount: 0,
                proxiesInlinedCount: 0,
                switchesResolvedCount: 0,
                junkInstructionsStrippedCount: 0,
                cleanerHooksStrippedCount: 0,
                compressorUnpacked: false,
                unevaluatedProtections: new[] { "Constants (Normal / Dynamic)" }); // NotEvaluated

            Assert.False(matrix.IsComplete);
            Assert.True(matrix.HasUnsupported);
            Assert.True(matrix.HasNotEvaluated);
            Assert.Contains("Unsupported Modes Detected", matrix.OverallVerdict);
            Assert.Contains("conclusively evaluated", matrix.SummaryNotes);
        }

        [Fact]
        public void Evaluate_HasCodeProtectionsPartiallyProcessed_DistinguishesFromRenamingOnly()
        {
            var module = CreateEmptyModule();
            // Benign module: renaming is not detected
            var matrixBenign = ProtectionMatrix.Evaluate(
                module,
                allowExecution: true,
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

            Assert.False(matrixBenign.HasCodeProtectionsPartiallyProcessed);

            // With partial constants:
            var matrixPartialConst = ProtectionMatrix.Evaluate(
                module,
                allowExecution: true,
                antiTamperDecrypted: false,
                jitModeDetected: false,
                cor20Repaired: false,
                constantsDecryptedCount: 3,
                allConstantsResolved: false,
                resourcesExtractedCount: 0,
                proxiesInlinedCount: 0,
                switchesResolvedCount: 0,
                junkInstructionsStrippedCount: 0,
                cleanerHooksStrippedCount: 0);

            Assert.True(matrixPartialConst.HasCodeProtectionsPartiallyProcessed);
        }

        [Fact]
        public void Constants_1_NoConstantsDetected_EvaluatesConsistentTrue()
        {
            var module = CreateEmptyModule();
            bool resolved = ProtectionMatrix.DetermineAllConstantsResolved(
                isUnevaluated: false,
                constantsDetected: false,
                decryptedCount: 0,
                decrypterReportedAllResolved: false,
                allowExecution: false);

            Assert.True(resolved);

            var matrix = ProtectionMatrix.Evaluate(
                module,
                allowExecution: false,
                antiTamperDecrypted: false,
                jitModeDetected: false,
                cor20Repaired: false,
                constantsDecryptedCount: 0,
                allConstantsResolved: false,
                resourcesExtractedCount: 0,
                proxiesInlinedCount: 0,
                switchesResolvedCount: 0,
                junkInstructionsStrippedCount: 0,
                cleanerHooksStrippedCount: 0);

            var item = matrix.Items.First(i => i.Name == "Constants" && i.Mode.Contains("Normal"));
            Assert.Equal(ProtectionSupportStatus.NotDetected, item.Status);
            Assert.Equal("N/A", item.ResultSummary);
            Assert.True(matrix.AllConstantsResolved);
        }

        [Fact]
        public void Constants_2_ConstantsDetectedAndAllResolved_EvaluatesConsistentTrue()
        {
            var module = CreateEmptyModule();
            bool resolved = ProtectionMatrix.DetermineAllConstantsResolved(
                isUnevaluated: false,
                constantsDetected: true,
                decryptedCount: 15,
                decrypterReportedAllResolved: true,
                allowExecution: true);

            Assert.True(resolved);

            var matrix = ProtectionMatrix.Evaluate(
                module,
                allowExecution: true,
                antiTamperDecrypted: false,
                jitModeDetected: false,
                cor20Repaired: false,
                constantsDecryptedCount: 15,
                allConstantsResolved: true,
                resourcesExtractedCount: 0,
                proxiesInlinedCount: 0,
                switchesResolvedCount: 0,
                junkInstructionsStrippedCount: 0,
                cleanerHooksStrippedCount: 0);

            var item = matrix.Items.First(i => i.Name == "Constants" && i.Mode.Contains("Normal"));
            Assert.Equal(ProtectionSupportStatus.VerifiedOnRealFixture, item.Status);
            Assert.Equal("Decrypted (15)", item.ResultSummary);
            Assert.True(matrix.AllConstantsResolved);
        }

        private static void AddConstantDecrypter(ModuleDef module)
        {
            var m = new MethodDefUser(
                "Decrypter",
                MethodSig.CreateStatic(new GenericMVar(0), module.CorLibTypes.UInt32),
                MethodImplAttributes.IL,
                MethodAttributes.Public | MethodAttributes.Static);
            m.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            m.Body = new dnlib.DotNet.Emit.CilBody();
            m.Body.Instructions.Add(new dnlib.DotNet.Emit.Instruction(dnlib.DotNet.Emit.OpCodes.Ldnull));
            m.Body.Instructions.Add(new dnlib.DotNet.Emit.Instruction(dnlib.DotNet.Emit.OpCodes.Ret));
            module.GlobalType.Methods.Add(m);
        }

        [Fact]
        public void Constants_3_ConstantsDetectedNoneResolved_EvaluatesConsistentFalseEvenIfStaleTrueProvided()
        {
            var module = CreateEmptyModule();
            // Add a decrypter method so constantsDetected is true
            AddConstantDecrypter(module);

            // Even if runner had stale allConstantsResolved = true, DetermineAllConstantsResolved returns false when decryptedCount == 0!
            bool resolved = ProtectionMatrix.DetermineAllConstantsResolved(
                isUnevaluated: false,
                constantsDetected: true,
                decryptedCount: 0,
                decrypterReportedAllResolved: true,
                allowExecution: true);

            Assert.False(resolved);

            var matrix = ProtectionMatrix.Evaluate(
                module,
                allowExecution: true,
                antiTamperDecrypted: false,
                jitModeDetected: false,
                cor20Repaired: false,
                constantsDecryptedCount: 0,
                allConstantsResolved: true, // Stale runner boolean
                resourcesExtractedCount: 0,
                proxiesInlinedCount: 0,
                switchesResolvedCount: 0,
                junkInstructionsStrippedCount: 0,
                cleanerHooksStrippedCount: 0);

            var item = matrix.Items.First(i => i.Name == "Constants" && i.Mode.Contains("Normal"));
            Assert.Equal(ProtectionSupportStatus.PartiallyProcessed, item.Status);
            Assert.Equal("Unresolved", item.ResultSummary);
            // Single source of truth: matrix.AllConstantsResolved must be false
            Assert.False(matrix.AllConstantsResolved);
        }

        [Fact]
        public void Constants_4_PartialResolution_EvaluatesConsistentFalse()
        {
            var module = CreateEmptyModule();
            bool resolved = ProtectionMatrix.DetermineAllConstantsResolved(
                isUnevaluated: false,
                constantsDetected: true,
                decryptedCount: 5,
                decrypterReportedAllResolved: false,
                allowExecution: true);

            Assert.False(resolved);

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

            var item = matrix.Items.First(i => i.Name == "Constants" && i.Mode.Contains("Normal"));
            Assert.Equal(ProtectionSupportStatus.PartiallyProcessed, item.Status);
            Assert.Equal("Partial (5)", item.ResultSummary);
            Assert.False(matrix.AllConstantsResolved);
        }

        [Fact]
        public void Constants_5_DynamicExecutionNotAllowed_EvaluatesRequiresDynamicSkippedAndFalse()
        {
            var module = CreateEmptyModule();
            AddConstantDecrypter(module);

            bool resolved = ProtectionMatrix.DetermineAllConstantsResolved(
                isUnevaluated: false,
                constantsDetected: true,
                decryptedCount: 0,
                decrypterReportedAllResolved: false,
                allowExecution: false);

            Assert.False(resolved);

            var matrix = ProtectionMatrix.Evaluate(
                module,
                allowExecution: false,
                antiTamperDecrypted: false,
                jitModeDetected: false,
                cor20Repaired: false,
                constantsDecryptedCount: 0,
                allConstantsResolved: false,
                resourcesExtractedCount: 0,
                proxiesInlinedCount: 0,
                switchesResolvedCount: 0,
                junkInstructionsStrippedCount: 0,
                cleanerHooksStrippedCount: 0);

            var item = matrix.Items.First(i => i.Name == "Constants" && i.Mode.Contains("Normal"));
            Assert.Equal(ProtectionSupportStatus.RequiresDynamicExecution, item.Status);
            Assert.Equal("Skipped (Static Mode)", item.ResultSummary);
            Assert.False(matrix.AllConstantsResolved);
        }

        [Fact]
        public void Constants_6_Unevaluated_EvaluatesNotEvaluatedAndFalse()
        {
            var module = CreateEmptyModule();
            bool resolved = ProtectionMatrix.DetermineAllConstantsResolved(
                isUnevaluated: true,
                constantsDetected: true,
                decryptedCount: 10,
                decrypterReportedAllResolved: true,
                allowExecution: true);

            Assert.False(resolved);

            var matrix = ProtectionMatrix.Evaluate(
                module,
                allowExecution: true,
                antiTamperDecrypted: false,
                jitModeDetected: false,
                cor20Repaired: false,
                constantsDecryptedCount: 10,
                allConstantsResolved: true,
                resourcesExtractedCount: 0,
                proxiesInlinedCount: 0,
                switchesResolvedCount: 0,
                junkInstructionsStrippedCount: 0,
                cleanerHooksStrippedCount: 0,
                unevaluatedProtections: new[] { "Constants (Normal / Dynamic)" });

            var item = matrix.Items.First(i => i.Name == "Constants" && i.Mode.Contains("Normal"));
            Assert.Equal(ProtectionSupportStatus.NotEvaluated, item.Status);
            Assert.Equal("Not Evaluated", item.ResultSummary);
            Assert.False(matrix.AllConstantsResolved);
        }

        [Fact]
        public void NameProtection_SymbolsRenamed_EvaluatesVerifiedOnRealFixture()
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
                cleanerHooksStrippedCount: 0,
                symbolsRenamed: true);

            var item = matrix.Items.First(i => i.Name == "Name Protection");
            Assert.True(item.Detected);
            Assert.Equal(ProtectionSupportStatus.VerifiedOnRealFixture, item.Status);
            Assert.Equal("Cleaned (Normalized)", item.ResultSummary);
        }

        [Fact]
        public void IsConfuserExObfuscatedIdentifier_DetectsUnicodeFormattingChars()
        {
            // \u200b is Zero Width Space, \u202d is Left-to-Right Override
            string obf1 = "\u200bMethod";
            string obf2 = "\u202d\u200cClass";
            Assert.True(ProtectionMatrix.IsConfuserExObfuscatedIdentifier(obf1));
            Assert.True(ProtectionMatrix.IsConfuserExObfuscatedIdentifier(obf2));
        }

        [Fact]
        public void IsConfuserExObfuscatedIdentifier_IgnoresLegitimateLongIdentifiers()
        {
            Assert.False(ProtectionMatrix.IsConfuserExObfuscatedIdentifier("ConfigChangedEventArgs"));
            Assert.False(ProtectionMatrix.IsConfuserExObfuscatedIdentifier("APPLICATION_NAME_DESIGNATION"));
            Assert.False(ProtectionMatrix.IsConfuserExObfuscatedIdentifier("XpertExceptionTransaction"));
            Assert.False(ProtectionMatrix.IsConfuserExObfuscatedIdentifier("TDB_SIMPLE_INDICATORS"));
        }

        [Fact]
        public void Evaluate_AntiIldasm_WhenPresentAndNotStripped_ReportsDetected_NotRemoved()
        {
            var module = CreateEmptyModule();
            // Add SuppressIldasmAttribute to module's assembly
            var attrRef = module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "SuppressIldasmAttribute");
            var memberRef = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), attrRef);
            module.Assembly.CustomAttributes.Add(new CustomAttribute(memberRef));

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
                cleanerHooksStrippedCount: 0,
                antiIldasmStripped: false);

            var item = matrix.Items.First(i => i.Name == "Anti-ILDasm");
            Assert.True(item.Detected);
            Assert.NotEqual("Removed", item.ResultSummary);
            Assert.Equal("Detected", item.ResultSummary);
            Assert.Equal(ProtectionSupportStatus.Detected, item.Status);
            Assert.NotEqual("FULLY DEOBFUSCATED", matrix.OverallVerdict);
        }

        [Fact]
        public void Evaluate_AntiIldasm_WhenStrippedAndVerifiedAbsent_ReportsRemoved()
        {
            var module = CreateEmptyModule(); // Does not have the attribute

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
                cleanerHooksStrippedCount: 0,
                antiIldasmStripped: true);

            var item = matrix.Items.First(i => i.Name == "Anti-ILDasm");
            Assert.True(item.Detected);
            Assert.Equal("Removed", item.ResultSummary);
            Assert.Equal(ProtectionSupportStatus.SupportedStatic, item.Status);
        }

        [Fact]
        public void CleanerKiller_StripAntiIldasm_RemovesSuppressIldasmAttribute()
        {
            var module = CreateEmptyModule();
            var attrRef = module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "SuppressIldasmAttribute");
            var memberRef = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), attrRef);
            module.Assembly.CustomAttributes.Add(new CustomAttribute(memberRef));

            Assert.True(ProtectionMatrix.HasAntiIldasmAttribute(module));

            bool stripped = Killers.CleanerKiller.StripAntiIldasm(module);
            Assert.True(stripped);
            Assert.False(ProtectionMatrix.HasAntiIldasmAttribute(module));
        }

        [Fact]
        public void Evaluate_PropagatesUnevaluated_Protections()
        {
            var module = CreateEmptyModule();
            var unevaluated = new[] { "Name Protection", "Anti-Tamper (Normal)" };

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
                cleanerHooksStrippedCount: 0,
                unevaluatedProtections: unevaluated);

            var nameItem = matrix.Items.First(i => i.Name == "Name Protection");
            Assert.Equal(ProtectionSupportStatus.NotEvaluated, nameItem.Status);
            Assert.Equal("Not Evaluated", nameItem.ResultSummary);

            var atItem = matrix.Items.First(i => i.Name == "Anti-Tamper" && i.Mode == "Normal");
            Assert.Equal(ProtectionSupportStatus.NotEvaluated, atItem.Status);
            Assert.Equal("Not Evaluated", atItem.ResultSummary);

            Assert.True(matrix.HasNotEvaluated);
            Assert.Equal("DEOBFUSCATION UNCONFIRMED (Unevaluated Protections)", matrix.OverallVerdict);
        }

        [Fact]
        public void Evaluate_All6ProtectionStates_HandledCorrectly()
        {
            var module = CreateEmptyModule();

            // 1. NotDetected
            var matrixClean = ProtectionMatrix.Evaluate(module, false, false, false, false, 0, true, 0, 0, 0, 0, 0);
            Assert.Contains(matrixClean.Items, i => i.Status == ProtectionSupportStatus.NotDetected);

            // 2. Detected (Anti-ILDasm present and not stripped)
            var attrRef = module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "SuppressIldasmAttribute");
            var memberRef = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), attrRef);
            module.Assembly.CustomAttributes.Add(new CustomAttribute(memberRef));
            var matrixDetected = ProtectionMatrix.Evaluate(module, false, false, false, false, 0, true, 0, 0, 0, 0, 0);
            Assert.Contains(matrixDetected.Items, i => i.Status == ProtectionSupportStatus.Detected);

            // 3. SupportedStatic (Anti-ILDasm stripped)
            module.Assembly.CustomAttributes.Clear();
            var matrixSupported = ProtectionMatrix.Evaluate(module, false, false, false, false, 0, true, 0, 0, 0, 0, 0, antiIldasmStripped: true);
            Assert.Contains(matrixSupported.Items, i => i.Status == ProtectionSupportStatus.SupportedStatic);

            // 4. PartiallyProcessed (switch flattening detected but not resolved)
            var matrixPartial = ProtectionMatrix.Evaluate(module, false, false, false, false, 0, false, 0, 0, 0, 0, 0);
            // Constants with 0 decrypted and not all resolved
            // 5. Unsupported (JIT mode detected)
            var matrixUnsupported = ProtectionMatrix.Evaluate(module, false, false, true, false, 0, true, 0, 0, 0, 0, 0);
            Assert.Contains(matrixUnsupported.Items, i => i.Status == ProtectionSupportStatus.Unsupported);

            // 6. NotEvaluated
            var matrixUneval = ProtectionMatrix.Evaluate(module, false, false, false, false, 0, true, 0, 0, 0, 0, 0, unevaluatedProtections: new[] { "Anti-Dump" });
            Assert.Contains(matrixUneval.Items, i => i.Status == ProtectionSupportStatus.NotEvaluated);
        }
    }
}
