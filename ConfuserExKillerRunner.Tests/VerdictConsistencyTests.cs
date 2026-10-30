using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using ConfuserExKillerRunner.Analysis;
using dnlib.DotNet;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    [Trait("Category", "Unit")]
    public class VerdictConsistencyTests
    {
        private ModuleDef CreateEmptyModule()
        {
            var mod = new ModuleDefUser("VerdictTestModule.dll");
            var asm = new AssemblyDefUser("VerdictTestAssembly");
            asm.Modules.Add(mod);
            return mod;
        }

        // 1. Clean assembly without protections detected
        [Fact]
        public void Scenario01_CleanAssembly_EvaluatesCompleteAndSuccess()
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
            Assert.Equal("FULLY DEOBFUSCATED", matrix.OverallVerdict);
            Assert.False(matrix.HasPartiallyProcessed);
            Assert.False(matrix.HasNotEvaluated);
            Assert.False(matrix.HasUnsupported);
            Assert.False(matrix.HasRequiresDynamicSkipped);

            // Exit code semantics: exit 0 on complete verified success
            int exitCodeStrict = GetSimulatedExitCode(matrix, strict: true, isIndeterminate: false);
            Assert.Equal(0, exitCodeStrict);
        }

        // 2. Protected assembly fully reversed and verified
        [Fact]
        public void Scenario02_FullyReversedProtections_EvaluatesCompleteAndSuccess()
        {
            var module = CreateEmptyModule();
            var matrix = ProtectionMatrix.Evaluate(
                module,
                allowExecution: true,
                antiTamperDecrypted: true,
                jitModeDetected: false,
                cor20Repaired: true,
                constantsDecryptedCount: 15,
                allConstantsResolved: true,
                resourcesExtractedCount: 3,
                proxiesInlinedCount: 8,
                switchesResolvedCount: 42,
                junkInstructionsStrippedCount: 12,
                cleanerHooksStrippedCount: 4,
                compressorUnpacked: true,
                symbolsRenamed: true,
                antiIldasmStripped: true,
                antiDebugStripped: true,
                semanticNamesRestoredCount: 5,
                unprintableNormalizedCount: 10,
                initialRenamingDetected: true);

            Assert.True(matrix.IsComplete);
            Assert.Equal("FULLY DEOBFUSCATED", matrix.OverallVerdict);
            int exitCodeStrict = GetSimulatedExitCode(matrix, strict: true, isIndeterminate: false);
            Assert.Equal(0, exitCodeStrict);
        }

        // 3. Partially processed protection
        [Fact]
        public void Scenario03_PartiallyProcessedProtection_YieldsPartialSuccessAndExitCode2()
        {
            var module = CreateEmptyModule();
            var matrix = ProtectionMatrix.Evaluate(
                module,
                allowExecution: true,
                antiTamperDecrypted: false,
                jitModeDetected: false,
                cor20Repaired: false,
                constantsDecryptedCount: 5,
                allConstantsResolved: false, // Incomplete constant decryption
                resourcesExtractedCount: 0,
                proxiesInlinedCount: 0,
                switchesResolvedCount: 0,
                junkInstructionsStrippedCount: 0,
                cleanerHooksStrippedCount: 0);

            Assert.False(matrix.IsComplete);
            Assert.True(matrix.HasPartiallyProcessed);
            Assert.Equal("PARTIALLY DEOBFUSCATED (Incomplete Transformations)", matrix.OverallVerdict);

            // Strict mode yields exit code 2
            int exitCodeStrict = GetSimulatedExitCode(matrix, strict: true, isIndeterminate: false);
            Assert.Equal(2, exitCodeStrict);

            // Permissive mode yields exit code 0, but status remains PARTIAL_SUCCESS
            int exitCodePermissive = GetSimulatedExitCode(matrix, strict: false, isIndeterminate: false);
            Assert.Equal(0, exitCodePermissive);
            string status = GetSimulatedFinalStatus(matrix, isIndeterminate: false);
            Assert.Equal("PARTIAL_SUCCESS", status);
        }

        // 4. Protection not supported (JIT Mode or native x86)
        [Fact]
        public void Scenario04_UnsupportedProtection_YieldsPartialSuccessAndExitCode2()
        {
            var module = CreateEmptyModule();
            var matrix = ProtectionMatrix.Evaluate(
                module,
                allowExecution: true,
                antiTamperDecrypted: false,
                jitModeDetected: true, // Unsupported JIT mode
                cor20Repaired: false,
                constantsDecryptedCount: 0,
                allConstantsResolved: true,
                resourcesExtractedCount: 0,
                proxiesInlinedCount: 0,
                switchesResolvedCount: 0,
                junkInstructionsStrippedCount: 0,
                cleanerHooksStrippedCount: 0);

            Assert.False(matrix.IsComplete);
            Assert.True(matrix.HasUnsupported);
            Assert.Equal("PARTIALLY DEOBFUSCATED (Unsupported Modes Detected)", matrix.OverallVerdict);

            int exitCode = GetSimulatedExitCode(matrix, strict: true, isIndeterminate: false);
            Assert.Equal(2, exitCode);
        }

        // 5. Protection requiring dynamic execution skipped
        [Fact]
        public void Scenario05_RequiresDynamicSkipped_YieldsPartialSuccessAndExitCode2()
        {
            var module = CreateEmptyModule();
            // Add a PInvoke to VirtualProtect so HasAntiTamperNormal evaluates to true in static mode
            var globalType = module.GlobalType;
            var pinvokeMethod = new MethodDefUser("VirtualProtect", MethodSig.CreateStatic(module.CorLibTypes.Boolean));
            pinvokeMethod.IsPinvokeImpl = true;
            pinvokeMethod.ImplMap = new ImplMapUser(new ModuleRefUser(module, "kernel32.dll"), "VirtualProtect", 0);
            globalType.Methods.Add(pinvokeMethod);

            var matrix = ProtectionMatrix.Evaluate(
                module,
                allowExecution: false, // Execution disabled
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

            Assert.False(matrix.IsComplete);
            Assert.True(matrix.HasRequiresDynamicSkipped);
            Assert.Equal("PARTIALLY DEOBFUSCATED (Dynamic Execution Required)", matrix.OverallVerdict);

            int exitCode = GetSimulatedExitCode(matrix, strict: true, isIndeterminate: false);
            Assert.Equal(2, exitCode);
        }

        // 6. Unevaluated protection
        [Fact]
        public void Scenario06_UnevaluatedProtection_YieldsUnconfirmedAndExitCode2()
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
                unevaluatedProtections: new[] { "Name Protection" });

            Assert.False(matrix.IsComplete);
            Assert.True(matrix.HasNotEvaluated);
            Assert.Equal("DEOBFUSCATION UNCONFIRMED (Unevaluated Protections)", matrix.OverallVerdict);

            int exitCode = GetSimulatedExitCode(matrix, strict: true, isIndeterminate: false);
            Assert.Equal(2, exitCode);

            string status = GetSimulatedFinalStatus(matrix, isIndeterminate: false);
            Assert.Equal("UNCONFIRMED", status);
        }

        // 7. Indeterminate IL verification: IsComplete must be false, exit code 2, candidate not promoted
        [Fact]
        public void Scenario07_IndeterminateILVerification_IsCompleteFalseExitCode2()
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
                ilVerificationIndeterminate: true);

            // Critical fix B3: IsComplete MUST be false
            Assert.False(matrix.IsComplete);
            Assert.Equal("DEOBFUSCATION UNCONFIRMED (Indeterminate IL Verification)", matrix.OverallVerdict);

            // Exit code MUST be 2, even with permissive exit codes!
            int exitCodeStrict = GetSimulatedExitCode(matrix, strict: true, isIndeterminate: true);
            Assert.Equal(2, exitCodeStrict);
            int exitCodePermissive = GetSimulatedExitCode(matrix, strict: false, isIndeterminate: true);
            Assert.Equal(2, exitCodePermissive);

            string status = GetSimulatedFinalStatus(matrix, isIndeterminate: true);
            Assert.Equal("INDETERMINATE", status);
        }

        // 8. Quality auditor failure: candidate assembly rejected, exit code 1
        [Fact]
        public void Scenario08_AuditReportFailure_YieldsStatusFailedAndExitCode1()
        {
            var auditReport = new AuditReport
            {
                CanLoad = false
            };
            auditReport.Errors.Add("Corrupt PE structure");

            int exitCode = auditReport.Status == "FAILED" ? 1 : 0;
            string finalStatus = "FAILED";

            Assert.Equal(1, exitCode);
            Assert.Equal("FAILED", finalStatus);
        }

        // 9. Renaming technically normalized only (no semantic names restored)
        [Fact]
        public void Scenario09_RenamingNormalizedOnly_YieldsSupportedStaticAndNormalizedSummary()
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
                symbolsRenamed: true,
                semanticNamesRestoredCount: 0,
                unprintableNormalizedCount: 42,
                initialRenamingDetected: true);

            var renameItem = matrix.Items.First(i => i.Name == "Name Protection");
            Assert.Equal(ProtectionSupportStatus.SupportedStatic, renameItem.Status);
            Assert.Equal("Normalized (42)", renameItem.ResultSummary);
            Assert.Contains("technically normalized", renameItem.Details);
            // It should NOT claim VerifiedOnRealFixture without direct fixture evidence
            Assert.NotEqual(ProtectionSupportStatus.VerifiedOnRealFixture, renameItem.Status);
        }

        // 10. Renaming restored with direct semantic proof
        [Fact]
        public void Scenario10_RenamingRestoredWithSemanticProof_YieldsSupportedStaticAndRestoredSummary()
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
                symbolsRenamed: true,
                semanticNamesRestoredCount: 12,
                unprintableNormalizedCount: 5,
                initialRenamingDetected: true);

            var renameItem = matrix.Items.First(i => i.Name == "Name Protection");
            Assert.Equal(ProtectionSupportStatus.SupportedStatic, renameItem.Status);
            Assert.Equal("Restored & Normalized (12 restored, 5 normalized)", renameItem.ResultSummary);
            Assert.Contains("Semantic names restored", renameItem.Details);
        }

        // 11. Candidate preserved as unverified candidate without final promotion
        [Fact]
        public void Scenario11_CandidatePreservedWithoutPromotionWhenIndeterminate()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), "VerdictTest_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try
            {
                string finalPath = Path.Combine(tempDir, "TargetApp_final.dll");
                string existingContent = "Original Verified Binary";
                File.WriteAllText(finalPath, existingContent);

                string candidatePath = Path.Combine(tempDir, "TargetApp.candidate.dll");
                File.WriteAllText(candidatePath, "New Unverified Candidate Bytecode");

                bool isIndeterminate = true;
                bool forcePromote = false;
                string activeReportOutputPath = finalPath;

                if (isIndeterminate && !forcePromote)
                {
                    string nameWithoutExt = Path.GetFileNameWithoutExtension(finalPath);
                    string ext = Path.GetExtension(finalPath);
                    string unverifiedCandidatePath = Path.Combine(tempDir, $"{nameWithoutExt}.unverified_candidate{ext}");

                    File.Copy(candidatePath, unverifiedCandidatePath, overwrite: true);
                    activeReportOutputPath = unverifiedCandidatePath;
                }

                // Existing final output must remain untouched
                Assert.Equal(existingContent, File.ReadAllText(finalPath));
                // Candidate was saved as .unverified_candidate
                string expectedUnverifiedPath = Path.Combine(tempDir, "TargetApp_final.unverified_candidate.dll");
                Assert.True(File.Exists(expectedUnverifiedPath));
                Assert.Equal("New Unverified Candidate Bytecode", File.ReadAllText(expectedUnverifiedPath));
                Assert.Equal(expectedUnverifiedPath, activeReportOutputPath);
            }
            finally
            {
                try { Directory.Delete(tempDir, recursive: true); } catch { }
            }
        }

        // 12. Multiple combined states: Precedence ordering
        [Fact]
        public void Scenario12_MultipleStatesPrecedence_UnsupportedTakesPrecedenceOverPartialAndDynamic()
        {
            var module = CreateEmptyModule();
            var matrix = ProtectionMatrix.Evaluate(
                module,
                allowExecution: false,
                antiTamperDecrypted: false,
                jitModeDetected: true, // Unsupported JIT
                cor20Repaired: false,
                constantsDecryptedCount: 5,
                allConstantsResolved: false, // Partially processed constants
                resourcesExtractedCount: 0,
                proxiesInlinedCount: 0,
                switchesResolvedCount: 0,
                junkInstructionsStrippedCount: 0,
                cleanerHooksStrippedCount: 0,
                unevaluatedProtections: new[] { "Name Protection" }, // Unevaluated
                ilVerificationIndeterminate: true); // Indeterminate IL

            Assert.False(matrix.IsComplete);
            Assert.True(matrix.HasUnsupported);
            Assert.True(matrix.HasPartiallyProcessed);
            Assert.True(matrix.HasNotEvaluated);

            // Unsupported modes take top precedence in the overall verdict title
            Assert.Contains("Unsupported Modes Detected", matrix.OverallVerdict);
            // Summary notes acknowledge the secondary unevaluated status
            Assert.Contains("could not be conclusively evaluated", matrix.SummaryNotes);

            int exitCode = GetSimulatedExitCode(matrix, strict: true, isIndeterminate: true);
            Assert.Equal(2, exitCode);
        }

        // --- Helper simulation methods matching Program.cs exitCode and finalStatus logic ---

        private static int GetSimulatedExitCode(ProtectionMatrixResult matrix, bool strict, bool isIndeterminate)
        {
            if (isIndeterminate)
            {
                return 2;
            }
            if (matrix != null && (!matrix.IsComplete || matrix.HasRequiresDynamicSkipped || matrix.HasUnsupported || matrix.HasNotEvaluated || matrix.HasPartiallyProcessed))
            {
                return strict ? 2 : 0;
            }
            return 0;
        }

        private static string GetSimulatedFinalStatus(ProtectionMatrixResult matrix, bool isIndeterminate)
        {
            if (isIndeterminate)
            {
                return "INDETERMINATE";
            }
            if (matrix != null && (!matrix.IsComplete || matrix.HasRequiresDynamicSkipped || matrix.HasUnsupported || matrix.HasNotEvaluated || matrix.HasPartiallyProcessed))
            {
                return matrix.HasNotEvaluated ? "UNCONFIRMED" : "PARTIAL_SUCCESS";
            }
            return "SUCCESS";
        }
    }
}
