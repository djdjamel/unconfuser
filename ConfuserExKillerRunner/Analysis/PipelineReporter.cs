using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using ConfuserExKillerRunner.Core;

namespace ConfuserExKillerRunner.Analysis
{
    public static class PipelineReporter
    {
        public static DeobfuscationReport BuildReport(
            string originalInputPath,
            string activeReportOutputPath,
            ArchitectureInfo archInfo,
            ProtectionMatrixResult matrix,
            AuditReport auditReport,
            int totalConstantsDecrypted,
            bool allConstantsResolved,
            int totalResourcesExtracted,
            int totalProxiesInlined,
            int totalSwitchesResolved,
            int totalJunkStripped,
            int totalCleanerHooks,
            Dictionary<string, HookTraceRecord> hookRegistry,
            Dictionary<string, long> stepTimings,
            long totalElapsedMs,
            List<string> exceptionsAndRollbacks,
            List<string> regressions,
            string finalStatus,
            int exitCode,
            bool isIndeterminate,
            NetDetectComparisonResult netDetectComp,
            List<HookTraceRecord> activePreservedHooks)
        {
            string timingNote = "Pipeline stage timings reflect discrete execution time per phase; totalElapsedMs reflects total wall-clock duration including baseline audit, intermediate disk serialization, candidate verification, and report generation.";
            string summaryNotes = isIndeterminate 
                ? (string.IsNullOrEmpty(matrix?.SummaryNotes) ? $"Candidate assembly was preserved as unverified candidate because IL verification was indeterminate. Existing final output (if any) was not overwritten. {timingNote}" : $"{matrix.SummaryNotes} | IL verification was indeterminate; candidate not promoted. {timingNote}")
                : (string.IsNullOrEmpty(matrix?.SummaryNotes) ? timingNote : $"{matrix.SummaryNotes} | {timingNote}");

            var report = new DeobfuscationReport
            {
                Input = new FileReportInfo
                {
                    Path = originalInputPath,
                    Sha256 = DeobfuscationReport.ComputeSha256(originalInputPath),
                    SizeBytes = File.Exists(originalInputPath) ? new FileInfo(originalInputPath).Length : 0,
                    TargetArchitecture = archInfo != null ? archInfo.Architecture.ToString() : "Unknown",
                    PeFormat = archInfo?.PeFormat ?? "Unknown",
                    TargetFramework = ArchitectureDetector.DetectTargetFramework(originalInputPath)
                },
                Output = new FileReportInfo
                {
                    Path = activeReportOutputPath,
                    Sha256 = (!string.IsNullOrEmpty(activeReportOutputPath) && File.Exists(activeReportOutputPath)) ? DeobfuscationReport.ComputeSha256(activeReportOutputPath) : string.Empty,
                    SizeBytes = (!string.IsNullOrEmpty(activeReportOutputPath) && File.Exists(activeReportOutputPath)) ? new FileInfo(activeReportOutputPath).Length : 0,
                    TargetArchitecture = archInfo != null ? archInfo.Architecture.ToString() : "Unknown",
                    PeFormat = archInfo?.PeFormat ?? "Unknown",
                    TargetFramework = ArchitectureDetector.DetectTargetFramework(activeReportOutputPath)
                },
                Protections = matrix?.Items ?? new List<ProtectionItem>(),
                Transformations = new TransformationReportMetrics
                {
                    MethodsInspected = auditReport?.TotalMethods ?? 0,
                    MethodsWithBodies = auditReport?.MethodsWithBody ?? 0,
                    ConstantsDecryptedCount = totalConstantsDecrypted,
                    AllConstantsResolved = matrix?.AllConstantsResolved ?? allConstantsResolved,
                    ResourcesExtractedCount = totalResourcesExtracted,
                    ProxiesInlinedCount = totalProxiesInlined,
                    SwitchesResolvedCount = totalSwitchesResolved,
                    JunkInstructionsStrippedCount = totalJunkStripped,
                    CleanerHooksStrippedCount = totalCleanerHooks
                },
                QualityAudit = new QualityAuditReportInfo
                {
                    Status = auditReport?.Status ?? "CLEAN",
                    CanLoad = auditReport?.CanLoad ?? true,
                    StructuralAuditPassed = auditReport?.StructuralAuditPassed ?? true,
                    ILVerificationStatus = auditReport?.ILVerificationStatus ?? "UNVERIFIED",
                    ILVerificationNotes = auditReport?.ILVerificationNotes ?? string.Empty,
                    InvalidInstructionsCount = auditReport?.InvalidInstructionsCount ?? 0,
                    InvalidBranchesCount = auditReport?.InvalidBranchesCount ?? 0,
                    InvalidEHCount = auditReport?.InvalidEHCount ?? 0,
                    StackUnderflowCount = auditReport?.StackUnderflowCount ?? 0,
                    UnresolvedCallSitesCount = auditReport?.UnresolvedCallSitesCount ?? 0,
                    Warnings = auditReport?.Warnings ?? new List<string>(),
                    Errors = auditReport?.Errors ?? new List<string>(),
                    RegressionsIntroducedCount = regressions?.Count ?? 0,
                    Regressions = regressions ?? new List<string>()
                },
                Hooks = hookRegistry?.Values?.ToList() ?? new List<HookTraceRecord>(),
                PassTimingsMs = stepTimings ?? new Dictionary<string, long>(),
                TotalElapsedMs = totalElapsedMs,
                PeakWorkingSetBytes = Process.GetCurrentProcess().PeakWorkingSet64,
                ExceptionsAndRollbacks = exceptionsAndRollbacks ?? new List<string>(),
                FinalStatus = finalStatus,
                OverallVerdict = matrix?.OverallVerdict ?? (isIndeterminate ? "DEOBFUSCATION UNCONFIRMED (Indeterminate IL Verification)" : finalStatus),
                ExitCode = exitCode,
                SummaryNotes = summaryNotes
            };

            if (netDetectComp != null && netDetectComp.Available)
            {
                report.NetDetect = new NetDetectReportInfo
                {
                    Available = true,
                    PreScanScore = netDetectComp.PreScanScore,
                    PostScanScore = netDetectComp.PostScanScore,
                    ScoreDelta = netDetectComp.ScoreDelta,
                    ScoreDeltaPercent = netDetectComp.ScoreDeltaPercent,
                    PrimaryDetector = netDetectComp.PrimaryDetector,
                    Confidence = netDetectComp.Confidence,
                    ResolvedSignatures = netDetectComp.ResolvedSignatures,
                    ExposedSignatures = netDetectComp.ExposedSignatures,
                    PreservedSignatures = netDetectComp.PreservedSignatures,
                    IndicatorInterpretation = netDetectComp.IndicatorInterpretation
                };
            }

            if (isIndeterminate)
            {
                report.KnownLimitations.Add("External IL verification was indeterminate (e.g. tool crash or internal error). Candidate not promoted to final output.");
            }
            if (matrix != null)
            {
                if (matrix.HasRequiresDynamicSkipped)
                    report.KnownLimitations.Add("Dynamic execution required for full deobfuscation (--allow-execution).");
                if (matrix.HasUnsupported)
                    report.KnownLimitations.Add("Unsupported native x86 machine-code or JIT hooks preserved.");
                if (!matrix.AllConstantsResolved)
                    report.KnownLimitations.Add("Encrypted constants were detected but not all references could be resolved.");
                if (matrix.HasPartiallyProcessed && matrix.AllConstantsResolved)
                    report.KnownLimitations.Add("Some protected members or proxies could not be resolved and were preserved.");
            }
            if (activePreservedHooks != null)
            {
                foreach (var hook in activePreservedHooks)
                {
                    report.KnownLimitations.Add($"Preserved Hook: [{hook.HookType}] {hook.MethodName}: {hook.Reason}");
                }
            }

            return report;
        }

        public static void SaveJsonReport(DeobfuscationReport report, string jsonReportPath, bool verbose)
        {
            if (report == null || string.IsNullOrEmpty(jsonReportPath))
                return;

            try
            {
                report.Save(jsonReportPath);
                Console.WriteLine($"[+] Deobfuscation audit report saved to: {jsonReportPath}");
            }
            catch (Exception ex)
            {
                if (verbose)
                    Console.WriteLine($"[!] Failed to write JSON report: {ex.Message}");
            }
        }
    }
}
