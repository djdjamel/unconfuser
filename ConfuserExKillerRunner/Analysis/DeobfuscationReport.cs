using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using ConfuserExKillerRunner.Core;

namespace ConfuserExKillerRunner.Analysis
{
    public sealed class FileReportInfo
    {
        public string Path { get; set; } = string.Empty;
        public string Sha256 { get; set; } = string.Empty;
        public long SizeBytes { get; set; }
        public string TargetArchitecture { get; set; } = "Unknown";
        public string TargetFramework { get; set; } = "Unknown";
    }

    public sealed class TransformationReportMetrics
    {
        public int MethodsInspected { get; set; }
        public int MethodsWithBodies { get; set; }
        public int ConstantsDecryptedCount { get; set; }
        public bool AllConstantsResolved { get; set; }
        public int ResourcesExtractedCount { get; set; }
        public int ProxiesInlinedCount { get; set; }
        public int SwitchesResolvedCount { get; set; }
        public int JunkInstructionsStrippedCount { get; set; }
        public int CleanerHooksStrippedCount { get; set; }
    }

    public sealed class QualityAuditReportInfo
    {
        public string Status { get; set; } = "UNKNOWN";
        public bool CanLoad { get; set; }
        public bool StructuralAuditPassed { get; set; }
        public string ILVerificationStatus { get; set; } = "UNVERIFIED";
        public string ILVerificationNotes { get; set; } = string.Empty;
        public int InvalidInstructionsCount { get; set; }
        public int InvalidBranchesCount { get; set; }
        public int InvalidEHCount { get; set; }
        public int StackUnderflowCount { get; set; }
        public int UnresolvedCallSitesCount { get; set; }
        public List<string> Warnings { get; set; } = new List<string>();
        public List<string> Errors { get; set; } = new List<string>();
        public int RegressionsIntroducedCount { get; set; }
        public List<string> Regressions { get; set; } = new List<string>();
    }

    public sealed class NetDetectReportInfo
    {
        public bool Available { get; set; }
        public int PreScanScore { get; set; }
        public int PostScanScore { get; set; }
        public int ScoreDelta { get; set; }
        public double ScoreDeltaPercent { get; set; }
        public string PrimaryDetector { get; set; } = "None";
        public string Confidence { get; set; } = "None";
        public List<string> ResolvedSignatures { get; set; } = new List<string>();
        public List<string> ExposedSignatures { get; set; } = new List<string>();
        public List<string> PreservedSignatures { get; set; } = new List<string>();
        public string IndicatorInterpretation { get; set; } = string.Empty;
    }

    public sealed class DeobfuscationReport
    {
        public string ReportVersion { get; set; } = "1.0.0";
        public string TimestampUtc { get; set; } = DateTime.UtcNow.ToString("o");

        public FileReportInfo Input { get; set; } = new FileReportInfo();
        public FileReportInfo Output { get; set; } = new FileReportInfo();

        public List<ProtectionItem> Protections { get; set; } = new List<ProtectionItem>();
        public TransformationReportMetrics Transformations { get; set; } = new TransformationReportMetrics();
        public QualityAuditReportInfo QualityAudit { get; set; } = new QualityAuditReportInfo();
        public NetDetectReportInfo NetDetect { get; set; }

        public Dictionary<string, long> PassTimingsMs { get; set; } = new Dictionary<string, long>(StringComparer.Ordinal);
        public long TotalElapsedMs { get; set; }
        public long PeakWorkingSetBytes { get; set; }

        public List<string> ExceptionsAndRollbacks { get; set; } = new List<string>();
        public List<string> KnownLimitations { get; set; } = new List<string>();

        public string FinalStatus { get; set; } = "UNKNOWN"; // SUCCESS, PARTIAL_SUCCESS, FAILED
        public string OverallVerdict { get; set; } = string.Empty;
        public int ExitCode { get; set; }
        public string SummaryNotes { get; set; } = string.Empty;

        public static string ComputeSha256(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return string.Empty;

            try
            {
                using (var sha = SHA256.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    byte[] hash = sha.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
            catch
            {
                return string.Empty;
            }
        }

        public JsonValue ToJsonValue()
        {
            var root = JsonValue.NewObject();
            root["reportVersion"] = JsonValue.From(ReportVersion);
            root["timestampUtc"] = JsonValue.From(TimestampUtc);

            // Input
            var inObj = JsonValue.NewObject();
            inObj["path"] = JsonValue.From(Input.Path ?? string.Empty);
            inObj["sha256"] = JsonValue.From(Input.Sha256 ?? string.Empty);
            inObj["sizeBytes"] = JsonValue.From(Input.SizeBytes);
            inObj["targetArchitecture"] = JsonValue.From(Input.TargetArchitecture ?? "Unknown");
            inObj["targetFramework"] = JsonValue.From(Input.TargetFramework ?? "Unknown");
            root["input"] = inObj;

            // Output
            var outObj = JsonValue.NewObject();
            outObj["path"] = JsonValue.From(Output.Path ?? string.Empty);
            outObj["sha256"] = JsonValue.From(Output.Sha256 ?? string.Empty);
            outObj["sizeBytes"] = JsonValue.From(Output.SizeBytes);
            outObj["produced"] = JsonValue.From(!string.IsNullOrEmpty(Output.Path) && File.Exists(Output.Path));
            root["output"] = outObj;

            // Protections
            var protArr = JsonValue.NewArray();
            if (Protections != null)
            {
                foreach (var p in Protections)
                {
                    var pObj = JsonValue.NewObject();
                    pObj["name"] = JsonValue.From(p.Name ?? string.Empty);
                    pObj["mode"] = JsonValue.From(p.Mode ?? string.Empty);
                    pObj["detected"] = JsonValue.From(p.Detected);
                    pObj["status"] = JsonValue.From(p.Status.ToString());
                    pObj["resultSummary"] = JsonValue.From(p.ResultSummary ?? string.Empty);
                    pObj["details"] = JsonValue.From(p.Details ?? string.Empty);
                    protArr.Add(pObj);
                }
            }
            root["protections"] = protArr;

            // Transformations
            var transObj = JsonValue.NewObject();
            transObj["methodsInspected"] = JsonValue.From(Transformations.MethodsInspected);
            transObj["methodsWithBodies"] = JsonValue.From(Transformations.MethodsWithBodies);
            transObj["constantsDecryptedCount"] = JsonValue.From(Transformations.ConstantsDecryptedCount);
            transObj["allConstantsResolved"] = JsonValue.From(Transformations.AllConstantsResolved);
            transObj["resourcesExtractedCount"] = JsonValue.From(Transformations.ResourcesExtractedCount);
            transObj["proxiesInlinedCount"] = JsonValue.From(Transformations.ProxiesInlinedCount);
            transObj["switchesResolvedCount"] = JsonValue.From(Transformations.SwitchesResolvedCount);
            transObj["junkInstructionsStrippedCount"] = JsonValue.From(Transformations.JunkInstructionsStrippedCount);
            transObj["cleanerHooksStrippedCount"] = JsonValue.From(Transformations.CleanerHooksStrippedCount);
            root["transformations"] = transObj;

            // QualityAudit
            var qaObj = JsonValue.NewObject();
            qaObj["status"] = JsonValue.From(QualityAudit.Status ?? "UNKNOWN");
            qaObj["canLoad"] = JsonValue.From(QualityAudit.CanLoad);
            qaObj["structuralAuditPassed"] = JsonValue.From(QualityAudit.StructuralAuditPassed);
            qaObj["ilVerificationStatus"] = JsonValue.From(QualityAudit.ILVerificationStatus ?? "UNVERIFIED");
            qaObj["ilVerificationNotes"] = JsonValue.From(QualityAudit.ILVerificationNotes ?? string.Empty);
            qaObj["invalidInstructionsCount"] = JsonValue.From(QualityAudit.InvalidInstructionsCount);
            qaObj["invalidBranchesCount"] = JsonValue.From(QualityAudit.InvalidBranchesCount);
            qaObj["invalidEHCount"] = JsonValue.From(QualityAudit.InvalidEHCount);
            qaObj["stackUnderflowCount"] = JsonValue.From(QualityAudit.StackUnderflowCount);
            qaObj["unresolvedCallSitesCount"] = JsonValue.From(QualityAudit.UnresolvedCallSitesCount);
            qaObj["regressionsIntroducedCount"] = JsonValue.From(QualityAudit.RegressionsIntroducedCount);

            var warnArr = JsonValue.NewArray();
            if (QualityAudit.Warnings != null)
                foreach (var w in QualityAudit.Warnings) warnArr.Add(JsonValue.From(w));
            qaObj["warnings"] = warnArr;

            var errArr = JsonValue.NewArray();
            if (QualityAudit.Errors != null)
                foreach (var e in QualityAudit.Errors) errArr.Add(JsonValue.From(e));
            qaObj["errors"] = errArr;

            var regArr = JsonValue.NewArray();
            if (QualityAudit.Regressions != null)
                foreach (var r in QualityAudit.Regressions) regArr.Add(JsonValue.From(r));
            qaObj["regressions"] = regArr;

            root["qualityAudit"] = qaObj;

            // NetDetect Triage Comparison
            if (NetDetect != null && NetDetect.Available)
            {
                var ndObj = JsonValue.NewObject();
                ndObj["available"] = JsonValue.From(true);
                ndObj["preScanScore"] = JsonValue.From(NetDetect.PreScanScore);
                ndObj["postScanScore"] = JsonValue.From(NetDetect.PostScanScore);
                ndObj["scoreDelta"] = JsonValue.From(NetDetect.ScoreDelta);
                ndObj["scoreDeltaPercent"] = JsonValue.From(NetDetect.ScoreDeltaPercent);
                ndObj["primaryDetector"] = JsonValue.From(NetDetect.PrimaryDetector ?? "None");
                ndObj["confidence"] = JsonValue.From(NetDetect.Confidence ?? "None");

                var resArr = JsonValue.NewArray();
                foreach (var s in NetDetect.ResolvedSignatures) resArr.Add(JsonValue.From(s));
                ndObj["resolvedSignatures"] = resArr;

                var expArr = JsonValue.NewArray();
                foreach (var s in NetDetect.ExposedSignatures) expArr.Add(JsonValue.From(s));
                ndObj["exposedSignatures"] = expArr;

                var presArr = JsonValue.NewArray();
                foreach (var s in NetDetect.PreservedSignatures) presArr.Add(JsonValue.From(s));
                ndObj["preservedSignatures"] = presArr;

                ndObj["indicatorInterpretation"] = JsonValue.From(NetDetect.IndicatorInterpretation ?? string.Empty);
                root["netDetect"] = ndObj;
            }

            // Timings
            var timingsObj = JsonValue.NewObject();
            if (PassTimingsMs != null)
            {
                foreach (var kvp in PassTimingsMs)
                    timingsObj[kvp.Key] = JsonValue.From(kvp.Value);
            }
            timingsObj["totalElapsedMs"] = JsonValue.From(TotalElapsedMs);
            timingsObj["peakWorkingSetBytes"] = JsonValue.From(PeakWorkingSetBytes);
            root["timings"] = timingsObj;

            // Exceptions & Rollbacks
            var excArr = JsonValue.NewArray();
            if (ExceptionsAndRollbacks != null)
                foreach (var ex in ExceptionsAndRollbacks) excArr.Add(JsonValue.From(ex));
            root["exceptionsAndRollbacks"] = excArr;

            // Known Limitations
            var limArr = JsonValue.NewArray();
            if (KnownLimitations != null)
                foreach (var l in KnownLimitations) limArr.Add(JsonValue.From(l));
            root["knownLimitations"] = limArr;

            // Verdict
            var verdObj = JsonValue.NewObject();
            verdObj["finalStatus"] = JsonValue.From(FinalStatus ?? "UNKNOWN");
            verdObj["overallVerdict"] = JsonValue.From(OverallVerdict ?? string.Empty);
            verdObj["exitCode"] = JsonValue.From(ExitCode);
            verdObj["summaryNotes"] = JsonValue.From(SummaryNotes ?? string.Empty);
            root["verdict"] = verdObj;

            return root;
        }

        public string ToJson(bool pretty = true)
        {
            return ToJsonValue().ToString(pretty);
        }

        public void Save(string outputPath)
        {
            if (string.IsNullOrEmpty(outputPath))
                return;

            string dir = Path.GetDirectoryName(outputPath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            File.WriteAllText(outputPath, ToJson(pretty: true));
        }
    }
}
