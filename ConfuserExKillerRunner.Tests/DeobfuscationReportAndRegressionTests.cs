using System;
using System.Collections.Generic;
using System.IO;
using ConfuserExKillerRunner.Analysis;
using ConfuserExKillerRunner.Core;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public class DeobfuscationReportAndRegressionTests : IDisposable
    {
        private readonly string _testDir;

        public DeobfuscationReportAndRegressionTests()
        {
            _testDir = Path.Combine(Path.GetTempPath(), "report_tests_" + Guid.NewGuid().ToString("N"));
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
        public void DetectRegressions_IdentifiesNewErrorsOnly()
        {
            var baseline = new AuditReport
            {
                CanLoad = true,
                Errors = new List<string> { "Pre-existing method defect at 0x06000001" }
            };

            var candidate = new AuditReport
            {
                CanLoad = true,
                Errors = new List<string>
                {
                    "Pre-existing method defect at 0x06000001",
                    "New Stack underflow introduced by engine at 0x06000005"
                }
            };

            var regressions = QualityAuditor.DetectRegressions(baseline, candidate);

            Assert.Single(regressions);
            Assert.Contains("New Stack underflow introduced by engine", regressions[0]);
        }

        [Fact]
        public void DetectRegressions_NoNewErrors_ReturnsEmpty()
        {
            var baseline = new AuditReport
            {
                CanLoad = true,
                Errors = new List<string> { "Pre-existing defect" }
            };

            var candidate = new AuditReport
            {
                CanLoad = true,
                Errors = new List<string> { "Pre-existing defect" }
            };

            var regressions = QualityAuditor.DetectRegressions(baseline, candidate);
            Assert.Empty(regressions);
        }

        [Fact]
        public void DeobfuscationReport_SaveAndParse_RoundtripsAllFields()
        {
            var report = new DeobfuscationReport
            {
                ReportVersion = "1.0.0",
                FinalStatus = "SUCCESS",
                OverallVerdict = "FULLY DEOBFUSCATED",
                ExitCode = 0,
                SummaryNotes = "All protections safely resolved.",
                TotalElapsedMs = 450,
                Input = new FileReportInfo
                {
                    Path = @"C:\in\sample.exe",
                    Sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    SizeBytes = 20480,
                    TargetArchitecture = "x86",
                    TargetFramework = ".NETFramework,Version=v4.8"
                },
                Output = new FileReportInfo
                {
                    Path = @"C:\out\sample_final.exe",
                    Sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    SizeBytes = 18432
                },
                Transformations = new TransformationReportMetrics
                {
                    MethodsInspected = 50,
                    MethodsWithBodies = 40,
                    ConstantsDecryptedCount = 12,
                    AllConstantsResolved = true,
                    ProxiesInlinedCount = 8,
                    SwitchesResolvedCount = 4,
                    CleanerHooksStrippedCount = 2,
                    JunkInstructionsStrippedCount = 20
                },
                QualityAudit = new QualityAuditReportInfo
                {
                    Status = "CLEAN",
                    CanLoad = true,
                    StructuralAuditPassed = true,
                    ILVerificationStatus = "PASSED",
                    ILVerificationNotes = "PEVerify passed."
                }
            };

            report.PassTimingsMs["Step1_AntiTamper"] = 120;
            report.PassTimingsMs["Step2_Constants"] = 150;
            report.Protections.Add(new ProtectionItem
            {
                Name = "Anti-Tamper",
                Mode = "Normal",
                Detected = true,
                Status = ProtectionSupportStatus.VerifiedOnRealFixture,
                ResultSummary = "Decrypted"
            });

            string reportFile = Path.Combine(_testDir, "test_report.json");
            report.Save(reportFile);

            Assert.True(File.Exists(reportFile));
            string jsonContent = File.ReadAllText(reportFile);

            var parsed = JsonValue.Parse(jsonContent);
            Assert.Equal("1.0.0", parsed["reportVersion"].AsString());
            Assert.Equal("SUCCESS", parsed["verdict"]["finalStatus"].AsString());
            Assert.Equal(0, parsed["verdict"]["exitCode"].AsInt());
            Assert.Equal(450, parsed["timings"]["totalElapsedMs"].AsInt());
            Assert.Equal(120, parsed["timings"]["Step1_AntiTamper"].AsInt());

            Assert.Equal(@"C:\in\sample.exe", parsed["input"]["path"].AsString());
            Assert.Equal("x86", parsed["input"]["targetArchitecture"].AsString());
            Assert.Equal(12, parsed["transformations"]["constantsDecryptedCount"].AsInt());
            Assert.Equal("CLEAN", parsed["qualityAudit"]["status"].AsString());
            Assert.Equal("PASSED", parsed["qualityAudit"]["ilVerificationStatus"].AsString());

            var prots = parsed["protections"];
            Assert.Equal(1, prots.Count);
            Assert.Equal("Anti-Tamper", prots[0]["name"].AsString());
            Assert.Equal("VerifiedOnRealFixture", prots[0]["status"].AsString());
        }

        [Fact]
        public void PipelineExecution_GeneratesStageTimingsAndMemoryMetricsInJsonReport()
        {
            string root = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", ".."));
            string samplePath = Path.Combine(root, "benchmarks", "BenignSample", "bin", "Release", "net8.0", "BenignSample.dll");
            if (!File.Exists(samplePath))
            {
                samplePath = Path.Combine(root, "benchmarks", "BenignSample", "bin", "Release", "net48", "BenignSample.exe");
            }

            string outPath = Path.Combine(_testDir, "timing_out.dll");
            string reportPath = Path.Combine(_testDir, "timing_report.json");

            int exitCode = Program.Main(new[]
            {
                samplePath,
                "-o", outPath,
                "--no-de4dot",
                "--no-netdetect",
                "--report-json", reportPath
            });

            Assert.Equal(0, exitCode);
            Assert.True(File.Exists(reportPath));

            string jsonContent = File.ReadAllText(reportPath);
            var parsed = JsonValue.Parse(jsonContent);

            var timings = parsed["timings"];
            Assert.NotNull(timings);
            Assert.True(timings["totalElapsedMs"].AsLong() >= 0);
            Assert.True(timings["peakWorkingSetBytes"].AsLong() > 0);
            Assert.False(timings["Stage0_Compressor"].IsNull);
            Assert.False(timings["Stage1_AntiTamper_HeaderRepair"].IsNull);
            Assert.False(timings["Stage2_Constants_Resources_Proxies"].IsNull);
            Assert.False(timings["Stage3_CleanerHooks"].IsNull);
            Assert.False(timings["Stage4_ControlFlow_DeadCode"].IsNull);
            Assert.False(timings["Stage6_FinalCleanup"].IsNull);
            Assert.False(timings["Stage7_QualityAudit"].IsNull);
        }
    }
}
