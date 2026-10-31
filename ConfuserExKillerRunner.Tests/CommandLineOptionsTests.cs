using System;
using System.IO;
using ConfuserExKillerRunner.Analysis;
using ConfuserExKillerRunner.Core;
using ConfuserExKillerRunner.Killers;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public class CommandLineOptionsTests
    {
        [Fact]
        [Trait("Category", "Unit")]
        public void CommandLineOptions_01_ExportMapping_WithRestoreNames_ShortOption_Success()
        {
            string tempTarget = Path.GetTempFileName();
            string mappingFile = Path.Combine(Path.GetTempPath(), "test_mapping_" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                var args = new[] { tempTarget, "--restore-names", "-m", mappingFile };
                var opts = CommandLineOptions.Parse(args, out string errorMessage);

                Assert.Null(errorMessage);
                Assert.NotNull(opts);
                Assert.True(opts.RestoreSemanticNames);
                Assert.Equal(Path.GetFullPath(mappingFile), opts.ExportMappingPath);
            }
            finally
            {
                if (File.Exists(tempTarget)) File.Delete(tempTarget);
                if (File.Exists(mappingFile)) File.Delete(mappingFile);
            }
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void CommandLineOptions_02_ExportMapping_WithSemanticNames_LongOption_Success()
        {
            string tempTarget = Path.GetTempFileName();
            string mappingFile = Path.Combine(Path.GetTempPath(), "test_mapping_" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                var args = new[] { tempTarget, "--semantic-names", "--export-mapping", mappingFile };
                var opts = CommandLineOptions.Parse(args, out string errorMessage);

                Assert.Null(errorMessage);
                Assert.NotNull(opts);
                Assert.True(opts.RestoreSemanticNames);
                Assert.Equal(Path.GetFullPath(mappingFile), opts.ExportMappingPath);
            }
            finally
            {
                if (File.Exists(tempTarget)) File.Delete(tempTarget);
                if (File.Exists(mappingFile)) File.Delete(mappingFile);
            }
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void CommandLineOptions_03_ExportMapping_WithoutRestoreNames_FailsValidation()
        {
            string tempTarget = Path.GetTempFileName();
            string mappingFile = Path.Combine(Path.GetTempPath(), "test_mapping_" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                var args = new[] { tempTarget, "-m", mappingFile };
                var opts = CommandLineOptions.Parse(args, out string errorMessage);

                Assert.Null(opts);
                Assert.NotNull(errorMessage);
                Assert.Contains("requires --restore-names", errorMessage);
            }
            finally
            {
                if (File.Exists(tempTarget)) File.Delete(tempTarget);
            }
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void CommandLineOptions_04_ExportMapping_LongOption_WithoutRestoreNames_FailsValidation()
        {
            string tempTarget = Path.GetTempFileName();
            string mappingFile = Path.Combine(Path.GetTempPath(), "test_mapping_" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                var args = new[] { tempTarget, "--export-mapping", mappingFile };
                var opts = CommandLineOptions.Parse(args, out string errorMessage);

                Assert.Null(opts);
                Assert.NotNull(errorMessage);
                Assert.Contains("requires --restore-names", errorMessage);
            }
            finally
            {
                if (File.Exists(tempTarget)) File.Delete(tempTarget);
            }
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void CommandLineOptions_05_ExportMapping_MissingPathArgument_FailsValidation()
        {
            string tempTarget = Path.GetTempFileName();
            try
            {
                // Missing path followed by end of args
                var args1 = new[] { tempTarget, "--restore-names", "-m" };
                var opts1 = CommandLineOptions.Parse(args1, out string err1);
                Assert.Null(opts1);
                Assert.Contains("requires a target file path", err1);

                // Missing path followed by another switch
                var args2 = new[] { tempTarget, "--restore-names", "--export-mapping", "--verbose" };
                var opts2 = CommandLineOptions.Parse(args2, out string err2);
                Assert.Null(opts2);
                Assert.Contains("requires a target file path", err2);
            }
            finally
            {
                if (File.Exists(tempTarget)) File.Delete(tempTarget);
            }
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void CommandLineOptions_06_SaveMappingReport_SuccessAndContentVerification()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), "mapping_test_" + Guid.NewGuid().ToString("N"));
            string reportFile = Path.Combine(tempDir, "subfolder", "exported_map.txt");
            try
            {
                var result = new SemanticRenamerResult
                {
                    TypesRenamed = 1,
                    MethodsRenamed = 1,
                    UnprintableNormalized = 1
                };
                result.Decisions.Add(new RenameDecision
                {
                    OriginalName = "Class101",
                    NewName = "MainClientForm",
                    SymbolType = "Type",
                    Confidence = RenameConfidence.StrongReference,
                    Justification = "Control.Name 'MainClientForm' match",
                    Applied = true
                });
                result.Decisions.Add(new RenameDecision
                {
                    OriginalName = "\u200B\u200CInitEngine",
                    NewName = "Normalized_Method_0001",
                    SymbolType = "Method",
                    Confidence = RenameConfidence.HighConfidence,
                    Justification = "Unprintable Unicode normalized",
                    Applied = true
                });

                // Save mapping report to nested directory that does not yet exist
                result.SaveMappingReport(reportFile);

                Assert.True(File.Exists(reportFile));
                string content = File.ReadAllText(reportFile);
                Assert.Contains("SEMANTIC RENAMING MAPPING REPORT", content);
                Assert.Contains("MainClientForm", content);
                Assert.Contains("Class101", content);
                Assert.Contains("Normalized_Method_0001", content);
            }
            finally
            {
                if (Directory.Exists(tempDir))
                {
                    try { Directory.Delete(tempDir, recursive: true); } catch { }
                }
            }
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void CommandLineOptions_07_SaveMappingReport_NullOrEmptyPath_ThrowsArgumentNullException()
        {
            var result = new SemanticRenamerResult();
            Assert.Throws<ArgumentNullException>(() => result.SaveMappingReport(null));
            Assert.Throws<ArgumentNullException>(() => result.SaveMappingReport(string.Empty));
        }

        [Fact]
        [Trait("Category", "Integration")]
        public void CommandLineOptions_08_ProgramMain_ExplicitMappingExportFailure_ReturnsExitCode1AndSetsStatusFailed()
        {
            // Deterministic I/O failure strategy: Create a temporary file, and point the mapping path to a subpath inside that file.
            // On any OS, a regular file cannot be treated as a parent directory, so Directory.CreateDirectory
            // deterministically throws an IOException without relying on OS-specific invalid path characters.
            string tempFile = Path.GetTempFileName();
            string impossibleMappingPath = Path.Combine(tempFile, "nested_dir", "mapping.txt");

            string tempDir = Path.Combine(Path.GetTempPath(), "cli_test_fail_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            string inPath = Path.Combine(tempDir, "input.exe");
            string outPath = Path.Combine(tempDir, "output.exe");
            string reportPath = Path.Combine(tempDir, "report.json");

            var originalError = Console.Error;
            var swError = new StringWriter();
            try
            {
                File.Copy(TestPathHelper.GetBenignSampleExe(), inPath, overwrite: true);
                Console.SetError(swError);

                var args = new[]
                {
                    inPath,
                    "-o", outPath,
                    "--restore-names",
                    "-m", impossibleMappingPath,
                    "--json-report", reportPath,
                    "--no-de4dot",
                    "--no-netdetect"
                };

                int exitCode = Program.Main(args);

                // 1. Explicit export failure must yield exit code 1
                Assert.Equal(1, exitCode);

                // 2. The error must be diagnosed in Console.Error and not swallowed or converted to a benign warning
                string errOutput = swError.ToString();
                Assert.Contains("Failed to export mapping report", errOutput);

                // 3. Final status in JSON report must be FAILED, exitCode 1, and exception documented
                Assert.True(File.Exists(reportPath));
                string jsonText = File.ReadAllText(reportPath);
                var parsed = JsonValue.Parse(jsonText);

                Assert.Equal("FAILED", parsed["verdict"]["finalStatus"].AsString());
                Assert.Equal(1, parsed["verdict"]["exitCode"].AsInt());

                var excList = parsed["exceptionsAndRollbacks"];
                Assert.True(excList.Count > 0);
                bool hasExplicitMappingError = false;
                for (int i = 0; i < excList.Count; i++)
                {
                    if (excList[i].AsString().Contains("Explicit mapping export failed"))
                    {
                        hasExplicitMappingError = true;
                        break;
                    }
                }
                Assert.True(hasExplicitMappingError);
            }
            finally
            {
                Console.SetError(originalError);
                try { if (File.Exists(tempFile)) File.Delete(tempFile); } catch { }
                try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true); } catch { }
            }
        }

        [Fact]
        [Trait("Category", "Integration")]
        public void CommandLineOptions_09_ProgramMain_DefaultMappingExport_DoesNotFailOnNormalRun()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), "cli_test_default_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            string inPath = Path.Combine(tempDir, "input.exe");
            string outPath = Path.Combine(tempDir, "output.exe");
            string reportPath = Path.Combine(tempDir, "report.json");

            try
            {
                File.Copy(TestPathHelper.GetBenignSampleExe(), inPath, overwrite: true);

                var args = new[]
                {
                    inPath,
                    "-o", outPath,
                    "--restore-names",
                    "--json-report", reportPath,
                    "--no-de4dot",
                    "--no-netdetect"
                };

                int exitCode = Program.Main(args);

                Assert.Equal(0, exitCode);
                Assert.True(File.Exists(outPath));

                // Default auto-export generates .rename_map.txt alongside output
                string expectedDefaultMap = Path.ChangeExtension(outPath, ".rename_map.txt");
                Assert.True(File.Exists(expectedDefaultMap));

                Assert.True(File.Exists(reportPath));
                var parsed = JsonValue.Parse(File.ReadAllText(reportPath));
                Assert.Equal("SUCCESS", parsed["verdict"]["finalStatus"].AsString());
                Assert.Equal(0, parsed["verdict"]["exitCode"].AsInt());
            }
            finally
            {
                try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true); } catch { }
            }
        }

        [Fact]
        [Trait("Category", "Unit")]
        public void CommandLineOptions_10_ExportMapping_InvalidPath_FailsValidation()
        {
            string tempTarget = Path.GetTempFileName();
            try
            {
                var args = new[] { tempTarget, "--restore-names", "-m", "   " };
                var opts = CommandLineOptions.Parse(args, out string err);
                Assert.Null(opts);
                Assert.Contains("Invalid path specified for --export-mapping", err);
            }
            finally
            {
                if (File.Exists(tempTarget)) File.Delete(tempTarget);
            }
        }
    }
}
