using System;
using System.IO;
using ConfuserExKillerRunner.Core;
using ConfuserExKillerRunner.Killers;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    [Trait("Category", "Unit")]
    public class CommandLineOptionsTests
    {
        [Fact]
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
        public void CommandLineOptions_07_SaveMappingReport_NullOrEmptyPath_ThrowsArgumentNullException()
        {
            var result = new SemanticRenamerResult();
            Assert.Throws<ArgumentNullException>(() => result.SaveMappingReport(null));
            Assert.Throws<ArgumentNullException>(() => result.SaveMappingReport(string.Empty));
        }
    }
}
