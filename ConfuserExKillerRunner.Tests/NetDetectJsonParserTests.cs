using System.Linq;
using ConfuserExKillerRunner.Analysis;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public class NetDetectJsonParserTests
    {
        [Fact]
        public void ParseNetDetectJson_NestedReport_ExtractsAllFields()
        {
            string json = @"
            {
                ""analysis"": {
                    ""file_path"": ""C:\\samples\\target.exe"",
                    ""file_size"": 10240
                },
                ""detection"": {
                    ""detected"": true,
                    ""primary_detector"": ""ConfuserEx"",
                    ""confidence"": ""HIGH"",
                    ""verdict_score"": 85,
                    ""summary"": ""Protected with ConfuserEx 1.0.0"",
                    ""protectors"": [
                        { ""name"": ""ConfuserEx"", ""score"": 85 }
                    ],
                    ""techniques"": [
                        { ""technique"": ""Anti-Tamper"", ""confidence"": ""HIGH"" },
                        { ""technique"": ""Constants Protection"", ""confidence"": ""MEDIUM"" }
                    ]
                }
            }";

            var result = NetDetectIntegration.ParseNetDetectJson(json);

            Assert.True(result.Available);
            Assert.True(result.Detected);
            Assert.Equal("ConfuserEx", result.PrimaryDetector);
            Assert.Equal("HIGH", result.Confidence);
            Assert.Equal(85, result.VerdictScore);
            Assert.Equal("Protected with ConfuserEx 1.0.0", result.Summary);
            Assert.Contains("ConfuserEx", result.Protectors);
            Assert.Contains("Anti-Tamper", result.GenericTechniques);
            Assert.Contains("Constants Protection", result.GenericTechniques);
            Assert.True(result.IsConfuserExPresent);
            Assert.True(result.HasAntiTamper);
            Assert.True(result.HasConstants);
            Assert.False(result.IsKoiVMPresent);
        }

        [Fact]
        public void ParseNetDetectJson_FlatReport_ExtractsCorrectly()
        {
            string json = @"
            {
                ""detected"": false,
                ""primary_detector"": ""None"",
                ""confidence"": ""LOW"",
                ""verdict_score"": 0,
                ""summary"": ""Clean / Unobfuscated"",
                ""protectors"": [],
                ""techniques"": []
            }";

            var result = NetDetectIntegration.ParseNetDetectJson(json);

            Assert.True(result.Available);
            Assert.False(result.Detected);
            Assert.Equal("None", result.PrimaryDetector);
            Assert.Equal(0, result.VerdictScore);
            Assert.Empty(result.Protectors);
            Assert.Empty(result.GenericTechniques);
        }

        [Fact]
        public void ParseNetDetectJson_KoiVMPresent_FlagsCriticalKoiVM()
        {
            string json = @"
            {
                ""detection"": {
                    ""detected"": true,
                    ""primary_detector"": ""KoiVM"",
                    ""confidence"": ""HIGH"",
                    ""verdict_score"": 150,
                    ""protectors"": [ { ""name"": ""KoiVM"" } ],
                    ""techniques"": [ { ""technique"": ""Virtual Machine Interpreter"" } ]
                }
            }";

            var result = NetDetectIntegration.ParseNetDetectJson(json);
            Assert.True(result.IsKoiVMPresent);
        }

        [Fact]
        public void ParseNetDetectJson_MissingOrMalformedProperties_DoesNotCrash()
        {
            string json = "{ \"partial\": 123 }";
            var result = NetDetectIntegration.ParseNetDetectJson(json);

            Assert.True(result.Available);
            Assert.False(result.Detected);
            Assert.Equal("None", result.PrimaryDetector);
            Assert.Equal(0, result.VerdictScore);
        }

        [Fact]
        public void Compare_ScoreIncrease_CorrectInterpretationAndExposedSignatures()
        {
            var preScan = new NetDetectScanResult
            {
                Available = true,
                VerdictScore = 9,
                PrimaryDetector = "ConfuserEx",
                Confidence = "HIGH",
                GenericTechniques = new System.Collections.Generic.List<string> { "Anti-Tamper", "Compressor" }
            };

            var postScan = new NetDetectScanResult
            {
                Available = true,
                VerdictScore = 14,
                PrimaryDetector = "ConfuserEx",
                Confidence = "HIGH",
                GenericTechniques = new System.Collections.Generic.List<string> { "Anti-Tamper", "Constants Protection", "Control Flow Switch" }
            };

            var comp = NetDetectIntegration.Compare(preScan, postScan);

            Assert.True(comp.Available);
            Assert.Equal(9, comp.PreScanScore);
            Assert.Equal(14, comp.PostScanScore);
            Assert.Equal(5, comp.ScoreDelta);
            Assert.True(comp.ScoreDeltaPercent > 55.0 && comp.ScoreDeltaPercent < 56.0);
            Assert.Contains("Compressor", comp.ResolvedSignatures);
            Assert.Contains("Constants Protection", comp.ExposedSignatures);
            Assert.Contains("Control Flow Switch", comp.ExposedSignatures);
            Assert.Contains("Anti-Tamper", comp.PreservedSignatures);
            Assert.Contains("correlates with 2 newly exposed indicator signature(s)", comp.IndicatorInterpretation);
            Assert.Contains("Constants Protection", comp.IndicatorInterpretation);
        }

        [Fact]
        public void Compare_ScoreIncrease_WithoutExposedSignatures_FormulatesUnconfirmedHypothesis()
        {
            var preScan = new NetDetectScanResult
            {
                Available = true,
                VerdictScore = 9,
                PrimaryDetector = "ConfuserEx",
                Confidence = "HIGH",
                GenericTechniques = new System.Collections.Generic.List<string> { "Anti-Tamper" }
            };

            var postScan = new NetDetectScanResult
            {
                Available = true,
                VerdictScore = 21,
                PrimaryDetector = "ConfuserEx",
                Confidence = "HIGH",
                GenericTechniques = new System.Collections.Generic.List<string> { "Anti-Tamper" }
            };

            var comp = NetDetectIntegration.Compare(preScan, postScan);

            Assert.True(comp.Available);
            Assert.Equal(12, comp.ScoreDelta);
            Assert.Empty(comp.ExposedSignatures);
            Assert.Contains("unconfirmed hypothesis: internal marker exposure vs potential transformation artifact", comp.IndicatorInterpretation);
            // Ensure the interpretation does not claim signatures absent from data
            Assert.DoesNotContain("Compressor", comp.IndicatorInterpretation);
            Assert.DoesNotContain("Anti-Debug", comp.IndicatorInterpretation);
        }

        [Fact]
        public void Compare_ScoreReduction_CorrectInterpretationAndResolvedSignatures()
        {
            var preScan = new NetDetectScanResult
            {
                Available = true,
                VerdictScore = 85,
                PrimaryDetector = "ConfuserEx",
                Confidence = "HIGH",
                GenericTechniques = new System.Collections.Generic.List<string> { "Anti-Tamper", "Constants Protection", "Control Flow Switch" }
            };

            var postScan = new NetDetectScanResult
            {
                Available = true,
                VerdictScore = 0,
                PrimaryDetector = "None",
                Confidence = "LOW",
                GenericTechniques = new System.Collections.Generic.List<string>()
            };

            var comp = NetDetectIntegration.Compare(preScan, postScan);

            Assert.True(comp.Available);
            Assert.Equal(85, comp.PreScanScore);
            Assert.Equal(0, comp.PostScanScore);
            Assert.Equal(-85, comp.ScoreDelta);
            Assert.Equal(-100.0, comp.ScoreDeltaPercent);
            Assert.Equal(3, comp.ResolvedSignatures.Count);
            Assert.Empty(comp.ExposedSignatures);
            Assert.Empty(comp.PreservedSignatures);
            Assert.Contains("reflects successful resolution of protector indicators", comp.IndicatorInterpretation);
        }

        [Fact]
        public void Parse_GenericTechniques_SupportsBothTechniqueAndNameFields()
        {
            string json = @"{
                ""detection"": {
                    ""detected"": true,
                    ""verdict_score"": 15,
                    ""primary_detector"": ""ConfuserEx"",
                    ""confidence"": ""HIGH"",
                    ""generic_techniques"": [
                        { ""technique"": ""Invisible Unicode Character Mangling"", ""severity"": ""HIGH"", ""weight"": 5 },
                        { ""name"": ""Suspected String Encryption"", ""severity"": ""MEDIUM"", ""weight"": 2 }
                    ]
                }
            }";

            var result = NetDetectIntegration.ParseNetDetectJson(json);

            Assert.True(result.Available);
            Assert.Equal(15, result.VerdictScore);
            Assert.Equal(2, result.GenericTechniques.Count);
            Assert.Contains("Invisible Unicode Character Mangling", result.GenericTechniques);
            Assert.Contains("Suspected String Encryption", result.GenericTechniques);
        }

        [Fact]
        public void Compare_UnavailableScan_ReturnsAvailableFalse()
        {
            var preScan = new NetDetectScanResult { Available = false };
            var postScan = new NetDetectScanResult { Available = true, VerdictScore = 10 };

            var comp = NetDetectIntegration.Compare(preScan, postScan);
            Assert.False(comp.Available);
        }
    }
}
