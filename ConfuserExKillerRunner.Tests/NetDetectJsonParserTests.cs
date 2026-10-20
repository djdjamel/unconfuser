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
    }
}
