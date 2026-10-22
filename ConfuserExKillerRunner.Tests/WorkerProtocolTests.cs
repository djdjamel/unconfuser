using System;
using ConfuserExKillerRunner.Core;
using ConfuserExKillerRunner.Killers;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    [Trait("Category", "Unit")]
    public class WorkerProtocolTests
    {
        [Fact]
        public void ParseAntiTamperMeta_WithValidObjectSections_PopulatesFieldsCorrectly()
        {
            string json = @"{
                ""Status"": ""DecryptionConfirmed"",
                ""Modified"": true,
                ""Message"": ""AntiTamper dynamic extraction succeeded."",
                ""DecryptedSections"": [
                    { ""Section"": "".text"" },
                    { ""Section"": "".data"" }
                ]
            }";

            var result = new AntiTamperResult();
            WorkerProtocol.ParseAntiTamperMeta(json, result);

            Assert.Equal(AntiTamperStatus.DecryptionConfirmed, result.Status);
            Assert.True(result.Modified);
            Assert.Equal("AntiTamper dynamic extraction succeeded.", result.Message);
            Assert.Equal(2, result.DecryptedSections.Count);
            Assert.Contains(".text", result.DecryptedSections);
            Assert.Contains(".data", result.DecryptedSections);
        }

        [Fact]
        public void ParseAntiTamperMeta_WithStringArraySections_PopulatesSectionsCorrectly()
        {
            string json = @"{
                ""Status"": ""NoChangesDetected"",
                ""Modified"": false,
                ""Message"": ""No encrypted sections found."",
                ""DecryptedSections"": ["".text"", "".rdata""]
            }";

            var result = new AntiTamperResult();
            WorkerProtocol.ParseAntiTamperMeta(json, result);

            Assert.Equal(AntiTamperStatus.NoChangesDetected, result.Status);
            Assert.False(result.Modified);
            Assert.Equal("No encrypted sections found.", result.Message);
            Assert.Equal(2, result.DecryptedSections.Count);
            Assert.Contains(".text", result.DecryptedSections);
            Assert.Contains(".rdata", result.DecryptedSections);
        }

        [Fact]
        public void ParseAntiTamperMeta_WithMalformedJson_DoesNotThrowAndPreservesDefaults()
        {
            string json = @"{ ""Status"": ""DecryptionConfirmed"", ""Modified"": true, UNCLOSED SYNTAX ERROR";

            var result = new AntiTamperResult { Status = AntiTamperStatus.Failed, Message = "Initial" };
            WorkerProtocol.ParseAntiTamperMeta(json, result);

            // Defaults preserved, no unhandled exception
            Assert.Equal(AntiTamperStatus.Failed, result.Status);
            Assert.Equal("Initial", result.Message);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("{}")]
        public void ParseAntiTamperMeta_WithEmptyOrBlankJson_HandledGracefully(string json)
        {
            var result = new AntiTamperResult();
            WorkerProtocol.ParseAntiTamperMeta(json, result);

            Assert.Equal(AntiTamperStatus.NotAttempted, result.Status);
            Assert.Empty(result.DecryptedSections);
        }

        [Fact]
        public void ParseCompressorMeta_WithHexEntryPointToken_ParsesSuccessfully()
        {
            string json = @"{
                ""Success"": true,
                ""Message"": ""Unpacked payload successfully."",
                ""EntryPointToken"": ""0x0600002A""
            }";

            var result = new DynamicCompressorResult();
            WorkerProtocol.ParseCompressorMeta(json, result);

            Assert.True(result.Success);
            Assert.Equal("Unpacked payload successfully.", result.Message);
            Assert.Equal(0x0600002Au, result.RecoveredEntryPointToken);
        }

        [Fact]
        public void ParseCompressorMeta_WithNumericEntryPointToken_ParsesSuccessfully()
        {
            string json = @"{
                ""Success"": true,
                ""Message"": ""Unpacked."",
                ""EntryPointToken"": 100663338
            }";

            var result = new DynamicCompressorResult();
            WorkerProtocol.ParseCompressorMeta(json, result);

            Assert.True(result.Success);
            Assert.Equal(100663338u, result.RecoveredEntryPointToken);
        }

        [Fact]
        public void ParseCompressorMeta_WithFailedJson_PopulatesFieldsWithoutThrowing()
        {
            string json = @"{
                ""Success"": false,
                ""Message"": ""Stub execution failed.""
            }";

            var result = new DynamicCompressorResult();
            WorkerProtocol.ParseCompressorMeta(json, result);

            Assert.False(result.Success);
            Assert.Equal("Stub execution failed.", result.Message);
            Assert.Equal(0u, result.RecoveredEntryPointToken);
        }

        [Fact]
        public void ParseCompressorMeta_WithMalformedJson_HandledGracefully()
        {
            string json = @"{ ""Success"": true, ""EntryPointToken"": INVALID";

            var result = new DynamicCompressorResult { Success = false, Message = "Initial" };
            WorkerProtocol.ParseCompressorMeta(json, result);

            Assert.False(result.Success);
            Assert.Equal("Initial", result.Message);
        }

        [Fact]
        public void ParseConstantsMeta_WithValidJson_ReturnsParsedValues()
        {
            string json = @"{
                ""Success"": true,
                ""DecryptedCount"": 42,
                ""ResolvedReferences"": 50,
                ""TotalReferences"": 50,
                ""AllResolved"": true,
                ""Message"": ""Completed: 42 constants decrypted""
            }";

            WorkerProtocol.ParseConstantsMeta(json, out int decryptedCount, out bool allResolved, out string message);

            Assert.Equal(42, decryptedCount);
            Assert.True(allResolved);
            Assert.Equal("Completed: 42 constants decrypted", message);
        }

        [Fact]
        public void ParseConstantsMeta_WithPartialFields_UsesSafeDefaults()
        {
            string json = @"{
                ""Success"": false,
                ""Message"": ""Worker failed during initialization""
            }";

            WorkerProtocol.ParseConstantsMeta(json, out int decryptedCount, out bool allResolved, out string message);

            Assert.Equal(0, decryptedCount);
            Assert.False(allResolved);
            Assert.Equal("Worker failed during initialization", message);
        }

        [Fact]
        public void ParseConstantsMeta_WithMalformedJson_ReturnsDefaultsWithoutThrowing()
        {
            string json = @"{ NOT VALID JSON";

            WorkerProtocol.ParseConstantsMeta(json, out int decryptedCount, out bool allResolved, out string message);

            Assert.Equal(0, decryptedCount);
            Assert.False(allResolved);
            Assert.Null(message);
        }

        [Fact]
        public void ParseResourceMeta_WithValidJson_PopulatesFields()
        {
            string json = @"{
                ""Success"": true,
                ""DecryptedCount"": 3,
                ""Message"": ""Decrypted 3 resources""
            }";

            var result = new DynamicResourceResult();
            WorkerProtocol.ParseResourceMeta(json, result);

            Assert.True(result.Success);
            Assert.Equal(3, result.ExtractedCount);
            Assert.Equal("Decrypted 3 resources", result.Message);
        }

        [Fact]
        public void ParseResourceMeta_WithMalformedJson_HandledGracefully()
        {
            string json = @"{ BROKEN JSON";

            var result = new DynamicResourceResult { Success = false, Message = "Default" };
            WorkerProtocol.ParseResourceMeta(json, result);

            Assert.False(result.Success);
            Assert.Equal("Default", result.Message);
        }

        [Fact]
        public void ParseFieldRvaMeta_WithValidJson_ReturnsCountAndMessage()
        {
            string json = @"{
                ""Success"": true,
                ""RestoredCount"": 8,
                ""Message"": ""Restored 8 FieldRVAs""
            }";

            WorkerProtocol.ParseFieldRvaMeta(json, out int restoredCount, out string message);

            Assert.Equal(8, restoredCount);
            Assert.Equal("Restored 8 FieldRVAs", message);
        }

        [Fact]
        public void ParseFieldRvaMeta_WithMalformedJson_ReturnsDefaults()
        {
            string json = @"{ CORRUPT JSON";

            WorkerProtocol.ParseFieldRvaMeta(json, out int restoredCount, out string message);

            Assert.Equal(0, restoredCount);
            Assert.Null(message);
        }
    }
}
