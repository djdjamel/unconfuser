using System;
using System.IO;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public class RealFixturePreparationTests
    {
        private static string GetRepoRoot()
        {
            string root = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", ".."));
            return root;
        }

        [Fact]
        public void ExecuteFixturePreparation_NonExistentScript_ThrowsException()
        {
            string root = GetRepoRoot();
            string nonExistentScript = Path.Combine(root, "benchmarks", "non_existent_script_" + Guid.NewGuid().ToString("N") + ".py");

            var ex = Assert.Throws<InvalidOperationException>(() =>
            {
                RealConfuserExFixtureTests.ExecuteFixturePreparation(root, nonExistentScript, timeoutMs: 5000);
            });

            Assert.Contains("failed", ex.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void ExecuteFixturePreparation_FailingScript_ThrowsInvalidOperationExceptionWithCapturedOutput()
        {
            string root = GetRepoRoot();
            string tempScript = Path.Combine(Path.GetTempPath(), "fail_script_" + Guid.NewGuid().ToString("N") + ".py");
            try
            {
                File.WriteAllText(tempScript, "import sys\nprint('Diagnostic stdout message')\nprint('Fatal stderr error', file=sys.stderr)\nsys.exit(42)\n");

                var ex = Assert.Throws<InvalidOperationException>(() =>
                {
                    RealConfuserExFixtureTests.ExecuteFixturePreparation(root, tempScript, timeoutMs: 5000);
                });

                Assert.Contains("exit code 42", ex.Message);
                Assert.Contains("Fatal stderr error", ex.Message);
            }
            finally
            {
                try { File.Delete(tempScript); } catch { }
            }
        }

        [Fact]
        public void ExecuteFixturePreparation_HangingScript_TimesOutAndKillsProcess()
        {
            string root = GetRepoRoot();
            string tempScript = Path.Combine(Path.GetTempPath(), "hang_script_" + Guid.NewGuid().ToString("N") + ".py");
            try
            {
                // Script sleeps for 30 seconds
                File.WriteAllText(tempScript, "import time\ntime.sleep(30)\n");

                // We provide a tiny timeout of 300 ms
                var ex = Assert.Throws<TimeoutException>(() =>
                {
                    RealConfuserExFixtureTests.ExecuteFixturePreparation(root, tempScript, timeoutMs: 300);
                });

                Assert.Contains("timed out", ex.Message, StringComparison.OrdinalIgnoreCase);
            }
            finally
            {
                try { File.Delete(tempScript); } catch { }
            }
        }

        [Fact]
        public void ExecuteFixturePreparation_RealScript_SucceedsAndGeneratesManifest()
        {
            string root = GetRepoRoot();
            string prepScript = Path.Combine(root, "benchmarks", "prepare_real_fixture.py");

            Assert.True(File.Exists(prepScript), $"prepare_real_fixture.py should exist at {prepScript}");

            // Execute preparation with standard timeout
            RealConfuserExFixtureTests.ExecuteFixturePreparation(root, prepScript, timeoutMs: 60000);

            string fixturePath = Path.Combine(root, "benchmarks", "fixtures", "real_confuserex", "BenignSample.exe");
            string manifestPath = Path.Combine(root, "benchmarks", "fixtures", "real_confuserex", "fixture_manifest.json");

            Assert.True(File.Exists(fixturePath), "BenignSample.exe should exist after preparation");
            Assert.True(File.Exists(manifestPath), "fixture_manifest.json should exist after preparation");

            string manifestJson = File.ReadAllText(manifestPath);
            Assert.Contains("confuserex_toolchain", manifestJson);
            Assert.Contains("source_module", manifestJson);
            Assert.Contains("protection_profile", manifestJson);
            Assert.Contains("fixture", manifestJson);
            Assert.Contains("2b3e5cb7f96589e5377700a5f7f25e9fc6a14539e85256e6ac6e85c07f769f61", manifestJson);
        }
    }
}
