using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using ConfuserExKillerRunner.Analysis;
using dnlib.DotNet;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    [Trait("Category", "Integration")]
    public class RealConfuserExFixtureTests : IDisposable
    {
        private readonly string _testDir;

        public RealConfuserExFixtureTests()
        {
            _testDir = Path.Combine(Path.GetTempPath(), "real_cex_tests_" + Guid.NewGuid().ToString("N"));
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

        internal static void ExecuteFixturePreparation(string root, string prepScript, int timeoutMs = 60000)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "python",
                Arguments = $"\"{prepScript}\"",
                WorkingDirectory = root,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };

            using (var p = Process.Start(psi))
            {
                if (p == null)
                    throw new InvalidOperationException("Failed to start python process for fixture preparation.");

                bool exited = p.WaitForExit(timeoutMs);
                if (!exited)
                {
                    try
                    {
                        p.Kill();
                    }
                    catch
                    {
                        // Process may have exited just before kill
                    }
                    throw new TimeoutException($"Fixture preparation script '{prepScript}' timed out after {timeoutMs}ms.");
                }

                if (p.ExitCode != 0)
                {
                    string err = p.StandardError.ReadToEnd();
                    string stdout = p.StandardOutput.ReadToEnd();
                    throw new InvalidOperationException($"Fixture preparation failed (exit code {p.ExitCode}): {err}\n{stdout}");
                }
            }
        }

        private static string GetFixturePath(string relativePath)
        {
            string root = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", ".."));
            string fullPath = Path.Combine(root, relativePath);
            if (!File.Exists(fullPath))
            {
                string prepScript = Path.Combine(root, "benchmarks", "prepare_real_fixture.py");
                if (relativePath.Contains("real_confuserex") && File.Exists(prepScript))
                {
                    ExecuteFixturePreparation(root, prepScript, timeoutMs: 60000);
                }
            }

            if (!File.Exists(fullPath))
                throw new FileNotFoundException($"Fixture not found at {fullPath}. Please run 'python benchmarks/prepare_real_fixture.py' to generate it.");
            return fullPath;
        }

        [Fact]
        public void RealConfuserEx_DynamicExecution_DeobfuscatesAndMatchesBaseline()
        {
            string fixturePath = GetFixturePath(Path.Combine("benchmarks", "fixtures", "real_confuserex", "BenignSample.exe"));
            string outPath = Path.Combine(_testDir, "real_cex_deobf.exe");

            int exitCode = Program.Main(new[]
            {
                fixturePath,
                "-o", outPath,
                "--allow-execution",
                "--no-de4dot",
                "--no-netdetect"
            });

            Assert.Equal(0, exitCode);
            Assert.True(File.Exists(outPath));
            string unverifiedPath = Path.Combine(_testDir, "real_cex_deobf.unverified_candidate.exe");
            Assert.False(File.Exists(unverifiedPath), "Did not expect an unverified candidate on a successful run.");

            // QualityAuditor verification
            var audit = QualityAuditor.Audit(outPath, runExternalVerifier: false);
            Assert.True(audit.CanLoad);
            Assert.True(audit.StructuralAuditPassed);
            Assert.Equal(0, audit.InvalidInstructionsCount);
            Assert.Equal(0, audit.StackUnderflowCount);

            // Execute deobfuscated binary and assert exact behavioral baseline match
            var psi = new ProcessStartInfo
            {
                FileName = outPath,
                Arguments = "test",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            Assert.NotNull(proc);
            string stdout = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(10000);

            Assert.Equal(0, proc.ExitCode);
            Assert.Contains("BENIGN_START", stdout);
            Assert.Contains("CONST_STR:ConfuserEx_Benchmark_Secret_String_2026", stdout);
            Assert.Contains("CONST_NUM:133742:9223372036854775800", stdout);
            Assert.Contains("CFLOW:100:30:35:95", stdout);
            Assert.Contains("PROXY:42", stdout);
            Assert.Contains("RESOURCE:HELLO_FROM_BENIGN_EMBEDDED_RESOURCE", stdout);
            Assert.Contains("GENERIC_WORKER:ITEM_PAYLOAD:TAG_99:POS:50", stdout);
            Assert.Contains("CAUGHT:Zero multiplier encountered:ZERO_OR_NEG", stdout);
            Assert.Contains("BENIGN_END", stdout);

            // Verify module structure: manifest resource re-embedded
            using var module = ModuleDefMD.Load(outPath);
            Assert.NotEmpty(module.Resources);
            bool hasResource = module.Resources.Any(r => r is EmbeddedResource er && er.GetResourceData().Length > 0);
            Assert.True(hasResource);
        }

        [Fact]
        public void RealConfuserEx_StaticExecution_PreservesAssemblyAndExitsWithPartialCode()
        {
            string fixturePath = GetFixturePath(Path.Combine("benchmarks", "fixtures", "real_confuserex", "BenignSample.exe"));
            string outPath = Path.Combine(_testDir, "real_cex_static.exe");

            int exitCode = Program.Main(new[]
            {
                fixturePath,
                "-o", outPath,
                "--no-de4dot",
                "--no-netdetect",
                "--strict-exit-codes"
            });

            // Dynamic constants & resources require runtime execution, so strict static exit code is 2
            Assert.Equal(2, exitCode);
            Assert.True(File.Exists(outPath));

            var audit = QualityAuditor.Audit(outPath, runExternalVerifier: false);
            Assert.True(audit.CanLoad);
            Assert.True(audit.StructuralAuditPassed);
        }

        [Fact]
        public void RealConfuserExAntiTamper_DynamicExecution_DecryptsSectionsAndMatchesBaseline()
        {
            string fixturePath = GetFixturePath(Path.Combine("benchmarks", "fixtures", "real_confuserex_antitamper", "BenignSample.exe"));
            string outPath = Path.Combine(_testDir, "real_at_deobf.exe");

            int exitCode = Program.Main(new[]
            {
                fixturePath,
                "-o", outPath,
                "--allow-execution",
                "--no-de4dot",
                "--no-netdetect"
            });

            Assert.Equal(0, exitCode);
            Assert.True(File.Exists(outPath), $"Expected cleaned assembly at {outPath}");
            string unverifiedPath = Path.Combine(_testDir, "real_at_deobf.unverified_candidate.exe");
            Assert.False(File.Exists(unverifiedPath), "Did not expect an unverified candidate on a successful run.");

            var audit = QualityAuditor.Audit(outPath, runExternalVerifier: false);
            Assert.True(audit.CanLoad);
            Assert.True(audit.StructuralAuditPassed);
            Assert.Equal(0, audit.InvalidInstructionsCount);
            Assert.Equal(0, audit.StackUnderflowCount);

            // Assertions on final state of protection & residual references
            using (var module = ModuleDefMD.Load(outPath))
            {
                var cctor = module.GlobalType?.FindStaticConstructor();
                Assert.NotNull(cctor);
                // Zero residual calls to AntiTamper protector in <Module>.cctor
                Assert.DoesNotContain(cctor.Body.Instructions, i =>
                    (i.OpCode == dnlib.DotNet.Emit.OpCodes.Call || i.OpCode == dnlib.DotNet.Emit.OpCodes.Callvirt) &&
                    i.Operand != null && i.Operand.ToString().Contains("AntiTamper"));

                // Protector P/Invoke (VirtualProtect) pruned from <Module>
                Assert.DoesNotContain(module.GlobalType.Methods, m => m.IsPinvokeImpl && m.ImplMap?.Name == "VirtualProtect");

                // Every user method has readable, non-empty CIL
                foreach (var type in module.GetTypes())
                {
                    if (type.IsGlobalModuleType) continue;
                    foreach (var m in type.Methods)
                    {
                        if (m.HasBody)
                        {
                            Assert.NotEmpty(m.Body.Instructions);
                        }
                    }
                }
            }

            var psi = new ProcessStartInfo
            {
                FileName = outPath,
                Arguments = "test",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            Assert.NotNull(proc);
            string stdout = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(10000);

            Assert.Equal(0, proc.ExitCode);
            Assert.Contains("BENIGN_START", stdout);
            Assert.Contains("BENIGN_END", stdout);
        }

        [Fact]
        public void RealConfuserExAntiTamper_StaticExecution_BypassesEncryptedILWithoutCorrupting()
        {
            string fixturePath = GetFixturePath(Path.Combine("benchmarks", "fixtures", "real_confuserex_antitamper", "BenignSample.exe"));
            string outPath = Path.Combine(_testDir, "real_at_static.exe");

            int exitCode = Program.Main(new[]
            {
                fixturePath,
                "-o", outPath,
                "--no-de4dot",
                "--no-netdetect",
                "--strict-exit-codes"
            });

            // Static mode skips AntiTamper decryption and returns exit code 2
            Assert.Equal(2, exitCode);
            Assert.True(File.Exists(outPath));

            using var module = ModuleDefMD.Load(outPath);
            Assert.NotNull(module);
            Assert.True(module.Types.Count > 0);
        }

        [Fact]
        public void RealConfuserEx_AntiTamperAndConstants_DynamicExecution_DeobfuscatesBothLayers()
        {
            string fixturePath = GetFixturePath(Path.Combine("benchmarks", "fixtures", "real_confuserex_antitamper_constants", "BenignSample.exe"));
            string outPath = Path.Combine(_testDir, "real_atc_deobf.exe");

            int exitCode = Program.Main(new[]
            {
                fixturePath,
                "-o", outPath,
                "--allow-execution",
                "--no-de4dot",
                "--no-netdetect"
            });

            Assert.Equal(0, exitCode);
            Assert.True(File.Exists(outPath));

            var audit = QualityAuditor.Audit(outPath, runExternalVerifier: false);
            Assert.True(audit.CanLoad);
            Assert.True(audit.StructuralAuditPassed);
            Assert.Equal(0, audit.InvalidInstructionsCount);

            var psi = new ProcessStartInfo
            {
                FileName = outPath,
                Arguments = "test",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            Assert.NotNull(proc);
            string stdout = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(10000);

            Assert.Equal(0, proc.ExitCode);
            Assert.Contains("BENIGN_START", stdout);
            Assert.Contains("CONST_STR:ConfuserEx_Benchmark_Secret_String_2026", stdout);
            Assert.Contains("CONST_NUM:133742:9223372036854775800", stdout);
            Assert.Contains("BENIGN_END", stdout);
        }

        [Fact]
        public void RealConfuserEx_ProxyAndControlFlow_DynamicExecution_DeobfuscatesBothLayers()
        {
            string fixturePath = GetFixturePath(Path.Combine("benchmarks", "fixtures", "real_confuserex_proxy_cflow", "BenignSample.exe"));
            string outPath = Path.Combine(_testDir, "real_pc_deobf.exe");

            int exitCode = Program.Main(new[]
            {
                fixturePath,
                "-o", outPath,
                "--allow-execution",
                "--no-de4dot",
                "--no-netdetect"
            });

            Assert.Equal(0, exitCode);
            Assert.True(File.Exists(outPath));

            var audit = QualityAuditor.Audit(outPath, runExternalVerifier: false);
            Assert.True(audit.CanLoad);
            Assert.True(audit.StructuralAuditPassed);
            Assert.Equal(0, audit.InvalidInstructionsCount);

            var psi = new ProcessStartInfo
            {
                FileName = outPath,
                Arguments = "test",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            Assert.NotNull(proc);
            string stdout = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(10000);

            Assert.Equal(0, proc.ExitCode);
            Assert.Contains("BENIGN_START", stdout);
            Assert.Contains("PROXY:42", stdout);
            Assert.Contains("CFLOW:100:30:35:95", stdout);
            Assert.Contains("BENIGN_END", stdout);
        }

        [Fact]
        public void RealConfuserEx_Compressor_DynamicExecution_UnpacksPayloadAndMatchesBaseline()
        {
            string fixturePath = GetFixturePath(Path.Combine("benchmarks", "fixtures", "real_confuserex_compressor", "BenignSample.exe"));
            string outPath = Path.Combine(_testDir, "real_comp_deobf.exe");

            int exitCode = Program.Main(new[]
            {
                fixturePath,
                "-o", outPath,
                "--allow-execution",
                "--no-de4dot",
                "--no-netdetect"
            });

            Assert.Equal(0, exitCode);
            Assert.True(File.Exists(outPath));

            var audit = QualityAuditor.Audit(outPath, runExternalVerifier: false);
            Assert.True(audit.CanLoad);
            Assert.True(audit.StructuralAuditPassed);
            Assert.Equal(0, audit.InvalidInstructionsCount);

            var psi = new ProcessStartInfo
            {
                FileName = outPath,
                Arguments = "test",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            Assert.NotNull(proc);
            string stdout = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(10000);

            Assert.Equal(0, proc.ExitCode);
            Assert.Contains("BENIGN_START", stdout);
            Assert.Contains("CONST_STR:ConfuserEx_Benchmark_Secret_String_2026", stdout);
            Assert.Contains("BENIGN_END", stdout);
        }
    }
}
