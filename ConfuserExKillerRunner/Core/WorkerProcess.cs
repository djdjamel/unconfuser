using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using ConfuserExKillerRunner.Killers;
using Tool;

namespace ConfuserExKillerRunner.Core
{
    public sealed class WorkerOptions
    {
        public int TimeoutMs { get; set; } = 30000;
        public string TempDirectory { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the isolated worker process is permitted
        /// to resolve referenced dependencies from the directory containing the target assembly.
        /// <para>
        /// <b>Security Notice:</b> Default is <c>false</c>. Enabling this option permits the worker
        /// to load assemblies from the target directory during dynamic decryption/unpacking.
        /// If the target assembly directory contains malicious or untrusted third-party assemblies,
        /// this could lead to unintended code execution in the worker process.
        /// Whenever possible, use <see cref="AllowedDependencyDirectories"/> (<c>--dep-dir</c>) to specify
        /// isolated, trusted directories for required dependencies instead.
        /// </para>
        /// </summary>
        public bool AllowTargetDirectoryDependencies { get; set; } = false;

        public List<string> AllowedDependencyDirectories { get; set; } = new List<string>();
        public TargetArchitecture PreferredArchitecture { get; set; } = TargetArchitecture.Unknown;
    }

    public sealed class DynamicResourceResult
    {
        public bool Success { get; set; }
        public byte[] DecryptedResourceContainer { get; set; }
        public int ExtractedCount { get; set; }
        public string Message { get; set; }
    }

    public sealed class DynamicCompressorResult
    {
        public bool Success { get; set; }
        public byte[] UnpackedAssemblyBytes { get; set; }
        public uint RecoveredEntryPointToken { get; set; }
        public string Message { get; set; }
    }

    public sealed class FieldRvaRequest
    {
        public string FieldName { get; set; }
        public uint Rva { get; set; }
        public uint Size { get; set; }
        public uint FileOffset { get; set; }
    }

    public sealed class FieldRvaResponse
    {
        public uint Rva { get; set; }
        public uint FileOffset { get; set; }
        public byte[] Data { get; set; }
    }

    public static class WorkerClient
    {
        public static string ResolveWorkerExecutable(TargetArchitecture targetArch = TargetArchitecture.Unknown)
        {
            string envWorker = Environment.GetEnvironmentVariable("UNCONFUSER_WORKER_PATH");
            if (!string.IsNullOrEmpty(envWorker) && File.Exists(envWorker))
                return Path.GetFullPath(envWorker);

            string currentExe = null;
            try
            {
                currentExe = Process.GetCurrentProcess().MainModule?.FileName;
            }
            catch { }

            bool isTestHost = !string.IsNullOrEmpty(currentExe) &&
                (currentExe.IndexOf("testhost", StringComparison.OrdinalIgnoreCase) >= 0 ||
                 currentExe.IndexOf("vstest", StringComparison.OrdinalIgnoreCase) >= 0 ||
                 currentExe.EndsWith("dotnet.exe", StringComparison.OrdinalIgnoreCase));

            string appDir = AppDomain.CurrentDomain.BaseDirectory;

            // If target specifically requires 32-bit x86 on a 64-bit machine, search for 32-bit x86 worker executable
            if (targetArch == TargetArchitecture.X86Required && Environment.Is64BitProcess)
            {
                var x86Candidates = new List<string>
                {
                    Path.Combine(appDir, "x86", "ConfuserExKillerRunner.exe"),
                    Path.Combine(appDir, "..", "net48", "ConfuserExKillerRunner.exe"),
                    Path.Combine(appDir, "..", "..", "net48", "ConfuserExKillerRunner.exe"),
                    Path.Combine(appDir, "..", "..", "..", "..", "ConfuserExKillerRunner", "bin", "Release", "net48", "ConfuserExKillerRunner.exe"),
                    Path.Combine(appDir, "..", "..", "..", "..", "ConfuserExKillerRunner", "bin", "Debug", "net48", "ConfuserExKillerRunner.exe")
                };

                foreach (var c in x86Candidates)
                {
                    if (File.Exists(c))
                        return Path.GetFullPath(c);
                }
            }

            if (isTestHost || string.IsNullOrEmpty(currentExe) || !File.Exists(currentExe))
            {
                var candidates = new List<string>
                {
                    Path.Combine(appDir, "ConfuserExKillerRunner.dll"),
                    Path.Combine(appDir, "ConfuserExKillerRunner.exe"),
                    Path.Combine(appDir, "..", "..", "..", "..", "ConfuserExKillerRunner", "bin", "Release", "net8.0-windows", "ConfuserExKillerRunner.dll"),
                    Path.Combine(appDir, "..", "..", "..", "..", "ConfuserExKillerRunner", "bin", "Release", "net8.0-windows", "ConfuserExKillerRunner.exe"),
                    Path.Combine(appDir, "..", "..", "..", "..", "ConfuserExKillerRunner", "bin", "Debug", "net8.0-windows", "ConfuserExKillerRunner.dll"),
                    Path.Combine(appDir, "..", "..", "..", "..", "ConfuserExKillerRunner", "bin", "Release", "net48", "ConfuserExKillerRunner.exe")
                };

                foreach (var c in candidates)
                {
                    if (File.Exists(c))
                        return Path.GetFullPath(c);
                }
            }

            return currentExe;
        }

        public static AntiTamperResult ExecuteAntiTamper(string targetAssemblyPath, byte[] peImageOld, WorkerOptions options)
        {
            if (string.IsNullOrEmpty(targetAssemblyPath) || !File.Exists(targetAssemblyPath))
                throw new FileNotFoundException("Target assembly not found", targetAssemblyPath);

            var result = new AntiTamperResult
            {
                Modified = false,
                Status = AntiTamperStatus.Failed,
                DecryptedPeImage = (byte[])peImageOld.Clone(),
                Message = "Worker initialization failed"
            };

            var archInfo = ArchitectureDetector.Detect(targetAssemblyPath);
            string workerExe = ResolveWorkerExecutable(archInfo.Architecture);

            if (string.IsNullOrEmpty(workerExe) || !File.Exists(workerExe))
            {
                result.Message = "Isolated worker executable could not be resolved.";
                Logger.LogError($"[WorkerClient] {result.Message}");
                return result;
            }

            if (archInfo.Architecture == TargetArchitecture.X86Required && Environment.Is64BitProcess &&
                !workerExe.Contains("net48") && !workerExe.Contains("x86"))
            {
                result.Message = "Target assembly requires 32-bit execution, but 32-bit worker is not available on this host.";
                Logger.LogWarning($"[WorkerClient] {result.Message}");
                return result;
            }

            string tempDir = !string.IsNullOrEmpty(options?.TempDirectory) && Directory.Exists(options.TempDirectory)
                ? options.TempDirectory
                : Path.GetTempPath();

            string guid = Guid.NewGuid().ToString("N");
            string tempPeOut = Path.Combine(tempDir, $"worker_antitamper_out_{guid}.bin");
            string tempMetaOut = Path.Combine(tempDir, $"worker_antitamper_meta_{guid}.json");

            try
            {
                var sbArgs = new StringBuilder();
                if (workerExe.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    sbArgs.Append($"\"{workerExe}\" ");
                }

                sbArgs.Append($"--internal-worker antitamper --input \"{targetAssemblyPath}\" --output-pe \"{tempPeOut}\" --output-meta \"{tempMetaOut}\"");

                if (options != null)
                {
                    if (options.AllowTargetDirectoryDependencies)
                        sbArgs.Append(" --allow-target-deps");

                    if (options.AllowedDependencyDirectories != null)
                    {
                        foreach (var dir in options.AllowedDependencyDirectories)
                        {
                            if (!string.IsNullOrEmpty(dir))
                                sbArgs.Append($" --allowed-dep-dir \"{dir}\"");
                        }
                    }
                }

                string runnerBin = workerExe.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? "dotnet" : workerExe;
                int timeoutMs = options != null && options.TimeoutMs > 0 ? options.TimeoutMs : 30000;

                Logger.LogInfo($"[WorkerClient] Spawning isolated worker ({Path.GetFileName(runnerBin)}) for AntiTamper (Timeout: {timeoutMs}ms)...");
                var procResult = ProcessRunner.RunIsolated(runnerBin, sbArgs.ToString(), tempDir, timeoutMs);

                if (procResult.TimedOut)
                {
                    result.Status = AntiTamperStatus.Failed;
                    result.Message = $"Worker process timed out after {timeoutMs}ms (infinite loop or hang in target module constructor). Worker process tree was forcibly terminated.";
                    Logger.LogError($"[WorkerClient] {result.Message}");
                    return result;
                }

                if (!File.Exists(tempMetaOut))
                {
                    result.Status = AntiTamperStatus.Failed;
                    result.Message = $"Worker process exited unexpectedly (ExitCode: {procResult.ExitCode}) without producing metadata: {procResult.StandardError.Trim()}";
                    Logger.LogError($"[WorkerClient] {result.Message}");
                    return result;
                }

                string metaContent = File.ReadAllText(tempMetaOut);
                ParseAntiTamperMeta(metaContent, result);

                if (result.Status == AntiTamperStatus.DecryptionConfirmed && File.Exists(tempPeOut))
                {
                    result.DecryptedPeImage = File.ReadAllBytes(tempPeOut);
                    result.Modified = true;
                    Logger.LogInfo($"[WorkerClient] Successfully retrieved decrypted PE ({result.DecryptedPeImage.Length} bytes) from worker.");
                }
                else
                {
                    result.DecryptedPeImage = (byte[])peImageOld.Clone();
                    result.Modified = false;
                }
            }
            catch (Exception ex)
            {
                result.Status = AntiTamperStatus.Failed;
                result.Message = $"Worker communication failure: {ex.Message}";
                result.DecryptedPeImage = (byte[])peImageOld.Clone();
                Logger.LogError($"[WorkerClient] {result.Message}");
            }
            finally
            {
                try { if (File.Exists(tempPeOut)) File.Delete(tempPeOut); } catch { }
                try { if (File.Exists(tempMetaOut)) File.Delete(tempMetaOut); } catch { }
            }

            return result;
        }

        public static DynamicResourceResult ExecuteResourceExtraction(string targetAssemblyPath, WorkerOptions options)
        {
            var res = new DynamicResourceResult { Success = false };
            var archInfo = ArchitectureDetector.Detect(targetAssemblyPath);
            string workerExe = ResolveWorkerExecutable(archInfo.Architecture);

            if (string.IsNullOrEmpty(workerExe) || !File.Exists(workerExe))
            {
                res.Message = "Worker executable not resolved for dynamic resource extraction.";
                return res;
            }

            string tempDir = !string.IsNullOrEmpty(options?.TempDirectory) && Directory.Exists(options.TempDirectory)
                ? options.TempDirectory
                : Path.GetTempPath();

            string guid = Guid.NewGuid().ToString("N");
            string tempResOut = Path.Combine(tempDir, $"worker_res_out_{guid}.bin");
            string tempMetaOut = Path.Combine(tempDir, $"worker_res_meta_{guid}.json");

            try
            {
                var sbArgs = new StringBuilder();
                if (workerExe.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                    sbArgs.Append($"\"{workerExe}\" ");

                sbArgs.Append($"--internal-worker resources --input \"{targetAssemblyPath}\" --output-res \"{tempResOut}\" --output-meta \"{tempMetaOut}\"");

                if (options != null)
                {
                    if (options.AllowTargetDirectoryDependencies)
                        sbArgs.Append(" --allow-target-deps");

                    if (options.AllowedDependencyDirectories != null)
                    {
                        foreach (var dir in options.AllowedDependencyDirectories)
                            sbArgs.Append($" --allowed-dep-dir \"{dir}\"");
                    }
                }

                string runnerBin = workerExe.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? "dotnet" : workerExe;
                int timeoutMs = options != null && options.TimeoutMs > 0 ? options.TimeoutMs : 30000;

                var procResult = ProcessRunner.RunIsolated(runnerBin, sbArgs.ToString(), tempDir, timeoutMs);

                if (procResult.TimedOut)
                {
                    res.Message = $"Resource worker timed out after {timeoutMs}ms. Worker process tree killed.";
                    return res;
                }

                if (File.Exists(tempMetaOut))
                {
                    string metaContent = File.ReadAllText(tempMetaOut);
                    WorkerProtocol.ParseResourceMeta(metaContent, res);
                }

                if (File.Exists(tempResOut) && new FileInfo(tempResOut).Length > 0)
                {
                    res.DecryptedResourceContainer = File.ReadAllBytes(tempResOut);
                    res.Success = true;
                    if (string.IsNullOrEmpty(res.Message))
                        res.Message = "Dynamic resource decryption succeeded in isolated worker.";
                }
                else
                {
                    if (string.IsNullOrEmpty(res.Message))
                        res.Message = $"Resource worker finished without payload: {procResult.StandardError.Trim()}";
                }
            }
            catch (Exception ex)
            {
                res.Message = $"Resource worker exception: {ex.Message}";
            }
            finally
            {
                try { if (File.Exists(tempResOut)) File.Delete(tempResOut); } catch { }
                try { if (File.Exists(tempMetaOut)) File.Delete(tempMetaOut); } catch { }
            }

            return res;
        }

        public static DynamicCompressorResult ExecuteCompressorUnpack(string targetAssemblyPath, WorkerOptions options)
        {
            var res = new DynamicCompressorResult { Success = false };
            var archInfo = ArchitectureDetector.Detect(targetAssemblyPath);
            string workerExe = ResolveWorkerExecutable(archInfo.Architecture);

            if (string.IsNullOrEmpty(workerExe) || !File.Exists(workerExe))
            {
                res.Message = "Worker executable not resolved for compressor unpacking.";
                return res;
            }

            string tempDir = !string.IsNullOrEmpty(options?.TempDirectory) && Directory.Exists(options.TempDirectory)
                ? options.TempDirectory
                : Path.GetTempPath();

            string guid = Guid.NewGuid().ToString("N");
            string tempPeOut = Path.Combine(tempDir, $"worker_compressor_out_{guid}.bin");
            string tempMetaOut = Path.Combine(tempDir, $"worker_compressor_meta_{guid}.json");

            try
            {
                var sbArgs = new StringBuilder();
                if (workerExe.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                    sbArgs.Append($"\"{workerExe}\" ");

                sbArgs.Append($"--internal-worker compressor --input \"{targetAssemblyPath}\" --output-pe \"{tempPeOut}\" --output-meta \"{tempMetaOut}\"");

                if (options != null)
                {
                    if (options.AllowTargetDirectoryDependencies)
                        sbArgs.Append(" --allow-target-deps");

                    if (options.AllowedDependencyDirectories != null)
                    {
                        foreach (var dir in options.AllowedDependencyDirectories)
                            sbArgs.Append($" --allowed-dep-dir \"{dir}\"");
                    }
                }

                string runnerBin = workerExe.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? "dotnet" : workerExe;
                int timeoutMs = options != null && options.TimeoutMs > 0 ? options.TimeoutMs : 30000;

                var procResult = ProcessRunner.RunIsolated(runnerBin, sbArgs.ToString(), tempDir, timeoutMs);

                if (procResult.TimedOut)
                {
                    res.Message = $"Compressor worker timed out after {timeoutMs}ms. Worker tree killed.";
                    return res;
                }

                if (File.Exists(tempMetaOut))
                {
                    string metaContent = File.ReadAllText(tempMetaOut);
                    WorkerProtocol.ParseCompressorMeta(metaContent, res);
                }

                if (File.Exists(tempPeOut) && new FileInfo(tempPeOut).Length > 0)
                {
                    res.UnpackedAssemblyBytes = File.ReadAllBytes(tempPeOut);
                    res.Success = true;
                    if (string.IsNullOrEmpty(res.Message))
                        res.Message = "Compressor unpacked via isolated worker.";
                }
                else
                {
                    if (string.IsNullOrEmpty(res.Message))
                        res.Message = $"Compressor worker finished without output: {procResult.StandardError.Trim()}";
                }
            }
            catch (Exception ex)
            {
                res.Message = $"Compressor worker exception: {ex.Message}";
            }
            finally
            {
                try { if (File.Exists(tempPeOut)) File.Delete(tempPeOut); } catch { }
                try { if (File.Exists(tempMetaOut)) File.Delete(tempMetaOut); } catch { }
            }

            return res;
        }

        public static (bool success, byte[] outputPe, int decryptedCount, bool allResolved, string message) ExecuteConstants(byte[] peBytes, WorkerOptions options)
        {
            if (peBytes == null) throw new ArgumentNullException(nameof(peBytes));

            var archInfo = ArchitectureDetector.Detect(peBytes);
            string workerExe = ResolveWorkerExecutable(archInfo.Architecture);

            if (string.IsNullOrEmpty(workerExe) || !File.Exists(workerExe))
            {
                return (false, peBytes, 0, false, $"Worker executable not found for architecture '{archInfo.Architecture}'");
            }

            string tempDir = !string.IsNullOrEmpty(options?.TempDirectory) && Directory.Exists(options.TempDirectory)
                ? options.TempDirectory
                : Path.GetTempPath();

            string guid = Guid.NewGuid().ToString("N");
            string tempIn = Path.Combine(tempDir, $"worker_const_in_{guid}.dll");
            string tempPeOut = Path.Combine(tempDir, $"worker_const_out_{guid}.bin");
            string tempMetaOut = Path.Combine(tempDir, $"worker_const_meta_{guid}.json");

            try
            {
                File.WriteAllBytes(tempIn, peBytes);

                var sbArgs = new StringBuilder();
                if (workerExe.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                    sbArgs.Append($"\"{workerExe}\" ");

                sbArgs.Append($"--internal-worker constants --input \"{tempIn}\" --output-pe \"{tempPeOut}\" --output-meta \"{tempMetaOut}\"");

                if (options != null)
                {
                    if (options.AllowTargetDirectoryDependencies)
                        sbArgs.Append(" --allow-target-deps");

                    if (options.AllowedDependencyDirectories != null)
                    {
                        foreach (var dir in options.AllowedDependencyDirectories)
                            sbArgs.Append($" --allowed-dep-dir \"{dir}\"");
                    }
                }

                string runnerBin = workerExe.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? "dotnet" : workerExe;
                int timeoutMs = options != null && options.TimeoutMs > 0 ? options.TimeoutMs : 30000;

                var procResult = ProcessRunner.RunIsolated(runnerBin, sbArgs.ToString(), tempDir, timeoutMs);

                if (procResult.TimedOut)
                {
                    return (false, peBytes, 0, false, $"Constant worker timed out after {timeoutMs}ms. Worker tree killed.");
                }

                string metaMessage = null;
                int decryptedCount = 0;
                bool allResolved = false;

                if (File.Exists(tempMetaOut))
                {
                    string meta = File.ReadAllText(tempMetaOut);
                    WorkerProtocol.ParseConstantsMeta(meta, out decryptedCount, out allResolved, out metaMessage);
                }

                if (!File.Exists(tempPeOut))
                {
                    string err = !string.IsNullOrEmpty(metaMessage)
                        ? metaMessage
                        : (!string.IsNullOrEmpty(procResult.StandardError) ? procResult.StandardError.Trim() : $"Worker process exited with code {procResult.ExitCode}");
                    return (false, peBytes, 0, false, $"Constant worker failed without output PE: {err}");
                }

                byte[] resultPe = File.ReadAllBytes(tempPeOut);
                string finalMsg = !string.IsNullOrEmpty(metaMessage)
                    ? metaMessage
                    : (decryptedCount > 0 ? $"Decrypted {decryptedCount} constants via isolated worker" : "No dynamic constants decrypted");

                return (true, resultPe, decryptedCount, allResolved, finalMsg);
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"[WorkerClient] Dynamic constant decryption exception: {ex.Message}");
                return (false, peBytes, 0, false, $"Constant worker exception: {ex.Message}");
            }
            finally
            {
                try { if (File.Exists(tempIn)) File.Delete(tempIn); } catch { }
                try { if (File.Exists(tempPeOut)) File.Delete(tempPeOut); } catch { }
                try { if (File.Exists(tempMetaOut)) File.Delete(tempMetaOut); } catch { }
            }
        }

        public static (bool success, byte[] outputPe, int restoredCount) ExecuteFieldRva(byte[] peBytes, WorkerOptions options)
        {
            if (peBytes == null) throw new ArgumentNullException(nameof(peBytes));

            var archInfo = ArchitectureDetector.Detect(peBytes);
            string workerExe = ResolveWorkerExecutable(archInfo.Architecture);

            if (string.IsNullOrEmpty(workerExe) || !File.Exists(workerExe))
            {
                return (false, peBytes, 0);
            }

            string tempDir = !string.IsNullOrEmpty(options?.TempDirectory) && Directory.Exists(options.TempDirectory)
                ? options.TempDirectory
                : Path.GetTempPath();

            string guid = Guid.NewGuid().ToString("N");
            string tempIn = Path.Combine(tempDir, $"worker_rva_in_{guid}.dll");
            string tempPeOut = Path.Combine(tempDir, $"worker_rva_out_{guid}.bin");
            string tempMetaOut = Path.Combine(tempDir, $"worker_rva_meta_{guid}.json");

            try
            {
                File.WriteAllBytes(tempIn, peBytes);

                var sbArgs = new StringBuilder();
                if (workerExe.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                    sbArgs.Append($"\"{workerExe}\" ");

                sbArgs.Append($"--internal-worker fieldrva --input \"{tempIn}\" --output-pe \"{tempPeOut}\" --output-meta \"{tempMetaOut}\"");

                if (options != null)
                {
                    if (options.AllowTargetDirectoryDependencies)
                        sbArgs.Append(" --allow-target-deps");

                    if (options.AllowedDependencyDirectories != null)
                    {
                        foreach (var dir in options.AllowedDependencyDirectories)
                            sbArgs.Append($" --allowed-dep-dir \"{dir}\"");
                    }
                }

                string runnerBin = workerExe.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? "dotnet" : workerExe;
                int timeoutMs = options != null && options.TimeoutMs > 0 ? options.TimeoutMs : 30000;

                var procResult = ProcessRunner.RunIsolated(runnerBin, sbArgs.ToString(), tempDir, timeoutMs);

                int restoredCount = 0;
                if (File.Exists(tempMetaOut))
                {
                    string meta = File.ReadAllText(tempMetaOut);
                    WorkerProtocol.ParseFieldRvaMeta(meta, out restoredCount, out string _);
                }

                if (restoredCount > 0 && File.Exists(tempPeOut))
                {
                    byte[] resultPe = File.ReadAllBytes(tempPeOut);
                    return (true, resultPe, restoredCount);
                }

                return (false, peBytes, 0);
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"[WorkerClient] Dynamic FieldRVA restoration exception: {ex.Message}");
                return (false, peBytes, 0);
            }
            finally
            {
                try { if (File.Exists(tempIn)) File.Delete(tempIn); } catch { }
                try { if (File.Exists(tempPeOut)) File.Delete(tempPeOut); } catch { }
                try { if (File.Exists(tempMetaOut)) File.Delete(tempMetaOut); } catch { }
            }
        }

        private static void ParseAntiTamperMeta(string json, AntiTamperResult result)
        {
            WorkerProtocol.ParseAntiTamperMeta(json, result);
        }
    }
}
