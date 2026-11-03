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
        private static TargetArchitecture GetOsLoaderArchitectureForAnyCpuExe()
        {
            var osArch = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture;
            if (osArch == System.Runtime.InteropServices.Architecture.Arm64)
                return TargetArchitecture.Arm64;
            if (osArch == System.Runtime.InteropServices.Architecture.X64 || Environment.Is64BitOperatingSystem)
                return TargetArchitecture.X64;
            if (osArch == System.Runtime.InteropServices.Architecture.X86)
                return TargetArchitecture.X86Required;
            return TargetArchitecture.Unknown;
        }

        public static string ResolveDotNetHostExecutable(string explicitDotNetHostPath = null)
        {
            if (!string.IsNullOrEmpty(explicitDotNetHostPath) && File.Exists(explicitDotNetHostPath))
                return Path.GetFullPath(explicitDotNetHostPath);

            string envHost = Environment.GetEnvironmentVariable("UNCONFUSER_DOTNET_HOST_PATH");
            if (!string.IsNullOrEmpty(envHost) && File.Exists(envHost))
                return Path.GetFullPath(envHost);

            // Resolve "dotnet.exe" in the exact same order ProcessRunner.RunIsolated uses
            string pathDotNet = ProcessRunner.ResolveExecutablePath("dotnet.exe") ?? ProcessRunner.ResolveExecutablePath("dotnet");
            if (!string.IsNullOrEmpty(pathDotNet) && File.Exists(pathDotNet))
                return Path.GetFullPath(pathDotNet);

            string dotnetRoot = Environment.GetEnvironmentVariable("DOTNET_ROOT");
            if (!string.IsNullOrEmpty(dotnetRoot))
            {
                string candidate = Path.Combine(dotnetRoot, "dotnet.exe");
                if (File.Exists(candidate))
                    return Path.GetFullPath(candidate);
            }

            try
            {
                string currentMain = Process.GetCurrentProcess().MainModule?.FileName;
                if (!string.IsNullOrEmpty(currentMain) &&
                    (currentMain.EndsWith("dotnet.exe", StringComparison.OrdinalIgnoreCase) ||
                     currentMain.EndsWith("/dotnet", StringComparison.OrdinalIgnoreCase)) &&
                    File.Exists(currentMain))
                {
                    return Path.GetFullPath(currentMain);
                }
            }
            catch
            {
            }

            return null;
        }

        public static TargetArchitecture GetWorkerEffectiveCpuArchitecture(
            string workerExe,
            ArchitectureInfo workerArchInfo = null,
            string dotnetHostPath = null)
        {
            if (workerArchInfo == null)
            {
                if (string.IsNullOrEmpty(workerExe) || !File.Exists(workerExe))
                    return TargetArchitecture.Unknown;
                workerArchInfo = ArchitectureDetector.Detect(workerExe);
            }

            if (workerArchInfo.HasArchitectureConflict || workerArchInfo.Architecture == TargetArchitecture.Unknown)
                return TargetArchitecture.Unknown;

            // When workerExe is a managed .dll, it is launched by the resolved dotnet.exe host process.
            // Its effective process architecture is determined by the actual dotnet.exe host binary (never assumed from OSArchitecture).
            if (!string.IsNullOrEmpty(workerExe) && workerExe.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            {
                string resolvedDotNetHost = ResolveDotNetHostExecutable(dotnetHostPath);
                if (string.IsNullOrEmpty(resolvedDotNetHost) || !File.Exists(resolvedDotNetHost))
                    return TargetArchitecture.Unknown;

                ArchitectureInfo hostArchInfo;
                try
                {
                    hostArchInfo = ArchitectureDetector.Detect(resolvedDotNetHost);
                }
                catch
                {
                    return TargetArchitecture.Unknown;
                }

                if (!ArchitectureDetector.AreHostAndPayloadArchitecturesCompatible(hostArchInfo.Architecture, workerArchInfo.Architecture))
                    return TargetArchitecture.Unknown;

                return hostArchInfo.Architecture;
            }

            switch (workerArchInfo.Architecture)
            {
                case TargetArchitecture.X86Required:
                    return TargetArchitecture.X86Required;
                case TargetArchitecture.X64:
                    return TargetArchitecture.X64;
                case TargetArchitecture.Arm64:
                    return TargetArchitecture.Arm64;
                case TargetArchitecture.X86Preferred:
                    return TargetArchitecture.X86Required;
                case TargetArchitecture.AnyCPU:
                    return GetOsLoaderArchitectureForAnyCpuExe();
                default:
                    return TargetArchitecture.Unknown;
            }
        }

        public static bool IsWorker64BitProcess(string workerExe)
        {
            if (string.IsNullOrEmpty(workerExe) || !File.Exists(workerExe))
                return Environment.Is64BitProcess;

            try
            {
                var effectiveArch = GetWorkerEffectiveCpuArchitecture(workerExe);
                if (effectiveArch == TargetArchitecture.X64 || effectiveArch == TargetArchitecture.Arm64)
                    return true;
                if (effectiveArch == TargetArchitecture.X86Required)
                    return false;
            }
            catch
            {
            }

            return Environment.Is64BitOperatingSystem;
        }

        public static bool IsWorkerCompatible(
            string workerExe,
            TargetArchitecture targetArch,
            bool targetRequiresModernDotNet,
            out string mismatchReason)
        {
            var targetRuntime = targetRequiresModernDotNet
                ? TargetRuntimeFamily.ModernDotNet
                : TargetRuntimeFamily.NetFramework;
            return IsWorkerCompatible(workerExe, targetArch, targetRuntime, out mismatchReason, dotnetHostPath: null);
        }

        public static bool IsWorkerCompatible(
            string workerExe,
            TargetArchitecture targetArch,
            TargetRuntimeFamily targetRuntime,
            out string mismatchReason,
            string dotnetHostPath = null)
        {
            mismatchReason = null;

            if (string.IsNullOrEmpty(workerExe) || !File.Exists(workerExe))
            {
                mismatchReason = "Isolated worker executable could not be resolved.";
                return false;
            }

            if (targetArch == TargetArchitecture.Unknown)
            {
                mismatchReason = "Target assembly has an unknown, invalid, or conflicting CPU architecture.";
                return false;
            }

            var workerArchInfo = ArchitectureDetector.Detect(workerExe);
            if (workerArchInfo.Architecture == TargetArchitecture.Unknown || workerArchInfo.HasArchitectureConflict)
            {
                mismatchReason = $"Resolved worker '{Path.GetFileName(workerExe)}' has an unknown, invalid, or conflicting PE architecture.";
                return false;
            }

            TargetArchitecture effectiveWorkerArch = GetWorkerEffectiveCpuArchitecture(workerExe, workerArchInfo, dotnetHostPath);
            if (effectiveWorkerArch == TargetArchitecture.Unknown)
            {
                mismatchReason = $"Resolved worker '{Path.GetFileName(workerExe)}' has an indeterminate or conflicting host/payload CPU architecture.";
                return false;
            }

            if (targetArch == TargetArchitecture.Arm64 && effectiveWorkerArch != TargetArchitecture.Arm64)
            {
                mismatchReason = $"Target assembly requires ARM64 execution, but resolved worker runs as {effectiveWorkerArch}.";
                return false;
            }

            if (effectiveWorkerArch == TargetArchitecture.Arm64 &&
                (targetArch == TargetArchitecture.X64 || targetArch == TargetArchitecture.X86Required))
            {
                mismatchReason = $"Target assembly requires {targetArch} execution, but resolved worker runs as ARM64.";
                return false;
            }

            if (targetArch == TargetArchitecture.X86Required && effectiveWorkerArch != TargetArchitecture.X86Required)
            {
                mismatchReason = "Target assembly requires 32-bit (x86) execution, but 32-bit worker is not available on this host.";
                return false;
            }

            if (targetArch == TargetArchitecture.X64 && effectiveWorkerArch != TargetArchitecture.X64)
            {
                mismatchReason = $"Target assembly requires 64-bit (x64) execution, but resolved worker runs as 32-bit ({effectiveWorkerArch}) process.";
                return false;
            }

            if (targetRuntime == TargetRuntimeFamily.Unknown)
            {
                mismatchReason = "Target assembly has an unknown or indeterminate .NET runtime family.";
                return false;
            }

            TargetRuntimeFamily workerRuntime = ArchitectureDetector.DetectRuntimeFamily(workerExe);
            if (workerRuntime == TargetRuntimeFamily.Unknown)
            {
                mismatchReason = $"Resolved worker '{Path.GetFileName(workerExe)}' has an unknown or indeterminate .NET runtime family.";
                return false;
            }

            if (targetRuntime == TargetRuntimeFamily.ModernDotNet && workerRuntime != TargetRuntimeFamily.ModernDotNet)
            {
                mismatchReason = $"Target assembly requires a modern .NET runtime (.NET Core / .NET 5+), but resolved worker '{Path.GetFileName(workerExe)}' targets .NET Framework.";
                return false;
            }

            if (targetRuntime == TargetRuntimeFamily.NetFramework && workerRuntime != TargetRuntimeFamily.NetFramework)
            {
                mismatchReason = $"Target assembly targets .NET Framework, but resolved worker '{Path.GetFileName(workerExe)}' targets a modern .NET runtime.";
                return false;
            }

            return true;
        }

        public static bool TryResolveCompatibleWorker(
            string targetAssemblyPath,
            out string workerExe,
            out string mismatchReason)
        {
            return TryResolveCompatibleWorker(targetAssemblyPath, out workerExe, out _, out mismatchReason, dotnetHostPath: null);
        }

        public static bool TryResolveCompatibleWorker(
            string targetAssemblyPath,
            out string workerExe,
            out string runnerExecutable,
            out string mismatchReason,
            string dotnetHostPath = null)
        {
            var archInfo = ArchitectureDetector.Detect(targetAssemblyPath);
            TargetRuntimeFamily targetRuntime = ArchitectureDetector.DetectRuntimeFamily(targetAssemblyPath);
            string pinnedDotNetHost = ResolveDotNetHostExecutable(dotnetHostPath);
            workerExe = ResolveWorkerExecutable(archInfo.Architecture, targetRuntime, pinnedDotNetHost);
            bool compatible = IsWorkerCompatible(workerExe, archInfo.Architecture, targetRuntime, out mismatchReason, pinnedDotNetHost);
            runnerExecutable = !string.IsNullOrEmpty(workerExe) && workerExe.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                ? pinnedDotNetHost
                : workerExe;
            if (compatible && (string.IsNullOrEmpty(runnerExecutable) || !File.Exists(runnerExecutable)))
            {
                mismatchReason = "Resolved worker runner executable could not be located on disk.";
                return false;
            }
            return compatible;
        }

        public static bool TryResolveCompatibleWorker(
            byte[] peBytes,
            out string workerExe,
            out string mismatchReason)
        {
            return TryResolveCompatibleWorker(peBytes, out workerExe, out _, out mismatchReason, dotnetHostPath: null);
        }

        public static bool TryResolveCompatibleWorker(
            byte[] peBytes,
            out string workerExe,
            out string runnerExecutable,
            out string mismatchReason,
            string dotnetHostPath = null)
        {
            var archInfo = ArchitectureDetector.Detect(peBytes);
            TargetRuntimeFamily targetRuntime = ArchitectureDetector.DetectRuntimeFamily(peBytes);
            string pinnedDotNetHost = ResolveDotNetHostExecutable(dotnetHostPath);
            workerExe = ResolveWorkerExecutable(archInfo.Architecture, targetRuntime, pinnedDotNetHost);
            bool compatible = IsWorkerCompatible(workerExe, archInfo.Architecture, targetRuntime, out mismatchReason, pinnedDotNetHost);
            runnerExecutable = !string.IsNullOrEmpty(workerExe) && workerExe.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                ? pinnedDotNetHost
                : workerExe;
            if (compatible && (string.IsNullOrEmpty(runnerExecutable) || !File.Exists(runnerExecutable)))
            {
                mismatchReason = "Resolved worker runner executable could not be located on disk.";
                return false;
            }
            return compatible;
        }

        public static string ResolveWorkerExecutable(TargetArchitecture targetArch, bool targetRequiresModernDotNet)
        {
            var targetRuntime = targetRequiresModernDotNet
                ? TargetRuntimeFamily.ModernDotNet
                : TargetRuntimeFamily.NetFramework;
            return ResolveWorkerExecutable(targetArch, targetRuntime, dotnetHostPath: null);
        }

        public static string ResolveWorkerExecutable(
            TargetArchitecture targetArch = TargetArchitecture.Unknown,
            TargetRuntimeFamily targetRuntime = TargetRuntimeFamily.Unknown,
            string dotnetHostPath = null)
        {
            string pinnedDotNetHost = ResolveDotNetHostExecutable(dotnetHostPath);

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

            var candidates = new List<string>();

            // If target specifically requires 32-bit x86 or targets .NET Framework, prioritize net48/x86 worker candidates first
            if (targetArch == TargetArchitecture.X86Required || targetRuntime == TargetRuntimeFamily.NetFramework)
            {
                candidates.Add(Path.Combine(appDir, "x86", "ConfuserExKillerRunner.exe"));
                candidates.Add(Path.Combine(appDir, "..", "net48", "ConfuserExKillerRunner.exe"));
                candidates.Add(Path.Combine(appDir, "..", "..", "net48", "ConfuserExKillerRunner.exe"));
                candidates.Add(Path.Combine(appDir, "..", "..", "..", "..", "ConfuserExKillerRunner", "bin", "Release", "net48", "ConfuserExKillerRunner.exe"));
                candidates.Add(Path.Combine(appDir, "..", "..", "..", "..", "ConfuserExKillerRunner", "bin", "Debug", "net48", "ConfuserExKillerRunner.exe"));
            }

            // If running directly as ConfuserExKillerRunner (not inside test host):
            // When targetRuntime is specified, only reuse currentExe if it is strictly compatible with both targetArch and targetRuntime.
            if (!isTestHost && !string.IsNullOrEmpty(currentExe) && File.Exists(currentExe))
            {
                if (targetRuntime != TargetRuntimeFamily.Unknown)
                {
                    if (IsWorkerCompatible(currentExe, targetArch, targetRuntime, out _, pinnedDotNetHost))
                        return currentExe;
                }
                else if (targetArch != TargetArchitecture.X86Required || !IsWorker64BitProcess(currentExe))
                {
                    return currentExe;
                }
            }

            candidates.Add(Path.Combine(appDir, "ConfuserExKillerRunner.dll"));
            candidates.Add(Path.Combine(appDir, "ConfuserExKillerRunner.exe"));
            candidates.Add(Path.Combine(appDir, "..", "net8.0-windows", "ConfuserExKillerRunner.dll"));
            candidates.Add(Path.Combine(appDir, "..", "net8.0-windows", "ConfuserExKillerRunner.exe"));
            candidates.Add(Path.Combine(appDir, "..", "net6.0-windows", "ConfuserExKillerRunner.dll"));
            candidates.Add(Path.Combine(appDir, "..", "net48", "ConfuserExKillerRunner.exe"));
            candidates.Add(Path.Combine(appDir, "..", "..", "..", "..", "ConfuserExKillerRunner", "bin", "Release", "net8.0-windows", "ConfuserExKillerRunner.dll"));
            candidates.Add(Path.Combine(appDir, "..", "..", "..", "..", "ConfuserExKillerRunner", "bin", "Release", "net8.0-windows", "ConfuserExKillerRunner.exe"));
            candidates.Add(Path.Combine(appDir, "..", "..", "..", "..", "ConfuserExKillerRunner", "bin", "Debug", "net8.0-windows", "ConfuserExKillerRunner.dll"));
            candidates.Add(Path.Combine(appDir, "..", "..", "..", "..", "ConfuserExKillerRunner", "bin", "Release", "net48", "ConfuserExKillerRunner.exe"));
            candidates.Add(Path.Combine(appDir, "..", "..", "..", "..", "ConfuserExKillerRunner", "bin", "Debug", "net48", "ConfuserExKillerRunner.exe"));

            // First pass: if targetRuntime is known, return the first existing candidate that is strictly compatible with both target architecture and runtime
            if (targetRuntime != TargetRuntimeFamily.Unknown)
            {
                foreach (var c in candidates)
                {
                    if (File.Exists(c))
                    {
                        string fullPath = Path.GetFullPath(c);
                        if (IsWorkerCompatible(fullPath, targetArch, targetRuntime, out _, pinnedDotNetHost))
                            return fullPath;
                    }
                }
            }

            // Second pass fallback: return first existing candidate so caller can report exact incompatibility reason
            foreach (var c in candidates)
            {
                if (File.Exists(c))
                    return Path.GetFullPath(c);
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

            if (!TryResolveCompatibleWorker(targetAssemblyPath, out string workerExe, out string runnerBin, out string mismatchReason))
            {
                result.Message = mismatchReason;
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
            if (!TryResolveCompatibleWorker(targetAssemblyPath, out string workerExe, out string runnerBin, out string mismatchReason))
            {
                res.Message = mismatchReason;
                Logger.LogWarning($"[WorkerClient] {res.Message}");
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
            if (!TryResolveCompatibleWorker(targetAssemblyPath, out string workerExe, out string runnerBin, out string mismatchReason))
            {
                res.Message = mismatchReason;
                Logger.LogWarning($"[WorkerClient] {res.Message}");
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

            if (!TryResolveCompatibleWorker(peBytes, out string workerExe, out string runnerBin, out string mismatchReason))
            {
                Logger.LogWarning($"[WorkerClient] {mismatchReason}");
                return (false, peBytes, 0, false, mismatchReason);
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

            if (!TryResolveCompatibleWorker(peBytes, out string workerExe, out string runnerBin, out string mismatchReason))
            {
                Logger.LogWarning($"[WorkerClient] {mismatchReason}");
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
