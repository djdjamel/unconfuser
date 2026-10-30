using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using Tool;

namespace ConfuserExKillerRunner.Core
{
    public sealed class ProcessResult
    {
        public int ExitCode { get; set; }
        public string StandardOutput { get; set; }
        public string StandardError { get; set; }
        public TimeSpan Duration { get; set; }
        public bool TimedOut { get; set; }
        public bool Success => !TimedOut && ExitCode == 0;
    }

    public static class ProcessRunner
    {
        /// <summary>
        /// Executes an untrusted process under strict fail-closed Windows Job Object isolation.
        /// Spawns the process in a suspended state (CREATE_SUSPENDED), assigns it to the Job Object,
        /// verifies containment, and only then resumes execution. This completely eliminates the
        /// race condition where an unconstrained process could run code or spawn descendants before job assignment.
        /// </summary>
        public static ProcessResult RunIsolated(
            string fileName,
            string arguments,
            string workingDirectory = null,
            int timeoutMs = 120000,
            JobLimits limits = null)
        {
            if (string.IsNullOrEmpty(fileName))
                throw new ArgumentNullException(nameof(fileName));

            // On non-Windows platforms, fallback to standard Run
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
            {
                return Run(fileName, arguments, workingDirectory, timeoutMs);
            }

            string resolvedExe = ResolveExecutablePath(fileName) ?? fileName;
            var outputBuilder = new StringBuilder();
            var errorBuilder = new StringBuilder();
            var stopwatch = Stopwatch.StartNew();

            using (var job = new JobObject(limits: limits ?? new JobLimits()))
            {
                if (!job.IsValid || !job.LimitsApplied)
                {
                    Logger.LogError($"[ProcessRunner] Fail-closed: Job Object initialization or limit application failed: {job.LastErrorString}");
                    return new ProcessResult
                    {
                        ExitCode = -1,
                        StandardOutput = string.Empty,
                        StandardError = $"Fail-closed security enforcement: Job Object initialization failed: {job.LastErrorString}",
                        Duration = TimeSpan.Zero,
                        TimedOut = false
                    };
                }

                bool created = job.TryCreateSuspendedProcess(
                    resolvedExe,
                    arguments,
                    workingDirectory,
                    out var procInfo,
                    out var hStdOut,
                    out var hStdErr,
                    out var errMsg);

                if (!created)
                {
                    Logger.LogError($"[ProcessRunner] TryCreateSuspendedProcess failed: {errMsg}");
                    return new ProcessResult
                    {
                        ExitCode = -1,
                        StandardOutput = string.Empty,
                        StandardError = errMsg ?? "Failed to create isolated suspended process.",
                        Duration = TimeSpan.Zero,
                        TimedOut = false
                    };
                }

                var safeOut = new SafeFileHandle(hStdOut, ownsHandle: true);
                var safeErr = new SafeFileHandle(hStdErr, ownsHandle: true);

                var outTask = Task.Run(() =>
                {
                    try
                    {
                        using (var stream = new FileStream(safeOut, FileAccess.Read, 4096, false))
                        using (var reader = new StreamReader(stream, Encoding.UTF8))
                        {
                            string line;
                            while ((line = reader.ReadLine()) != null)
                            {
                                lock (outputBuilder) outputBuilder.AppendLine(line);
                            }
                        }
                    }
                    catch { }
                });

                var errTask = Task.Run(() =>
                {
                    try
                    {
                        using (var stream = new FileStream(safeErr, FileAccess.Read, 4096, false))
                        using (var reader = new StreamReader(stream, Encoding.UTF8))
                        {
                            string line;
                            while ((line = reader.ReadLine()) != null)
                            {
                                lock (errorBuilder) errorBuilder.AppendLine(line);
                            }
                        }
                    }
                    catch { }
                });

                uint waitRes = JobObject.WaitForSingleObject(procInfo.hProcess, (uint)Math.Max(100, timeoutMs));
                stopwatch.Stop();

                if (waitRes == JobObject.WAIT_TIMEOUT)
                {
                    job.Terminate(1);
                    try
                    {
                        using (var proc = Process.GetProcessById(procInfo.dwProcessId))
                        {
                            KillProcessTree(proc);
                        }
                    }
                    catch { }

                    JobObject.SafeCloseHandle(procInfo.hThread);
                    JobObject.SafeCloseHandle(procInfo.hProcess);

                    try { Task.WaitAll(new[] { outTask, errTask }, 1000); } catch { }

                    return new ProcessResult
                    {
                        ExitCode = -1,
                        StandardOutput = outputBuilder.ToString(),
                        StandardError = errorBuilder.ToString(),
                        Duration = stopwatch.Elapsed,
                        TimedOut = true
                    };
                }

                // Process completed normally
                JobObject.GetExitCodeProcess(procInfo.hProcess, out uint exitCode);
                JobObject.SafeCloseHandle(procInfo.hThread);
                JobObject.SafeCloseHandle(procInfo.hProcess);

                try { Task.WaitAll(new[] { outTask, errTask }, 2000); } catch { }

                return new ProcessResult
                {
                    ExitCode = (int)exitCode,
                    StandardOutput = outputBuilder.ToString(),
                    StandardError = errorBuilder.ToString(),
                    Duration = stopwatch.Elapsed,
                    TimedOut = false
                };
            }
        }

        public static ProcessResult Run(string fileName, string arguments, string workingDirectory = null, int timeoutMs = 120000)
        {
            if (string.IsNullOrEmpty(fileName))
                throw new ArgumentNullException(nameof(fileName));

            var outputBuilder = new StringBuilder();
            var errorBuilder = new StringBuilder();
            var stopwatch = Stopwatch.StartNew();

            var psi = new ProcessStartInfo(fileName, arguments)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            if (!string.IsNullOrEmpty(workingDirectory) && Directory.Exists(workingDirectory))
            {
                psi.WorkingDirectory = workingDirectory;
            }

            using (var job = Environment.OSVersion.Platform == PlatformID.Win32NT ? new JobObject(limits: new JobLimits()) : null)
            using (var proc = new Process { StartInfo = psi })
            {
                proc.OutputDataReceived += (sender, e) =>
                {
                    if (e.Data != null)
                        lock (outputBuilder) outputBuilder.AppendLine(e.Data);
                };
                proc.ErrorDataReceived += (sender, e) =>
                {
                    if (e.Data != null)
                        lock (errorBuilder) errorBuilder.AppendLine(e.Data);
                };

                proc.Start();
                if (job != null)
                {
                    bool assigned = job.AssignProcess(proc);
                    if (!assigned)
                    {
                        Logger.LogWarning($"[ProcessRunner] Failed to assign process {proc.Id} to Job Object: {job.LastErrorString}");
                    }
                }
                proc.BeginOutputReadLine();
                proc.BeginErrorReadLine();

                bool exited = proc.WaitForExit(timeoutMs);
                stopwatch.Stop();

                if (!exited)
                {
                    job?.Terminate(1);
                    KillProcessTree(proc);
                    return new ProcessResult
                    {
                        ExitCode = -1,
                        StandardOutput = outputBuilder.ToString(),
                        StandardError = errorBuilder.ToString(),
                        Duration = stopwatch.Elapsed,
                        TimedOut = true
                    };
                }

                // Ensure asynchronous output buffers have flushed
                proc.WaitForExit();

                return new ProcessResult
                {
                    ExitCode = proc.ExitCode,
                    StandardOutput = outputBuilder.ToString(),
                    StandardError = errorBuilder.ToString(),
                    Duration = stopwatch.Elapsed,
                    TimedOut = false
                };
            }
        }

        public static void KillProcessTree(Process proc)
        {
            if (proc == null) return;
            try
            {
                if (proc.HasExited) return;
            }
            catch { return; }

#if NET6_0_OR_GREATER || NETCOREAPP
            try
            {
                proc.Kill(entireProcessTree: true);
                return;
            }
            catch { }
#endif

            try
            {
                if (Environment.OSVersion.Platform == PlatformID.Win32NT)
                {
                    var psi = new ProcessStartInfo("taskkill", $"/F /T /PID {proc.Id}")
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false
                    };
                    using (var killProc = Process.Start(psi))
                    {
                        killProc?.WaitForExit(3000);
                    }
                }
            }
            catch { }

            try
            {
                if (!proc.HasExited)
                    proc.Kill();
            }
            catch { }
        }

        public static string ResolveDe4dotPath(string explicitPath = null)
        {
            // 1. Explicit parameter
            if (!string.IsNullOrEmpty(explicitPath) && File.Exists(explicitPath))
                return Path.GetFullPath(explicitPath);

            // 2. Dedicated environment variable
            string envPath = Environment.GetEnvironmentVariable("DE4DOT_PATH");
            if (!string.IsNullOrEmpty(envPath) && File.Exists(envPath))
                return Path.GetFullPath(envPath);

            // 3. Known application and tools directories
            string appDir = AppDomain.CurrentDomain.BaseDirectory;
            if (!string.IsNullOrEmpty(appDir))
            {
                string appDe4Dot = Path.Combine(appDir, "de4dot.exe");
                if (File.Exists(appDe4Dot))
                    return Path.GetFullPath(appDe4Dot);

                string appTools = Path.Combine(appDir, "tools", "de4dot", "de4dot.exe");
                if (File.Exists(appTools))
                    return Path.GetFullPath(appTools);

                // Check workspace root if running within solution tree
                string dir = appDir;
                while (!string.IsNullOrEmpty(dir))
                {
                    string candidate = Path.Combine(dir, "tools", "de4dot", "de4dot.exe");
                    if (File.Exists(candidate))
                        return Path.GetFullPath(candidate);

                    if (File.Exists(Path.Combine(dir, "unconfuser.sln")) || Directory.Exists(Path.Combine(dir, ".git")))
                    {
                        break;
                    }

                    var parent = Directory.GetParent(dir);
                    if (parent == null) break;
                    dir = parent.FullName;
                }
            }

            // 4. PATH environment variable
            return ResolveExecutablePath("de4dot.exe");
        }

        public static string ResolveExecutablePath(string exeName)
        {
            if (string.IsNullOrEmpty(exeName)) return null;
            if (File.Exists(exeName)) return Path.GetFullPath(exeName);

            string pathEnv = Environment.GetEnvironmentVariable("PATH");
            if (!string.IsNullOrEmpty(pathEnv))
            {
                foreach (var dir in pathEnv.Split(Path.PathSeparator))
                {
                    try
                    {
                        string trimmed = dir.Trim();
                        if (string.IsNullOrEmpty(trimmed)) continue;
                        string fullPath = Path.Combine(trimmed, exeName);
                        if (File.Exists(fullPath))
                            return Path.GetFullPath(fullPath);
                    }
                    catch { }
                }
            }

            return null;
        }
    }
}
