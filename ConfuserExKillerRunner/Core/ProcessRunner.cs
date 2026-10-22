using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

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

            using (var job = Environment.OSVersion.Platform == PlatformID.Win32NT ? new JobObject() : null)
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
                job?.AssignProcess(proc);
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
            if (!string.IsNullOrEmpty(explicitPath) && File.Exists(explicitPath))
                return Path.GetFullPath(explicitPath);

            string envPath = Environment.GetEnvironmentVariable("DE4DOT_PATH");
            if (!string.IsNullOrEmpty(envPath) && File.Exists(envPath))
                return Path.GetFullPath(envPath);

            string appDir = AppDomain.CurrentDomain.BaseDirectory;
            var candidatePaths = new List<string>
            {
                Path.Combine(appDir, "de4dot.exe"),
                Path.Combine(appDir, "tools", "de4dot", "de4dot.exe"),
                Path.Combine(Directory.GetCurrentDirectory(), "de4dot.exe"),
                Path.Combine(Directory.GetCurrentDirectory(), "tools", "de4dot", "de4dot.exe")
            };

            // Search upward parent directories for tools/de4dot/de4dot.exe
            string current = appDir;
            for (int i = 0; i < 5; i++)
            {
                var parent = Directory.GetParent(current);
                if (parent == null) break;
                candidatePaths.Add(Path.Combine(parent.FullName, "tools", "de4dot", "de4dot.exe"));
                candidatePaths.Add(Path.Combine(parent.FullName, "de4dot.exe"));
                candidatePaths.Add(Path.Combine(parent.FullName, "bin", "Release", "net48", "tools", "de4dot", "de4dot.exe"));
                candidatePaths.Add(Path.Combine(parent.FullName, "bin", "Debug", "net48", "tools", "de4dot", "de4dot.exe"));
                candidatePaths.Add(Path.Combine(parent.FullName, "ConfuserExKillerRunner", "bin", "Release", "net48", "tools", "de4dot", "de4dot.exe"));
                candidatePaths.Add(Path.Combine(parent.FullName, "ConfuserExKillerRunner", "bin", "Debug", "net48", "tools", "de4dot", "de4dot.exe"));
                current = parent.FullName;
            }

            foreach (var candidate in candidatePaths)
            {
                if (File.Exists(candidate))
                    return Path.GetFullPath(candidate);
            }

            // Check PATH environment variable
            string pathEnv = Environment.GetEnvironmentVariable("PATH");
            if (!string.IsNullOrEmpty(pathEnv))
            {
                foreach (var dir in pathEnv.Split(Path.PathSeparator))
                {
                    try
                    {
                        string fullPath = Path.Combine(dir.Trim(), "de4dot.exe");
                        if (File.Exists(fullPath))
                            return Path.GetFullPath(fullPath);
                    }
                    catch { }
                }
            }

            return null;
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
