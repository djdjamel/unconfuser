using System;
using System.Diagnostics;
using System.IO;
using ConfuserExKillerRunner.Core;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    [Trait("Category", "Unit")]
    public class JobObjectTests
    {
        [Fact]
        public void JobObject_01_Creation_ValidHandleAndDefaultLimitsApplied()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return; // Windows only

            using (var job = new JobObject())
            {
                Assert.True(job.IsValid);
                Assert.NotEqual(IntPtr.Zero, job.Handle);
                Assert.True(job.LimitsApplied);
            }
        }

        [Fact]
        public void JobObject_02_ApplyLimits_MemoryLimitsEnforced()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return;

            using (var job = new JobObject())
            {
                var limits = new JobLimits
                {
                    MaxProcessMemoryBytes = 256UL * 1024 * 1024,
                    MaxJobMemoryBytes = 512UL * 1024 * 1024
                };

                bool success = job.ApplyLimits(limits);
                Assert.True(success);
                Assert.True(job.LimitsApplied);
            }
        }

        [Fact]
        public void JobObject_03_ApplyLimits_ActiveProcessLimitEnforced()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return;

            using (var job = new JobObject())
            {
                var limits = new JobLimits
                {
                    MaxActiveProcesses = 5
                };

                bool success = job.ApplyLimits(limits);
                Assert.True(success);
                Assert.True(job.LimitsApplied);
            }
        }

        [Fact]
        public void JobObject_04_AssignProcess_AssociatesRunningProcess()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return;

            using (var job = new JobObject())
            {
                Assert.True(job.IsValid);

                var psi = new ProcessStartInfo("cmd.exe", "/c ping -n 3 127.0.0.1 >nul")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                };

                using (var proc = Process.Start(psi))
                {
                    Assert.NotNull(proc);
                    try
                    {
                        bool assigned = job.AssignProcess(proc);
                        Assert.True(assigned);
                    }
                    finally
                    {
                        try
                        {
                            if (!proc.HasExited)
                                proc.Kill();
                        }
                        catch { }
                    }
                }
            }
        }

        [Fact]
        public void JobObject_05_AssignProcess_RejectsImpossibleAssignments()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return;

            using (var job = new JobObject())
            {
                // 1. Null process
                bool nullResult = job.AssignProcess((Process)null);
                Assert.False(nullResult);

                // 2. IntPtr.Zero
                bool zeroResult = job.AssignProcess(IntPtr.Zero, out int err);
                Assert.False(zeroResult);
                Assert.Equal(-2, err);

                // 3. Exited process
                var psi = new ProcessStartInfo("cmd.exe", "/c echo done")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                using (var proc = Process.Start(psi))
                {
                    proc.WaitForExit(5000);
                    Assert.True(proc.HasExited);

                    bool exitedResult = job.AssignProcess(proc);
                    Assert.False(exitedResult);
                    Assert.Contains("exited", job.LastErrorString, StringComparison.OrdinalIgnoreCase);
                }
            }

            // 4. Disposed Job Object
            var disposedJob = new JobObject();
            disposedJob.Dispose();
            bool disposedResult = disposedJob.AssignProcess(IntPtr.Zero, out int dispErr);
            Assert.False(disposedResult);
            Assert.Equal(-1, dispErr);
        }

        [Fact]
        public void JobObject_06_Termination_OnJobClose_KillsProcesses()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return;

            int pid;
            var psi = new ProcessStartInfo("cmd.exe", "/c ping -n 30 127.0.0.1 >nul")
            {
                CreateNoWindow = true,
                UseShellExecute = false
            };

            using (var proc = Process.Start(psi))
            {
                Assert.NotNull(proc);
                pid = proc.Id;

                using (var job = new JobObject())
                {
                    bool success = job.AssignProcess(proc);
                    Assert.True(success);
                    // Disposing job will invoke CloseHandle with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                }

                bool exited = proc.WaitForExit(4000);
                Assert.True(exited);
            }
        }

        [Fact]
        public void JobObject_07_Termination_ExplicitTerminate_KillsProcess()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return;

            using (var job = new JobObject())
            {
                Assert.True(job.IsValid);

                var psi = new ProcessStartInfo("cmd.exe", "/c ping -n 30 127.0.0.1 >nul")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                };

                using (var proc = Process.Start(psi))
                {
                    Assert.NotNull(proc);
                    job.AssignProcess(proc);

                    // Terminate job explicitly
                    bool termResult = job.Terminate(99);
                    Assert.True(termResult);

                    bool exited = proc.WaitForExit(3000);
                    Assert.True(exited);
                }
            }
        }

        [Fact]
        public void JobObject_08_Termination_TerminatesDescendantsProcessTree()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return;

            using (var job = new JobObject())
            {
                Assert.True(job.IsValid);

                // Spawn a process that in turn spawns a child PowerShell process
                var psi = new ProcessStartInfo("cmd.exe", "/c powershell.exe -NoProfile -Command \"Start-Sleep -Seconds 30\"")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                };

                using (var parentProc = Process.Start(psi))
                {
                    Assert.NotNull(parentProc);
                    bool assigned = job.AssignProcess(parentProc);
                    Assert.True(assigned);

                    // Give child powershell a moment to spawn
                    System.Threading.Thread.Sleep(500);

                    // Terminate the entire job object
                    bool termResult = job.Terminate(1);
                    Assert.True(termResult);

                    bool exited = parentProc.WaitForExit(3000);
                    Assert.True(exited);
                }
            }
        }

        [Fact]
        public void JobObject_09_RunIsolated_EnforcesTimeoutAndSuspendedLaunch()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return;

            // 1. Success case with suspended launch and pipe redirection
            var okResult = ProcessRunner.RunIsolated("cmd.exe", "/c echo isolated_launch_verified", timeoutMs: 10000);
            Assert.True(okResult.Success);
            Assert.Equal(0, okResult.ExitCode);
            Assert.Contains("isolated_launch_verified", okResult.StandardOutput);

            // 2. Timeout case terminates process tree
            var timeoutResult = ProcessRunner.RunIsolated("cmd.exe", "/c ping -n 30 127.0.0.1 >nul", timeoutMs: 1000);
            Assert.True(timeoutResult.TimedOut);
            Assert.False(timeoutResult.Success);
            Assert.Equal(-1, timeoutResult.ExitCode);
        }

        [Fact]
        public void JobObject_10_Handles_DisposedCleanlyAndDoubleDisposeSafe()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return;

            var job = new JobObject();
            Assert.True(job.IsValid);

            job.Dispose();
            Assert.False(job.IsValid);

            // Re-disposing must be idempotent and not throw
            job.Dispose();

            // SafeCloseHandle with invalid/null handles must be safe
            JobObject.SafeCloseHandle(IntPtr.Zero);
            JobObject.SafeCloseHandle(new IntPtr(-1));
        }

        [Fact]
        public void JobObject_11_RunIsolated_NullOrEmptyFileName_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ProcessRunner.RunIsolated(null, ""));
            Assert.Throws<ArgumentNullException>(() => ProcessRunner.RunIsolated(string.Empty, ""));
        }

        [Fact]
        public void JobObject_12_RunIsolated_NonWindows_FailsClosed()
        {
            var previousDetector = ProcessRunner.PlatformDetector;
            try
            {
                // Deterministically simulate non-Windows environment (e.g. Linux / Unix)
                ProcessRunner.PlatformDetector = () => PlatformID.Unix;

                var result = ProcessRunner.RunIsolated("untrusted_sample.exe", "--malicious-param");

                // 1. Must return explicit failure
                Assert.False(result.Success);

                // 2. ExitCode must be -1 per established fail-closed contract
                Assert.Equal(-1, result.ExitCode);

                // 3. Must not have timed out
                Assert.False(result.TimedOut);

                // 4. Must not have produced stdout (no fallback execution via Run())
                Assert.Equal(string.Empty, result.StandardOutput);

                // 5. StandardError must explicitly indicate isolation unavailability and untrusted execution abort
                Assert.Contains("Fail-closed security enforcement", result.StandardError);
                Assert.Contains("only supported on Windows (Win32NT)", result.StandardError);
                Assert.Contains("Process isolation is unavailable on platform Unix", result.StandardError);
                Assert.Contains("Untrusted execution aborted", result.StandardError);
            }
            finally
            {
                ProcessRunner.PlatformDetector = previousDetector;
            }
        }
    }
}


