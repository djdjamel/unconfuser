using System;
using System.Diagnostics;
using ConfuserExKillerRunner.Core;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    [Trait("Category", "Unit")]
    public class JobObjectTests
    {
        [Fact]
        public void JobObject_OnWindows_CreatesValidHandleAndAppliesKillOnClose()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return; // Windows only

            using (var job = new JobObject())
            {
                Assert.True(job.IsValid);
                Assert.NotEqual(IntPtr.Zero, job.Handle);

                bool success = job.SetExtendedLimits(JobObjectLimitFlags.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE);
                Assert.True(success);
            }
        }

        [Fact]
        public void JobObject_AssignProcess_AssociatesRunningProcess()
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
        public void JobObject_Terminate_TerminatesJobProcessesInstantly()
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

                    // Terminate job
                    bool termResult = job.Terminate(99);
                    Assert.True(termResult);

                    bool exited = proc.WaitForExit(3000);
                    Assert.True(exited);
                }
            }
        }

        [Fact]
        public void JobObject_Dispose_MultipleCallsSafe()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return;

            var job = new JobObject();
            Assert.True(job.IsValid);

            job.Dispose();
            Assert.False(job.IsValid);

            // Re-disposing should not throw
            job.Dispose();
        }
    }
}
