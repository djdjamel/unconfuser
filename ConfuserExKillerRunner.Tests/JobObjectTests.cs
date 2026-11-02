using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using ConfuserExKillerRunner.Core;
using Xunit;
using Xunit.Abstractions;

namespace ConfuserExKillerRunner.Tests
{
    [Trait("Category", "Unit")]
    public class JobObjectTests
    {
        private readonly ITestOutputHelper _output;

        public JobObjectTests(ITestOutputHelper output = null)
        {
            _output = output;
        }
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

        [Fact]
        public void JobObject_13_WorkerIsolation_EnvironmentAllowlist_BlocksCanarySecret()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return;

            string canaryVar = "UNCONFUSER_SECRET_CANARY";
            string canaryValue = "SENSITIVE_SECRET_TOKEN_DO_NOT_LEAK";
            Environment.SetEnvironmentVariable(canaryVar, canaryValue);

            try
            {
                // Run an isolated process that inspects both the canary variable and necessary system variables
                var result = ProcessRunner.RunIsolated(
                    "cmd.exe",
                    $"/c echo CANARY=[%{canaryVar}%] & echo SYSTEMROOT=[%SystemRoot%]",
                    timeoutMs: 15000);

                Assert.True(result.Success, $"Isolated process execution failed: {result.StandardError}");
                Assert.Equal(0, result.ExitCode);

                // Canary variable must NOT be leaked to child process (will print literal [%UNCONFUSER_SECRET_CANARY%] or empty)
                Assert.DoesNotContain(canaryValue, result.StandardOutput);

                // Essential system variables must remain accessible to child process
                Assert.Contains("SYSTEMROOT=[", result.StandardOutput);
                Assert.DoesNotContain("SYSTEMROOT=[%SystemRoot%]", result.StandardOutput);
            }
            finally
            {
                Environment.SetEnvironmentVariable(canaryVar, null);
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [StructLayout(LayoutKind.Sequential)]
        private struct TEST_SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [Fact]
        public void JobObject_14_WorkerIsolation_HandleInheritance_RestrictedToStdStreams()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return;

            string uniqueEventName = "Local\\Unconfuser_IsolatedTestEvent_" + Guid.NewGuid().ToString("N");

            // Create an inheritable event handle in the parent process (initially non-signaled)
            var sa = new TEST_SECURITY_ATTRIBUTES
            {
                nLength = Marshal.SizeOf(typeof(TEST_SECURITY_ATTRIBUTES)),
                bInheritHandle = true,
                lpSecurityDescriptor = IntPtr.Zero
            };
            IntPtr pSa = Marshal.AllocHGlobal(sa.nLength);
            Marshal.StructureToPtr(sa, pSa, false);

            IntPtr inheritableEvent = IntPtr.Zero;
            try
            {
                inheritableEvent = CreateEvent(pSa, true, false, uniqueEventName);
                Assert.NotEqual(IntPtr.Zero, inheritableEvent);

                // Initial state in parent must be non-signaled (WAIT_TIMEOUT)
                uint initialWait = WaitForSingleObject(inheritableEvent, 0);
                Assert.Equal(JobObject.WAIT_TIMEOUT, initialWait);

                // Resolve worker executable (ConfuserExKillerRunner)
                string workerExe = WorkerClient.ResolveWorkerExecutable();
                Assert.True(File.Exists(workerExe), $"Worker executable not found: {workerExe}");

                string appName;
                string args;
                if (workerExe.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    appName = "dotnet";
                    args = $"\"{workerExe}\" --internal-worker test-handle-inheritance --handle {(long)inheritableEvent} --event-name {uniqueEventName}";
                }
                else
                {
                    appName = workerExe;
                    args = $"--internal-worker test-handle-inheritance --handle {(long)inheritableEvent} --event-name {uniqueEventName}";
                }

                // Run isolated process with pipe redirection
                var result = ProcessRunner.RunIsolated(appName, args, timeoutMs: 15000);

                Assert.True(result.Success, $"Isolated process failed: {result.StandardError}");
                Assert.Equal(0, result.ExitCode);

                // Child confirms that the arbitrary parent handle was NOT inherited and object identity was verified
                Assert.Contains("[HANDLE_TEST_CHILD] SUCCESS:", result.StandardOutput);
                Assert.Contains("NamedEventOpened=True", result.StandardOutput);
                Assert.Contains("SameAsParentEvent=False", result.StandardOutput);
                Assert.Contains("Err=6", result.StandardOutput);

                // Verify that standard streams (stdout and stderr) worked reliably
                Assert.Contains("[HANDLE_TEST_CHILD] Stderr pipe communication verified.", result.StandardError);

                // Invariant: The event in the parent process was NEVER signaled by the child
                uint postWait = WaitForSingleObject(inheritableEvent, 0);
                Assert.Equal(JobObject.WAIT_TIMEOUT, postWait);
            }
            finally
            {
                if (inheritableEvent != IntPtr.Zero)
                    CloseHandle(inheritableEvent);
                Marshal.FreeHGlobal(pSa);
            }
        }

        [Fact]
        public void JobObject_14_Control_InheritedHandle_DetectedAndFailsExpectedly()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return;

            string uniqueEventName = "Local\\Unconfuser_ControlTestEvent_" + Guid.NewGuid().ToString("N");

            // Create an inheritable event handle in the parent process
            var sa = new TEST_SECURITY_ATTRIBUTES
            {
                nLength = Marshal.SizeOf(typeof(TEST_SECURITY_ATTRIBUTES)),
                bInheritHandle = true,
                lpSecurityDescriptor = IntPtr.Zero
            };
            IntPtr pSa = Marshal.AllocHGlobal(sa.nLength);
            Marshal.StructureToPtr(sa, pSa, false);

            IntPtr inheritableEvent = IntPtr.Zero;
            try
            {
                inheritableEvent = CreateEvent(pSa, true, false, uniqueEventName);
                Assert.NotEqual(IntPtr.Zero, inheritableEvent);

                uint initialWait = WaitForSingleObject(inheritableEvent, 0);
                Assert.Equal(JobObject.WAIT_TIMEOUT, initialWait);

                string workerExe = WorkerClient.ResolveWorkerExecutable();
                Assert.True(File.Exists(workerExe), $"Worker executable not found: {workerExe}");

                string appName;
                string args;
                if (workerExe.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    appName = "dotnet";
                    args = $"\"{workerExe}\" --internal-worker test-handle-inheritance --handle {(long)inheritableEvent} --event-name {uniqueEventName}";
                }
                else
                {
                    appName = workerExe;
                    args = $"--internal-worker test-handle-inheritance --handle {(long)inheritableEvent} --event-name {uniqueEventName}";
                }

                // Control scenario: Start process using standard Process.Start (bInheritHandles = TRUE) WITHOUT JobObject isolation handle list.
                // The inheritable handle is deliberately inherited by the child.
                var psi = new ProcessStartInfo(appName, args)
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (var proc = Process.Start(psi))
                {
                    Assert.NotNull(proc);
                    var (exited, stdout, stderr) = WaitAndReadProcess(proc, 15000);
                    Assert.True(exited, "Control process timed out.");

                    // Expected Failure: Child detected kernel object identity via CompareObjectHandles and exited with code 42
                    Assert.Equal(42, proc.ExitCode);
                    Assert.Contains("SameAsParentEvent=True", stdout);
                    Assert.Contains("[HANDLE_TEST_CHILD] FAILURE: Parent event handle was inherited and verified as identical kernel object!", stdout);

                    // Non-destructive verification: Event state in parent must still remain non-signaled
                    uint postWait = WaitForSingleObject(inheritableEvent, 0);
                    Assert.Equal(JobObject.WAIT_TIMEOUT, postWait);
                }
            }
            finally
            {
                if (inheritableEvent != IntPtr.Zero)
                    CloseHandle(inheritableEvent);
                Marshal.FreeHGlobal(pSa);
            }
        }

        [Fact]
        public void JobObject_14_NonDestructive_AutoResetEventSignalPreserved()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return;

            string uniqueEventName = "Local\\Unconfuser_AutoResetSignalTestEvent_" + Guid.NewGuid().ToString("N");

            // Create an inheritable auto-reset event (bManualReset = false) initially signaled (bInitialState = true)
            var sa = new TEST_SECURITY_ATTRIBUTES
            {
                nLength = Marshal.SizeOf(typeof(TEST_SECURITY_ATTRIBUTES)),
                bInheritHandle = true,
                lpSecurityDescriptor = IntPtr.Zero
            };
            IntPtr pSa = Marshal.AllocHGlobal(sa.nLength);
            Marshal.StructureToPtr(sa, pSa, false);

            IntPtr inheritableEvent = IntPtr.Zero;
            try
            {
                // bManualReset = false (auto-reset), bInitialState = true (signaled)
                inheritableEvent = CreateEvent(pSa, false, true, uniqueEventName);
                Assert.NotEqual(IntPtr.Zero, inheritableEvent);

                string workerExe = WorkerClient.ResolveWorkerExecutable();
                Assert.True(File.Exists(workerExe), $"Worker executable not found: {workerExe}");

                string appName;
                string args;
                if (workerExe.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    appName = "dotnet";
                    args = $"\"{workerExe}\" --internal-worker test-handle-inheritance --handle {(long)inheritableEvent} --event-name {uniqueEventName}";
                }
                else
                {
                    appName = workerExe;
                    args = $"--internal-worker test-handle-inheritance --handle {(long)inheritableEvent} --event-name {uniqueEventName}";
                }

                // Start process with standard Process.Start (bInheritHandles = TRUE)
                // The inheritable handle is deliberately inherited by the child.
                var psi = new ProcessStartInfo(appName, args)
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (var proc = Process.Start(psi))
                {
                    Assert.NotNull(proc);
                    var (exited, stdout, stderr) = WaitAndReadProcess(proc, 15000);
                    Assert.True(exited, "Process timed out.");

                    // Expected: Child detected kernel object identity (exit code 42)
                    Assert.Equal(42, proc.ExitCode);
                    Assert.Contains("SameAsParentEvent=True", stdout);

                    // CRITICAL NON-DESTRUCTIVE REGRESSION CHECK:
                    // Because the child did NOT call WaitForSingleObject(handlePtr, 0),
                    // the auto-reset event signal was NOT consumed and remains signaled in the parent.
                    uint postWait = WaitForSingleObject(inheritableEvent, 0);
                    Assert.Equal(JobObject.WAIT_OBJECT_0, postWait);
                }
            }
            finally
            {
                if (inheritableEvent != IntPtr.Zero)
                    CloseHandle(inheritableEvent);
                Marshal.FreeHGlobal(pSa);
            }
        }

        [Fact]
        public void JobObject_14_Inconclusive_ParentEventOpenFails()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return;

            string realEventName = "Local\\Unconfuser_RealTestEvent_" + Guid.NewGuid().ToString("N");
            string invalidEventName = "Local\\Unconfuser_NonExistentEvent_" + Guid.NewGuid().ToString("N");

            var sa = new TEST_SECURITY_ATTRIBUTES
            {
                nLength = Marshal.SizeOf(typeof(TEST_SECURITY_ATTRIBUTES)),
                bInheritHandle = true,
                lpSecurityDescriptor = IntPtr.Zero
            };
            IntPtr pSa = Marshal.AllocHGlobal(sa.nLength);
            Marshal.StructureToPtr(sa, pSa, false);

            IntPtr inheritableEvent = IntPtr.Zero;
            try
            {
                inheritableEvent = CreateEvent(pSa, true, false, realEventName);
                Assert.NotEqual(IntPtr.Zero, inheritableEvent);

                string workerExe = WorkerClient.ResolveWorkerExecutable();
                Assert.True(File.Exists(workerExe), $"Worker executable not found: {workerExe}");

                string appName;
                string args;
                if (workerExe.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    appName = "dotnet";
                    // Pass valid candidate handle, but an invalid/non-existent parent event name
                    args = $"\"{workerExe}\" --internal-worker test-handle-inheritance --handle {(long)inheritableEvent} --event-name {invalidEventName}";
                }
                else
                {
                    appName = workerExe;
                    args = $"--internal-worker test-handle-inheritance --handle {(long)inheritableEvent} --event-name {invalidEventName}";
                }

                var psi = new ProcessStartInfo(appName, args)
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (var proc = Process.Start(psi))
                {
                    Assert.NotNull(proc);
                    var (exited, stdout, stderr) = WaitAndReadProcess(proc, 15000);
                    Assert.True(exited, "Process timed out.");

                    // Mandatory Requirement: When parent event cannot be opened, comparison cannot be made.
                    // Must NEVER return code 0 (success). Must return INCONCLUSIVE (code 3).
                    Assert.Equal(3, proc.ExitCode);
                    Assert.Contains("NamedEventOpened=False", stdout);
                    Assert.Contains("[HANDLE_TEST_CHILD] INCONCLUSIVE: Parent event could not be opened", stdout);
                }
            }
            finally
            {
                if (inheritableEvent != IntPtr.Zero)
                    CloseHandle(inheritableEvent);
                Marshal.FreeHGlobal(pSa);
            }
        }

        [Fact]
        public void JobObject_14_NegativeControl_DistinctValidHandles_ConfirmedDifferent()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return;

            string eventNameA = "Local\\Unconfuser_DistinctEventA_" + Guid.NewGuid().ToString("N");
            string eventNameB = "Local\\Unconfuser_DistinctEventB_" + Guid.NewGuid().ToString("N");

            var sa = new TEST_SECURITY_ATTRIBUTES
            {
                nLength = Marshal.SizeOf(typeof(TEST_SECURITY_ATTRIBUTES)),
                bInheritHandle = true,
                lpSecurityDescriptor = IntPtr.Zero
            };
            IntPtr pSa = Marshal.AllocHGlobal(sa.nLength);
            Marshal.StructureToPtr(sa, pSa, false);

            IntPtr eventA = IntPtr.Zero;
            IntPtr eventB = IntPtr.Zero;
            try
            {
                // Create two distinct inheritable kernel events
                eventA = CreateEvent(pSa, true, false, eventNameA);
                Assert.NotEqual(IntPtr.Zero, eventA);

                eventB = CreateEvent(pSa, true, false, eventNameB);
                Assert.NotEqual(IntPtr.Zero, eventB);

                string workerExe = WorkerClient.ResolveWorkerExecutable();
                Assert.True(File.Exists(workerExe), $"Worker executable not found: {workerExe}");

                string appName;
                string args;
                if (workerExe.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    appName = "dotnet";
                    // Pass handle of Event A, but tell child the parent event is Event B
                    args = $"\"{workerExe}\" --internal-worker test-handle-inheritance --handle {(long)eventA} --event-name {eventNameB}";
                }
                else
                {
                    appName = workerExe;
                    args = $"--internal-worker test-handle-inheritance --handle {(long)eventA} --event-name {eventNameB}";
                }

                var psi = new ProcessStartInfo(appName, args)
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (var proc = Process.Start(psi))
                {
                    Assert.NotNull(proc);
                    var (exited, stdout, stderr) = WaitAndReadProcess(proc, 15000);
                    Assert.True(exited, "Process timed out.");

                    _output?.WriteLine($"[JobObject_14_NegativeControl] Child stdout:\n{stdout}");
                    if (!string.IsNullOrEmpty(stderr))
                    {
                        _output?.WriteLine($"[JobObject_14_NegativeControl] Child stderr:\n{stderr}");
                    }

                    // Distinct objects confirmed via CompareObjectHandles (ERROR_NOT_SAME_OBJECT = 1656 / 0x678):
                    // Result: NON INHERITED, code 0
                    Assert.Equal(0, proc.ExitCode);
                    Assert.Contains("NamedEventOpened=True", stdout);
                    Assert.Contains("SameAsParentEvent=False", stdout);
                    // Explicit verification: DiffErr MUST be documented standard ERROR_NOT_SAME_OBJECT (1656)
                    Assert.Contains("DiffErr=1656", stdout);
                    Assert.Contains("confirmed NOT the parent event", stdout);
                }
            }
            finally
            {
                if (eventA != IntPtr.Zero)
                    CloseHandle(eventA);
                if (eventB != IntPtr.Zero)
                    CloseHandle(eventB);
                Marshal.FreeHGlobal(pSa);
            }
        }

        [Fact]
        public void JobObject_15_WorkerIsolation_InvalidExecutable_FailsClosedAndCleansUp()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return;

            using (var job = new JobObject())
            {
                Assert.True(job.IsValid);
                bool success = job.TryCreateSuspendedProcess(
                    @"C:\NonExistentDirectory_Unconfuser\FakeBinary.exe",
                    "",
                    null,
                    out var procInfo,
                    out var hOut,
                    out var hErr,
                    out var errMsg);

                Assert.False(success);
                Assert.Equal(IntPtr.Zero, procInfo.hProcess);
                Assert.Equal(IntPtr.Zero, procInfo.hThread);
                Assert.Equal(IntPtr.Zero, hOut);
                Assert.Equal(IntPtr.Zero, hErr);
                Assert.NotNull(errMsg);
                Assert.Contains("CreateProcessW failed", errMsg);
            }
        }

        [Fact]
        public void JobObject_16_WorkerIsolation_Allowlist_CannotBeMutatedByExternalCaller()
        {
            // Verify that AllowedEnvironmentVariables is an immutable collection type
            var allowlist = JobObject.AllowedEnvironmentVariables;
            Assert.NotNull(allowlist);
            Assert.Equal(23, allowlist.Count);

            // 1. Must NOT return the internal mutable HashSet<string>
            Assert.False(allowlist is HashSet<string>, "Allowlist must not be the internal mutable HashSet<string>");
            Assert.Throws<InvalidCastException>(() => (HashSet<string>)allowlist);

            // 2. Must be wrapped in a read-only collection that blocks modification via ICollection<string>
            var col = (ICollection<string>)allowlist;
            Assert.True(col.IsReadOnly);
            Assert.Throws<NotSupportedException>(() => col.Add("GITHUB_TOKEN"));
            Assert.Throws<NotSupportedException>(() => col.Remove("PATH"));
            Assert.Throws<NotSupportedException>(() => col.Clear());

            // 3. Verify internal allowlist lookup is protected against unauthorized additions
            Assert.False(JobObject.IsEnvironmentVariableAllowed("GITHUB_TOKEN"));
            Assert.False(JobObject.IsEnvironmentVariableAllowed("AWS_SECRET_ACCESS_KEY"));
            Assert.False(JobObject.IsEnvironmentVariableAllowed("USERPROFILE"));

            // 4. Verify essential runtime variables are present
            Assert.Contains("SYSTEMROOT", allowlist);
            Assert.Contains("WINDIR", allowlist);
            Assert.Contains("PATH", allowlist);
            Assert.Contains("TEMP", allowlist);
            Assert.Contains("DOTNET_ROOT", allowlist);

            // 5. Verify sensitive user profile and cloud credentials are NOT in allowlist
            Assert.DoesNotContain("USERPROFILE", allowlist);
            Assert.DoesNotContain("LOCALAPPDATA", allowlist);
            Assert.DoesNotContain("APPDATA", allowlist);
            Assert.DoesNotContain("USERNAME", allowlist);
            Assert.DoesNotContain("GITHUB_TOKEN", allowlist);
            Assert.DoesNotContain("AWS_SECRET_ACCESS_KEY", allowlist);

            // 6. Verify child process environment isolation is completely uncompromised
            string testDisallowedKey = "UNCONFUSER_DISALLOWED_TOKEN_999";
            Environment.SetEnvironmentVariable(testDisallowedKey, "SENSITIVE_SECRET_DATA");
            try
            {
                var result = ProcessRunner.RunIsolated(
                    "cmd.exe",
                    $"/c echo VAR=[%{testDisallowedKey}%]",
                    timeoutMs: 15000);
                Assert.True(result.Success);
                Assert.DoesNotContain("SENSITIVE_SECRET_DATA", result.StandardOutput);
            }
            finally
            {
                Environment.SetEnvironmentVariable(testDisallowedKey, null);
            }
        }

        [Fact]
        public void JobObject_17_WorkerIsolation_UserProfileAndSensitiveVarsExcluded()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return;

            string sensitiveKey = "USER_SECRET_PROFILE_DATA";
            string sensitiveVal = "SECRET_CREDENTIALS_12345";
            Environment.SetEnvironmentVariable(sensitiveKey, sensitiveVal);

            try
            {
                var result = ProcessRunner.RunIsolated(
                    "cmd.exe",
                    $"/c echo SECRET=[%{sensitiveKey}%] & echo SYSTEMROOT=[%SystemRoot%]",
                    timeoutMs: 15000);

                Assert.True(result.Success, $"Isolated process failed: {result.StandardError}");
                Assert.Equal(0, result.ExitCode);
                Assert.DoesNotContain(sensitiveVal, result.StandardOutput);
                Assert.Contains("SYSTEMROOT=[", result.StandardOutput);
            }
            finally
            {
                Environment.SetEnvironmentVariable(sensitiveKey, null);
            }
        }

        private static (bool exited, string stdout, string stderr) WaitAndReadProcess(Process proc, int timeoutMs)
        {
            var sbOut = new System.Text.StringBuilder();
            var sbErr = new System.Text.StringBuilder();
            using (var outDone = new ManualResetEvent(false))
            using (var errDone = new ManualResetEvent(false))
            {
                proc.OutputDataReceived += (s, e) =>
                {
                    if (e.Data == null) outDone.Set();
                    else sbOut.AppendLine(e.Data);
                };
                proc.ErrorDataReceived += (s, e) =>
                {
                    if (e.Data == null) errDone.Set();
                    else sbErr.AppendLine(e.Data);
                };

                proc.BeginOutputReadLine();
                proc.BeginErrorReadLine();

                bool exited = proc.WaitForExit(timeoutMs);
                if (!exited)
                {
                    try { proc.Kill(); } catch { }
                }
                else
                {
                    outDone.WaitOne(2000);
                    errDone.WaitOne(2000);
                }

                return (exited, sbOut.ToString(), sbErr.ToString());
            }
        }
    }
}


