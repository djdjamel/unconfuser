using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using Tool;

namespace ConfuserExKillerRunner.Core
{
    [Flags]
    public enum JobObjectLimitFlags : uint
    {
        JOB_OBJECT_LIMIT_WORKINGSET = 0x00000001,
        JOB_OBJECT_LIMIT_PROCESS_TIME = 0x00000002,
        JOB_OBJECT_LIMIT_JOB_TIME = 0x00000004,
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008,
        JOB_OBJECT_LIMIT_AFFINITY = 0x00000010,
        JOB_OBJECT_LIMIT_PRIORITY_CLASS = 0x00000020,
        JOB_OBJECT_LIMIT_PRESERVE_JOB_TIME = 0x00000040,
        JOB_OBJECT_LIMIT_SCHEDULING_CLASS = 0x00000080,
        JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100,
        JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200,
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400,
        JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800,
        JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000,
        JOB_OBJECT_LIMIT_SUBSET_AFFINITY = 0x00004000
    }

    public enum JobObjectInfoClass
    {
        BasicLimitInformation = 2,
        BasicUIRestrictions = 4,
        SecurityLimitInformation = 5,
        EndOfJobTimeInformation = 6,
        AssociateCompletionPortInformation = 7,
        ExtendedLimitInformation = 9,
        GroupInformation = 11,
        NotificationLimitInformation = 12,
        LimitViolationInformation = 13,
        GroupInformationEx = 14,
        CpuRateControlInformation = 15,
        CompletionFilter = 16,
        CompletionCounter = 17,
        FreezeInformation = 18,
        ExtendedLimitInformationEx = 19
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryLimit;
        public UIntPtr PeakJobMemoryLimit;
    }

    /// <summary>
    /// Configurable resource limits enforced on a Windows Job Object.
    /// Default values are sized for benign decompilation/deobfuscation workloads.
    /// </summary>
    public sealed class JobLimits
    {
        public ulong MaxProcessMemoryBytes { get; set; } = 512UL * 1024 * 1024;  // 512 MB per process
        public ulong MaxJobMemoryBytes { get; set; } = 1024UL * 1024 * 1024;     // 1 GB total job memory
        public uint MaxActiveProcesses { get; set; } = 10;                      // Max 10 active processes
        public long PerProcessCpuTime100Ns { get; set; } = 600_000_000;          // 60 seconds CPU time
        public bool KillOnJobClose { get; set; } = true;
        public bool DieOnUnhandledException { get; set; } = true;
    }

    /// <summary>
    /// Encapsulates a Windows Job Object to enforce resource limits, eliminate launch race conditions
    /// via CREATE_SUSPENDED, and guarantee process tree termination via JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
    /// </summary>
    public sealed class JobObject : IDisposable
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(
            IntPtr hJob,
            JobObjectInfoClass JobObjectInformationClass,
            IntPtr lpJobObjectInformation,
            uint cbJobObjectInformationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateJobObject(IntPtr hJob, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const int STARTF_USESTDHANDLES = 0x00000100;
        private const uint HANDLE_FLAG_INHERIT = 0x00000001;
        public const uint WAIT_OBJECT_0 = 0x00000000;
        public const uint WAIT_TIMEOUT = 0x00000102;
        public const uint WAIT_FAILED = 0xFFFFFFFF;
        public const uint INFINITE = 0xFFFFFFFF;

        private IntPtr _handle;
        private bool _disposed;

        public bool IsValid => _handle != IntPtr.Zero;
        public IntPtr Handle => _handle;
        public bool LimitsApplied { get; private set; }
        public int LastWin32Error { get; private set; }
        public string LastErrorString { get; private set; }

        public JobObject(string name = null, JobLimits limits = null)
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return;

            try
            {
                _handle = CreateJobObject(IntPtr.Zero, name);
                if (_handle != IntPtr.Zero)
                {
                    ApplyLimits(limits ?? new JobLimits());
                }
                else
                {
                    LastWin32Error = Marshal.GetLastWin32Error();
                    LastErrorString = $"CreateJobObject failed with Win32 error {LastWin32Error}: {new Win32Exception(LastWin32Error).Message}";
                    Logger.LogWarning($"[JobObject] {LastErrorString}");
                }
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"[JobObject] Failed to initialize Windows Job Object: {ex.Message}");
                _handle = IntPtr.Zero;
            }
        }

        ~JobObject()
        {
            Dispose(false);
        }

        public bool ApplyLimits(JobLimits limits)
        {
            if (_handle == IntPtr.Zero || limits == null) return false;

            try
            {
                var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                uint flags = 0;

                if (limits.KillOnJobClose)
                    flags |= (uint)JobObjectLimitFlags.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

                if (limits.DieOnUnhandledException)
                    flags |= (uint)JobObjectLimitFlags.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

                if (limits.MaxProcessMemoryBytes > 0)
                {
                    flags |= (uint)JobObjectLimitFlags.JOB_OBJECT_LIMIT_PROCESS_MEMORY;
                    info.ProcessMemoryLimit = new UIntPtr(limits.MaxProcessMemoryBytes);
                }

                if (limits.MaxJobMemoryBytes > 0)
                {
                    flags |= (uint)JobObjectLimitFlags.JOB_OBJECT_LIMIT_JOB_MEMORY;
                    info.JobMemoryLimit = new UIntPtr(limits.MaxJobMemoryBytes);
                }

                if (limits.MaxActiveProcesses > 0)
                {
                    flags |= (uint)JobObjectLimitFlags.JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
                    info.BasicLimitInformation.ActiveProcessLimit = limits.MaxActiveProcesses;
                }

                if (limits.PerProcessCpuTime100Ns > 0)
                {
                    flags |= (uint)JobObjectLimitFlags.JOB_OBJECT_LIMIT_PROCESS_TIME;
                    info.BasicLimitInformation.PerProcessUserTimeLimit = limits.PerProcessCpuTime100Ns;
                }

                info.BasicLimitInformation.LimitFlags = flags;

                int length = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
                IntPtr ptr = Marshal.AllocHGlobal(length);
                try
                {
                    Marshal.StructureToPtr(info, ptr, false);
                    bool success = SetInformationJobObject(_handle, JobObjectInfoClass.ExtendedLimitInformation, ptr, (uint)length);
                    if (!success)
                    {
                        LastWin32Error = Marshal.GetLastWin32Error();
                        LastErrorString = $"SetInformationJobObject failed with Win32 error {LastWin32Error}: {new Win32Exception(LastWin32Error).Message}";
                        Logger.LogWarning($"[JobObject] {LastErrorString}");
                        LimitsApplied = false;
                        return false;
                    }
                    LimitsApplied = true;
                    return true;
                }
                finally
                {
                    Marshal.FreeHGlobal(ptr);
                }
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"[JobObject] Failed to set job object limits: {ex.Message}");
                LimitsApplied = false;
                return false;
            }
        }

        public bool SetExtendedLimits(
            JobObjectLimitFlags flags,
            long perProcessUserTimeLimit = 0,
            UIntPtr? maxWorkingSet = null,
            UIntPtr? jobMemoryLimit = null)
        {
            if (_handle == IntPtr.Zero) return false;

            try
            {
                var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                info.BasicLimitInformation.LimitFlags = (uint)flags;

                if (perProcessUserTimeLimit > 0)
                    info.BasicLimitInformation.PerProcessUserTimeLimit = perProcessUserTimeLimit;

                if (maxWorkingSet.HasValue)
                {
                    info.BasicLimitInformation.LimitFlags |= (uint)JobObjectLimitFlags.JOB_OBJECT_LIMIT_WORKINGSET;
                    info.BasicLimitInformation.MaximumWorkingSetSize = maxWorkingSet.Value;
                }

                if (jobMemoryLimit.HasValue)
                {
                    info.BasicLimitInformation.LimitFlags |= (uint)JobObjectLimitFlags.JOB_OBJECT_LIMIT_JOB_MEMORY;
                    info.JobMemoryLimit = jobMemoryLimit.Value;
                }

                int length = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
                IntPtr ptr = Marshal.AllocHGlobal(length);
                try
                {
                    Marshal.StructureToPtr(info, ptr, false);
                    bool ok = SetInformationJobObject(_handle, JobObjectInfoClass.ExtendedLimitInformation, ptr, (uint)length);
                    if (ok) LimitsApplied = true;
                    return ok;
                }
                finally
                {
                    Marshal.FreeHGlobal(ptr);
                }
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"[JobObject] Failed to set job object information: {ex.Message}");
                return false;
            }
        }

        public bool AssignProcess(IntPtr hProcess, out int win32Error)
        {
            win32Error = 0;
            if (_handle == IntPtr.Zero)
            {
                win32Error = -1;
                LastErrorString = "Job Object handle is invalid or uninitialized";
                return false;
            }
            if (hProcess == IntPtr.Zero)
            {
                win32Error = -2;
                LastErrorString = "Process handle is IntPtr.Zero";
                return false;
            }

            bool success = AssignProcessToJobObject(_handle, hProcess);
            if (!success)
            {
                win32Error = Marshal.GetLastWin32Error();
                LastWin32Error = win32Error;
                LastErrorString = $"AssignProcessToJobObject failed with Win32 error {win32Error}: {new Win32Exception(win32Error).Message}";
                Logger.LogWarning($"[JobObject] {LastErrorString}");
                return false;
            }

            return true;
        }

        public bool AssignProcess(Process process)
        {
            if (process == null) return false;

            try
            {
                if (process.HasExited)
                {
                    LastWin32Error = -3;
                    LastErrorString = "Cannot assign process: process has already exited.";
                    return false;
                }
                return AssignProcess(process.Handle, out _);
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"[JobObject] AssignProcess failed: {ex.Message}");
                LastErrorString = ex.Message;
                return false;
            }
        }

        /// <summary>
        /// Spawns a process in a suspended state (CREATE_SUSPENDED), assigns it to this Job Object,
        /// verifies assignment under a fail-closed policy, and only resumes execution once Job Object
        /// containment is verified. Completely eliminates the process-spawn race condition.
        /// </summary>
        public bool TryCreateSuspendedProcess(
            string applicationPath,
            string commandLine,
            string workingDirectory,
            out PROCESS_INFORMATION procInfo,
            out IntPtr hStdOutRead,
            out IntPtr hStdErrRead,
            out string errorMessage)
        {
            procInfo = default;
            hStdOutRead = IntPtr.Zero;
            hStdErrRead = IntPtr.Zero;
            errorMessage = null;

            if (_handle == IntPtr.Zero || !LimitsApplied)
            {
                errorMessage = "JobObject is not initialized or limits have not been applied.";
                return false;
            }

            var sa = new SECURITY_ATTRIBUTES
            {
                nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)),
                bInheritHandle = true,
                lpSecurityDescriptor = IntPtr.Zero
            };

            IntPtr hStdOutWrite = IntPtr.Zero;
            IntPtr hStdErrWrite = IntPtr.Zero;
            IntPtr hStdInRead = IntPtr.Zero;
            IntPtr hStdInWrite = IntPtr.Zero;

            if (!CreatePipe(out hStdOutRead, out hStdOutWrite, ref sa, 0) ||
                !CreatePipe(out hStdErrRead, out hStdErrWrite, ref sa, 0) ||
                !CreatePipe(out hStdInRead, out hStdInWrite, ref sa, 0))
            {
                int err = Marshal.GetLastWin32Error();
                if (hStdOutRead != IntPtr.Zero) CloseHandle(hStdOutRead);
                if (hStdOutWrite != IntPtr.Zero) CloseHandle(hStdOutWrite);
                if (hStdErrRead != IntPtr.Zero) CloseHandle(hStdErrRead);
                if (hStdErrWrite != IntPtr.Zero) CloseHandle(hStdErrWrite);
                if (hStdInRead != IntPtr.Zero) CloseHandle(hStdInRead);
                if (hStdInWrite != IntPtr.Zero) CloseHandle(hStdInWrite);
                errorMessage = $"CreatePipe failed with Win32 error {err}: {new Win32Exception(err).Message}";
                return false;
            }

            // Parent read ends should not be inherited by child; parent stdin write end should not be inherited
            if (!SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0) ||
                !SetHandleInformation(hStdErrRead, HANDLE_FLAG_INHERIT, 0) ||
                !SetHandleInformation(hStdInWrite, HANDLE_FLAG_INHERIT, 0))
            {
                int err = Marshal.GetLastWin32Error();
                CloseHandle(hStdOutRead);
                CloseHandle(hStdOutWrite);
                CloseHandle(hStdErrRead);
                CloseHandle(hStdErrWrite);
                CloseHandle(hStdInRead);
                CloseHandle(hStdInWrite);
                hStdOutRead = IntPtr.Zero;
                hStdErrRead = IntPtr.Zero;
                errorMessage = $"SetHandleInformation failed with Win32 error {err}: {new Win32Exception(err).Message}";
                return false;
            }

            var si = new STARTUPINFO
            {
                cb = Marshal.SizeOf(typeof(STARTUPINFO)),
                dwFlags = STARTF_USESTDHANDLES,
                hStdOutput = hStdOutWrite,
                hStdError = hStdErrWrite,
                hStdInput = hStdInRead
            };

            uint creationFlags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
            string fullCmdLine = string.IsNullOrEmpty(commandLine) ? $"\"{applicationPath}\"" : $"\"{applicationPath}\" {commandLine}";

            bool created = CreateProcess(
                null,
                fullCmdLine,
                IntPtr.Zero,
                IntPtr.Zero,
                true, // inherit handles
                creationFlags,
                IntPtr.Zero,
                string.IsNullOrEmpty(workingDirectory) ? null : workingDirectory,
                ref si,
                out procInfo);

            // Child process has received pipe handles; close write ends & child stdin read end in parent
            CloseHandle(hStdOutWrite);
            CloseHandle(hStdErrWrite);
            CloseHandle(hStdInRead);
            CloseHandle(hStdInWrite); // Closing write end provides immediate EOF if child reads stdin

            if (!created)
            {
                int err = Marshal.GetLastWin32Error();
                CloseHandle(hStdOutRead);
                CloseHandle(hStdErrRead);
                hStdOutRead = IntPtr.Zero;
                hStdErrRead = IntPtr.Zero;
                errorMessage = $"CreateProcess failed with Win32 error {err}: {new Win32Exception(err).Message}";
                return false;
            }

            // Process created in SUSPENDED state! Assign to Job Object before resuming
            if (!AssignProcess(procInfo.hProcess, out int assignErr))
            {
                // Fail-closed policy: Terminate process immediately before it executes any instruction
                TerminateProcess(procInfo.hProcess, 1);
                CloseHandle(procInfo.hThread);
                CloseHandle(procInfo.hProcess);
                CloseHandle(hStdOutRead);
                CloseHandle(hStdErrRead);
                hStdOutRead = IntPtr.Zero;
                hStdErrRead = IntPtr.Zero;
                procInfo = default;
                errorMessage = $"Fail-closed security enforcement: Process assignment to Job Object failed (Win32 error {assignErr}). Process terminated.";
                Logger.LogError($"[JobObject] {errorMessage}");
                return false;
            }

            // Containment verified: resume main thread
            uint resumeRes = ResumeThread(procInfo.hThread);
            if (resumeRes == uint.MaxValue)
            {
                int resumeErr = Marshal.GetLastWin32Error();
                TerminateProcess(procInfo.hProcess, 1);
                CloseHandle(procInfo.hThread);
                CloseHandle(procInfo.hProcess);
                CloseHandle(hStdOutRead);
                CloseHandle(hStdErrRead);
                hStdOutRead = IntPtr.Zero;
                hStdErrRead = IntPtr.Zero;
                procInfo = default;
                errorMessage = $"Fail-closed security enforcement: ResumeThread failed (Win32 error {resumeErr}). Process terminated.";
                Logger.LogError($"[JobObject] {errorMessage}");
                return false;
            }
            return true;
        }

        public bool Terminate(uint exitCode = 1)
        {
            if (_handle == IntPtr.Zero) return false;

            try
            {
                return TerminateJobObject(_handle, exitCode);
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"[JobObject] TerminateJobObject failed: {ex.Message}");
                return false;
            }
        }

        public static void SafeCloseHandle(IntPtr handle)
        {
            if (handle != IntPtr.Zero)
            {
                CloseHandle(handle);
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (_handle != IntPtr.Zero)
                {
                    CloseHandle(_handle);
                    _handle = IntPtr.Zero;
                }
                _disposed = true;
            }
        }
    }
}
