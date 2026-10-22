using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
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
    /// Encapsulates a Windows Job Object to enforce resource limits and guarantee process tree termination
    /// via JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
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

        private IntPtr _handle;
        private bool _disposed;

        public bool IsValid => _handle != IntPtr.Zero;
        public IntPtr Handle => _handle;

        public JobObject(string name = null)
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return;

            try
            {
                _handle = CreateJobObject(IntPtr.Zero, name);
                if (_handle != IntPtr.Zero)
                {
                    // Enforce automatic process termination when job handle is closed or runner exits
                    SetExtendedLimits(JobObjectLimitFlags.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE);
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
                    return SetInformationJobObject(_handle, JobObjectInfoClass.ExtendedLimitInformation, ptr, (uint)length);
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

        public bool AssignProcess(Process process)
        {
            if (_handle == IntPtr.Zero || process == null) return false;

            try
            {
                if (process.HasExited) return false;
                return AssignProcessToJobObject(_handle, process.Handle);
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"[JobObject] AssignProcess failed: {ex.Message}");
                return false;
            }
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
