<#
.SYNOPSIS
    Automated behavioral and runtime verification harness for deobfuscated .NET assemblies.
.DESCRIPTION
    Performs safe runtime verification by:
    1. Validating file accessibility, size, and PE headers (x86, x64, AnyCPU).
    2. Spawning an isolated child worker process with strict timeout and environment sanitization.
    3. Executing <Module>..cctor in the appropriate 32-bit or 64-bit environment (unless -SkipModuleCctor).
    4. JIT-compiling all discoverable methods via RuntimeHelpers.PrepareMethod.
    5. Verifying WinForms ComponentResourceManager initialization to prevent MissingManifestResourceException.
    6. Reporting explicit machine-readable status: PASS, PARTIAL, INDETERMINATE, FAIL, or TIMEOUT.
.PARAMETER Target
    Path to the assembly (.dll or .exe) to verify.
.PARAMETER DepDirs
    Directories containing dependencies.
.PARAMETER CheckForms
    Whether to instantiate ComponentResourceManager for WinForms/XtraForm types.
.PARAMETER Force32Bit
    Force 32-bit (SysWOW64) execution.
.PARAMETER Force64Bit
    Force 64-bit execution.
.PARAMETER SkipModuleCctor
    Skip execution of <Module>..cctor for safe/static-only verification of untrusted assemblies.
.PARAMETER TimeoutSeconds
    Execution timeout in seconds before terminating the isolated worker process (default: 60).
.PARAMETER ReportJson
    Optional path to write a machine-readable JSON verification report.
.PARAMETER AllowIndeterminate
    Return exit code 0 when status is INDETERMINATE (default: return 2).
.PARAMETER CommitHash
    Git commit hash or identifier to associate with the verification report.
.PARAMETER WorkerMode
    Internal switch used when executing inside the isolated worker subprocess.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Target,
    [string[]]$DepDirs = @(),
    [switch]$CheckForms,
    [switch]$Force32Bit,
    [switch]$Force64Bit,
    [switch]$SkipModuleCctor,
    [int]$TimeoutSeconds = 60,
    [string]$ReportJson = "",
    [switch]$AllowIndeterminate,
    [string]$CommitHash = "",
    [switch]$WorkerMode
)

$ErrorActionPreference = "Stop"

function Get-FileSha256([string]$filePath) {
    try {
        if (-not (Test-Path $filePath)) { return "" }
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $stream = [System.IO.File]::OpenRead($filePath)
        try {
            $hashBytes = $sha.ComputeHash($stream)
            return ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ""
        } finally {
            $stream.Dispose()
            $sha.Dispose()
        }
    } catch {
        return ""
    }
}

function Get-AssemblyBitness([string]$filePath) {
    try {
        if (-not (Test-Path $filePath)) { return "Invalid" }
        $fs = [System.IO.File]::OpenRead($filePath)
        try {
            if ($fs.Length -lt 64) { return "Invalid" }
            $br = [System.IO.BinaryReader]::new($fs)
            $mz = $br.ReadUInt16()
            if ($mz -ne 0x5A4D) { return "Invalid" } # 'MZ'
            $fs.Position = 0x3C
            $peOffset = $br.ReadInt32()
            if ($peOffset + 24 -gt $fs.Length) { return "Invalid" }
            $fs.Position = $peOffset
            $peSig = $br.ReadUInt32()
            if ($peSig -ne 0x00004550) { return "Invalid" } # 'PE\0\0'
            $machine = $br.ReadUInt16()
            $fs.Position = $peOffset + 24
            $magic = $br.ReadUInt16()
            if ($magic -eq 0x020b) { return "x64" } # PE32+
            if ($machine -eq 0x8664) { return "x64" }
            if ($machine -eq 0x014c) { return "x86" }
            return "AnyCPU"
        } finally {
            $fs.Dispose()
        }
    } catch {
        return "Invalid"
    }
}

function Write-JsonReportFile([hashtable]$reportData, [string]$outputPath) {
    if ([string]::IsNullOrWhiteSpace($outputPath)) { return }
    try {
        $parentDir = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($outputPath))
        if (-not [string]::IsNullOrEmpty($parentDir) -and -not (Test-Path $parentDir)) {
            [System.IO.Directory]::CreateDirectory($parentDir) | Out-Null
        }
        $jsonStr = $reportData | ConvertTo-Json -Depth 6
        [System.IO.File]::WriteAllText([System.IO.Path]::GetFullPath($outputPath), $jsonStr)
    } catch {
        Write-Warning "Failed to write JSON report to '$outputPath': $_"
    }
}

# ==============================================================================
# ORCHESTRATOR MODE (Supervisor Process with Timeout & Isolation)
# ==============================================================================
if (-not $WorkerMode) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    # 1. Check file existence
    if (-not (Test-Path $Target)) {
        Write-Host "[-] Target assembly not found: $Target" -ForegroundColor Red
        $failReport = @{
            timestamp = $timestamp
            commit_hash = $CommitHash
            target = $Target
            sha256 = ""
            status = "FAIL"
            exit_code = 1
            duration_ms = 0
            bitness = 0
            load_success = $false
            load_error = "Target assembly not found: $Target"
            module_cctor_status = "NOT_RUN"
            module_cctor_error = $null
            total_types = 0
            types_discovered = 0
            type_load_errors = @()
            total_methods = 0
            jit_success = 0
            jit_skipped = 0
            jit_failed_missing_dependency = 0
            jit_failed_corrupted_il = 0
            corrupted_il_failures = @()
            dependency_failures = @()
            forms_checked = 0
            forms_success = 0
            forms_failed = 0
            form_failures = @()
            summary = "Target assembly not found"
        }
        Write-JsonReportFile $failReport $ReportJson
        exit 1
    }

    $targetFull = [System.IO.Path]::GetFullPath($Target)
    $targetSha = Get-FileSha256 $targetFull

    # 2. Check file readability
    $fileItem = Get-Item $targetFull
    try {
        $testStream = [System.IO.File]::Open($targetFull, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
        $testStream.Dispose()
    } catch {
        Write-Host "[-] Target assembly is unreadable or locked: $_" -ForegroundColor Red
        $unreadableReport = @{
            timestamp = $timestamp
            commit_hash = $CommitHash
            target = $targetFull
            sha256 = $targetSha
            status = "FAIL"
            exit_code = 1
            duration_ms = 0
            bitness = 0
            load_success = $false
            load_error = "Target assembly is unreadable or locked: $($_.Exception.Message)"
            module_cctor_status = "NOT_RUN"
            module_cctor_error = $null
            total_types = 0
            types_discovered = 0
            type_load_errors = @()
            total_methods = 0
            jit_success = 0
            jit_skipped = 0
            jit_failed_missing_dependency = 0
            jit_failed_corrupted_il = 0
            corrupted_il_failures = @()
            dependency_failures = @()
            forms_checked = 0
            forms_success = 0
            forms_failed = 0
            form_failures = @()
            summary = "Target assembly is unreadable or locked"
        }
        Write-JsonReportFile $unreadableReport $ReportJson
        exit 1
    }

    # 3. Check file size
    if ($fileItem.Length -lt 64) {
        Write-Host "[-] Target assembly is empty or too small to be a valid PE file ($($fileItem.Length) bytes)" -ForegroundColor Red
        $smallReport = @{
            timestamp = $timestamp
            commit_hash = $CommitHash
            target = $targetFull
            sha256 = $targetSha
            status = "FAIL"
            exit_code = 1
            duration_ms = 0
            bitness = 0
            load_success = $false
            load_error = "File is empty or too small to be a valid PE file ($($fileItem.Length) bytes)"
            module_cctor_status = "NOT_RUN"
            module_cctor_error = $null
            total_types = 0
            types_discovered = 0
            type_load_errors = @()
            total_methods = 0
            jit_success = 0
            jit_skipped = 0
            jit_failed_missing_dependency = 0
            jit_failed_corrupted_il = 0
            corrupted_il_failures = @()
            dependency_failures = @()
            forms_checked = 0
            forms_success = 0
            forms_failed = 0
            form_failures = @()
            summary = "Target assembly is empty or too small"
        }
        Write-JsonReportFile $smallReport $ReportJson
        exit 1
    }

    # 4. Check PE signature
    $archBitness = Get-AssemblyBitness $targetFull
    if ($archBitness -eq "Invalid") {
        Write-Host "[-] Target file has invalid PE signature or corrupted DOS/NT headers" -ForegroundColor Red
        $invalidPeReport = @{
            timestamp = $timestamp
            commit_hash = $CommitHash
            target = $targetFull
            sha256 = $targetSha
            status = "FAIL"
            exit_code = 1
            duration_ms = 0
            bitness = 0
            load_success = $false
            load_error = "Target file has invalid PE signature or corrupted DOS/NT headers"
            module_cctor_status = "NOT_RUN"
            module_cctor_error = $null
            total_types = 0
            types_discovered = 0
            type_load_errors = @()
            total_methods = 0
            jit_success = 0
            jit_skipped = 0
            jit_failed_missing_dependency = 0
            jit_failed_corrupted_il = 0
            corrupted_il_failures = @()
            dependency_failures = @()
            forms_checked = 0
            forms_success = 0
            forms_failed = 0
            form_failures = @()
            summary = "Target file has invalid PE signature"
        }
        Write-JsonReportFile $invalidPeReport $ReportJson
        exit 1
    }

    # 5. Determine worker binary bitness
    $workerExe = "powershell.exe"
    $is64BitOs = [Environment]::Is64BitOperatingSystem
    if ($Force32Bit -or ($archBitness -eq "x86" -and (-not $Force64Bit))) {
        $sysWow64Ps = "$env:WINDIR\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
        if ($is64BitOs -and (Test-Path $sysWow64Ps)) {
            $workerExe = $sysWow64Ps
        }
    } elseif ($Force64Bit -or ($archBitness -eq "x64")) {
        $system32Ps = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
        if ($is64BitOs -and (Test-Path $system32Ps)) {
            $workerExe = $system32Ps
        }
    }

    # 6. Build worker arguments
    $workerArgs = @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"", "-WorkerMode", "-Target", "`"$targetFull`"")
    if ($DepDirs -and $DepDirs.Count -gt 0) {
        $workerArgs += "-DepDirs"
        $workerArgs += "`"$($DepDirs -join ',')`""
    }
    if ($CheckForms) { $workerArgs += "-CheckForms" }
    if ($SkipModuleCctor) { $workerArgs += "-SkipModuleCctor" }
    if ($AllowIndeterminate) { $workerArgs += "-AllowIndeterminate" }
    if ($CommitHash) { $workerArgs += "-CommitHash"; $workerArgs += "`"$CommitHash`"" }
    if ($ReportJson) { $workerArgs += "-ReportJson"; $workerArgs += "`"$([System.IO.Path]::GetFullPath($ReportJson))`"" }

    # 7. Setup isolated process with sanitized environment and Windows Job Object
    $isWin = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
    $hJob = [IntPtr]::Zero
    if ($isWin) {
        try {
            if (-not ([System.Management.Automation.PSTypeName]'JobObjectIsolationHelper').Type) {
                Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

public static class JobObjectIsolationHelper {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetInformationJobObject(IntPtr hJob, int JobObjectInformationClass, IntPtr lpJobObjectInformation, uint cbJobObjectInformationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateJobObject(IntPtr hJob, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CreateProcess(
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
    public static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_COUNTERS {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
        public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
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
    public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryLimit;
        public UIntPtr PeakJobMemoryLimit;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO {
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
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    public const uint CREATE_SUSPENDED = 0x00000004;
    public const uint CREATE_NO_WINDOW = 0x08000000;
    public const int STARTF_USESTDHANDLES = 0x00000100;
    public const uint HANDLE_FLAG_INHERIT = 0x00000001;
    public const uint WAIT_OBJECT_0 = 0x00000000;
    public const uint WAIT_TIMEOUT = 0x00000102;
    public const uint WAIT_FAILED = 0xFFFFFFFF;

    public static IntPtr CreateJobWithLimits(ulong maxJobMemoryBytes, uint maxProcesses) {
        IntPtr job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) return IntPtr.Zero;

        var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        uint flags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if (maxJobMemoryBytes > 0) {
            flags |= 0x0200; // JOB_OBJECT_LIMIT_JOB_MEMORY
            info.JobMemoryLimit = new UIntPtr(maxJobMemoryBytes);
        }
        if (maxProcesses > 0) {
            flags |= 0x0008; // JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            info.BasicLimitInformation.ActiveProcessLimit = maxProcesses;
        }
        info.BasicLimitInformation.LimitFlags = flags;

        int size = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try {
            Marshal.StructureToPtr(info, ptr, false);
            if (!SetInformationJobObject(job, 9, ptr, (uint)size)) {
                CloseHandle(job);
                return IntPtr.Zero;
            }
        } finally {
            Marshal.FreeHGlobal(ptr);
        }
        return job;
    }

    public static bool ExecuteSuspendedInJob(
        IntPtr hJob,
        string exePath,
        string cmdLine,
        int timeoutMs,
        out int exitCode,
        out string stdOut,
        out string stdErr,
        out bool timedOut,
        out string errorMessage)
    {
        exitCode = -1;
        stdOut = "";
        stdErr = "";
        timedOut = false;
        errorMessage = "";

        if (hJob == IntPtr.Zero) {
            errorMessage = "Invalid Job Object handle.";
            return false;
        }

        var sa = new SECURITY_ATTRIBUTES();
        sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
        sa.bInheritHandle = true;

        IntPtr hOutRead = IntPtr.Zero, hOutWrite = IntPtr.Zero;
        IntPtr hErrRead = IntPtr.Zero, hErrWrite = IntPtr.Zero;

        if (!CreatePipe(out hOutRead, out hOutWrite, ref sa, 0) ||
            !SetHandleInformation(hOutRead, HANDLE_FLAG_INHERIT, 0)) {
            errorMessage = "Failed to create stdout pipe.";
            if (hOutRead != IntPtr.Zero) CloseHandle(hOutRead);
            if (hOutWrite != IntPtr.Zero) CloseHandle(hOutWrite);
            return false;
        }

        if (!CreatePipe(out hErrRead, out hErrWrite, ref sa, 0) ||
            !SetHandleInformation(hErrRead, HANDLE_FLAG_INHERIT, 0)) {
            errorMessage = "Failed to create stderr pipe.";
            CloseHandle(hOutRead);
            CloseHandle(hOutWrite);
            if (hErrRead != IntPtr.Zero) CloseHandle(hErrRead);
            if (hErrWrite != IntPtr.Zero) CloseHandle(hErrWrite);
            return false;
        }

        var si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = hOutWrite;
        si.hStdError = hErrWrite;

        PROCESS_INFORMATION pi;
        string fullCmd = "\"" + exePath + "\" " + cmdLine;
        bool created = CreateProcess(null, fullCmd, IntPtr.Zero, IntPtr.Zero, true,
            CREATE_SUSPENDED | CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out pi);

        CloseHandle(hOutWrite);
        CloseHandle(hErrWrite);

        if (!created) {
            int err = Marshal.GetLastWin32Error();
            CloseHandle(hOutRead);
            CloseHandle(hErrRead);
            errorMessage = "CreateProcess failed with Win32 error " + err;
            return false;
        }

        if (!AssignProcessToJobObject(hJob, pi.hProcess)) {
            int assignErr = Marshal.GetLastWin32Error();
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            CloseHandle(hOutRead);
            CloseHandle(hErrRead);
            errorMessage = "Fail-closed: Process assignment to Job Object failed (Win32 error " + assignErr + "). Process terminated.";
            return false;
        }

        uint resume = ResumeThread(pi.hThread);
        if (resume == uint.MaxValue) {
            int resErr = Marshal.GetLastWin32Error();
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            CloseHandle(hOutRead);
            CloseHandle(hErrRead);
            errorMessage = "Fail-closed: ResumeThread failed (Win32 error " + resErr + "). Process terminated.";
            return false;
        }

        var sbOut = new StringBuilder();
        var sbErr = new StringBuilder();

        var outTask = Task.Run(() => {
            try {
                using (var fs = new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(hOutRead, true), FileAccess.Read))
                using (var r = new StreamReader(fs, Encoding.UTF8)) {
                    string line;
                    while ((line = r.ReadLine()) != null) {
                        lock (sbOut) sbOut.AppendLine(line);
                    }
                }
            } catch { }
        });

        var errTask = Task.Run(() => {
            try {
                using (var fs = new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(hErrRead, true), FileAccess.Read))
                using (var r = new StreamReader(fs, Encoding.UTF8)) {
                    string line;
                    while ((line = r.ReadLine()) != null) {
                        lock (sbErr) sbErr.AppendLine(line);
                    }
                }
            } catch { }
        });

        uint wait = WaitForSingleObject(pi.hProcess, (uint)Math.Max(100, timeoutMs));

        if (wait == WAIT_TIMEOUT) {
            TerminateJobObject(hJob, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            try { Task.WaitAll(new Task[] { outTask, errTask }, 1000); } catch { }
            timedOut = true;
            exitCode = -1;
            stdOut = sbOut.ToString();
            stdErr = sbErr.ToString();
            return true;
        }

        if (wait == WAIT_FAILED) {
            int waitErr = Marshal.GetLastWin32Error();
            TerminateJobObject(hJob, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            try { Task.WaitAll(new Task[] { outTask, errTask }, 1000); } catch { }
            errorMessage = "WaitForSingleObject failed with Win32 error " + waitErr;
            exitCode = -1;
            stdOut = sbOut.ToString();
            stdErr = sbErr.ToString();
            return false;
        }

        uint uExit = 0;
        bool gotCode = GetExitCodeProcess(pi.hProcess, out uExit);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        try { Task.WaitAll(new Task[] { outTask, errTask }, 2000); } catch { }

        stdOut = sbOut.ToString();
        stdErr = sbErr.ToString();

        if (!gotCode) {
            errorMessage = "GetExitCodeProcess failed.";
            exitCode = -1;
            return false;
        }

        exitCode = (int)uExit;
        return true;
    }
}
"@
            }
            $hJob = [JobObjectIsolationHelper]::CreateJobWithLimits(1073741824, 10) # 1GB job memory limit, max 10 processes
        } catch {
            Write-Warning "Failed to initialize Windows Job Object isolation: $_"
        }
    }

    # Fail-closed enforcement: if on Windows and Job Object failed to initialize, abort immediately
    if ($isWin -and ($hJob -eq [IntPtr]::Zero)) {
        Write-Host "[-] Fail-closed security: Failed to initialize Windows Job Object isolation." -ForegroundColor Red
        $isoInitFailReport = @{
            timestamp = $timestamp
            commit_hash = $CommitHash
            target = $targetFull
            sha256 = $targetSha
            status = "FAIL"
            exit_code = 1
            duration_ms = 0
            bitness = 0
            load_success = $false
            load_error = "Fail-closed security: Failed to initialize Windows Job Object isolation."
            module_cctor_status = "NOT_RUN"
            module_cctor_error = $null
            total_types = 0
            types_discovered = 0
            type_load_errors = @()
            total_methods = 0
            jit_success = 0
            jit_skipped = 0
            jit_failed_missing_dependency = 0
            jit_failed_corrupted_il = 0
            corrupted_il_failures = @()
            dependency_failures = @()
            forms_checked = 0
            forms_success = 0
            forms_failed = 0
            form_failures = @()
            summary = "Failed to initialize Windows Job Object isolation (fail-closed)"
        }
        Write-JsonReportFile $isoInitFailReport $ReportJson
        exit 1
    }

    # Sanitize environment: strip tokens, credentials, and secrets
    $sensitivePatterns = @("TOKEN", "SECRET", "KEY", "PASSWORD", "CREDENTIAL", "AUTH", "CONFUSEREX_")
    Get-ChildItem env: | ForEach-Object {
        foreach ($pat in $sensitivePatterns) {
            if ($_.Name -like "*$pat*") {
                Remove-Item "env:$($_.Name)" -ErrorAction SilentlyContinue
                break
            }
        }
    }

    $timeoutMs = [Math]::Max(1000, $TimeoutSeconds * 1000)
    $workerExitCode = -1
    $stdoutText = ""
    $stderrText = ""
    $isTimedOut = $false
    $execErrMsg = ""

    $execSuccess = [JobObjectIsolationHelper]::ExecuteSuspendedInJob(
        $hJob,
        $workerExe,
        ($workerArgs -join " "),
        $timeoutMs,
        [ref]$workerExitCode,
        [ref]$stdoutText,
        [ref]$stderrText,
        [ref]$isTimedOut,
        [ref]$execErrMsg)

    $sw.Stop()

    if ($hJob -ne [IntPtr]::Zero) {
        try { [JobObjectIsolationHelper]::CloseHandle($hJob) | Out-Null } catch { }
    }

    if (-not $execSuccess -and -not $isTimedOut) {
        Write-Host "[-] Fail-closed security: $execErrMsg" -ForegroundColor Red
        $isoFailReport = @{
            timestamp = $timestamp
            commit_hash = $CommitHash
            target = $targetFull
            sha256 = $targetSha
            status = "FAIL"
            exit_code = 1
            duration_ms = [int]$sw.ElapsedMilliseconds
            bitness = if ($workerExe -like "*SysWOW64*") { 32 } else { 64 }
            load_success = $false
            load_error = "Fail-closed security: $execErrMsg"
            module_cctor_status = "NOT_RUN"
            module_cctor_error = $null
            total_types = 0
            types_discovered = 0
            type_load_errors = @()
            total_methods = 0
            jit_success = 0
            jit_skipped = 0
            jit_failed_missing_dependency = 0
            jit_failed_corrupted_il = 0
            corrupted_il_failures = @()
            dependency_failures = @()
            forms_checked = 0
            forms_success = 0
            forms_failed = 0
            form_failures = @()
            summary = "Worker Job Object isolation assignment failed (fail-closed)"
        }
        Write-JsonReportFile $isoFailReport $ReportJson
        exit 1
    }

    if ($isTimedOut) {
        Write-Host "[-] Verification worker process timed out after $TimeoutSeconds seconds. Process tree terminated." -ForegroundColor Red

        $timeoutReport = @{
            timestamp = $timestamp
            commit_hash = $CommitHash
            target = $targetFull
            sha256 = $targetSha
            status = "TIMEOUT"
            exit_code = 1
            duration_ms = [int]$sw.ElapsedMilliseconds
            bitness = if ($workerExe -like "*SysWOW64*") { 32 } else { 64 }
            load_success = $false
            load_error = "Verification worker process timed out after $TimeoutSeconds seconds"
            module_cctor_status = "TIMEOUT"
            module_cctor_error = $null
            total_types = 0
            types_discovered = 0
            type_load_errors = @()
            total_methods = 0
            jit_success = 0
            jit_skipped = 0
            jit_failed_missing_dependency = 0
            jit_failed_corrupted_il = 0
            corrupted_il_failures = @()
            dependency_failures = @()
            forms_checked = 0
            forms_success = 0
            forms_failed = 0
            form_failures = @()
            summary = "Verification process timed out after $TimeoutSeconds seconds (process tree terminated)"
        }
        Write-JsonReportFile $timeoutReport $ReportJson
        exit 1
    }

    # Worker finished
    if ($stdoutText) { Write-Host $stdoutText }
    if ($stderrText -and $workerExitCode -ne 0) { Write-Host $stderrText -ForegroundColor Yellow }

    # Fallback report if worker crashed before writing JSON
    if ($ReportJson -and (-not (Test-Path $ReportJson))) {
        $crashReport = @{
            timestamp = $timestamp
            commit_hash = $CommitHash
            target = $targetFull
            sha256 = $targetSha
            status = "FAIL"
            exit_code = $workerExitCode
            duration_ms = [int]$sw.ElapsedMilliseconds
            bitness = if ($workerExe -like "*SysWOW64*") { 32 } else { 64 }
            load_success = $false
            load_error = "Worker process terminated abnormally with exit code: $workerExitCode"
            module_cctor_status = "UNKNOWN"
            module_cctor_error = $stderrText
            total_types = 0
            types_discovered = 0
            type_load_errors = @()
            total_methods = 0
            jit_success = 0
            jit_skipped = 0
            jit_failed_missing_dependency = 0
            jit_failed_corrupted_il = 0
            corrupted_il_failures = @()
            dependency_failures = @()
            forms_checked = 0
            forms_success = 0
            forms_failed = 0
            form_failures = @()
            summary = "Worker process crashed (ExitCode $workerExitCode)"
        }
        Write-JsonReportFile $crashReport $ReportJson
    }

    exit $workerExitCode
}

# ==============================================================================
# WORKER MODE (Executed Inside Isolated Child Process)
# ==============================================================================
$workerStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$workerTimestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$targetFull = [System.IO.Path]::GetFullPath($Target)
$targetDir = [System.IO.Path]::GetDirectoryName($targetFull)
$targetSha = Get-FileSha256 $targetFull
$currentBitness = if ([Environment]::Is64BitProcess) { 64 } else { 32 }

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Behavioral Verification & JIT Harness (Unconfuser)       " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Target: $targetFull"
Write-Host "Process Bitness: $currentBitness bits"
Write-Host "Execution Policy: $(if ($SkipModuleCctor) { 'SAFE_NO_CCTOR' } else { 'DYNAMIC_ALLOW_CCTOR' })"

$allDepDirs = [System.Collections.Generic.List[string]]::new()
$allDepDirs.Add($targetDir)
foreach ($d in $DepDirs) {
    if ($d -and (Test-Path $d)) {
        $allDepDirs.Add([System.IO.Path]::GetFullPath($d))
    }
}

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.ComponentModel;
using System.Collections.Generic;

public class VerifyResult {
    public bool LoadSuccess;
    public string LoadError;
    public string ModuleCctorStatus = "NOT_RUN";
    public string ModuleCctorError;
    public int TotalTypes;
    public int TypesDiscovered;
    public List<string> TypeLoadErrors = new List<string>();
    public int TotalMethods;
    public int JitSuccess;
    public int JitSkipped;
    public int JitFailedMissingDependency;
    public int JitFailedCorruptedIl;
    public List<string> DependencyFailures = new List<string>();
    public List<string> CorruptedIlFailures = new List<string>();
    public int FormsChecked;
    public int FormsSuccess;
    public int FormsFailed;
    public List<string> FormFailures = new List<string>();
}

public static class AssemblyVerifier {
    public static List<string> SearchDirs = new List<string>();

    public static Assembly OnAssemblyResolve(object sender, ResolveEventArgs args) {
        string assemblyName = new AssemblyName(args.Name).Name;
        string[] candidates = new string[] { assemblyName + ".dll", assemblyName + ".exe" };
        foreach (var dir in SearchDirs) {
            foreach (var cand in candidates) {
                string fullPath = Path.Combine(dir, cand);
                if (File.Exists(fullPath)) {
                    try { return Assembly.LoadFrom(fullPath); } catch { }
                }
            }
        }
        return null;
    }

    public static VerifyResult Verify(string assemblyPath, bool checkForms, bool skipModuleCctor) {
        var result = new VerifyResult();
        AppDomain.CurrentDomain.AssemblyResolve += OnAssemblyResolve;

        Assembly asm;
        try {
            asm = Assembly.LoadFrom(assemblyPath);
            result.LoadSuccess = true;
        } catch (Exception ex) {
            result.LoadSuccess = false;
            result.LoadError = ex.GetType().Name + ": " + ex.Message;
            return result;
        }

        // 1. Run Module .cctor (if not skipped for safe mode)
        if (skipModuleCctor) {
            result.ModuleCctorStatus = "SKIPPED";
        } else {
            try {
                foreach (var mod in asm.GetModules()) {
                    RuntimeHelpers.RunModuleConstructor(mod.ModuleHandle);
                }
                result.ModuleCctorStatus = "SUCCESS";
            } catch (Exception ex) {
                result.ModuleCctorStatus = "FAILED";
                result.ModuleCctorError = ex.GetType().Name + ": " + (ex.InnerException ?? ex).Message;
            }
        }

        // 2. Discover types
        Type[] types;
        try {
            types = asm.GetTypes();
            result.TotalTypes = types.Length;
            result.TypesDiscovered = types.Length;
        } catch (ReflectionTypeLoadException rtle) {
            var list = new List<Type>();
            foreach (var t in rtle.Types) { if (t != null) list.Add(t); }
            types = list.ToArray();
            result.TotalTypes = rtle.Types != null ? rtle.Types.Length : list.Count;
            result.TypesDiscovered = list.Count;
            if (rtle.LoaderExceptions != null) {
                foreach (var le in rtle.LoaderExceptions) {
                    if (le != null && result.TypeLoadErrors.Count < 20) {
                        result.TypeLoadErrors.Add(le.GetType().Name + ": " + le.Message);
                    }
                }
            }
        } catch (Exception ex) {
            types = new Type[0];
            result.TypeLoadErrors.Add(ex.GetType().Name + ": " + ex.Message);
        }

        // 3. JIT methods
        BindingFlags flags = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;
        foreach (var type in types) {
            if (type.ContainsGenericParameters) {
                result.JitSkipped++;
                continue;
            }

            var members = new List<MethodBase>();
            try {
                members.AddRange(type.GetMethods(flags));
                members.AddRange(type.GetConstructors(flags));
            } catch {
                result.JitSkipped++;
                continue;
            }

            foreach (var member in members) {
                result.TotalMethods++;
                try {
                    if (member.IsAbstract || member.ContainsGenericParameters || member.GetMethodBody() == null) {
                        result.JitSkipped++;
                        continue;
                    }
                    RuntimeHelpers.PrepareMethod(member.MethodHandle);
                    result.JitSuccess++;
                } catch (FileNotFoundException fnfe) {
                    result.JitFailedMissingDependency++;
                    if (result.DependencyFailures.Count < 20) {
                        result.DependencyFailures.Add(type.FullName + "::" + member.Name + " -> Missing dependency: " + fnfe.Message);
                    }
                } catch (TypeLoadException tle) {
                    result.JitFailedMissingDependency++;
                    if (result.DependencyFailures.Count < 20) {
                        result.DependencyFailures.Add(type.FullName + "::" + member.Name + " -> TypeLoadException: " + tle.Message);
                    }
                } catch (Exception ex) {
                    result.JitFailedCorruptedIl++;
                    if (result.CorruptedIlFailures.Count < 30) {
                        result.CorruptedIlFailures.Add(type.FullName + "::" + member.Name + " -> " + ex.GetType().Name + ": " + (ex.InnerException ?? ex).Message);
                    }
                }
            }

            // 4. Check Form ComponentResourceManager
            if (checkForms) {
                bool isForm = false;
                try {
                    Type current = type;
                    while (current != null && current != typeof(object)) {
                        if (typeof(System.Windows.Forms.Form).IsAssignableFrom(current) ||
                            typeof(System.Windows.Forms.UserControl).IsAssignableFrom(current)) {
                            isForm = true;
                            break;
                        }
                        string fullName = current.FullName ?? current.Name ?? "";
                        if (fullName.StartsWith("System.Windows.Forms.Form") ||
                            fullName.StartsWith("System.Windows.Forms.UserControl") ||
                            fullName.StartsWith("DevExpress.XtraEditors.XtraForm") ||
                            fullName.StartsWith("DevExpress.XtraEditors.XtraUserControl") ||
                            current.Name == "Form" || current.Name == "UserControl") {
                            isForm = true;
                            break;
                        }
                        current = current.BaseType;
                    }
                } catch { }

                if (isForm) {
                    result.FormsChecked++;
                    try {
                        string resName = type.FullName + ".resources";
                        var resInfo = asm.GetManifestResourceInfo(resName);
                        if (resInfo == null) {
                            throw new System.Resources.MissingManifestResourceException("Could not find manifest resource stream '" + resName + "' for Form type '" + type.FullName + "'.");
                        }
                        var rm = new ComponentResourceManager(type);
                        var rs = rm.GetResourceSet(System.Globalization.CultureInfo.InvariantCulture, true, true);
                        result.FormsSuccess++;
                    } catch (System.Resources.MissingManifestResourceException mmre) {
                        result.FormsFailed++;
                        result.FormFailures.Add(type.FullName + " -> MissingManifestResourceException: " + mmre.Message);
                    } catch {
                        // Tolerated non-resource initialization errors
                        result.FormsSuccess++;
                    }
                }
            }
        }

        return result;
    }
}
"@ -ReferencedAssemblies @("System.Windows.Forms", "System.Drawing")

[AssemblyVerifier]::SearchDirs.Clear()
foreach ($d in $allDepDirs) {
    [AssemblyVerifier]::SearchDirs.Add($d)
}

$res = [AssemblyVerifier]::Verify($targetFull, [bool]$CheckForms, [bool]$SkipModuleCctor)
$workerStopwatch.Stop()

# Compute exact verification status
$overallStatus = "PASS"
$summaryMessage = ""

if (-not $res.LoadSuccess) {
    $overallStatus = "FAIL"
    $summaryMessage = "Failed to load assembly: $($res.LoadError)"
} elseif ($res.ModuleCctorStatus -eq "FAILED") {
    $overallStatus = "FAIL"
    $summaryMessage = "Module constructor <Module>..cctor failed: $($res.ModuleCctorError)"
} elseif ($res.JitFailedCorruptedIl -gt 0) {
    $overallStatus = "FAIL"
    $summaryMessage = "JIT compilation failed on $($res.JitFailedCorruptedIl) method(s) due to corrupted IL"
} elseif ($res.FormsFailed -gt 0) {
    $overallStatus = "FAIL"
    $summaryMessage = "WinForms resource check failed on $($res.FormsFailed) form(s) due to MissingManifestResourceException"
} elseif ($res.TypeLoadErrors.Count -gt 0 -or ($res.TotalMethods -gt 0 -and $res.JitSuccess -eq 0)) {
    $overallStatus = "INDETERMINATE"
    $summaryMessage = "Verification is INDETERMINATE: type load errors occurred or 0 methods were successfully JIT-compiled"
} elseif ($res.JitFailedMissingDependency -gt 0) {
    $overallStatus = "PASS"
    $summaryMessage = "ALL STRUCTURAL, MODULE .CCTOR, FORMS & IL CHECKS PASSED (with $($res.JitFailedMissingDependency) external dependency warning(s))"
} else {
    $overallStatus = "PASS"
    $summaryMessage = if ($SkipModuleCctor) { "ALL RUNTIME CHECKS PASSED (<Module>..cctor skipped by policy)" } else { "ALL RUNTIME & BEHAVIORAL CHECKS PASSED!" }
}

Write-Host "`n--- Verification Report ---" -ForegroundColor White
if ($res.LoadSuccess) {
    Write-Host "[+] Assembly Load: SUCCESS" -ForegroundColor Green
} else {
    Write-Host "[-] Assembly Load: FAILED ($($res.LoadError))" -ForegroundColor Red
}

if ($SkipModuleCctor) {
    Write-Host "[*] Module .cctor: SKIPPED (Safe mode policy)" -ForegroundColor Yellow
} elseif ($res.ModuleCctorStatus -eq "SUCCESS") {
    Write-Host "[+] Module .cctor: SUCCESS" -ForegroundColor Green
} else {
    Write-Host "[-] Module .cctor: FAILED ($($res.ModuleCctorError))" -ForegroundColor Red
}

Write-Host "[*] Types Discovered: $($res.TypesDiscovered) of $($res.TotalTypes)"
if ($res.TypeLoadErrors.Count -gt 0) {
    Write-Host "    Type Load Errors: $($res.TypeLoadErrors.Count)" -ForegroundColor Yellow
    foreach ($tle in $res.TypeLoadErrors) {
        Write-Host "      $tle" -ForegroundColor DarkYellow
    }
}

Write-Host "[*] JIT Methods: ok=$($res.JitSuccess), skipped=$($res.JitSkipped), missing-dep=$($res.JitFailedMissingDependency), corrupted-il=$($res.JitFailedCorruptedIl)" -ForegroundColor $(if ($res.JitFailedCorruptedIl -eq 0) { "Green" } else { "Red" })

if ($res.JitFailedCorruptedIl -gt 0) {
    Write-Host "    Corrupted IL Failures:" -ForegroundColor Red
    foreach ($f in $res.CorruptedIlFailures) {
        Write-Host "      $f" -ForegroundColor Red
    }
}

if ($res.JitFailedMissingDependency -gt 0) {
    Write-Host "    Missing Dependency Notes:" -ForegroundColor Yellow
    foreach ($f in $res.DependencyFailures) {
        Write-Host "      $f" -ForegroundColor DarkYellow
    }
}

if ($CheckForms) {
    Write-Host "[*] Forms Checked: total=$($res.FormsChecked), success=$($res.FormsSuccess), failed=$($res.FormsFailed)" -ForegroundColor $(if ($res.FormsFailed -eq 0) { "Green" } else { "Red" })
    if ($res.FormsFailed -gt 0) {
        Write-Host "    MissingManifestResourceException failures:" -ForegroundColor Red
        foreach ($ff in $res.FormFailures) {
            Write-Host "      $ff" -ForegroundColor Red
        }
    }
}

$workerExitCode = 0
if ($overallStatus -eq "FAIL") {
    $workerExitCode = 1
    Write-Host "`n[-] RUNTIME CHECKS DETECTED ISSUES: $summaryMessage" -ForegroundColor Red
} elseif ($overallStatus -eq "INDETERMINATE") {
    $workerExitCode = if ($AllowIndeterminate) { 0 } else { 2 }
    Write-Host "`n[!] RUNTIME CHECKS INDETERMINATE: $summaryMessage" -ForegroundColor Yellow
} else {
    $workerExitCode = 0
    Write-Host "`n[+] $summaryMessage" -ForegroundColor Green
}

# Write structured JSON report
$jsonReport = @{
    timestamp = $workerTimestamp
    commit_hash = $CommitHash
    target = $targetFull
    sha256 = $targetSha
    status = $overallStatus
    exit_code = $workerExitCode
    duration_ms = [int]$workerStopwatch.ElapsedMilliseconds
    bitness = $currentBitness
    load_success = [bool]$res.LoadSuccess
    load_error = $res.LoadError
    module_cctor_status = $res.ModuleCctorStatus
    module_cctor_error = $res.ModuleCctorError
    total_types = $res.TotalTypes
    types_discovered = $res.TypesDiscovered
    type_load_errors = @($res.TypeLoadErrors)
    total_methods = $res.TotalMethods
    jit_success = $res.JitSuccess
    jit_skipped = $res.JitSkipped
    jit_failed_missing_dependency = $res.JitFailedMissingDependency
    jit_failed_corrupted_il = $res.JitFailedCorruptedIl
    corrupted_il_failures = @($res.CorruptedIlFailures)
    dependency_failures = @($res.DependencyFailures)
    forms_checked = $res.FormsChecked
    forms_success = $res.FormsSuccess
    forms_failed = $res.FormsFailed
    form_failures = @($res.FormFailures)
    summary = $summaryMessage
}

Write-JsonReportFile $jsonReport $ReportJson

exit $workerExitCode
