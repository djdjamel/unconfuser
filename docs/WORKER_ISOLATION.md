# Worker Process Isolation & Security Architecture

## 1. Scope & Objective

Unconfuser utilizes out-of-process dynamic worker processes to unpack, decrypt, and inspect certain obfuscated constructs that require execution of runtime decryptors (such as Anti-Tamper module constructor decryption, dynamic string/constant decryption, and compressor assembly unpacking).

Because untrusted third-party code may be present in obfuscated assemblies, Unconfuser enforces rigorous process-level containment. However, it is essential to understand the exact security guarantees and limitations of this model.

---

## 2. Windows Job Object Containment: What is Protected

Unconfuser places all dynamic worker processes and verification runs within dedicated Windows Job Objects configured with extended limit information:

### 2.1 Elimination of the Launch Race Condition (`CREATE_SUSPENDED`)
- When spawning dynamic workers via `ProcessRunner.RunIsolated`, the target process is created natively with `CREATE_SUSPENDED | CREATE_NO_WINDOW`.
- The process is assigned to the Job Object *before* any user or managed code executes.
- **Fail-Closed Security Policy**: If `AssignProcessToJobObject` fails for any reason (e.g. security policy, invalid handle, quota), the suspended process is terminated immediately with `TerminateProcess` and never allowed to resume.
- Only once containment is confirmed does Unconfuser call `ResumeThread` to initiate execution.

### 2.2 Guaranteed Process Tree Termination (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`)
- By default, Job Objects are created with the `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` (0x2000) flag.
- When the parent process terminates, crashes, or closes the job handle, Windows kernel automatically terminates all processes in the job, including any children, grandchildren, or detached workers.
- Additionally, timeouts in `ProcessRunner` and `Verify-DeobfuscatedBinary.ps1` explicitly call `TerminateJobObject` followed by process tree termination commands (`taskkill /F /T /PID`).

### 2.3 Strict Resource Limits
The `JobLimits` class enforces defensive defaults against denial-of-service, fork bombs, and memory exhaustion:
- **Per-Process Memory Limit**: 512 MB (`JOB_OBJECT_LIMIT_PROCESS_MEMORY`).
- **Total Job Memory Limit**: 1,024 MB (`JOB_OBJECT_LIMIT_JOB_MEMORY`).
- **Active Process Limit**: Maximum 10 concurrent processes (`JOB_OBJECT_LIMIT_ACTIVE_PROCESS`).
- **CPU Time Limit**: 60 seconds of CPU time (`JOB_OBJECT_LIMIT_PROCESS_TIME`).
- **Die on Unhandled Exception**: Prevents crash dialog hangs (`JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`).

### 2.4 Dependency Isolation & Environment Sanitization
- By default, workers do not resolve dependencies from the target directory (`AllowTargetDirectoryDependencies = false`).
- Dedicated `--allowed-dep-dir` switches restrict assembly resolution to safe, trusted dependency locations.
- Sensitive environment variables (containing tokens, keys, credentials, or secrets) are scrubbed before worker launch.

---

## 3. What the Job Object Does NOT Protect (Security Boundaries & Limitations)

> [!WARNING]
> A Windows Job Object is a resource management and process-group containment mechanism, **NOT** a full security sandbox or hypervisor boundary.

Dynamic execution with Job Object containment does **NOT** provide:

1. **Filesystem Isolation**:
   - The worker runs under the credentials of the calling user. Any filesystem locations writeable by the current user remain accessible unless restricted by OS permissions.
2. **Network Isolation**:
   - Windows Job Objects do not restrict outbound or inbound network sockets without Windows Filtering Platform (WFP) rules or Windows AppContainer isolation.
3. **Registry Isolation**:
   - The worker process shares the same Windows registry hive as the calling user.
4. **IPC and OS Object Isolation**:
   - Named pipes, mutexes, shared memory, and window stations created in the same session may be accessible.
5. **Zero-Day Kernel Exploits**:
   - Code running with user permissions can theoretically exploit unpatched OS kernel vulnerabilities to escape process boundaries.

---

## 4. Best Practices for Untrusted or Malicious Binaries

For benign assemblies protected with commercial or open-source obfuscators (reverse-engineering research, interoperability, or recovery of lost source code), the built-in Job Object isolation provides robust defense against infinite loops, crashes, resource leaks, and fork bombs.

For **actively malicious, hostile, or unknown binaries** (e.g., malware analysis):
- **ALWAYS execute Unconfuser inside a dedicated, non-networked virtual machine (VM)** (e.g. Hyper-V, VMware, VirtualBox, or Windows Sandbox).
- Take clean snapshots before execution.
- Restrict VM network access to host-only or isolated virtual networks.
- Never run dynamic deobfuscation or verification of hostile malware on production development workstations with access to internal corporate networks or credentials.
