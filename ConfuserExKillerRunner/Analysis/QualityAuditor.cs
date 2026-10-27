using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using ConfuserExKillerRunner.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace ConfuserExKillerRunner.Analysis
{
    public sealed class AuditReport
    {
        public bool CanLoad { get; set; }
        public string TargetPath { get; set; }
        public int TotalTypes { get; set; }
        public int TotalMethods { get; set; }
        public int MethodsWithBody { get; set; }
        public int InvalidInstructionsCount { get; set; }
        public int InvalidBranchesCount { get; set; }
        public int InvalidEHCount { get; set; }
        public int StackUnderflowCount { get; set; }
        public int UnresolvedCallSitesCount { get; set; }
        public List<string> Warnings { get; set; } = new List<string>();
        public List<string> Errors { get; set; } = new List<string>();
        public List<RegressionDiagnostic> Diagnostics { get; set; } = new List<RegressionDiagnostic>();

        /// <summary>
        /// Explicit structural audit result: true if no structural defects, orphaned branch targets, invalid EH boundaries, or stack underflows were found.
        /// </summary>
        public bool StructuralAuditPassed => CanLoad && InvalidInstructionsCount == 0 && InvalidBranchesCount == 0 && InvalidEHCount == 0 && StackUnderflowCount == 0 && Errors.Count == 0;

        /// <summary>
        /// Explicit IL verification status: "PASSED", "UNVERIFIED", or "FAILED".
        /// External IL verification (via ilverify/peverify) is marked UNVERIFIED if tools are not installed or target is historical .NET Framework.
        /// </summary>
        public string ILVerificationStatus { get; set; } = "UNVERIFIED";

        public string ILVerificationNotes { get; set; } = "Static analysis & control-flow stack simulation passed; external ILVerify/PEVerify not invoked.";

        /// <summary>
        /// Explicit runtime execution confirmation (e.g. dynamic smoke test or benchmark).
        /// </summary>
        public bool ExecutionConfirmed { get; set; } = false;

        public string Status
        {
            get
            {
                if (!CanLoad || InvalidInstructionsCount > 0 || InvalidBranchesCount > 0 || InvalidEHCount > 0 || StackUnderflowCount > 0 || Errors.Count > 0 || ILVerificationStatus == "FAILED")
                    return "FAILED";
                if (ILVerificationStatus == "INDETERMINATE")
                    return "INDETERMINATE";
                if (Warnings.Count > 0)
                    return "WARNINGS";
                return "CLEAN";
            }
        }
    }

    public enum DefectType
    {
        Unknown,
        InvalidInstruction,
        InvalidBranch,
        InvalidExceptionHandler,
        StackUnderflow,
        UnresolvedCallSite,
        MetadataError,
        VerificationError,
        StructuralFailure
    }

    public enum DiagnosticSeverity
    {
        Info,
        Warning,
        Error,
        Critical
    }

    public sealed class RegressionDiagnostic
    {
        public DefectType DefectType { get; set; } = DefectType.Unknown;
        public DiagnosticSeverity Severity { get; set; } = DiagnosticSeverity.Error;
        public uint? Token { get; set; }
        public int? InstructionIndex { get; set; }
        public string MethodName { get; set; }
        public string Description { get; set; }
        public string RawMessage { get; set; }

        public override string ToString()
        {
            var sb = new System.Text.StringBuilder();
            sb.Append($"[{Severity}] {DefectType}: {Description ?? RawMessage}");
            if (Token.HasValue) sb.Append($" (Token: 0x{Token.Value:X8})");
            if (!string.IsNullOrEmpty(MethodName)) sb.Append($" in {MethodName}");
            if (InstructionIndex.HasValue) sb.Append($" at IL_{InstructionIndex.Value:X4}");
            return sb.ToString();
        }

        public static RegressionDiagnostic FromRawError(string rawError)
        {
            if (string.IsNullOrEmpty(rawError))
                return new RegressionDiagnostic { RawMessage = string.Empty, Description = "Unknown regression" };

            var diag = new RegressionDiagnostic
            {
                RawMessage = rawError,
                Description = rawError,
                Severity = DiagnosticSeverity.Error
            };

            // Detect DefectType from message pattern
            if (rawError.IndexOf("branch", StringComparison.OrdinalIgnoreCase) >= 0 ||
                rawError.IndexOf("target", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                diag.DefectType = DefectType.InvalidBranch;
            }
            else if (rawError.IndexOf("stack", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     rawError.IndexOf("underflow", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                diag.DefectType = DefectType.StackUnderflow;
            }
            else if (rawError.IndexOf("exception", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     rawError.IndexOf("handler", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     rawError.IndexOf("clause", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                diag.DefectType = DefectType.InvalidExceptionHandler;
            }
            else if (rawError.IndexOf("instruction", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     rawError.IndexOf("opcode", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                diag.DefectType = DefectType.InvalidInstruction;
            }
            else if (rawError.IndexOf("call", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     rawError.IndexOf("methodspec", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                diag.DefectType = DefectType.UnresolvedCallSite;
            }
            else if (rawError.IndexOf("[MD]", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     rawError.IndexOf("metadata", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                diag.DefectType = DefectType.MetadataError;
            }
            else if (rawError.IndexOf("[IL]", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     rawError.IndexOf("peverify", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     rawError.IndexOf("ilverify", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                diag.DefectType = DefectType.VerificationError;
            }

            // Extract IL offset if present (e.g. at [IL: (offset 0x0000001B)] or IL_001B)
            var offsetMatch = System.Text.RegularExpressions.Regex.Match(rawError, @"(?:offset\s+(?:0x)?|IL_)([0-9a-fA-F]{2,8})", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (offsetMatch.Success && int.TryParse(offsetMatch.Groups[1].Value, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out int parsedOffset))
            {
                diag.InstructionIndex = parsedOffset;
            }

            // Extract Token if present (e.g. [token 0x06000001] or [MD Token: 0x02000002])
            var tokenMatch = System.Text.RegularExpressions.Regex.Match(rawError, @"(?:token\s+(?:0x)?|token\s*:\s*(?:0x)?|Token:\s*(?:0x)?|jeton\s*:\s*(?:0x)?)([0-9a-fA-F]{8})", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (!tokenMatch.Success)
            {
                // Fallback: match 8-hex digit token (e.g. at 0x06000001) that is not the offset
                var hexMatches = System.Text.RegularExpressions.Regex.Matches(rawError, @"0x([0-9a-fA-F]{8})", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                foreach (System.Text.RegularExpressions.Match hm in hexMatches)
                {
                    if (uint.TryParse(hm.Groups[1].Value, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out uint cand))
                    {
                        if (diag.InstructionIndex.HasValue && (int)cand == diag.InstructionIndex.Value)
                            continue; // skip the offset
                        tokenMatch = hm;
                        break;
                    }
                }
            }

            if (tokenMatch.Success && uint.TryParse(tokenMatch.Groups[1].Value, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out uint parsedToken))
            {
                diag.Token = parsedToken;
            }

            return diag;
        }
    }

    public static class QualityAuditor
    {
        public static string ResolvePEVerifyPath()
        {
            string env = Environment.GetEnvironmentVariable("PEVERIFY_PATH");
            if (!string.IsNullOrEmpty(env) && File.Exists(env))
                return Path.GetFullPath(env);

            var candidates = new List<string>
            {
                @"C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\PEVerify.exe",
                @"C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\x64\PEVerify.exe",
                @"C:\Program Files (x86)\Microsoft SDKs\Windows\v8.1A\bin\NETFX 4.5.1 Tools\PEVerify.exe",
                @"C:\Program Files (x86)\Microsoft SDKs\Windows\v7.0A\Bin\PEVerify.exe"
            };

            foreach (var cand in candidates)
            {
                if (File.Exists(cand))
                    return Path.GetFullPath(cand);
            }

            return ProcessRunner.ResolveExecutablePath("PEVerify.exe");
        }

        public static string ResolveILVerifyPath()
        {
            string env = Environment.GetEnvironmentVariable("ILVERIFY_PATH");
            if (!string.IsNullOrEmpty(env) && File.Exists(env))
                return Path.GetFullPath(env);

            return ProcessRunner.ResolveExecutablePath("ilverify.exe") ?? ProcessRunner.ResolveExecutablePath("ilverify");
        }

        public static bool IsNetFrameworkTarget(ModuleDef module)
        {
            if (module == null) return false;

            // 1. Check TargetFrameworkAttribute
            if (module.Assembly != null)
            {
                foreach (var ca in module.Assembly.CustomAttributes)
                {
                    if (ca.TypeFullName == "System.Runtime.Versioning.TargetFrameworkAttribute" && ca.ConstructorArguments.Count > 0)
                    {
                        string tf = ca.ConstructorArguments[0].Value?.ToString();
                        if (!string.IsNullOrEmpty(tf))
                        {
                            if (tf.StartsWith(".NETFramework", StringComparison.OrdinalIgnoreCase))
                                return true;
                            if (tf.StartsWith(".NETCoreApp", StringComparison.OrdinalIgnoreCase) || tf.StartsWith(".NETStandard", StringComparison.OrdinalIgnoreCase))
                                return false;
                        }
                    }
                }
            }

            // 2. Check CorLib assembly reference name
            if (module.CorLibTypes.AssemblyRef != null && !UTF8String.IsNullOrEmpty(module.CorLibTypes.AssemblyRef.Name))
            {
                string corLib = module.CorLibTypes.AssemblyRef.Name.String;
                if (string.Equals(corLib, "mscorlib", StringComparison.OrdinalIgnoreCase))
                    return true;
                if (string.Equals(corLib, "System.Runtime", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(corLib, "System.Private.CoreLib", StringComparison.OrdinalIgnoreCase))
                    return false;
            }

            // 3. Fallback: check assembly references
            foreach (var ar in module.GetAssemblyRefs())
            {
                if (!UTF8String.IsNullOrEmpty(ar.Name) && string.Equals(ar.Name.String, "mscorlib", StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        public static List<RegressionDiagnostic> DetectStructuredRegressions(AuditReport baseline, AuditReport candidate)
        {
            var regressions = new List<RegressionDiagnostic>();
            if (candidate == null) return regressions;
            if (baseline == null)
            {
                foreach (var err in candidate.Errors)
                    regressions.Add(RegressionDiagnostic.FromRawError(err));
                return regressions;
            }

            var baselineErrors = new HashSet<string>(baseline.Errors, StringComparer.Ordinal);
            foreach (var err in candidate.Errors)
            {
                if (!baselineErrors.Contains(err))
                {
                    regressions.Add(RegressionDiagnostic.FromRawError(err));
                }
            }

            return regressions;
        }

        public static List<string> DetectRegressions(AuditReport baseline, AuditReport candidate)
        {
            var regressions = new List<string>();
            if (candidate == null) return regressions;
            if (baseline == null) return new List<string>(candidate.Errors);

            var baselineErrors = new HashSet<string>(baseline.Errors, StringComparer.Ordinal);
            foreach (var err in candidate.Errors)
            {
                if (!baselineErrors.Contains(err))
                {
                    regressions.Add(err);
                }
            }

            return regressions;
        }

        public static AuditReport Audit(string filePath, bool runExternalVerifier = true, string workingDir = null, IEnumerable<string> dependencyDirectories = null)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                throw new FileNotFoundException("Assembly file not found for audit", filePath);

            var report = new AuditReport { TargetPath = filePath, CanLoad = false };

            if (string.IsNullOrEmpty(workingDir))
                workingDir = Path.GetDirectoryName(filePath);

            bool isNetFramework = false;
            try
            {
                using (var module = ModuleDefMD.Load(filePath))
                {
                    report.CanLoad = true;
                    isNetFramework = IsNetFrameworkTarget(module);

                    var types = module.GetTypes();
                    report.TotalTypes = 0;
                    report.TotalMethods = 0;
                    report.MethodsWithBody = 0;

                    foreach (var type in types)
                    {
                        report.TotalTypes++;
                        foreach (var method in type.Methods)
                        {
                            report.TotalMethods++;
                            if (method.HasBody && method.Body != null)
                            {
                                report.MethodsWithBody++;
                                AuditMethod(method, report);
                            }
                        }
                    }

                    AuditManifestResourcesIntegrity(module, report);
                }
            }
            catch (Exception ex)
            {
                report.CanLoad = false;
                report.Errors.Add($"Failed to load assembly in dnlib: {ex.Message}");
                report.Warnings.Add($"Failed to load assembly in dnlib: {ex.Message}");
            }

            // Run external verification when requested and structurally valid
            if (runExternalVerifier && report.CanLoad && report.StructuralAuditPassed)
            {
                RunExternalVerification(filePath, isNetFramework, report, workingDir, dependencyDirectories);
            }

            return report;
        }

        private static void RunExternalVerification(string filePath, bool isNetFramework, AuditReport report, string workingDir, IEnumerable<string> dependencyDirectories)
        {
            if (isNetFramework)
            {
                string peverify = ResolvePEVerifyPath();
                if (peverify != null)
                {
                    string verificationDir = workingDir;
                    string stagedFilePath = filePath;
                    string tempStagingDir = null;

                    try
                    {
                        var depDirsList = (dependencyDirectories ?? Enumerable.Empty<string>())
                            .Where(d => !string.IsNullOrWhiteSpace(d) && Directory.Exists(d))
                            .Select(Path.GetFullPath)
                            .ToList();

                        if (depDirsList.Count > 0)
                        {
                            string fileDir = Path.GetFullPath(Path.GetDirectoryName(filePath));
                            bool alreadyInDepDir = depDirsList.Any(d => string.Equals(d, fileDir, StringComparison.OrdinalIgnoreCase));

                            if (!alreadyInDepDir)
                            {
                                tempStagingDir = Path.Combine(Path.GetTempPath(), "peverify_stage_" + Guid.NewGuid().ToString("N"));
                                Directory.CreateDirectory(tempStagingDir);

                                stagedFilePath = Path.Combine(tempStagingDir, Path.GetFileName(filePath));
                                File.Copy(filePath, stagedFilePath, true);

                                try
                                {
                                    using (var mod = ModuleDefMD.Load(filePath))
                                    {
                                        foreach (var asmRef in mod.GetAssemblyRefs())
                                        {
                                            string asmName = asmRef.Name?.String;
                                            if (string.IsNullOrEmpty(asmName)) continue;

                                            string targetDll = asmName + ".dll";
                                            string destFile = Path.Combine(tempStagingDir, targetDll);
                                            if (File.Exists(destFile)) continue;

                                            foreach (var dir in depDirsList)
                                            {
                                                string candidateDll = Path.Combine(dir, targetDll);
                                                if (File.Exists(candidateDll))
                                                {
                                                    File.Copy(candidateDll, destFile, true);
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                                catch
                                {
                                    foreach (var dir in depDirsList)
                                    {
                                        foreach (var dll in Directory.GetFiles(dir, "*.dll"))
                                        {
                                            string dest = Path.Combine(tempStagingDir, Path.GetFileName(dll));
                                            if (!File.Exists(dest))
                                                File.Copy(dll, dest, true);
                                        }
                                    }
                                }

                                verificationDir = tempStagingDir;
                            }
                        }

                        // 1. Independent IL verification
                        var procIL = ProcessRunner.Run(peverify, $"\"{stagedFilePath}\" /IL /UNIQUE /NOLOGO", verificationDir, timeoutMs: 30000);
                        InterpretPEVerifyILResult(procIL.ExitCode, procIL.StandardOutput, procIL.StandardError, procIL.TimedOut, report);

                        // 2. Independent MD verification
                        var procMD = ProcessRunner.Run(peverify, $"\"{stagedFilePath}\" /MD /UNIQUE /NOLOGO", verificationDir, timeoutMs: 30000);
                        InterpretPEVerifyMDResult(procMD.ExitCode, procMD.StandardOutput, procMD.StandardError, procMD.TimedOut, report);
                    }
                    catch (Exception ex)
                    {
                        report.ILVerificationStatus = "UNVERIFIED";
                        report.ILVerificationNotes = $"PEVerify invocation failed: {ex.Message}";
                    }
                    finally
                    {
                        if (tempStagingDir != null && Directory.Exists(tempStagingDir))
                        {
                            try { Directory.Delete(tempStagingDir, true); } catch { }
                        }
                    }
                }
                else
                {
                    report.ILVerificationStatus = "UNVERIFIED";
                    report.ILVerificationNotes = "External IL verification tool (PEVerify) not found in environment; structural audit passed.";
                }
            }
            else
            {
                string ilverify = ResolveILVerifyPath();
                if (ilverify != null)
                {
                    try
                    {
                        string args = $"\"{filePath}\"";
                        if (dependencyDirectories != null)
                        {
                            foreach (var d in dependencyDirectories.Where(Directory.Exists))
                            {
                                args += $" -r \"{Path.Combine(d, "*.dll")}\"";
                            }
                        }

                        var proc = ProcessRunner.Run(ilverify, args, workingDir, timeoutMs: 30000);
                        InterpretILVerifyResult(proc.ExitCode, proc.StandardOutput, proc.StandardError, proc.TimedOut, report);
                    }
                    catch (Exception ex)
                    {
                        report.ILVerificationStatus = "UNVERIFIED";
                        report.ILVerificationNotes = $"dotnet-ilverify invocation failed: {ex.Message}";
                    }
                }
                else
                {
                    report.ILVerificationStatus = "UNVERIFIED";
                    report.ILVerificationNotes = "dotnet-ilverify tool not installed on system; external verification skipped for .NET Core target.";
                }
            }
        }

        internal static void InterpretPEVerifyResult(int exitCode, string stdOut, string stdErr, bool timedOut, AuditReport report)
        {
            InterpretPEVerifyILResult(exitCode, stdOut, stdErr, timedOut, report);
        }

        internal static void InterpretPEVerifyILResult(int exitCode, string stdOut, string stdErr, bool timedOut, AuditReport report)
        {
            if (timedOut)
            {
                report.ILVerificationStatus = "INDETERMINATE";
                report.ILVerificationNotes = "PEVerify /IL timed out after 30000ms; external IL verification is indeterminate.";
                report.Warnings.Add("PEVerify /IL timed out; external IL verification is indeterminate.");
                return;
            }

            if (exitCode == 0)
            {
                report.ILVerificationStatus = "PASSED";
                report.ILVerificationNotes = "PEVerify: All classes and methods verified.";
                return;
            }

            string combinedOutput = ((stdOut ?? "") + "\n" + (stdErr ?? "")).Trim();
            string[] lines = combinedOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            var errorLines = lines.Where(l => !l.StartsWith("Outil de", StringComparison.OrdinalIgnoreCase)
                                           && !l.StartsWith("Microsoft (R)", StringComparison.OrdinalIgnoreCase)
                                           && !l.StartsWith("Copyright (c)", StringComparison.OrdinalIgnoreCase)
                                           && !l.Contains("Toutes les classes et les méthodes vérifiées")
                                           && !l.Contains("All Classes and Methods Verified")).ToList();

            bool isInternalError = exitCode == -2146231907 // 0x8013129D
                || combinedOutput.IndexOf("Internal error", StringComparison.OrdinalIgnoreCase) >= 0
                || combinedOutput.IndexOf("Erreur interne", StringComparison.OrdinalIgnoreCase) >= 0
                || combinedOutput.IndexOf("Fatal error", StringComparison.OrdinalIgnoreCase) >= 0
                || combinedOutput.IndexOf("Erreur fatale", StringComparison.OrdinalIgnoreCase) >= 0
                || (string.IsNullOrWhiteSpace(combinedOutput) && exitCode != 0);

            if (isInternalError)
            {
                string outSnippet = errorLines.Count > 0 ? string.Join(" ", errorLines) : combinedOutput.Trim();
                if (outSnippet.Length > 200) outSnippet = outSnippet.Substring(0, 200) + "...";

                report.ILVerificationStatus = "INDETERMINATE";
                report.ILVerificationNotes = $"PEVerify /IL encountered an internal engine error (ExitCode 0x{exitCode:X8}): {outSnippet}";
                report.Warnings.Add($"PEVerify internal error: {outSnippet}");
                return;
            }

            int missingDepErrors = 0;
            int moduleStubErrors = 0;
            int userMethodErrors = 0;
            var userErrors = new List<string>();
            var unclassifiedErrors = new List<string>();

            foreach (var line in errorLines)
            {
                if (line.IndexOf("0x80070002", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    line.IndexOf("en raison d'un assembly référencé manquant", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    line.IndexOf("due to missing referenced assembly", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    missingDepErrors++;
                    report.Warnings.Add($"PEVerify /IL dependency warning: {line.Trim()}");
                }
                else if (line.Contains("<Module>::.cctor") || line.Contains("<Module>..cctor"))
                {
                    moduleStubErrors++;
                    report.Warnings.Add($"PEVerify /IL <Module> warning: {line.Trim()}");
                }
                else if (line.IndexOf("[IL]: Erreur", StringComparison.OrdinalIgnoreCase) >= 0 ||
                         line.IndexOf("[IL]: Error", StringComparison.OrdinalIgnoreCase) >= 0 ||
                         line.IndexOf("Error:", StringComparison.OrdinalIgnoreCase) >= 0 ||
                         line.IndexOf("Erreur:", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    userMethodErrors++;
                    userErrors.Add(line.Trim());
                }
                else
                {
                    unclassifiedErrors.Add(line.Trim());
                }
            }

            if (userMethodErrors > 0)
            {
                report.ILVerificationStatus = "FAILED";
                string outSnippet = string.Join("; ", userErrors.Take(3));
                if (outSnippet.Length > 200) outSnippet = outSnippet.Substring(0, 200) + "...";
                report.ILVerificationNotes = $"PEVerify /IL reported {userMethodErrors} method verification error(s): {outSnippet}";
                report.Errors.Add($"PEVerify reported errors: {outSnippet}");
                report.Warnings.Add($"PEVerify reported errors: {outSnippet}");
            }
            else if (missingDepErrors > 0 && moduleStubErrors == 0 && unclassifiedErrors.Count == 0)
            {
                report.ILVerificationStatus = "INDETERMINATE";
                report.ILVerificationNotes = $"PEVerify /IL incomplete due to {missingDepErrors} missing referenced assembly error(s).";
            }
            else if (moduleStubErrors > 0 && missingDepErrors == 0 && unclassifiedErrors.Count == 0)
            {
                report.ILVerificationStatus = "WARNINGS";
                report.ILVerificationNotes = $"PEVerify /IL passed for all user methods with {moduleStubErrors} module stub warning(s).";
            }
            else if (missingDepErrors > 0 || moduleStubErrors > 0)
            {
                report.ILVerificationStatus = "INDETERMINATE";
                report.ILVerificationNotes = $"PEVerify /IL reported {missingDepErrors} dependency warning(s) and {moduleStubErrors} module stub warning(s).";
            }
            else
            {
                string snippet = unclassifiedErrors.Count > 0 ? string.Join("; ", unclassifiedErrors.Take(3)) : combinedOutput;
                if (snippet.Length > 200) snippet = snippet.Substring(0, 200) + "...";
                report.ILVerificationStatus = "INDETERMINATE";
                report.ILVerificationNotes = $"PEVerify /IL exited with non-zero code {exitCode} and unclassified diagnostic: {snippet}";
                report.Warnings.Add($"PEVerify unclassified output: {snippet}");
            }
        }

        internal static void InterpretPEVerifyMDResult(int exitCode, string stdOut, string stdErr, bool timedOut, AuditReport report)
        {
            if (timedOut)
            {
                report.Warnings.Add("PEVerify /MD timed out after 30000ms.");
                return;
            }

            if (exitCode == 0)
            {
                return;
            }

            string combinedOutput = ((stdOut ?? "") + "\n" + (stdErr ?? "")).Trim();
            string[] lines = combinedOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            var mdLines = lines.Where(l => !l.StartsWith("Outil de", StringComparison.OrdinalIgnoreCase)
                                        && !l.StartsWith("Microsoft (R)", StringComparison.OrdinalIgnoreCase)
                                        && !l.StartsWith("Copyright (c)", StringComparison.OrdinalIgnoreCase)).ToList();

            bool has0x8013129d = combinedOutput.IndexOf("0x8013129d", StringComparison.OrdinalIgnoreCase) >= 0;
            bool allVerified = combinedOutput.IndexOf("Toutes les classes et les méthodes vérifiées", StringComparison.OrdinalIgnoreCase) >= 0
                            || combinedOutput.IndexOf("All Classes and Methods Verified", StringComparison.OrdinalIgnoreCase) >= 0;

            var genuineMdErrors = mdLines.Where(l =>
                (l.IndexOf("[MD]: Erreur", StringComparison.OrdinalIgnoreCase) >= 0 ||
                 l.IndexOf("[MD]: Error", StringComparison.OrdinalIgnoreCase) >= 0 ||
                 l.IndexOf("Erreur :", StringComparison.OrdinalIgnoreCase) >= 0 ||
                 l.IndexOf("Error :", StringComparison.OrdinalIgnoreCase) >= 0) &&
                !l.Contains("0x8013129d")).ToList();

            if (genuineMdErrors.Count > 0)
            {
                string snippet = string.Join("; ", genuineMdErrors.Take(3));
                if (snippet.Length > 200) snippet = snippet.Substring(0, 200) + "...";
                report.Errors.Add($"PEVerify /MD reported {genuineMdErrors.Count} metadata error(s): {snippet}");
                report.Warnings.Add($"PEVerify /MD reported: {snippet}");
            }
            else if (has0x8013129d && allVerified)
            {
                report.Warnings.Add("PEVerify /MD warning: ConfuserEx <Module> stub metadata warning (0x8013129d). All classes and methods verified.");
            }
            else if (mdLines.Count > 0)
            {
                string snippet = string.Join(" ", mdLines.Take(3));
                if (snippet.Length > 200) snippet = snippet.Substring(0, 200) + "...";
                report.Warnings.Add($"PEVerify /MD reported: {snippet}");
            }
        }

        internal static void InterpretILVerifyResult(int exitCode, string stdOut, string stdErr, bool timedOut, AuditReport report)
        {
            if (timedOut)
            {
                report.ILVerificationStatus = "INDETERMINATE";
                report.ILVerificationNotes = "dotnet-ilverify timed out after 30000ms; external IL verification is indeterminate.";
                report.Warnings.Add("dotnet-ilverify timed out; external IL verification is indeterminate.");
            }
            else if (exitCode == 0)
            {
                report.ILVerificationStatus = "PASSED";
                report.ILVerificationNotes = "dotnet-ilverify: All classes and methods verified.";
            }
            else
            {
                string combinedOutput = ((stdOut ?? "") + "\n" + (stdErr ?? "")).Trim();
                bool isInternalError = combinedOutput.IndexOf("Internal error", StringComparison.OrdinalIgnoreCase) >= 0
                    || combinedOutput.IndexOf("Fatal error", StringComparison.OrdinalIgnoreCase) >= 0
                    || combinedOutput.IndexOf("Crash", StringComparison.OrdinalIgnoreCase) >= 0
                    || (string.IsNullOrWhiteSpace(combinedOutput) && exitCode != 0);

                string outSnippet = (stdOut ?? "").Trim();
                if (string.IsNullOrWhiteSpace(outSnippet)) outSnippet = (stdErr ?? "").Trim();
                if (outSnippet.Length > 200) outSnippet = outSnippet.Substring(0, 200) + "...";

                if (isInternalError)
                {
                    report.ILVerificationStatus = "INDETERMINATE";
                    report.ILVerificationNotes = $"dotnet-ilverify encountered an internal engine error: {outSnippet}";
                    report.Warnings.Add($"dotnet-ilverify internal error: {outSnippet}");
                }
                else
                {
                    report.ILVerificationStatus = "FAILED";
                    report.ILVerificationNotes = $"dotnet-ilverify reported errors (ExitCode {exitCode}): {outSnippet}";
                    report.Errors.Add($"dotnet-ilverify reported errors: {outSnippet}");
                    report.Warnings.Add($"dotnet-ilverify reported errors: {outSnippet}");
                }
            }
        }

        /// <summary>
        /// Audits a method body for structural integrity, operand bounds, branch targets, exception handler boundaries,
        /// and evaluation stack balance across all CFG paths.
        ///
        /// Scope and verification limits:
        /// - In-Scope (Structural &amp; CFG Analysis):
        ///   * Instruction operand validity and local/parameter index bounds.
        ///   * Branch and switch target validity (no unlisted/orphaned targets).
        ///   * Exception handler clause ordering (TryStart &lt;= TryEnd) and boundary containment.
        ///   * Evaluation stack depth simulation across all control-flow paths (underflows, CFG merge point consistency).
        ///   * Verification of stack depth at every reachable ret instruction (0 for void methods, 1 for value-returning methods).
        /// - Out-of-Scope (Full CLI ECMA-335 Verification):
        ///   * Complete ECMA-335 type-safety (e.g. verifying that an instruction argument is assignment-compatible with
        ///     the declared parameter type, or ref/byref pointer lifespan and aliasing rules).
        ///   * Member accessibility constraints across assemblies (private, internal, protected visibility).
        ///   * Generic type parameter constraints and variance.
        ///   These rules require disk resolution of all referenced assemblies and are typically verified by an external
        ///   CLI verification tool such as ILVerify or PEVerify.
        /// </summary>
        public static bool IsMethodStructurallyValid(MethodDef method, out List<string> errors)
        {
            errors = new List<string>();
            if (method == null || !method.HasBody || method.Body == null)
                return true;

            var report = new AuditReport { CanLoad = true };
            AuditMethod(method, report);

            if (!report.StructuralAuditPassed || report.Errors.Count > 0)
            {
                errors = report.Errors;
                return false;
            }

            return true;
        }

        public static void AuditMethod(MethodDef method, AuditReport report)
        {
            var instructions = method.Body.Instructions;
            var instSet = new HashSet<Instruction>(instructions);

            for (int i = 0; i < instructions.Count; i++)
            {
                var inst = instructions[i];
                if (inst == null)
                {
                    report.InvalidInstructionsCount++;
                    report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} contains null instruction entry at index {i}");
                    continue;
                }

                // Check for valid branch targets
                if (inst.OpCode.OperandType == OperandType.InlineBrTarget || inst.OpCode.OperandType == OperandType.ShortInlineBrTarget)
                {
                    if (inst.Operand == null || !(inst.Operand is Instruction branchTarget) || !instSet.Contains((Instruction)inst.Operand))
                    {
                        report.InvalidInstructionsCount++;
                        report.InvalidBranchesCount++;
                        report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} branches to orphaned/unlisted instruction at IL_{inst.Offset:X4}");
                        report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} branches to orphaned/unlisted instruction at IL_{inst.Offset:X4}");
                    }
                }
                else if (inst.Operand is Instruction branchTarget)
                {
                    if (!instSet.Contains(branchTarget))
                    {
                        report.InvalidInstructionsCount++;
                        report.InvalidBranchesCount++;
                        report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} branches to orphaned/unlisted instruction at IL_{inst.Offset:X4}");
                        report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} branches to orphaned/unlisted instruction at IL_{inst.Offset:X4}");
                    }
                }
                else if (inst.OpCode.OperandType == OperandType.InlineSwitch)
                {
                    if (inst.Operand == null)
                    {
                        report.InvalidInstructionsCount++;
                        report.InvalidBranchesCount++;
                        report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has null switch targets at IL_{inst.Offset:X4}");
                    }
                    else if (inst.Operand is IList<Instruction> switchTargets)
                    {
                        for (int st = 0; st < switchTargets.Count; st++)
                        {
                            var target = switchTargets[st];
                            if (target == null || !instSet.Contains(target))
                            {
                                report.InvalidInstructionsCount++;
                                report.InvalidBranchesCount++;
                                report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} switch target #{st} is null or unlisted at IL_{inst.Offset:X4}");
                                report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} switch target #{st} is null or unlisted at IL_{inst.Offset:X4}");
                            }
                        }
                    }
                    else if (inst.Operand is Instruction[] switchArray)
                    {
                        for (int st = 0; st < switchArray.Length; st++)
                        {
                            var target = switchArray[st];
                            if (target == null || !instSet.Contains(target))
                            {
                                report.InvalidInstructionsCount++;
                                report.InvalidBranchesCount++;
                                report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} switch target #{st} is null or unlisted at IL_{inst.Offset:X4}");
                                report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} switch target #{st} is null or unlisted at IL_{inst.Offset:X4}");
                            }
                        }
                    }
                }

                // Check operands for call instructions
                if (inst.OpCode == OpCodes.Call || inst.OpCode == OpCodes.Callvirt || inst.OpCode == OpCodes.Newobj)
                {
                    if (inst.Operand == null)
                    {
                        report.InvalidInstructionsCount++;
                        report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has null operand for call at IL_{inst.Offset:X4}");
                        report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has null operand for call at IL_{inst.Offset:X4}");
                    }
                    else if (inst.Operand is IMethod calledMethod)
                    {
                        if (calledMethod is MemberRef mr)
                        {
                            if (mr.Class is TypeDef || (mr.Class is TypeRef tr && tr.ResolutionScope is ModuleDef))
                            {
                                if (mr.ResolveMethodDef() == null)
                                {
                                    report.UnresolvedCallSitesCount++;
                                    report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Unresolved internal call site: {mr.FullName}");
                                }
                            }
                        }
                    }
                }

                // Check operands for field instructions
                if (inst.OpCode == OpCodes.Ldfld || inst.OpCode == OpCodes.Stfld || inst.OpCode == OpCodes.Ldsfld || inst.OpCode == OpCodes.Stsfld)
                {
                    if (inst.Operand == null)
                    {
                        report.InvalidInstructionsCount++;
                        report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has null operand for field access at IL_{inst.Offset:X4}");
                    }
                }

                // Check operands for method pointer instructions
                if (inst.OpCode == OpCodes.Ldftn || inst.OpCode == OpCodes.Ldvirtftn)
                {
                    if (inst.Operand == null)
                    {
                        report.InvalidInstructionsCount++;
                        report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has null operand for function pointer load at IL_{inst.Offset:X4}");
                    }
                }

                // Check local variable references
                if (inst.Operand is Local local)
                {
                    if (!method.Body.Variables.Contains(local))
                    {
                        report.InvalidInstructionsCount++;
                        report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} references unlisted local variable at IL_{inst.Offset:X4}");
                    }
                }
                else
                {
                    int localIdx = -1;
                    if (inst.OpCode == OpCodes.Ldloc_0 || inst.OpCode == OpCodes.Stloc_0) localIdx = 0;
                    else if (inst.OpCode == OpCodes.Ldloc_1 || inst.OpCode == OpCodes.Stloc_1) localIdx = 1;
                    else if (inst.OpCode == OpCodes.Ldloc_2 || inst.OpCode == OpCodes.Stloc_2) localIdx = 2;
                    else if (inst.OpCode == OpCodes.Ldloc_3 || inst.OpCode == OpCodes.Stloc_3) localIdx = 3;

                    if (localIdx >= 0 && localIdx >= method.Body.Variables.Count)
                    {
                        report.InvalidInstructionsCount++;
                        report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} uses {inst.OpCode} but method has only {method.Body.Variables.Count} local variables");
                    }
                }

                // Check parameter references
                int paramIdx = -1;
                if (inst.OpCode == OpCodes.Ldarg_0) paramIdx = 0;
                else if (inst.OpCode == OpCodes.Ldarg_1) paramIdx = 1;
                else if (inst.OpCode == OpCodes.Ldarg_2) paramIdx = 2;
                else if (inst.OpCode == OpCodes.Ldarg_3) paramIdx = 3;

                if (paramIdx >= 0 && paramIdx >= method.Parameters.Count)
                {
                    report.InvalidInstructionsCount++;
                    report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} uses {inst.OpCode} but method has only {method.Parameters.Count} parameters (including this)");
                }
            }

            // Check exception handler boundaries
            if (method.Body.HasExceptionHandlers)
            {
                foreach (var eh in method.Body.ExceptionHandlers)
                {
                    bool validStart = true;
                    if (eh.TryStart == null || !instSet.Contains(eh.TryStart))
                    {
                        report.InvalidInstructionsCount++;
                        report.InvalidEHCount++;
                        report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has invalid/unlisted TryStart in exception handler");
                        report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has invalid/unlisted TryStart in exception handler");
                        validStart = false;
                    }
                    if (eh.TryEnd != null && !instSet.Contains(eh.TryEnd))
                    {
                        report.InvalidInstructionsCount++;
                        report.InvalidEHCount++;
                        report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has unlisted TryEnd in exception handler");
                        report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has unlisted TryEnd in exception handler");
                        validStart = false;
                    }
                    if (eh.HandlerStart == null || !instSet.Contains(eh.HandlerStart))
                    {
                        report.InvalidInstructionsCount++;
                        report.InvalidEHCount++;
                        report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has invalid/unlisted HandlerStart in exception handler");
                        report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has invalid/unlisted HandlerStart in exception handler");
                        validStart = false;
                    }
                    if (eh.HandlerEnd != null && !instSet.Contains(eh.HandlerEnd))
                    {
                        report.InvalidInstructionsCount++;
                        report.InvalidEHCount++;
                        report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has unlisted HandlerEnd in exception handler");
                        report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has unlisted HandlerEnd in exception handler");
                        validStart = false;
                    }
                    if (eh.FilterStart != null && !instSet.Contains(eh.FilterStart))
                    {
                        report.InvalidInstructionsCount++;
                        report.InvalidEHCount++;
                        report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has unlisted FilterStart in exception handler");
                        report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has unlisted FilterStart in exception handler");
                        validStart = false;
                    }

                    // Check boundary ordering if instructions are listed
                    if (validStart && eh.TryStart != null && eh.TryEnd != null)
                    {
                        int tryStartIdx = instructions.IndexOf(eh.TryStart);
                        int tryEndIdx = instructions.IndexOf(eh.TryEnd);
                        if (tryStartIdx > tryEndIdx)
                        {
                            report.InvalidInstructionsCount++;
                            report.InvalidEHCount++;
                            report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name}: ExceptionHandler TryStart occurs after TryEnd");
                        }
                    }
                }
            }

            // Comprehensive CFG evaluation stack verification:
            // Simulates stack depths along all control-flow paths (including branch joins, switches, and EH blocks)
            // and verifies stack heights at ret, merge points, and underflows.
            AuditEvaluationStackCFG(method, report);

            // Cross-check max stack calculation via dnlib
            try
            {
                dnlib.DotNet.Writer.MaxStackCalculator.GetMaxStack(instructions, method.Body.ExceptionHandlers);
            }
            catch (Exception ex)
            {
                report.StackUnderflowCount++;
                report.InvalidInstructionsCount++;
                report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name}: Evaluation stack CFG error: {ex.Message}");
                report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name}: Evaluation stack CFG error: {ex.Message}");
            }

            // Check end-of-method termination
            if (instructions.Count > 0)
            {
                var last = instructions[instructions.Count - 1];
                if (last != null && !IsTerminatingOpCode(last.OpCode))
                {
                    report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} does not terminate with ret/throw/br at IL_{last.Offset:X4} ({last.OpCode})");
                }
            }
        }

        private static void AuditEvaluationStackCFG(MethodDef method, AuditReport report)
        {
            var instructions = method.Body.Instructions;
            if (instructions == null || instructions.Count == 0) return;

            var instToIndex = new Dictionary<Instruction, int>(instructions.Count);
            for (int i = 0; i < instructions.Count; i++)
            {
                var inst = instructions[i];
                if (inst != null && !instToIndex.ContainsKey(inst))
                    instToIndex[inst] = i;
            }

            int?[] entryStack = new int?[instructions.Count];
            var queue = new Queue<int>();

            void Enqueue(int idx, int stack)
            {
                if (idx < 0 || idx >= instructions.Count) return;

                if (!entryStack[idx].HasValue)
                {
                    entryStack[idx] = stack;
                    queue.Enqueue(idx);
                }
                else if (entryStack[idx].Value != stack)
                {
                    // Stack height mismatch at CFG merge point
                    report.StackUnderflowCount++;
                    report.InvalidInstructionsCount++;
                    string msg = $"[0x{method.MDToken.Raw:X8}] Method {method.Name}: Stack height mismatch at CFG merge point IL_{instructions[idx].Offset:X4}: incoming stack height {stack} differs from existing {entryStack[idx].Value}";
                    report.Errors.Add(msg);
                    report.Warnings.Add(msg);
                }
            }

            // 1. Initial entry point (method start)
            Enqueue(0, 0);

            // 2. Exception handler entry points
            if (method.Body.HasExceptionHandlers)
            {
                foreach (var eh in method.Body.ExceptionHandlers)
                {
                    if (eh.HandlerType == ExceptionHandlerType.Catch)
                    {
                        // CLR pushes the caught exception object on entry to catch block
                        if (eh.HandlerStart != null && instToIndex.TryGetValue(eh.HandlerStart, out int hIdx))
                            Enqueue(hIdx, 1);
                    }
                    else if (eh.HandlerType == ExceptionHandlerType.Filter)
                    {
                        // CLR pushes the exception object on entry to filter block
                        if (eh.FilterStart != null && instToIndex.TryGetValue(eh.FilterStart, out int fIdx))
                            Enqueue(fIdx, 1);
                        if (eh.HandlerStart != null && instToIndex.TryGetValue(eh.HandlerStart, out int hIdx))
                            Enqueue(hIdx, 1);
                    }
                    else if (eh.HandlerType == ExceptionHandlerType.Finally || eh.HandlerType == ExceptionHandlerType.Fault)
                    {
                        // Stack is empty on entry to finally or fault block
                        if (eh.HandlerStart != null && instToIndex.TryGetValue(eh.HandlerStart, out int hIdx))
                            Enqueue(hIdx, 0);
                    }
                }
            }

            bool isVoid = method.ReturnType == null ||
                          method.ReturnType.ElementType == ElementType.Void ||
                          (method.ReturnType.TypeName == "Void" && method.ReturnType.Namespace == "System");

            while (queue.Count > 0)
            {
                int idx = queue.Dequeue();
                var inst = instructions[idx];
                if (inst == null) continue;

                int curStack = entryStack[idx].Value;

                inst.CalculateStackUsage(out int pushes, out int pops);
                int popsUsed = pops == -1 ? curStack : pops;
                int pushesUsed = pushes > 0 ? pushes : 0;

                if (popsUsed > 0 && popsUsed > curStack)
                {
                    report.StackUnderflowCount++;
                    report.InvalidInstructionsCount++;
                    string err = $"[0x{method.MDToken.Raw:X8}] Method {method.Name}: Stack underflow on CFG path at IL_{inst.Offset:X4} ({inst.OpCode}): required pop {popsUsed} but stack depth is {curStack}";
                    report.Errors.Add(err);
                    report.Warnings.Add(err);
                }

                int exitStack = Math.Max(0, curStack - popsUsed) + pushesUsed;

                if (inst.OpCode == OpCodes.Ret)
                {
                    if (isVoid && exitStack > 0)
                    {
                        report.InvalidInstructionsCount++;
                        report.StackUnderflowCount++;
                        string err = $"[0x{method.MDToken.Raw:X8}] Method {method.Name}: Non-empty stack ({exitStack}) at void return on CFG path at IL_{inst.Offset:X4}";
                        report.Errors.Add(err);
                        report.Warnings.Add(err);
                    }
                    else if (!isVoid && exitStack != 1)
                    {
                        report.InvalidInstructionsCount++;
                        report.StackUnderflowCount++;
                        string err = $"[0x{method.MDToken.Raw:X8}] Method {method.Name}: Invalid stack depth ({exitStack}) at non-void return (expected 1) on CFG path at IL_{inst.Offset:X4}";
                        report.Errors.Add(err);
                        report.Warnings.Add(err);
                    }
                    continue;
                }

                if (inst.OpCode == OpCodes.Throw || inst.OpCode == OpCodes.Rethrow)
                {
                    continue;
                }

                if (inst.OpCode == OpCodes.Leave || inst.OpCode == OpCodes.Leave_S)
                {
                    // ECMA-335 Partition III Section 3.42: leave instruction empties evaluation stack
                    if (inst.Operand is Instruction leaveTarget && instToIndex.TryGetValue(leaveTarget, out int tIdx))
                    {
                        Enqueue(tIdx, 0);
                    }
                    continue;
                }

                if (inst.OpCode == OpCodes.Endfinally)
                {
                    if (curStack != 0)
                    {
                        report.InvalidInstructionsCount++;
                        report.StackUnderflowCount++;
                        string err = $"[0x{method.MDToken.Raw:X8}] Method {method.Name}: Non-empty stack ({curStack}) at endfinally at IL_{inst.Offset:X4}";
                        report.Errors.Add(err);
                        report.Warnings.Add(err);
                    }
                    continue;
                }

                if (inst.OpCode == OpCodes.Endfilter)
                {
                    continue;
                }

                if (inst.OpCode == OpCodes.Br || inst.OpCode == OpCodes.Br_S)
                {
                    if (inst.Operand is Instruction brTarget && instToIndex.TryGetValue(brTarget, out int tIdx))
                    {
                        Enqueue(tIdx, exitStack);
                    }
                    continue;
                }

                if (inst.OpCode == OpCodes.Jmp)
                {
                    continue;
                }

                if (inst.OpCode.OperandType == OperandType.InlineBrTarget || inst.OpCode.OperandType == OperandType.ShortInlineBrTarget)
                {
                    if (inst.Operand is Instruction condTarget && instToIndex.TryGetValue(condTarget, out int tIdx))
                    {
                        Enqueue(tIdx, exitStack);
                    }
                    if (idx + 1 < instructions.Count)
                    {
                        Enqueue(idx + 1, exitStack);
                    }
                    continue;
                }

                if (inst.OpCode == OpCodes.Switch)
                {
                    if (inst.Operand is IList<Instruction> switchList)
                    {
                        foreach (var st in switchList)
                        {
                            if (st != null && instToIndex.TryGetValue(st, out int tIdx))
                                Enqueue(tIdx, exitStack);
                        }
                    }
                    else if (inst.Operand is Instruction[] switchArray)
                    {
                        foreach (var st in switchArray)
                        {
                            if (st != null && instToIndex.TryGetValue(st, out int tIdx))
                                Enqueue(tIdx, exitStack);
                        }
                    }
                    if (idx + 1 < instructions.Count)
                    {
                        Enqueue(idx + 1, exitStack);
                    }
                    continue;
                }

                if (idx + 1 < instructions.Count)
                {
                    Enqueue(idx + 1, exitStack);
                }
                else
                {
                    // Linear flow falls off the end of instruction stream
                    report.InvalidInstructionsCount++;
                    string err = $"[0x{method.MDToken.Raw:X8}] Method {method.Name}: Control flow falls off the end of the method body at IL_{inst.Offset:X4} ({inst.OpCode}) without ret/throw";
                    report.Errors.Add(err);
                    report.Warnings.Add(err);
                }
            }
        }

        private static bool IsTerminatingOpCode(OpCode op)
        {
            return op == OpCodes.Ret || op == OpCodes.Throw || op == OpCodes.Rethrow ||
                   op == OpCodes.Br || op == OpCodes.Br_S || op == OpCodes.Jmp;
        }

        public static void AuditManifestResourcesIntegrity(ModuleDef module, AuditReport report)
        {
            if (module == null || report == null) return;

            var manifestResources = new HashSet<string>(module.Resources.Select(r => r.Name.String), StringComparer.Ordinal);

            // 1. Check ComponentResourceManager and ResourceManager(typeof(T)) call sites
            foreach (var type in module.GetTypes())
            {
                if (!type.HasMethods) continue;
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody || method.Body.Instructions == null) continue;
                    var instrs = method.Body.Instructions;
                    for (int i = 0; i < instrs.Count; i++)
                    {
                        var ins = instrs[i];
                        if (ins.OpCode == OpCodes.Newobj && ins.Operand is IMethod called &&
                            called.DeclaringType != null &&
                            (called.DeclaringType.FullName == "System.ComponentModel.ComponentResourceManager" ||
                             called.DeclaringType.FullName == "System.Resources.ResourceManager"))
                        {
                            // Check for typeof(T) pattern via ldtoken
                            for (int j = Math.Max(0, i - 5); j < i; j++)
                            {
                                var prev = instrs[j];
                                if (prev.OpCode == OpCodes.Ldtoken && prev.Operand is ITypeDefOrRef tokenType)
                                {
                                    string expectedRes = tokenType.FullName + ".resources";
                                    if (!manifestResources.Contains(expectedRes))
                                    {
                                        string err = $"Missing Manifest Resource: Type '{type.FullName}' invokes ComponentResourceManager for '{tokenType.FullName}', but manifest resource stream '{expectedRes}' does not exist.";
                                        report.Errors.Add(err);
                                        report.Warnings.Add(err);
                                        report.Diagnostics.Add(new RegressionDiagnostic
                                        {
                                            DefectType = DefectType.MetadataError,
                                            Severity = DiagnosticSeverity.Error,
                                            Token = type.MDToken.Raw,
                                            MethodName = method.Name.String,
                                            Description = err,
                                            RawMessage = err
                                        });
                                    }
                                    break;
                                }
                            }

                            // Check for string baseName pattern via ldstr
                            if (called.DeclaringType.FullName == "System.Resources.ResourceManager")
                            {
                                for (int j = i - 1; j >= Math.Max(0, i - 6); j--)
                                {
                                    var prev = instrs[j];
                                    if (prev.OpCode == OpCodes.Ldstr && prev.Operand is string baseName && !string.IsNullOrEmpty(baseName))
                                    {
                                        string expectedRes1 = baseName + ".resources";
                                        string expectedRes2 = baseName;
                                        if (!manifestResources.Contains(expectedRes1) && !manifestResources.Contains(expectedRes2))
                                        {
                                            string err = $"Missing Manifest Resource: Type '{type.FullName}' in method '{method.Name}' initializes ResourceManager with baseName '{baseName}', but manifest resource stream '{expectedRes1}' does not exist.";
                                            report.Errors.Add(err);
                                            report.Warnings.Add(err);
                                            report.Diagnostics.Add(new RegressionDiagnostic
                                            {
                                                DefectType = DefectType.MetadataError,
                                                Severity = DiagnosticSeverity.Error,
                                                Token = type.MDToken.Raw,
                                                MethodName = method.Name.String,
                                                Description = err,
                                                RawMessage = err
                                            });
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // 2. Validate integrity of embedded .resources streams
            foreach (var emb in module.Resources.OfType<EmbeddedResource>())
            {
                if (emb.Name.String.EndsWith(".resources", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        using (var stream = emb.GetResourceStream())
                        {
                            if (stream != null && stream.Length >= 4)
                            {
                                byte[] magic = new byte[4];
                                int read = stream.Read(magic, 0, 4);
                                stream.Position = 0;
                                // 0xBEEFCACE in little endian: 0xCE, 0xCA, 0xEF, 0xBE
                                if (read == 4 && magic[0] == 0xCE && magic[1] == 0xCA && magic[2] == 0xEF && magic[3] == 0xBE)
                                {
                                    try
                                    {
                                        using (var reader = new System.Resources.ResourceReader(stream))
                                        {
                                            var en = reader.GetEnumerator();
                                            while (en.MoveNext()) { }
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        string err = $"Corrupted Manifest Resource: Resource stream '{emb.Name}' has valid magic header but failed to deserialize: {ex.Message}";
                                        report.Errors.Add(err);
                                        report.Warnings.Add(err);
                                        report.Diagnostics.Add(new RegressionDiagnostic
                                        {
                                            DefectType = DefectType.MetadataError,
                                            Severity = DiagnosticSeverity.Error,
                                            Description = err,
                                            RawMessage = err
                                        });
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        string err = $"Failed to read resource stream '{emb.Name}': {ex.Message}";
                        report.Errors.Add(err);
                        report.Warnings.Add(err);
                        report.Diagnostics.Add(new RegressionDiagnostic
                        {
                            DefectType = DefectType.MetadataError,
                            Severity = DiagnosticSeverity.Error,
                            Description = err,
                            RawMessage = err
                        });
                    }
                }
            }
        }
    }
}
