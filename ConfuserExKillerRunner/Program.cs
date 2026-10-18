using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using ConfuserExKillerRunner.Analysis;
using ConfuserExKillerRunner.Core;
using ConfuserExKillerRunner.Killers;
using ConfuserExTools.AntiTamperKiller;
using ConfuserExTools.ConfuserExKiller;
using ConfuserExTools.ConstantKiller;
using ConfuserExTools.ProxyKiller;
using dnlib.DotNet;
using dnlib.DotNet.Writer;

namespace ConfuserExKillerRunner
{
    class Program
    {
        static int Main(string[] args)
        {
            if (args.Length == 0 || args.Contains("-h") || args.Contains("--help"))
            {
                PrintUsage();
                return 0;
            }

            string assemblyPath = null;
            bool allowExecution = false;
            string explicitDe4dotPath = null;
            bool skipDe4dot = false;
            bool skipNetDetect = false;
            string outputPath = null;
            bool verbose = false;

            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];
                if (arg == "--allow-execution")
                {
                    allowExecution = true;
                }
                else if (arg == "--no-de4dot")
                {
                    skipDe4dot = true;
                }
                else if (arg == "--no-netdetect")
                {
                    skipNetDetect = true;
                }
                else if (arg == "--verbose")
                {
                    verbose = true;
                }
                else if ((arg == "--de4dot" || arg == "-d") && i + 1 < args.Length)
                {
                    explicitDe4dotPath = args[++i];
                }
                else if ((arg == "-o" || arg == "--output") && i + 1 < args.Length)
                {
                    outputPath = args[++i];
                }
                else if (!arg.StartsWith("-") && assemblyPath == null)
                {
                    assemblyPath = Path.GetFullPath(arg);
                }
            }

            Tool.Logger.Initialize(verbose);

            if (string.IsNullOrEmpty(assemblyPath))
            {
                Console.WriteLine("[ERROR] No target assembly specified.");
                PrintUsage();
                return 1;
            }

            if (!File.Exists(assemblyPath))
            {
                Console.WriteLine($"[ERROR] File not found: {assemblyPath}");
                return 1;
            }

            Console.WriteLine("===============================================================");
            Console.WriteLine("          ConfuserExKillerRunner - Deobfuscation Engine        ");
            Console.WriteLine("===============================================================");
            string originalInputPath = Path.GetFullPath(assemblyPath);
            Console.WriteLine($"[*] Target: {assemblyPath}");
            Console.WriteLine($"[*] Process Bitness: {(Environment.Is64BitProcess ? "64-bit" : "32-bit")}");

            // Architecture Analysis
            var archInfo = ArchitectureDetector.Detect(assemblyPath);
            Console.WriteLine($"[*] Target Architecture: {archInfo.Architecture} (Machine=0x{archInfo.Machine:X4}, PE32+={archInfo.IsPe32Plus}, 32BitReq={archInfo.Is32BitRequired})");

            if (!archInfo.IsCompatibleWithCurrentProcess())
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[!] WARNING: Target architecture ({archInfo.Architecture}) may be incompatible with current {(Environment.Is64BitProcess ? "64-bit" : "32-bit")} process.");
                Console.WriteLine("[!] If dynamic execution is enabled, BadImageFormatException may occur.");
                Console.ResetColor();
            }

            // Dedicated temporary directory for intermediate pipeline artifacts (.unwrapped, .cexk, -cleaned, .candidate)
            string executionTempDir = Path.Combine(Path.GetTempPath(), "unconfuser_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(executionTempDir);

            // Target dependency resolver (only active when dynamic execution is explicitly permitted)
            string targetDir = Path.GetDirectoryName(originalInputPath);
            AppDomain.CurrentDomain.AssemblyResolve += (sender, resolveArgs) =>
            {
                if (!allowExecution)
                    return null;

                try
                {
                    string simpleName = new AssemblyName(resolveArgs.Name).Name;
                    if (string.IsNullOrEmpty(simpleName)) return null;

                    // Do not load core or framework assemblies from target folder
                    if (simpleName.Equals("mscorlib", StringComparison.OrdinalIgnoreCase) ||
                        simpleName.StartsWith("System.", StringComparison.OrdinalIgnoreCase) ||
                        simpleName.StartsWith("Microsoft.", StringComparison.OrdinalIgnoreCase) ||
                        simpleName.Equals("dnlib", StringComparison.OrdinalIgnoreCase) ||
                        simpleName.Equals("de4dot.blocks", StringComparison.OrdinalIgnoreCase))
                    {
                        return null;
                    }

                    string candidate = Path.Combine(targetDir, simpleName + ".dll");
                    if (File.Exists(candidate))
                        return Assembly.LoadFrom(candidate);
                    candidate = Path.Combine(targetDir, simpleName + ".exe");
                    if (File.Exists(candidate))
                        return Assembly.LoadFrom(candidate);
                }
                catch { }
                return null;
            };

            try
            {
                byte[] peImageOld = File.ReadAllBytes(assemblyPath);
                byte[] peImage = (byte[])peImageOld.Clone();
                Module reflModule = null;

                NetDetectScanResult preScan = null;
                if (!skipNetDetect)
                {
                    preScan = NetDetectIntegration.RunScan(assemblyPath);
                    NetDetectIntegration.PrintPreScanReport(preScan);
                }

                // Stage 0: Unpack ConfuserEx Compressor if present
                try
                {
                    using (var probeMod = ModuleDefMD.Load(peImage))
                    {
                        var unpackResult = CompressorUnpacker.TryUnpack(probeMod, peImage, allowExecution);
                        if (unpackResult.SuccessfullyUnpacked)
                        {
                            Console.WriteLine($"[+] CompressorUnpacker: {unpackResult.Message}");
                            peImage = unpackResult.UnpackedAssemblyBytes;
                            peImageOld = (byte[])peImage.Clone();
                            string unwrappedPath = Path.Combine(executionTempDir, Path.GetFileNameWithoutExtension(assemblyPath) + ".unwrapped" + Path.GetExtension(assemblyPath));
                            File.WriteAllBytes(unwrappedPath, peImage);
                            assemblyPath = unwrappedPath;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] CompressorUnpacker probing failed: {ex.Message}");
                }

                // Step 1: Safety Gate & Anti-Tamper
                bool antiTamperDecrypted = false;
                if (!allowExecution)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine();
                    Console.WriteLine("[!] ========================== SAFETY GATE ==========================");
                    Console.WriteLine("[!] Execution mode is DISABLED (default: pure static analysis).");
                    Console.WriteLine("[!] Untrusted target constructors (<Module>.cctor) will NOT be executed.");
                    Console.WriteLine("[!] Running in Pure Static Analysis mode.");
                    Console.WriteLine("[!] To enable runtime AntiTamper and dynamic Constant decryption,");
                    Console.WriteLine("[!] re-run with '--allow-execution'.");
                    Console.WriteLine("[!] =================================================================");
                    Console.WriteLine();
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine();
                    Console.WriteLine("[!] ==================== SECURITY WARNING: DYNAMIC EXECUTION ====================");
                    Console.WriteLine("[!] Dynamic execution mode (--allow-execution) is ACTIVE.");
                    Console.WriteLine("[!] Target module code (<Module>.cctor and initializers) will be EXECUTED in this process.");
                    Console.WriteLine("[!] THIS MODE DOES NOT PROVIDE AN OS SECURITY SANDBOX.");
                    Console.WriteLine("[!] UNTRUSTED OR MALICIOUS SAMPLES MUST BE RUN IN AN ISOLATED VM WITHOUT NETWORK ACCESS.");
                    Console.WriteLine("[!] ==============================================================================");
                    Console.WriteLine();
                    Console.ResetColor();

                    Console.WriteLine("[*] Step 1: Running AntiTamperKiller (Dynamic Execution Enabled)...");
                    try
                    {
                        reflModule = Assembly.LoadFile(assemblyPath).ManifestModule;
                        var atResult = AntiTamperKiller.Execute(reflModule, peImageOld);
                        var processed = ProcessAntiTamperResult(atResult, peImageOld);
                        antiTamperDecrypted = processed.antiTamperDecrypted;
                        peImage = processed.effectivePeImage;

                        switch (atResult.Status)
                        {
                            case AntiTamperStatus.DecryptionConfirmed:
                                Console.WriteLine($"[+] AntiTamper: Decryption confirmed across {atResult.DecryptedSections.Count} section(s) ({string.Join(", ", atResult.DecryptedSections)})");
                                break;

                            case AntiTamperStatus.ChangesDetected:
                                Console.WriteLine($"[!] AntiTamper: Changes detected in {atResult.DecryptedSections.Count} section(s), but method decryption unconfirmed. Retaining hooks.");
                                break;

                            case AntiTamperStatus.NoChangesDetected:
                                Console.WriteLine("[-] AntiTamper: No section differences detected");
                                break;

                            case AntiTamperStatus.Failed:
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine($"[!] AntiTamper dynamic execution failed: {atResult.Message}");
                                Console.ResetColor();
                                break;

                            default:
                                Console.WriteLine("[-] AntiTamper: Dynamic execution not attempted");
                                break;
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"[!] AntiTamper dynamic execution failed: {ex.Message}");
                        Console.ResetColor();
                        peImage = (byte[])peImageOld.Clone();
                        antiTamperDecrypted = false;
                    }
                }

                byte[] bytesToLoad = (byte[])peImage.Clone();
                bool initialLoadOk = false;
                try
                {
                    using (var testMod = ModuleDefMD.Load(bytesToLoad)) { }
                    initialLoadOk = true;
                }
                catch (Exception initialEx)
                {
                    Tool.Logger.LogInfo($"Initial ModuleDefMD load failed: {initialEx.Message}. Evaluating COR20 repair...");
                }

                if (!initialLoadOk)
                {
                    byte[] candidateBytes = (byte[])peImage.Clone();
                    var repairResult = Cor20Repair.Repair(candidateBytes, peImageOld);

                    if (repairResult.Success && (repairResult.CbRepaired || repairResult.MetaDataRvaRepaired))
                    {
                        if (repairResult.CbRepaired)
                            Console.WriteLine($"[+] Anti-Dump: Fixed COR20 header cb from {repairResult.OriginalCb} to 72");
                        if (repairResult.MetaDataRvaRepaired)
                            Console.WriteLine($"[+] Anti-Dump: Restored MetaData RVA to 0x{repairResult.RepairedMetaDataRva:X8}");

                        try
                        {
                            using (var testMod = ModuleDefMD.Load(candidateBytes)) { }
                            bytesToLoad = candidateBytes;
                            initialLoadOk = true;
                        }
                        catch (Exception postRepairEx)
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine($"[!] ModuleDefMD load failed after COR20 repair attempt: {postRepairEx.Message}");
                            Console.ResetColor();
                        }
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"[!] COR20 repair inapplicable or failed: {repairResult.Message}");
                        Console.ResetColor();
                    }

                    if (!initialLoadOk)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"[!] Fatal: Cannot load target assembly as a valid .NET module: {assemblyPath}");
                        Console.ResetColor();
                        return 1;
                    }
                }
                else
                {
                    // If initial load succeeded, check if COR20 header cb or RVA needs normalization
                    var repairResult = Cor20Repair.Repair(bytesToLoad, peImageOld);
                    if (repairResult.Success && (repairResult.CbRepaired || repairResult.MetaDataRvaRepaired))
                    {
                        if (repairResult.CbRepaired)
                            Console.WriteLine($"[+] Anti-Dump: Fixed COR20 header cb from {repairResult.OriginalCb} to 72");
                        if (repairResult.MetaDataRvaRepaired)
                            Console.WriteLine($"[+] Anti-Dump: Restored MetaData RVA to 0x{repairResult.RepairedMetaDataRva:X8}");
                    }
                }

                string fileExt = Path.GetExtension(assemblyPath);
                string baseName = Path.GetFileNameWithoutExtension(assemblyPath);
                string cexkPath = Path.Combine(executionTempDir, baseName + ".cexk" + fileExt);

                bool resourcesDecrypted = false;
                bool constantsDecrypted = false;

            // Step 2: Proxy + Constants via dnlib
            Console.WriteLine("[*] Step 2: Running FieldRvaKiller, ProxyKiller, and ConstantKiller...");
            using (var module = ModuleDefMD.Load(bytesToLoad))
            {
                if (AntiTamperKiller.DetectJitMode(module))
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("[!] WARNING: ConfuserEx JIT mode artifacts detected in module.");
                    Console.ResetColor();
                }

                if (reflModule != null)
                {
                    var rvaResult = FieldRvaKiller.Execute(module, reflModule, bytesToLoad);
                    if (rvaResult.RestoredFieldsCount > 0)
                        Console.WriteLine($"[+] FieldRvaKiller: Restored {rvaResult.RestoredFieldsCount} static field initializers ({string.Join(", ", rvaResult.RestoredFields)})");
                }

                // Step 2.1: In-memory Resource Extraction & Re-Embedding (runs before method AST deletions)
                Console.WriteLine("[*] Step 2.1: Running ResourceKiller (Extracting decrypted resources)...");
                var resResult = ResourceKiller.Execute(module, reflModule);
                resourcesDecrypted = resResult.ResourcesDecrypted;
                if (resResult.HandlerStripped)
                    Console.WriteLine("[+] ResourceKiller: Stripped runtime ResourceResolve hook");
                if (resResult.ResourcesDecrypted)
                    Console.WriteLine($"[+] ResourceKiller: Extracted & re-embedded {resResult.DecryptedResourcesCount} decrypted resources ({resResult.TotalManifestResourcesCount} total in manifest)");

                // Step 2.2: ProxyKiller + ConstantKiller
                int proxyCount = ProxyKillerImpl.Execute(module, false, true);
                Console.WriteLine($"[+] ProxyKiller: {proxyCount} proxy methods/delegates inlined");

                int constCount = ConstantKillerImpl.Execute(module, reflModule);
                constantsDecrypted = constCount > 0;
                Console.WriteLine($"[+] ConstantKiller: {constCount} constants decrypted (with stack evaluation)");

                // Step 3: Protector hook stripping
                Console.WriteLine("[*] Step 3: Cleaning Protector Hooks...");
                var cleanResult = CleanerKiller.StripProtectorHooks(module, resourcesDecrypted: resourcesDecrypted, constantsDecrypted: constantsDecrypted, antiTamperDecrypted: antiTamperDecrypted);
                if (cleanResult.StrippedHooksCount > 0)
                    Console.WriteLine($"[+] CleanerKiller: Stripped {cleanResult.StrippedHooksCount} protector initializers from <Module>.cctor");

                // Step 3.5: DeadCodeStripper & PredicateKiller pre-switch
                Console.WriteLine("[*] Step 3.5: Running DeadCodeStripper & PredicateKiller...");
                var dcsPre = DeadCodeStripper.Execute(module);
                if (dcsPre.MethodsOptimized > 0)
                    Console.WriteLine($"[+] DeadCodeStripper (Pre): {dcsPre.Message}");

                var predResult = PredicateKiller.Execute(module);
                if (predResult.MethodsOptimized > 0)
                    Console.WriteLine($"[+] PredicateKiller: {predResult.Message}");

                // Step 4: SwitchKiller + Post-Switch DeadCodeStripper
                Console.WriteLine("[*] Step 4: Running SwitchKiller (control flow cleanup)...");
                int switchCount = SwitchKillerImpl.Execute(module);
                Console.WriteLine($"[+] SwitchKiller: {switchCount} switches resolved");

                var dcsPost = DeadCodeStripper.Execute(module);
                if (dcsPost.MethodsOptimized > 0)
                    Console.WriteLine($"[+] DeadCodeStripper (Post): {dcsPost.Message}");

                Console.WriteLine($"[*] Writing intermediate module: {cexkPath}");
                var writerOpts = new ModuleWriterOptions(module) { Logger = DnlibLogger.Instance };
                writerOpts.MetaDataOptions.Flags |= MetaDataFlags.KeepOldMaxStack;
                module.Write(cexkPath, writerOpts);
            }

            string currentIntermediate = cexkPath;

            // Step 5: de4dot-cex
            string cleanedPath = Path.Combine(executionTempDir, baseName + "-cleaned" + fileExt);
            string de4dotExecutable = skipDe4dot ? null : ProcessRunner.ResolveDe4dotPath(explicitDe4dotPath);

            if (!skipDe4dot && de4dotExecutable != null)
            {
                // Delete stale output from a previous run to avoid false acceptance
                if (File.Exists(cleanedPath))
                {
                    try { File.Delete(cleanedPath); } catch { }
                }

                Console.WriteLine($"[*] Step 5: Running de4dot-cex ({de4dotExecutable})...");
                string de4dotArgs = $"\"{cexkPath}\" -p crx -o \"{cleanedPath}\"";
                var de4dotResult = ProcessRunner.Run(de4dotExecutable, de4dotArgs, executionTempDir, timeoutMs: 180000);

                if (verbose || !de4dotResult.Success)
                {
                    foreach (var line in de4dotResult.StandardOutput.Split('\n'))
                    {
                        string trimmed = line.Trim();
                        if (!string.IsNullOrWhiteSpace(trimmed) && !trimmed.StartsWith("de4dot") && !trimmed.StartsWith("Latest"))
                            Console.WriteLine("  " + trimmed);
                    }
                }

                if (de4dotResult.Success && File.Exists(cleanedPath))
                {
                    Console.WriteLine($"[+] de4dot-cex completed: {cleanedPath}");
                    currentIntermediate = cleanedPath;
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"[!] de4dot-cex did not produce fresh output. Continuing with {cexkPath}");
                    Console.ResetColor();
                }
            }
            else if (!skipDe4dot)
            {
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine("[!] de4dot-cex not found (searched CLI --de4dot, DE4DOT_PATH, tools/, PATH).");
                Console.WriteLine("[!] Skipping external de4dot pass.");
                Console.ResetColor();
            }

            // Step 6: Final SwitchKiller pass on intermediate output
            Console.WriteLine("[*] Step 6: Running final cleanup pass...");
            string finalDefaultPath = Path.Combine(targetDir, baseName + "_final" + fileExt);
            string finalOutputPath = !string.IsNullOrEmpty(outputPath) ? Path.GetFullPath(outputPath) : finalDefaultPath;

            if (string.Equals(finalOutputPath, originalInputPath, StringComparison.OrdinalIgnoreCase))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[!] Output destination cannot overwrite the original input assembly.");
                Console.ResetColor();
                return 1;
            }

            string finalOutputDir = Path.GetDirectoryName(finalOutputPath);
            if (!string.IsNullOrEmpty(finalOutputDir) && !Directory.Exists(finalOutputDir))
            {
                Directory.CreateDirectory(finalOutputDir);
            }

            string candidateExt = Path.GetExtension(finalOutputPath);
            string candidateBase = Path.GetFileNameWithoutExtension(finalOutputPath);
            string candidatePath = Path.Combine(executionTempDir, candidateBase + ".candidate." + Guid.NewGuid().ToString("N").Substring(0, 8) + candidateExt);

            using (var module2 = ModuleDefMD.Load(currentIntermediate))
            {
                CleanerKiller.StripProtectorHooks(module2, resourcesDecrypted: resourcesDecrypted, constantsDecrypted: constantsDecrypted, antiTamperDecrypted: antiTamperDecrypted);
                PredicateKiller.Execute(module2);
                DeadCodeStripper.Execute(module2);
                int switchCount2 = SwitchKillerImpl.Execute(module2);
                DeadCodeStripper.Execute(module2);
                Console.WriteLine($"[+] Final SwitchKiller: {switchCount2} switches resolved");
                FinalizeMethodBodies(module2);
                var writerOpts2 = new ModuleWriterOptions(module2) { Logger = DnlibLogger.Instance };
                writerOpts2.MetaDataOptions.Flags |= MetaDataFlags.KeepOldMaxStack;
                module2.Write(candidatePath, writerOpts2);
            }

            // Quality Audit: Validate candidate before promotion
            Console.WriteLine();
            Console.WriteLine("===============================================================");
            Console.WriteLine("    Assembly Structural & Control-Flow Integrity Audit Report  ");
            Console.WriteLine("===============================================================");
            var auditReport = QualityAuditor.Audit(candidatePath);
            Console.WriteLine($"[*] Status:                 [{auditReport.Status}]");
            Console.WriteLine($"[*] Loadable (dnlib):       [{(auditReport.CanLoad ? "YES" : "NO")}]");
            Console.WriteLine($"[*] Structural Integrity:   [{(auditReport.StructuralAuditPassed ? "PASSED" : "FAILED")}]");
            Console.WriteLine($"[*] IL Verification:        [{auditReport.ILVerificationStatus}] ({auditReport.ILVerificationNotes})");
            Console.WriteLine($"[*] Dynamic Execution:      [{(allowExecution ? "ACTIVE" : "DISABLED")}]");
            Console.WriteLine($"[*] Types Audited:          {auditReport.TotalTypes}");
            Console.WriteLine($"[*] Methods Audited:        {auditReport.TotalMethods} ({auditReport.MethodsWithBody} with IL bodies)");
            Console.WriteLine($"[*] Invalid Instructions:   {auditReport.InvalidInstructionsCount}");
            Console.WriteLine($"[*] Stack Underflows:       {auditReport.StackUnderflowCount}");
            Console.WriteLine($"[*] Unresolved Call Sites:  {auditReport.UnresolvedCallSitesCount}");

            if (auditReport.Warnings.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                foreach (var w in auditReport.Warnings.Take(5))
                    Console.WriteLine($"  [!] {w}");
                if (auditReport.Warnings.Count > 5)
                    Console.WriteLine($"  ... and {auditReport.Warnings.Count - 5} more warnings.");
                Console.ResetColor();
            }
            Console.WriteLine("===============================================================");

            if (auditReport.Status == "FAILED")
            {
                try { if (File.Exists(candidatePath)) File.Delete(candidatePath); } catch { }
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[!] Deobfuscation audit reported FAILED. Candidate assembly rejected; no corrupt output written.");
                Console.ResetColor();
                return 1;
            }

            // Audit passed: Promote candidate to final output path without deleting existing output before replacement succeeds
            try
            {
                if (File.Exists(finalOutputPath))
                {
                    string backupPath = finalOutputPath + ".bak." + Guid.NewGuid().ToString("N").Substring(0, 8);
                    try
                    {
                        File.Replace(candidatePath, finalOutputPath, backupPath, ignoreMetadataErrors: true);
                        try { File.Delete(backupPath); } catch { }
                    }
                    catch
                    {
                        File.Copy(candidatePath, finalOutputPath, overwrite: true);
                        try { File.Delete(candidatePath); } catch { }
                    }
                }
                else
                {
                    File.Copy(candidatePath, finalOutputPath, overwrite: true);
                    try { File.Delete(candidatePath); } catch { }
                }
            }
            catch (Exception ex)
            {
                try { if (File.Exists(candidatePath)) File.Delete(candidatePath); } catch { }
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[!] Failed to promote candidate to final output path: {ex.Message}");
                Console.ResetColor();
                return 1;
            }

            if (auditReport.Status == "CLEAN")
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[+] Structural integrity audit passed (no structural defects detected). Output saved to: {finalOutputPath}");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[!] Structural integrity audit completed with {auditReport.Warnings.Count} warning(s) (Candidate Promoted). Output saved to: {finalOutputPath}");
                Console.ResetColor();
            }

            // NetDetect Post-Scan Reduction Audit
            if (!skipNetDetect && preScan != null && preScan.Available)
            {
                var postScan = NetDetectIntegration.RunScan(finalOutputPath);
                NetDetectIntegration.PrintComparisonReport(preScan, postScan);
            }

            return 0;
            }
            finally
            {
                try
                {
                    if (Directory.Exists(executionTempDir))
                    {
                        Directory.Delete(executionTempDir, recursive: true);
                    }
                }
                catch
                {
                    // Ignore temp directory deletion errors on exit
                }
            }
        }

        static void PrintUsage()
        {
            Console.WriteLine("ConfuserExKillerRunner - High-Performance ConfuserEx Deobfuscator");
            Console.WriteLine("Usage: ConfuserExKillerRunner.exe <path_to_assembly> [options]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  --allow-execution       Allow target module reflection execution (AntiTamper / Constants)");
            Console.WriteLine("                          CAUTION: Runs untrusted <Module>.cctor in host context!");
            Console.WriteLine("  -o, --output <path>     Specify custom destination path for final cleaned assembly");
            Console.WriteLine("  -d, --de4dot <path>     Specify explicit path to de4dot-cex executable");
            Console.WriteLine("  --no-de4dot             Skip de4dot external process pass");
            Console.WriteLine("  --no-netdetect          Skip NetDetect pre/post obfuscation audit");
            Console.WriteLine("  --verbose               Enable verbose console output");
            Console.WriteLine("  -h, --help              Show this help message");
        }

        private static void FinalizeMethodBodies(ModuleDef module)
        {
            foreach (var method in module.EnumerateMethods())
            {
                if (!method.HasBody || method.Body == null)
                    continue;

                var body = method.Body;
                try
                {
                    body.SimplifyBranches();
                    body.OptimizeBranches();
                    body.OptimizeMacros();
                    body.UpdateInstructionOffsets();

                    uint calc = dnlib.DotNet.Writer.MaxStackCalculator.GetMaxStack(body.Instructions, body.ExceptionHandlers);
                    ushort safeMax = (ushort)Math.Max((uint)body.MaxStack, calc);
                    body.MaxStack = Math.Max(safeMax, (ushort)8);
                    body.KeepOldMaxStack = true;
                }
                catch (Exception ex)
                {
                    Tool.Logger.LogWarning($"[0x{method.MDToken.Raw:X8}] FinalizeMethodBodies for {method.Name}: {ex.Message}. Keeping existing MaxStack {body.MaxStack}.");
                    body.KeepOldMaxStack = true;
                }
            }
        }

        public static (bool antiTamperDecrypted, byte[] effectivePeImage) ProcessAntiTamperResult(AntiTamperResult atResult, byte[] peImageOld)
        {
            if (atResult == null)
                return (false, (byte[])peImageOld.Clone());

            switch (atResult.Status)
            {
                case AntiTamperStatus.DecryptionConfirmed:
                    return (true, atResult.DecryptedPeImage ?? (byte[])peImageOld.Clone());

                case AntiTamperStatus.ChangesDetected:
                    return (false, atResult.DecryptedPeImage ?? (byte[])peImageOld.Clone());

                case AntiTamperStatus.NoChangesDetected:
                case AntiTamperStatus.Failed:
                case AntiTamperStatus.NotAttempted:
                default:
                    return (false, (byte[])peImageOld.Clone());
            }
        }
    }
}
