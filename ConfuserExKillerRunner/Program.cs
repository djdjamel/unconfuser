using System;
using System.Collections.Generic;
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
    public class Program
    {
        public static int Main(string[] args)
        {
            if (args != null && args.Length > 0 && args[0] == "--internal-worker")
            {
                return WorkerHost.Run(args);
            }

            if (args == null || args.Length == 0 || args.Contains("-h") || args.Contains("--help"))
            {
                PrintUsage();
                return 0;
            }

            string assemblyPath = null;
            bool allowExecution = false;
            int workerTimeoutMs = 30000;
            bool allowTargetDeps = false;
            var allowedDepDirs = new System.Collections.Generic.List<string>();
            string explicitDe4dotPath = null;
            bool skipDe4dot = false;
            bool skipNetDetect = false;
            string outputPath = null;
            string jsonReportPath = null;
            bool strictExitCodes = false;
            bool verbose = false;

            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];
                if (arg == "--allow-execution")
                {
                    allowExecution = true;
                }
                else if (arg == "--worker-timeout" && i + 1 < args.Length && int.TryParse(args[i + 1], out int parsedTimeout))
                {
                    workerTimeoutMs = parsedTimeout;
                    i++;
                }
                else if (arg == "--allow-target-deps")
                {
                    allowTargetDeps = true;
                }
                else if ((arg == "--dep-dir" || arg == "--allowed-dep-dir") && i + 1 < args.Length)
                {
                    allowedDepDirs.Add(args[++i]);
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
                else if ((arg == "--json-report" || arg == "--report-json" || arg == "--report" || arg == "-r" || arg == "--json" || arg == "-j") && i + 1 < args.Length)
                {
                    jsonReportPath = Path.GetFullPath(args[++i]);
                }
                else if (arg == "--strict-exit-codes")
                {
                    strictExitCodes = true;
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
            string targetDir = Path.GetDirectoryName(originalInputPath);
            Console.WriteLine($"[*] Target: {assemblyPath}");
            Console.WriteLine($"[*] Process Bitness: {(Environment.Is64BitProcess ? "64-bit" : "32-bit")}");

            // Architecture Analysis
            var archInfo = ArchitectureDetector.Detect(assemblyPath);
            Console.WriteLine($"[*] Target Architecture: {archInfo.Architecture} (Machine=0x{archInfo.Machine:X4}, PE32+={archInfo.IsPe32Plus}, 32BitReq={archInfo.Is32BitRequired})");

            if (!archInfo.IsCompatibleWithCurrentProcess())
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[!] WARNING: Target architecture ({archInfo.Architecture}) may be incompatible with current {(Environment.Is64BitProcess ? "64-bit" : "32-bit")} process.");
                Console.WriteLine("[!] If dynamic execution is enabled, an architecture-adapted worker process will be resolved.");
                Console.ResetColor();
            }

            // Dedicated temporary directory for intermediate pipeline artifacts (.unwrapped, .cexk, -cleaned, .candidate)
            string executionTempDir = Path.Combine(Path.GetTempPath(), "unconfuser_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(executionTempDir);

            var swTotal = Stopwatch.StartNew();
            var stepTimings = new Dictionary<string, long>(StringComparer.Ordinal);
            var exceptionsAndRollbacks = new List<string>();

            AuditReport baselineAudit = null;
            try
            {
                var swBaseline = Stopwatch.StartNew();
                baselineAudit = QualityAuditor.Audit(originalInputPath, runExternalVerifier: false, dependencyDirectories: allowedDepDirs);
                stepTimings["Baseline_QualityAudit"] = swBaseline.ElapsedMilliseconds;
            }
            catch (Exception ex)
            {
                exceptionsAndRollbacks.Add($"Baseline audit error: {ex.Message}");
            }

            try
            {
                byte[] peImageOld = File.ReadAllBytes(assemblyPath);
                byte[] peImage = (byte[])peImageOld.Clone();

                NetDetectScanResult preScan = null;
                if (!skipNetDetect)
                {
                    var swPre = Stopwatch.StartNew();
                    preScan = NetDetectIntegration.RunScan(assemblyPath);
                    stepTimings["PreScan_NetDetect"] = swPre.ElapsedMilliseconds;
                    NetDetectIntegration.PrintPreScanReport(preScan);
                }

                // Stage 0: Unpack ConfuserEx Compressor if present
                var swStage0 = Stopwatch.StartNew();
                bool compressorWasUnpacked = false;
                bool antiIldasmWasStripped = false;
                try
                {
                    bool isCompressorStub = false;
                    using (var probeMod = ModuleDefMD.Load(peImage))
                    {
                        var staticResult = CompressorUnpacker.TryUnpack(probeMod, peImage, allowExecution: false);
                        if (staticResult.SuccessfullyUnpacked && staticResult.UnpackedAssemblyBytes != null)
                        {
                            compressorWasUnpacked = true;
                            Console.WriteLine($"[+] CompressorUnpacker: {staticResult.Message}");
                            peImage = staticResult.UnpackedAssemblyBytes;
                            peImageOld = (byte[])peImage.Clone();
                            string unwrappedPath = Path.Combine(executionTempDir, Path.GetFileNameWithoutExtension(assemblyPath) + ".unwrapped" + Path.GetExtension(assemblyPath));
                            File.WriteAllBytes(unwrappedPath, peImage);
                            assemblyPath = unwrappedPath;
                        }
                        else if (staticResult.Classification == PackerClassification.ConfuserExCompressorStub || staticResult.IsCompressed)
                        {
                            isCompressorStub = true;
                        }
                    }

                    if (!compressorWasUnpacked && isCompressorStub)
                    {
                        if (!allowExecution)
                        {
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.WriteLine("[!] ConfuserEx Compressor stub detected, but static unpacking failed.");
                            Console.WriteLine("[!] Dynamic compressor unpacking requires '--allow-execution'. Target assembly preserved.");
                            Console.ResetColor();
                        }
                        else
                        {
                            Console.WriteLine($"[*] Stage 0: ConfuserEx Compressor stub detected. Spawning isolated worker for dynamic unpacking (Timeout: {workerTimeoutMs}ms)...");
                            var workerOpts = new WorkerOptions
                            {
                                TimeoutMs = workerTimeoutMs,
                                AllowTargetDirectoryDependencies = allowTargetDeps,
                                AllowedDependencyDirectories = allowedDepDirs,
                                TempDirectory = executionTempDir
                            };

                            var dynamicResult = WorkerClient.ExecuteCompressorUnpack(assemblyPath, workerOpts);
                            if (dynamicResult != null && dynamicResult.Success && dynamicResult.UnpackedAssemblyBytes != null)
                            {
                                compressorWasUnpacked = true;
                                Console.WriteLine($"[+] CompressorUnpacker: {dynamicResult.Message}");
                                peImage = dynamicResult.UnpackedAssemblyBytes;
                                peImageOld = (byte[])peImage.Clone();
                                string unwrappedPath = Path.Combine(executionTempDir, Path.GetFileNameWithoutExtension(assemblyPath) + ".unwrapped" + Path.GetExtension(assemblyPath));
                                File.WriteAllBytes(unwrappedPath, peImage);
                                assemblyPath = unwrappedPath;
                            }
                            else
                            {
                                string msg = dynamicResult?.Message ?? "Dynamic compressor unpacking returned no payload";
                                Console.ForegroundColor = ConsoleColor.Yellow;
                                Console.WriteLine($"[!] CompressorUnpacker (Worker): {msg}. Target assembly preserved.");
                                Console.ResetColor();
                                exceptionsAndRollbacks.Add($"Compressor dynamic unpack failed: {msg}");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] CompressorUnpacker probing failed: {ex.Message}");
                }
                stepTimings["Stage0_Compressor"] = swStage0.ElapsedMilliseconds;

                // Step 1: Safety Gate & Anti-Tamper
                var swStage1 = Stopwatch.StartNew();
                bool antiTamperDecrypted = false;
                bool staticAntiTamperDetected = false;
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

                    try
                    {
                        using (var probeMod = ModuleDefMD.Load(peImage))
                        {
                            if (ProtectionMatrix.HasAntiTamperNormal(probeMod))
                            {
                                staticAntiTamperDetected = true;
                                Console.ForegroundColor = ConsoleColor.Yellow;
                                Console.WriteLine("[!] Anti-Tamper encrypted section hooks detected in pure static mode.");
                                Console.WriteLine("[!] Method bytecode is encrypted in PE sections and cannot be statically deobfuscated.");
                                Console.WriteLine("[!] Re-run with '--allow-execution' to decrypt and deobfuscate.");
                                Console.ResetColor();
                            }
                        }
                    }
                    catch { }
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine();
                    Console.WriteLine("[!] ==================== SECURITY NOTICE: DYNAMIC EXECUTION ====================");
                    Console.WriteLine("[!] Dynamic execution mode (--allow-execution) is ACTIVE.");
                    Console.WriteLine("[!] Target code will be executed inside an ISOLATED WORKER SUBPROCESS.");
                    Console.WriteLine("[!] A subprocess provides crash, fault, and timeout isolation, but is NOT an OS security sandbox.");
                    Console.WriteLine("[!] Untrusted malware could still affect OS state within worker process rights.");
                    Console.WriteLine("[!] For untrusted samples, run in a dedicated VM with network access disabled.");
                    Console.WriteLine("[!] ===========================================================================");
                    Console.WriteLine();
                    Console.ResetColor();

                    Console.WriteLine($"[*] Step 1: Running AntiTamperKiller (Isolated Worker Process, Timeout: {workerTimeoutMs}ms)...");
                    var workerOpts = new WorkerOptions
                    {
                        TimeoutMs = workerTimeoutMs,
                        AllowTargetDirectoryDependencies = allowTargetDeps,
                        AllowedDependencyDirectories = allowedDepDirs,
                        TempDirectory = executionTempDir
                    };

                    try
                    {
                        var atResult = WorkerClient.ExecuteAntiTamper(assemblyPath, peImageOld, workerOpts);
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

                bool cor20WasRepaired = false;
                bool jitDetected = false;
                int totalConstantsDecrypted = 0;
                bool allConstantsResolved = false;
                int totalResourcesExtracted = 0;
                int totalProxiesInlined = 0;
                int totalSwitchesResolved = 0;
                int totalJunkStripped = 0;
                int totalCleanerHooks = 0;
                var preservedHooks = new List<string>();
                var hookRegistry = new Dictionary<string, HookTraceRecord>(StringComparer.Ordinal);

                if (!initialLoadOk)
                {
                    byte[] candidateBytes = (byte[])peImage.Clone();
                    var repairResult = Cor20Repair.Repair(candidateBytes, peImageOld);

                    if (repairResult.Success && (repairResult.CbRepaired || repairResult.MetaDataRvaRepaired || repairResult.BsjbRepaired))
                    {
                        cor20WasRepaired = true;
                        if (repairResult.CbRepaired)
                            Console.WriteLine($"[+] Anti-Dump: Fixed COR20 header cb from {repairResult.OriginalCb} to 72");
                        if (repairResult.MetaDataRvaRepaired)
                            Console.WriteLine($"[+] Anti-Dump: Restored MetaData RVA to 0x{repairResult.RepairedMetaDataRva:X8}");
                        if (repairResult.BsjbRepaired)
                            Console.WriteLine("[+] Anti-Dump: Restored BSJB metadata header signature");

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
                    if (repairResult.Success && (repairResult.CbRepaired || repairResult.MetaDataRvaRepaired || repairResult.BsjbRepaired))
                    {
                        cor20WasRepaired = true;
                        if (repairResult.CbRepaired)
                            Console.WriteLine($"[+] Anti-Dump: Fixed COR20 header cb from {repairResult.OriginalCb} to 72");
                        if (repairResult.MetaDataRvaRepaired)
                            Console.WriteLine($"[+] Anti-Dump: Restored MetaData RVA to 0x{repairResult.RepairedMetaDataRva:X8}");
                        if (repairResult.BsjbRepaired)
                            Console.WriteLine("[+] Anti-Dump: Restored BSJB metadata header signature");
                    }
                }
                stepTimings["Stage1_AntiTamper_HeaderRepair"] = swStage1.ElapsedMilliseconds;

                // If Anti-Tamper decrypted methods in a custom PE section, normalize the PE layout through dnlib
                // so all method bodies are placed in standard .text section before passing to isolated worker processes.
                if (antiTamperDecrypted)
                {
                    try
                    {
                        using (var normMod = ModuleDefMD.Load(bytesToLoad))
                        using (var ms = new MemoryStream())
                        {
                            var writerOpts = new ModuleWriterOptions(normMod)
                            {
                                Logger = DummyLogger.NoThrowInstance
                            };
                            normMod.Write(ms, writerOpts);
                            bytesToLoad = ms.ToArray();
                        }
                    }
                    catch (Exception ex)
                    {
                        Tool.Logger.LogWarning($"[AntiTamper] Pre-worker PE normalization failed: {ex.Message}");
                    }
                }

                string fileExt = Path.GetExtension(assemblyPath);
                string baseName = Path.GetFileNameWithoutExtension(assemblyPath);
                string cexkPath = Path.Combine(executionTempDir, baseName + ".cexk" + fileExt);

                bool resourcesDecrypted = false;
                bool constantsDecrypted = false;

                // Step 2: Dynamic passes via isolated worker (FieldRVA, Constants)
                var swStage2 = Stopwatch.StartNew();
                Console.WriteLine("[*] Step 2: Running FieldRvaKiller, ProxyKiller, and ConstantKiller...");
                if (allowExecution)
                {
                    var workerOpts = new WorkerOptions
                    {
                        TimeoutMs = workerTimeoutMs,
                        AllowTargetDirectoryDependencies = allowTargetDeps,
                        AllowedDependencyDirectories = allowedDepDirs,
                        TempDirectory = executionTempDir
                    };

                    // Step 2.0a: FieldRVA Restoration
                    var rvaResult = WorkerClient.ExecuteFieldRva(bytesToLoad, workerOpts);
                    if (rvaResult.success && rvaResult.restoredCount > 0)
                    {
                        bytesToLoad = rvaResult.outputPe;
                        Console.WriteLine($"[+] FieldRvaKiller: Restored {rvaResult.restoredCount} static field initializers via isolated worker");
                    }

                    // Step 2.0b: Constant Decryption via isolated worker
                    var dynamicConst = WorkerClient.ExecuteConstants(bytesToLoad, workerOpts);
                    if (dynamicConst.success)
                    {
                        if (dynamicConst.decryptedCount > 0)
                        {
                            bytesToLoad = dynamicConst.outputPe;
                            constantsDecrypted = dynamicConst.allResolved;
                            totalConstantsDecrypted = dynamicConst.decryptedCount;
                            allConstantsResolved = dynamicConst.allResolved;
                            Console.WriteLine($"[+] ConstantKiller: {dynamicConst.decryptedCount} constants decrypted (with stack evaluation)");
                            if (!dynamicConst.allResolved)
                                Console.WriteLine("[!] ConstantKiller: Partial decryption. Decrypter and buffer preserved.");
                        }
                        else
                        {
                            constantsDecrypted = dynamicConst.allResolved;
                            allConstantsResolved = dynamicConst.allResolved;
                            Console.WriteLine($"[*] ConstantKiller: Isolated worker executed ({dynamicConst.message}).");
                        }
                    }
                    else
                    {
                        allConstantsResolved = false;
                        Tool.Logger.LogWarning($"[ConstantKiller] Isolated worker constant decryption failed: {dynamicConst.message}");
                    }
                }

                using (var module = ModuleDefMD.Load(bytesToLoad))
                {
                    jitDetected = !antiTamperDecrypted && !staticAntiTamperDetected && AntiTamperKiller.DetectJitMode(module);
                    if (jitDetected)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("[!] WARNING: ConfuserEx Anti-Tamper mode JIT détecté (déchiffrement JIT non pris en charge : détecté, non déchiffré).");
                        Console.ResetColor();
                    }

                    if (!staticAntiTamperDetected)
                    {
                        // Step 2.1: In-memory Resource Extraction & Re-Embedding (runs before method AST deletions)
                        Console.WriteLine("[*] Step 2.1: Running ResourceKiller (Extracting decrypted resources)...");
                        if (allowExecution)
                        {
                            var workerOpts = new WorkerOptions
                            {
                                TimeoutMs = workerTimeoutMs,
                                AllowTargetDirectoryDependencies = allowTargetDeps,
                                AllowedDependencyDirectories = allowedDepDirs,
                                TempDirectory = executionTempDir
                            };

                            string resInputPath = assemblyPath;
                            if (antiTamperDecrypted)
                            {
                                resInputPath = Path.Combine(executionTempDir, $"worker_at_decrypted_{Guid.NewGuid():N}.dll");
                                File.WriteAllBytes(resInputPath, bytesToLoad);
                            }

                            try
                            {
                                var dynamicRes = WorkerClient.ExecuteResourceExtraction(resInputPath, workerOpts);
                                if (dynamicRes.Success && dynamicRes.DecryptedResourceContainer != null && dynamicRes.DecryptedResourceContainer.Length > 0)
                                {
                                    using (var resMod = ModuleDefMD.Load(dynamicRes.DecryptedResourceContainer))
                                    {
                                        int reEmbeddedCount = 0;
                                        foreach (var r in resMod.Resources)
                                        {
                                            var existing = module.Resources.Find(r.Name);
                                            if (existing != null) module.Resources.Remove(existing);

                                            if (r is EmbeddedResource er)
                                            {
                                                module.Resources.Add(new EmbeddedResource(er.Name, er.GetResourceData(), er.Attributes));
                                            }
                                            else
                                            {
                                                module.Resources.Add(r);
                                            }
                                            reEmbeddedCount++;
                                        }

                                        resourcesDecrypted = true;
                                        totalResourcesExtracted = reEmbeddedCount;
                                        Console.WriteLine($"[+] ResourceKiller: Extracted & re-embedded {reEmbeddedCount} decrypted resources via isolated worker ({module.Resources.Count} total in manifest)");
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                Tool.Logger.LogWarning($"[ResourceKiller] Re-embedding decrypted resources from worker failed: {ex.Message}");
                            }
                            finally
                            {
                                if (antiTamperDecrypted && resInputPath != assemblyPath)
                                {
                                    try { File.Delete(resInputPath); } catch { }
                                }
                            }
                        }

                        var resResult = ResourceKiller.Execute(module, reflModule: null, resourcesAlreadyDecrypted: resourcesDecrypted);
                        if (resResult.HandlerStripped)
                        {
                            totalCleanerHooks++;
                            Console.WriteLine("[+] ResourceKiller: Stripped runtime ResourceResolve hook");
                        }
                        if (resResult.HookRecords != null)
                        {
                            foreach (var hr in resResult.HookRecords)
                                hookRegistry[hr.HookId] = hr;
                        }
                        if (resResult.RetainedHooksDetails != null && resResult.RetainedHooksDetails.Count > 0)
                            preservedHooks.AddRange(resResult.RetainedHooksDetails);

                        // Step 2.2: ProxyKiller + ConstantKiller
                        int proxyCount = ProxyKillerImpl.Execute(module, false, true);
                        totalProxiesInlined += proxyCount;
                        Console.WriteLine($"[+] ProxyKiller: {proxyCount} proxy methods/delegates inlined");

                        if (!constantsDecrypted)
                        {
                            if (!allowExecution)
                            {
                                var constResult = ConstantKillerImpl.Execute(module, reflModule: null);
                                constantsDecrypted = constResult.AllReferencesResolved;
                                totalConstantsDecrypted += constResult.DecryptedConstantsCount;
                                allConstantsResolved = constResult.AllReferencesResolved;
                                if (constResult.DecryptedConstantsCount > 0)
                                {
                                    Console.WriteLine($"[+] ConstantKiller: {constResult.DecryptedConstantsCount} constants decrypted (with stack evaluation)");
                                    if (constResult.TotalReferencesCount > 0 && !constResult.AllReferencesResolved)
                                        Console.WriteLine($"[!] ConstantKiller: Partial decryption ({constResult.ResolvedReferencesCount}/{constResult.TotalReferencesCount} references rewritten). Decrypter and buffer preserved.");
                                }
                            }
                            else
                            {
                                // Dynamic execution was already performed by isolated worker.
                                // In the orchestrator host, reflModule is null; do not trigger false fallback warning.
                            }
                        }
                        stepTimings["Stage2_Constants_Resources_Proxies"] = swStage2.ElapsedMilliseconds;

                        // Step 3: Protector hook stripping
                        var swStage3 = Stopwatch.StartNew();
                        Console.WriteLine("[*] Step 3: Cleaning Protector Hooks...");
                        var cleanResult = CleanerKiller.StripProtectorHooks(module, resourcesDecrypted: resourcesDecrypted, constantsDecrypted: constantsDecrypted, antiTamperDecrypted: antiTamperDecrypted);
                        if (cleanResult.AntiIldasmStripped) antiIldasmWasStripped = true;
                        totalCleanerHooks += cleanResult.StrippedHooksCount + cleanResult.RemovedMethodsCount;
                        if (cleanResult.StrippedHooksCount > 0)
                            Console.WriteLine($"[+] CleanerKiller: Stripped {cleanResult.StrippedHooksCount} protector initializers from <Module>.cctor");
                        if (cleanResult.HookRecords != null)
                        {
                            foreach (var hr in cleanResult.HookRecords)
                                hookRegistry[hr.HookId] = hr;
                        }
                        if (cleanResult.RetainedHooksDetails != null && cleanResult.RetainedHooksDetails.Count > 0)
                            preservedHooks.AddRange(cleanResult.RetainedHooksDetails);
                        stepTimings["Stage3_CleanerHooks"] = swStage3.ElapsedMilliseconds;

                        // Step 3.5: DeadCodeStripper & PredicateKiller pre-switch
                        var swStage4 = Stopwatch.StartNew();
                        Console.WriteLine("[*] Step 3.5: Running DeadCodeStripper & PredicateKiller...");
                        var dcsPre = DeadCodeStripper.Execute(module);
                        totalJunkStripped += dcsPre.JunkPairsStripped + dcsPre.TrampolinesFlattened;
                        if (dcsPre.MethodsOptimized > 0)
                            Console.WriteLine($"[+] DeadCodeStripper (Pre): {dcsPre.Message}");

                        var predResult = PredicateKiller.Execute(module);
                        if (predResult.MethodsOptimized > 0)
                            Console.WriteLine($"[+] PredicateKiller: {predResult.Message}");

                        // Step 4: SwitchKiller + Post-Switch DeadCodeStripper
                        Console.WriteLine("[*] Step 4: Running SwitchKiller (control flow cleanup)...");
                        int switchCount = SwitchKillerImpl.Execute(module);
                        totalSwitchesResolved += switchCount;
                        Console.WriteLine($"[+] SwitchKiller: {switchCount} switches resolved");

                        var dcsPost = DeadCodeStripper.Execute(module);
                        totalJunkStripped += dcsPost.JunkPairsStripped + dcsPost.TrampolinesFlattened;
                        if (dcsPost.MethodsOptimized > 0)
                            Console.WriteLine($"[+] DeadCodeStripper (Post): {dcsPost.Message}");
                        stepTimings["Stage4_ControlFlow_DeadCode"] = swStage4.ElapsedMilliseconds;
                    }
                    else
                    {
                        Console.WriteLine("[!] Static mode: Skipping AST & IL rewriting on Anti-Tamper encrypted method bodies.");
                    }

                var swIntermediateWrite = Stopwatch.StartNew();
                Console.WriteLine($"[*] Writing intermediate module: {cexkPath}");
                var writerOpts = new ModuleWriterOptions(module) { Logger = DnlibLogger.Instance };
                writerOpts.MetaDataOptions.Flags |= MetaDataFlags.KeepOldMaxStack;
                module.Write(cexkPath, writerOpts);
                stepTimings["Intermediate_DiskWrite"] = swIntermediateWrite.ElapsedMilliseconds;
            }

            string currentIntermediate = cexkPath;
            bool de4dotSucceeded = false;

            // Step 5: de4dot-cex
            var swStage5 = Stopwatch.StartNew();
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
                if (allowedDepDirs != null)
                {
                    foreach (var depDir in allowedDepDirs)
                    {
                        if (!string.IsNullOrEmpty(depDir) && Directory.Exists(depDir))
                            de4dotArgs += $" --asm-path \"{depDir}\"";
                    }
                }
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
                    de4dotSucceeded = true;
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
            stepTimings["Stage5_ExternalDeobfuscator"] = swStage5.ElapsedMilliseconds;

            // Step 6: Final SwitchKiller pass on intermediate output
            var swStage6 = Stopwatch.StartNew();
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
                if (!staticAntiTamperDetected)
                {
                    var cleanFinal = CleanerKiller.StripProtectorHooks(module2, resourcesDecrypted: resourcesDecrypted, constantsDecrypted: constantsDecrypted, antiTamperDecrypted: antiTamperDecrypted);
                    if (cleanFinal.AntiIldasmStripped) antiIldasmWasStripped = true;
                    totalCleanerHooks += cleanFinal.StrippedHooksCount + cleanFinal.RemovedMethodsCount;
                    if (cleanFinal.HookRecords != null)
                    {
                        foreach (var hr in cleanFinal.HookRecords)
                            hookRegistry[hr.HookId] = hr;
                    }
                    if (cleanFinal.RetainedHooksDetails != null && cleanFinal.RetainedHooksDetails.Count > 0)
                        preservedHooks.AddRange(cleanFinal.RetainedHooksDetails);
                    PredicateKiller.Execute(module2);
                    var dcsFinal1 = DeadCodeStripper.Execute(module2);
                    totalJunkStripped += dcsFinal1.JunkPairsStripped + dcsFinal1.TrampolinesFlattened;
                    int switchCount2 = SwitchKillerImpl.Execute(module2);
                    totalSwitchesResolved += switchCount2;
                    var dcsFinal2 = DeadCodeStripper.Execute(module2);
                    totalJunkStripped += dcsFinal2.JunkPairsStripped + dcsFinal2.TrampolinesFlattened;
                    Console.WriteLine($"[+] Final SwitchKiller: {switchCount2} switches resolved");
                    FinalizeMethodBodies(module2);
                }

                // Reconcile hook registry against final assembly state to ensure accurate traceability
                var finalCctor = module2.GlobalType?.FindStaticConstructor();
                var remainingCctorCalls = new HashSet<string>();
                if (finalCctor != null && finalCctor.HasBody)
                {
                    foreach (var ins in finalCctor.Body.Instructions)
                    {
                        if ((ins.OpCode == dnlib.DotNet.Emit.OpCodes.Call || ins.OpCode == dnlib.DotNet.Emit.OpCodes.Callvirt) && ins.Operand is IMethod calledM)
                        {
                            if (!UTF8String.IsNullOrEmpty(calledM.Name))
                                remainingCctorCalls.Add(calledM.Name.String);
                        }
                    }
                }
                var globalMethods = new HashSet<string>(module2.GlobalType?.Methods.Select(m => m.Name.String) ?? Enumerable.Empty<string>());

                foreach (var hook in hookRegistry.Values)
                {
                    if (hook.Action == "Retained")
                    {
                        bool callRemains = remainingCctorCalls.Contains(hook.MethodName);
                        bool methodRemains = globalMethods.Contains(hook.MethodName);

                        if (!callRemains && !methodRemains)
                        {
                            hook.Action = "Stripped";
                            hook.Reason = $"Hook method {hook.MethodName} and its call were pruned from <Module> during intermediate deobfuscation passes.";
                        }
                        else if (!callRemains)
                        {
                            hook.Action = "Stripped";
                            hook.Reason = $"Hook call to {hook.MethodName} was eliminated from <Module>.cctor during intermediate deobfuscation passes.";
                        }
                    }
                }

                var writerOpts2 = new ModuleWriterOptions(module2) { Logger = DnlibLogger.Instance };
                writerOpts2.MetaDataOptions.Flags |= MetaDataFlags.KeepOldMaxStack;
                module2.Write(candidatePath, writerOpts2);
            }
            stepTimings["Stage6_FinalCleanup"] = swStage6.ElapsedMilliseconds;

            var activePreservedHooks = hookRegistry.Values.Where(h => h.Action == "Retained").ToList();
            preservedHooks.Clear();
            foreach (var h in activePreservedHooks)
            {
                preservedHooks.Add(h.Reason);
            }
            if (activePreservedHooks.Count > 0)
            {
                Console.WriteLine($"[*] Preserved Hooks in <Module>.cctor ({activePreservedHooks.Count}):");
                foreach (var hook in activePreservedHooks)
                {
                    Console.WriteLine($"  [i] [{hook.HookType}] {hook.MethodName} (Confidence: {hook.Confidence}): {hook.Reason}");
                }
            }

            // Quality Audit: Validate candidate before promotion
            Console.WriteLine();
            Console.WriteLine("===============================================================");
            Console.WriteLine("    Assembly Structural & Control-Flow Integrity Audit Report  ");
            Console.WriteLine("===============================================================");
            var swAudit = Stopwatch.StartNew();
            var auditReport = QualityAuditor.Audit(candidatePath, runExternalVerifier: true, workingDir: targetDir, dependencyDirectories: allowedDepDirs);
            var regressions = QualityAuditor.DetectRegressions(baselineAudit, auditReport);
            stepTimings["Stage7_QualityAudit"] = swAudit.ElapsedMilliseconds;
            if (regressions.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                foreach (var reg in regressions)
                {
                    Console.WriteLine($"  [!] Engine Regression Detected: {reg}");
                    auditReport.Errors.Add("Engine Regression: " + reg);
                }
                Console.ResetColor();
            }
            foreach (var hook in activePreservedHooks)
            {
                auditReport.Warnings.Add($"Preserved Hook: [{hook.HookType}] {hook.MethodName}: {hook.Reason}");
            }

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

            if (auditReport.Status == "FAILED" && (!staticAntiTamperDetected || regressions.Count > 0))
            {
                try { if (File.Exists(candidatePath)) File.Delete(candidatePath); } catch { }
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[!] Deobfuscation audit reported FAILED. Candidate assembly rejected; no corrupt output written.");
                Console.ResetColor();

                if (!string.IsNullOrEmpty(jsonReportPath))
                {
                    try
                    {
                        var failReport = new DeobfuscationReport
                        {
                            Input = new FileReportInfo
                            {
                                Path = originalInputPath,
                                Sha256 = DeobfuscationReport.ComputeSha256(originalInputPath),
                                SizeBytes = new FileInfo(originalInputPath).Length,
                                TargetArchitecture = archInfo != null ? archInfo.Architecture.ToString() : "Unknown",
                                PeFormat = archInfo?.PeFormat ?? "Unknown",
                                TargetFramework = ArchitectureDetector.DetectTargetFramework(originalInputPath)
                            },
                            Output = new FileReportInfo
                            {
                                Path = finalOutputPath,
                                Sha256 = string.Empty,
                                SizeBytes = 0,
                                TargetArchitecture = archInfo != null ? archInfo.Architecture.ToString() : "Unknown",
                                PeFormat = archInfo?.PeFormat ?? "Unknown",
                                TargetFramework = "Unknown"
                            },
                            QualityAudit = new QualityAuditReportInfo
                            {
                                Status = auditReport.Status,
                                CanLoad = auditReport.CanLoad,
                                StructuralAuditPassed = auditReport.StructuralAuditPassed,
                                ILVerificationStatus = auditReport.ILVerificationStatus,
                                ILVerificationNotes = auditReport.ILVerificationNotes,
                                InvalidInstructionsCount = auditReport.InvalidInstructionsCount,
                                InvalidBranchesCount = auditReport.InvalidBranchesCount,
                                InvalidEHCount = auditReport.InvalidEHCount,
                                StackUnderflowCount = auditReport.StackUnderflowCount,
                                UnresolvedCallSitesCount = auditReport.UnresolvedCallSitesCount,
                                Warnings = auditReport.Warnings,
                                Errors = auditReport.Errors,
                                RegressionsIntroducedCount = regressions.Count,
                                Regressions = regressions
                            },
                            PassTimingsMs = stepTimings,
                            TotalElapsedMs = swTotal.ElapsedMilliseconds,
                            PeakWorkingSetBytes = Process.GetCurrentProcess().PeakWorkingSet64,
                            ExceptionsAndRollbacks = exceptionsAndRollbacks,
                            FinalStatus = "FAILED",
                            OverallVerdict = "FAILED (Candidate Assembly Rejected by QualityAuditor)",
                            ExitCode = 1,
                            SummaryNotes = "Candidate assembly was rejected because it failed structural integrity or external verification audits."
                        };
                        failReport.Save(jsonReportPath);
                    }
                    catch { }
                }

                return 1;
            }

            bool isIndeterminate = auditReport.Status == "INDETERMINATE";
            string activeReportOutputPath = finalOutputPath;

            if (isIndeterminate)
            {
                string dir = Path.GetDirectoryName(finalOutputPath);
                if (string.IsNullOrEmpty(dir)) dir = Directory.GetCurrentDirectory();
                string nameWithoutExt = Path.GetFileNameWithoutExtension(finalOutputPath);
                string ext = Path.GetExtension(finalOutputPath);
                string unverifiedCandidatePath = Path.Combine(dir, $"{nameWithoutExt}.unverified_candidate{ext}");

                try
                {
                    File.Copy(candidatePath, unverifiedCandidatePath, overwrite: true);
                    try { File.Delete(candidatePath); } catch { }
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[!] Failed to save unverified candidate: {ex.Message}");
                    Console.ResetColor();
                }

                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[!] Candidate assembly IL verification is INDETERMINATE: {auditReport.ILVerificationNotes}");
                Console.WriteLine($"[!] Candidate NOT promoted to final output path ({finalOutputPath}). Preserved as unverified candidate at: {unverifiedCandidatePath}");
                if (File.Exists(finalOutputPath))
                {
                    Console.WriteLine($"[*] Previously verified output preserved and NOT overwritten: {finalOutputPath}");
                }
                Console.ResetColor();

                activeReportOutputPath = unverifiedCandidatePath;
            }
            else
            {
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
                    if (auditReport.ILVerificationStatus == "PASSED")
                        Console.WriteLine($"[+] Quality audit passed (Structural + External IL verification PASSED). Output saved to: {finalOutputPath}");
                    else
                        Console.WriteLine($"[+] Structural integrity audit passed (no structural defects detected; External IL: {auditReport.ILVerificationStatus}). Output saved to: {finalOutputPath}");
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"[!] Structural integrity audit completed with {auditReport.Warnings.Count} warning(s) (Candidate Promoted; External IL: {auditReport.ILVerificationStatus}). Output saved to: {finalOutputPath}");
                    Console.ResetColor();
                }
            }

            // NetDetect Post-Scan Reduction Audit
            NetDetectComparisonResult netDetectComp = null;
            if (!skipNetDetect && preScan != null && preScan.Available)
            {
                var swPostScan = Stopwatch.StartNew();
                var postScan = NetDetectIntegration.RunScan(activeReportOutputPath);
                stepTimings["PostScan_NetDetect"] = swPostScan.ElapsedMilliseconds;
                NetDetectIntegration.PrintComparisonReport(preScan, postScan);
                netDetectComp = NetDetectIntegration.Compare(preScan, postScan);
            }

            // Protection Coverage & Support Matrix
            ProtectionMatrixResult matrix = null;
            try
            {
                var swMatrix = Stopwatch.StartNew();
                using (var finalModule = ModuleDefMD.Load(activeReportOutputPath))
                {
                    var unevaluated = new List<string>();
                    if (skipDe4dot && ProtectionMatrix.HasRenamingProtection(finalModule))
                    {
                        unevaluated.Add("Name Protection");
                    }

                    matrix = ProtectionMatrix.Evaluate(
                        finalModule,
                        allowExecution: allowExecution,
                        antiTamperDecrypted: antiTamperDecrypted,
                        jitModeDetected: jitDetected,
                        cor20Repaired: cor20WasRepaired,
                        constantsDecryptedCount: totalConstantsDecrypted,
                        allConstantsResolved: allConstantsResolved,
                        resourcesExtractedCount: totalResourcesExtracted,
                        proxiesInlinedCount: totalProxiesInlined,
                        switchesResolvedCount: totalSwitchesResolved,
                        junkInstructionsStrippedCount: totalJunkStripped,
                        cleanerHooksStrippedCount: totalCleanerHooks,
                        compressorUnpacked: compressorWasUnpacked,
                        unevaluatedProtections: unevaluated,
                        symbolsRenamed: de4dotSucceeded,
                        antiIldasmStripped: antiIldasmWasStripped);

                    stepTimings["Stage8_ProtectionMatrix_Evaluation"] = swMatrix.ElapsedMilliseconds;
                    Console.WriteLine(ProtectionMatrix.FormatReport(matrix));
                }
            }
            catch (Exception ex)
            {
                if (verbose)
                    Console.WriteLine($"[!] Could not generate protection coverage matrix: {ex.Message}");
            }

            Console.WriteLine();
            Console.WriteLine("---------------------------------------------------------------");
            Console.WriteLine("                 PIPELINE STAGE TIMINGS                        ");
            Console.WriteLine("---------------------------------------------------------------");
            foreach (var kvp in stepTimings)
            {
                Console.WriteLine(string.Format("[*] {0,-38} : {1,6} ms", kvp.Key, kvp.Value));
            }
            Console.WriteLine(string.Format("[*] {0,-38} : {1,6} ms", "Total Pipeline Elapsed", swTotal.ElapsedMilliseconds));
            Console.WriteLine("---------------------------------------------------------------");

            int exitCode = 0;
            string finalStatus = "SUCCESS";
            if (isIndeterminate)
            {
                exitCode = 2;
                finalStatus = "INDETERMINATE";
            }
            else if (matrix != null && (matrix.HasRequiresDynamicSkipped || matrix.HasUnsupported || matrix.HasNotEvaluated || matrix.HasCodeProtectionsPartiallyProcessed || (strictExitCodes && matrix.HasPartiallyProcessed)))
            {
                exitCode = 2;
                finalStatus = "PARTIAL_SUCCESS";
            }
            else
            {
                exitCode = 0;
                finalStatus = "SUCCESS";
            }

            if (!string.IsNullOrEmpty(jsonReportPath))
            {
                try
                {
                    string timingNote = "Pipeline stage timings reflect discrete execution time per phase; totalElapsedMs reflects total wall-clock duration including baseline audit, intermediate disk serialization, candidate verification, and report generation.";
                    string summaryNotes = isIndeterminate 
                        ? (string.IsNullOrEmpty(matrix?.SummaryNotes) ? $"Candidate assembly was preserved as unverified candidate because IL verification was indeterminate. Existing final output (if any) was not overwritten. {timingNote}" : $"{matrix.SummaryNotes} | IL verification was indeterminate; candidate not promoted. {timingNote}")
                        : (string.IsNullOrEmpty(matrix?.SummaryNotes) ? timingNote : $"{matrix.SummaryNotes} | {timingNote}");

                    var report = new DeobfuscationReport
                    {
                        Input = new FileReportInfo
                        {
                            Path = originalInputPath,
                            Sha256 = DeobfuscationReport.ComputeSha256(originalInputPath),
                            SizeBytes = new FileInfo(originalInputPath).Length,
                            TargetArchitecture = archInfo != null ? archInfo.Architecture.ToString() : "Unknown",
                            PeFormat = archInfo?.PeFormat ?? "Unknown",
                            TargetFramework = ArchitectureDetector.DetectTargetFramework(originalInputPath)
                        },
                        Output = new FileReportInfo
                        {
                            Path = activeReportOutputPath,
                            Sha256 = File.Exists(activeReportOutputPath) ? DeobfuscationReport.ComputeSha256(activeReportOutputPath) : string.Empty,
                            SizeBytes = File.Exists(activeReportOutputPath) ? new FileInfo(activeReportOutputPath).Length : 0,
                            TargetArchitecture = archInfo != null ? archInfo.Architecture.ToString() : "Unknown",
                            PeFormat = archInfo?.PeFormat ?? "Unknown",
                            TargetFramework = ArchitectureDetector.DetectTargetFramework(activeReportOutputPath)
                        },
                        Protections = matrix?.Items ?? new List<ProtectionItem>(),
                        Transformations = new TransformationReportMetrics
                        {
                            MethodsInspected = auditReport?.TotalMethods ?? 0,
                            MethodsWithBodies = auditReport?.MethodsWithBody ?? 0,
                            ConstantsDecryptedCount = totalConstantsDecrypted,
                            AllConstantsResolved = matrix?.AllConstantsResolved ?? allConstantsResolved,
                            ResourcesExtractedCount = totalResourcesExtracted,
                            ProxiesInlinedCount = totalProxiesInlined,
                            SwitchesResolvedCount = totalSwitchesResolved,
                            JunkInstructionsStrippedCount = totalJunkStripped,
                            CleanerHooksStrippedCount = totalCleanerHooks
                        },
                        QualityAudit = new QualityAuditReportInfo
                        {
                            Status = auditReport?.Status ?? "CLEAN",
                            CanLoad = auditReport?.CanLoad ?? true,
                            StructuralAuditPassed = auditReport?.StructuralAuditPassed ?? true,
                            ILVerificationStatus = auditReport?.ILVerificationStatus ?? "UNVERIFIED",
                            ILVerificationNotes = auditReport?.ILVerificationNotes ?? string.Empty,
                            InvalidInstructionsCount = auditReport?.InvalidInstructionsCount ?? 0,
                            InvalidBranchesCount = auditReport?.InvalidBranchesCount ?? 0,
                            InvalidEHCount = auditReport?.InvalidEHCount ?? 0,
                            StackUnderflowCount = auditReport?.StackUnderflowCount ?? 0,
                            UnresolvedCallSitesCount = auditReport?.UnresolvedCallSitesCount ?? 0,
                            Warnings = auditReport?.Warnings ?? new List<string>(),
                            Errors = auditReport?.Errors ?? new List<string>(),
                            RegressionsIntroducedCount = regressions?.Count ?? 0,
                            Regressions = regressions ?? new List<string>()
                        },
                        Hooks = hookRegistry.Values.ToList(),
                        PassTimingsMs = stepTimings,
                        TotalElapsedMs = swTotal.ElapsedMilliseconds,
                        PeakWorkingSetBytes = Process.GetCurrentProcess().PeakWorkingSet64,
                        ExceptionsAndRollbacks = exceptionsAndRollbacks,
                        FinalStatus = finalStatus,
                        OverallVerdict = isIndeterminate ? "INDETERMINATE (IL Verification Inconclusive - Candidate Not Promoted)" : (matrix?.OverallVerdict ?? finalStatus),
                        ExitCode = exitCode,
                        SummaryNotes = summaryNotes
                    };

                    if (netDetectComp != null && netDetectComp.Available)
                    {
                        report.NetDetect = new NetDetectReportInfo
                        {
                            Available = true,
                            PreScanScore = netDetectComp.PreScanScore,
                            PostScanScore = netDetectComp.PostScanScore,
                            ScoreDelta = netDetectComp.ScoreDelta,
                            ScoreDeltaPercent = netDetectComp.ScoreDeltaPercent,
                            PrimaryDetector = netDetectComp.PrimaryDetector,
                            Confidence = netDetectComp.Confidence,
                            ResolvedSignatures = netDetectComp.ResolvedSignatures,
                            ExposedSignatures = netDetectComp.ExposedSignatures,
                            PreservedSignatures = netDetectComp.PreservedSignatures,
                            IndicatorInterpretation = netDetectComp.IndicatorInterpretation
                        };
                    }

                    if (isIndeterminate)
                    {
                        report.KnownLimitations.Add("External IL verification was indeterminate (e.g. tool crash or internal error). Candidate not promoted to final output.");
                    }
                    if (matrix != null)
                    {
                        if (matrix.HasRequiresDynamicSkipped)
                            report.KnownLimitations.Add("Dynamic execution required for full deobfuscation (--allow-execution).");
                        if (matrix.HasUnsupported)
                            report.KnownLimitations.Add("Unsupported native x86 machine-code or JIT hooks preserved.");
                        if (!matrix.AllConstantsResolved)
                            report.KnownLimitations.Add("Encrypted constants were detected but not all references could be resolved.");
                        if (matrix.HasPartiallyProcessed && matrix.AllConstantsResolved)
                            report.KnownLimitations.Add("Some protected members or proxies could not be resolved and were preserved.");
                    }
                    foreach (var hook in activePreservedHooks)
                    {
                        report.KnownLimitations.Add($"Preserved Hook: [{hook.HookType}] {hook.MethodName}: {hook.Reason}");
                    }

                    report.Save(jsonReportPath);
                    Console.WriteLine($"[+] Deobfuscation audit report saved to: {jsonReportPath}");
                }
                catch (Exception ex)
                {
                    if (verbose)
                        Console.WriteLine($"[!] Failed to write JSON report: {ex.Message}");
                }
            }

            return exitCode;
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
            Console.WriteLine("  --allow-execution       Allow target module execution via isolated worker process (AntiTamper / Resources)");
            Console.WriteLine("                          Spawns an isolated worker process with strict timeout and process tree termination.");
            Console.WriteLine("                          NOTE: Subprocess isolation is NOT an OS security sandbox. Run untrusted samples in a VM.");
            Console.WriteLine("  --worker-timeout <ms>   Timeout in milliseconds for isolated worker process (default: 30000)");
            Console.WriteLine("  --allow-target-deps     Permit worker to resolve dependencies from target assembly directory");
            Console.WriteLine("  --dep-dir <path>        Add explicitly authorized directory for dependency resolution");
            Console.WriteLine("  -o, --output <path>     Specify custom destination path for final cleaned assembly");
            Console.WriteLine("  -d, --de4dot <path>     Specify explicit path to de4dot-cex executable");
            Console.WriteLine("  --no-de4dot             Skip de4dot external process pass");
            Console.WriteLine("  --no-netdetect          Skip NetDetect pre/post obfuscation audit");
            Console.WriteLine("  --json-report, --report-json <path>  Generate structured versioned JSON audit report");
            Console.WriteLine("  --strict-exit-codes     Return exit code 2 on any partial deobfuscation");
            Console.WriteLine("  --verbose               Enable verbose console output");
            Console.WriteLine("  -h, --help              Show this help message");
            Console.WriteLine();
            Console.WriteLine("Exit Codes:");
            Console.WriteLine("  0: Success - all requested protections resolved or fully clean output");
            Console.WriteLine("  1: Fatal Error - corrupt assembly, structural audit failed, or unhandled exception");
            Console.WriteLine("  2: Partial Result - candidate promoted with known limitations (dynamic required, unsupported)");
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
                    body.SimplifyMacros(method.Parameters);
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
                case AntiTamperStatus.NoChangesDetected:
                case AntiTamperStatus.Failed:
                case AntiTamperStatus.NotAttempted:
                default:
                    return (false, (byte[])peImageOld.Clone());
            }
        }
    }
}
