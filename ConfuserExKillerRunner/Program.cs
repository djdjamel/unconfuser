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

            // Hook target directory assembly resolution to prevent DLL hijacking
            string targetDir = Path.GetDirectoryName(assemblyPath);
            AppDomain.CurrentDomain.AssemblyResolve += (sender, resolveArgs) =>
            {
                try
                {
                    string simpleName = new AssemblyName(resolveArgs.Name).Name;
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
                        string unwrappedPath = Path.Combine(targetDir, Path.GetFileNameWithoutExtension(assemblyPath) + ".unwrapped" + Path.GetExtension(assemblyPath));
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
            if (!allowExecution)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine();
                Console.WriteLine("[!] ========================== SAFETY GATE ==========================");
                Console.WriteLine("[!] Execution mode is DISABLED (omitted --allow-execution).");
                Console.WriteLine("[!] Untrusted target constructors (<Module>.cctor) will NOT be executed.");
                Console.WriteLine("[!] Running in Pure Static Analysis mode.");
                Console.WriteLine("[!] To enable runtime AntiTamper and dynamic Constant decryption,");
                Console.WriteLine("[!] re-run with '--allow-execution' in an isolated sandbox.");
                Console.WriteLine("[!] =================================================================");
                Console.WriteLine();
                Console.ResetColor();
            }
            else
            {
                Console.WriteLine("[*] Step 1: Running AntiTamperKiller (Dynamic Execution Enabled)...");
                try
                {
                    reflModule = Assembly.LoadFile(assemblyPath).ManifestModule;
                    var atResult = AntiTamperKiller.Execute(reflModule, peImageOld);
                    peImage = atResult.DecryptedPeImage;
                    if (atResult.Modified)
                        Console.WriteLine($"[+] AntiTamper: Decrypted {atResult.DecryptedSections.Count} sections ({string.Join(", ", atResult.DecryptedSections)})");
                    else
                        Console.WriteLine("[-] AntiTamper: No section changes detected");
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[!] AntiTamper dynamic execution failed: {ex.Message}");
                    Console.ResetColor();
                    peImage = (byte[])peImageOld.Clone();
                }
            }

            // Bounds-checked COR20 header repair
            var repairResult = Cor20Repair.Repair(peImage, peImageOld);
            if (repairResult.CbRepaired)
                Console.WriteLine($"[+] Anti-Dump: Fixed COR20 header cb from {repairResult.OriginalCb} to 72");
            if (repairResult.MetaDataRvaRepaired)
                Console.WriteLine($"[+] Anti-Dump: Restored MetaData RVA to 0x{repairResult.RepairedMetaDataRva:X8}");

            byte[] bytesToLoad = peImage;
            try
            {
                using (var testMod = ModuleDefMD.Load(peImage)) { }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] ModuleDefMD load check: {ex.Message}");
                Cor20Repair.Repair(bytesToLoad, peImageOld);
            }

            string fileExt = Path.GetExtension(assemblyPath);
            string baseName = Path.GetFileNameWithoutExtension(assemblyPath);
            string cexkPath = Path.Combine(targetDir, baseName + ".cexk" + fileExt);

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
                if (resResult.HandlerStripped)
                    Console.WriteLine("[+] ResourceKiller: Stripped runtime ResourceResolve hook");
                if (resResult.ResourcesDecrypted)
                    Console.WriteLine($"[+] ResourceKiller: Extracted & re-embedded {resResult.DecryptedResourcesCount} decrypted resources ({resResult.TotalManifestResourcesCount} total in manifest)");

                // Step 2.2: ProxyKiller + ConstantKiller
                int proxyCount = ProxyKillerImpl.Execute(module, false, true);
                Console.WriteLine($"[+] ProxyKiller: {proxyCount} proxy methods/delegates inlined");

                int constCount = ConstantKillerImpl.Execute(module, reflModule);
                Console.WriteLine($"[+] ConstantKiller: {constCount} constants decrypted (with stack evaluation)");

                // Step 3: Protector hook stripping
                Console.WriteLine("[*] Step 3: Cleaning Protector Hooks...");
                var cleanResult = CleanerKiller.StripProtectorHooks(module);
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
            string cleanedPath = Path.Combine(targetDir, baseName + "-cleaned" + fileExt);
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
                var de4dotResult = ProcessRunner.Run(de4dotExecutable, de4dotArgs, targetDir, timeoutMs: 180000);

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
            string finalOutputPath = !string.IsNullOrEmpty(outputPath) ? outputPath : finalDefaultPath;

            using (var module2 = ModuleDefMD.Load(currentIntermediate))
            {
                CleanerKiller.StripProtectorHooks(module2);
                PredicateKiller.Execute(module2);
                DeadCodeStripper.Execute(module2);
                int switchCount2 = SwitchKillerImpl.Execute(module2);
                DeadCodeStripper.Execute(module2);
                Console.WriteLine($"[+] Final SwitchKiller: {switchCount2} switches resolved");
                var writerOpts2 = new ModuleWriterOptions(module2) { Logger = DnlibLogger.Instance };
                writerOpts2.MetaDataOptions.Flags |= MetaDataFlags.KeepOldMaxStack;
                module2.Write(finalOutputPath, writerOpts2);
            }

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[+] Deobfuscation Complete! Final output saved to: {finalOutputPath}");
            Console.ResetColor();

            // Quality Audit
            Console.WriteLine();
            Console.WriteLine("===============================================================");
            Console.WriteLine("              Assembly Quality Verification Report             ");
            Console.WriteLine("===============================================================");
            var auditReport = QualityAuditor.Audit(finalOutputPath);
            Console.WriteLine($"[*] Status:                 [{auditReport.Status}]");
            Console.WriteLine($"[*] Types Audited:          {auditReport.TotalTypes}");
            Console.WriteLine($"[*] Methods Audited:        {auditReport.TotalMethods} ({auditReport.MethodsWithBody} with IL bodies)");
            Console.WriteLine($"[*] Invalid Instructions:   {auditReport.InvalidInstructionsCount}");
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

            // NetDetect Post-Scan Reduction Audit
            if (!skipNetDetect && preScan != null && preScan.Available)
            {
                var postScan = NetDetectIntegration.RunScan(finalOutputPath);
                NetDetectIntegration.PrintComparisonReport(preScan, postScan);
            }

            if (auditReport.Status == "FAILED")
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[!] Deobfuscation audit reported FAILED. Exiting with error code 1.");
                Console.ResetColor();
                return 1;
            }

            return 0;
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
    }
}
