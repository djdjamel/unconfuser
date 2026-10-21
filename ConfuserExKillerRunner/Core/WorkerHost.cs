using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using ConfuserExKillerRunner.Killers;
using ConfuserExTools.ConstantKiller;
using ConfuserExTools.ProxyKiller;
using dnlib.DotNet;
using Tool;

namespace ConfuserExKillerRunner.Core
{
    public static class WorkerHost
    {
        public static int Run(string[] args)
        {
            if (args == null || args.Length < 2)
            {
                Console.Error.WriteLine("[WorkerHost] Missing subcommand for --internal-worker");
                return 1;
            }

            string command = args[1].ToLowerInvariant();
            try
            {
                switch (command)
                {
                    case "antitamper":
                        return RunAntiTamper(args);

                    case "resources":
                        return RunResources(args);

                    case "compressor":
                        return RunCompressor(args);

                    case "constants":
                        return RunConstants(args);

                    case "fieldrva":
                        return RunFieldRva(args);

                    default:
                        Console.Error.WriteLine($"[WorkerHost] Unknown worker command: {command}");
                        return 1;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[WorkerHost] Fatal worker exception in '{command}': {ex.Message}");
                return 1;
            }
        }

        private static int RunAntiTamper(string[] args)
        {
            string inputPath = null;
            string outputPePath = null;
            string outputMetaPath = null;
            bool allowTargetDeps = false;
            var allowedDepDirs = new List<string>();

            for (int i = 2; i < args.Length; i++)
            {
                if (args[i] == "--input" && i + 1 < args.Length)
                    inputPath = Path.GetFullPath(args[++i]);
                else if (args[i] == "--output-pe" && i + 1 < args.Length)
                    outputPePath = Path.GetFullPath(args[++i]);
                else if (args[i] == "--output-meta" && i + 1 < args.Length)
                    outputMetaPath = Path.GetFullPath(args[++i]);
                else if (args[i] == "--allow-target-deps")
                    allowTargetDeps = true;
                else if (args[i] == "--allowed-dep-dir" && i + 1 < args.Length)
                    allowedDepDirs.Add(Path.GetFullPath(args[++i]));
            }

            if (string.IsNullOrEmpty(inputPath) || !File.Exists(inputPath))
            {
                Console.Error.WriteLine("[WorkerHost] Invalid input path for AntiTamper");
                return 1;
            }

            SetupRestrictedResolver(inputPath, allowedDepDirs, allowTargetDeps);

            byte[] originalPeBytes = File.ReadAllBytes(inputPath);
            Assembly loadedAsm = null;
            try
            {
                loadedAsm = Assembly.LoadFile(inputPath);
            }
            catch (Exception ex)
            {
                WriteAntiTamperMeta(outputMetaPath, AntiTamperStatus.Failed, false, $"Assembly.LoadFile failed in worker: {ex.Message}", new List<string>());
                return 1;
            }

            var atResult = AntiTamperKiller.Execute(loadedAsm.ManifestModule, originalPeBytes);

            if (atResult.Status == AntiTamperStatus.DecryptionConfirmed && atResult.DecryptedPeImage != null)
            {
                if (!string.IsNullOrEmpty(outputPePath))
                    File.WriteAllBytes(outputPePath, atResult.DecryptedPeImage);
            }

            WriteAntiTamperMeta(outputMetaPath, atResult.Status, atResult.Modified, atResult.Message, atResult.DecryptedSections);
            return atResult.Status == AntiTamperStatus.DecryptionConfirmed || atResult.Status == AntiTamperStatus.NoChangesDetected ? 0 : 2;
        }

        private static int RunResources(string[] args)
        {
            string inputPath = null;
            string outputResPath = null;
            string outputMetaPath = null;
            bool allowTargetDeps = false;
            var allowedDepDirs = new List<string>();

            for (int i = 2; i < args.Length; i++)
            {
                if (args[i] == "--input" && i + 1 < args.Length)
                    inputPath = Path.GetFullPath(args[++i]);
                else if (args[i] == "--output-res" && i + 1 < args.Length)
                    outputResPath = Path.GetFullPath(args[++i]);
                else if (args[i] == "--output-meta" && i + 1 < args.Length)
                    outputMetaPath = Path.GetFullPath(args[++i]);
                else if (args[i] == "--allow-target-deps")
                    allowTargetDeps = true;
                else if (args[i] == "--allowed-dep-dir" && i + 1 < args.Length)
                    allowedDepDirs.Add(Path.GetFullPath(args[++i]));
            }

            if (string.IsNullOrEmpty(inputPath) || !File.Exists(inputPath))
                return 1;

            SetupRestrictedResolver(inputPath, allowedDepDirs, allowTargetDeps);

            try
            {
                using (var module = ModuleDefMD.Load(inputPath))
                {
                    var result = new ResourceKillerResult();
                    ResourceKiller.TryDecryptAndReEmbedResources(module, result);

                    if (result.ResourcesDecrypted)
                    {
                        // In TryDecryptAndReEmbedResources, resources were placed into module.Resources.
                        // Write the modified assembly or container out so the client can import them.
                        using (var ms = new MemoryStream())
                        {
                            var writerOpts = new dnlib.DotNet.Writer.ModuleWriterOptions(module)
                            {
                                Logger = DummyLogger.NoThrowInstance
                            };
                            module.Write(ms, writerOpts);
                            File.WriteAllBytes(outputResPath, ms.ToArray());
                        }

                        if (!string.IsNullOrEmpty(outputMetaPath))
                        {
                            File.WriteAllText(outputMetaPath,
                                $"{{\"Success\": true, \"DecryptedCount\": {result.DecryptedResourcesCount}, \"Message\": \"{EscapeJson(result.Message)}\"}}");
                        }
                        return 0;
                    }
                    else
                    {
                        if (!string.IsNullOrEmpty(outputMetaPath))
                        {
                            File.WriteAllText(outputMetaPath,
                                $"{{\"Success\": false, \"DecryptedCount\": 0, \"Message\": \"{EscapeJson(result.Message ?? "Decryption unconfirmed")}\"}}");
                        }
                        return 2;
                    }
                }
            }
            catch (Exception ex)
            {
                if (!string.IsNullOrEmpty(outputMetaPath))
                {
                    File.WriteAllText(outputMetaPath,
                        $"{{\"Success\": false, \"DecryptedCount\": 0, \"Message\": \"{EscapeJson(ex.Message)}\"}}");
                }
                return 1;
            }
        }

        private static int RunCompressor(string[] args)
        {
            string inputPath = null;
            string outputPePath = null;
            string outputMetaPath = null;
            bool allowTargetDeps = false;
            var allowedDepDirs = new List<string>();

            for (int i = 2; i < args.Length; i++)
            {
                if (args[i] == "--input" && i + 1 < args.Length)
                    inputPath = Path.GetFullPath(args[++i]);
                else if (args[i] == "--output-pe" && i + 1 < args.Length)
                    outputPePath = Path.GetFullPath(args[++i]);
                else if (args[i] == "--output-meta" && i + 1 < args.Length)
                    outputMetaPath = Path.GetFullPath(args[++i]);
                else if (args[i] == "--allow-target-deps")
                    allowTargetDeps = true;
                else if (args[i] == "--allowed-dep-dir" && i + 1 < args.Length)
                    allowedDepDirs.Add(Path.GetFullPath(args[++i]));
            }

            if (string.IsNullOrEmpty(inputPath) || !File.Exists(inputPath))
                return 1;

            SetupRestrictedResolver(inputPath, allowedDepDirs, allowTargetDeps);

            try
            {
                byte[] rawBytes = File.ReadAllBytes(inputPath);
                using (var module = ModuleDefMD.Load(rawBytes))
                {
                    // Call dynamic unpacker
                    var unpackResult = CompressorUnpacker.TryUnpack(module, rawBytes, allowExecution: true);
                    if (unpackResult.SuccessfullyUnpacked && unpackResult.UnpackedAssemblyBytes != null)
                    {
                        File.WriteAllBytes(outputPePath, unpackResult.UnpackedAssemblyBytes);
                        if (!string.IsNullOrEmpty(outputMetaPath))
                        {
                            File.WriteAllText(outputMetaPath,
                                $"{{\"Success\": true, \"Message\": \"{EscapeJson(unpackResult.Message)}\", \"EntryPointToken\": \"0x{unpackResult.RecoveredEntryPointToken:X8}\"}}");
                        }
                        return 0;
                    }
                    else
                    {
                        if (!string.IsNullOrEmpty(outputMetaPath))
                        {
                            File.WriteAllText(outputMetaPath,
                                $"{{\"Success\": false, \"Message\": \"{EscapeJson(unpackResult.Message ?? "Unpack failed")}\"}}");
                        }
                        return 2;
                    }
                }
            }
            catch (Exception ex)
            {
                if (!string.IsNullOrEmpty(outputMetaPath))
                {
                    File.WriteAllText(outputMetaPath,
                        $"{{\"Success\": false, \"Message\": \"{EscapeJson(ex.Message)}\"}}");
                }
                return 1;
            }
        }

        private static int RunConstants(string[] args)
        {
            string inputPath = null;
            string outputPePath = null;
            string outputMetaPath = null;
            bool allowTargetDeps = false;
            var allowedDepDirs = new List<string>();

            for (int i = 2; i < args.Length; i++)
            {
                if (args[i] == "--input" && i + 1 < args.Length)
                    inputPath = Path.GetFullPath(args[++i]);
                else if (args[i] == "--output-pe" && i + 1 < args.Length)
                    outputPePath = Path.GetFullPath(args[++i]);
                else if (args[i] == "--output-meta" && i + 1 < args.Length)
                    outputMetaPath = Path.GetFullPath(args[++i]);
                else if (args[i] == "--allow-target-deps")
                    allowTargetDeps = true;
                else if (args[i] == "--allowed-dep-dir" && i + 1 < args.Length)
                    allowedDepDirs.Add(Path.GetFullPath(args[++i]));
            }

            if (string.IsNullOrEmpty(inputPath) || !File.Exists(inputPath))
                return 1;

            SetupRestrictedResolver(inputPath, allowedDepDirs, allowTargetDeps);

            try
            {
                Assembly loadedAsm = Assembly.LoadFile(inputPath);
                using (var module = ModuleDefMD.Load(inputPath))
                {
                    var constResult = ConstantKillerImpl.Execute(module, loadedAsm.ManifestModule);

                    using (var ms = new MemoryStream())
                    {
                        var writerOpts = new dnlib.DotNet.Writer.ModuleWriterOptions(module)
                        {
                            Logger = DummyLogger.NoThrowInstance
                        };
                        module.Write(ms, writerOpts);
                        File.WriteAllBytes(outputPePath, ms.ToArray());
                    }

                    if (!string.IsNullOrEmpty(outputMetaPath))
                    {
                        File.WriteAllText(outputMetaPath,
                            $"{{\"Success\": true, \"DecryptedCount\": {constResult.DecryptedConstantsCount}, \"ResolvedReferences\": {constResult.ResolvedReferencesCount}, \"TotalReferences\": {constResult.TotalReferencesCount}, \"AllResolved\": {(constResult.AllReferencesResolved ? "true" : "false")}, \"Message\": \"Completed: {constResult.DecryptedConstantsCount} constants decrypted\"}}");
                    }
                    return 0;
                }
            }
            catch (Exception ex)
            {
                if (!string.IsNullOrEmpty(outputMetaPath))
                {
                    File.WriteAllText(outputMetaPath, $"{{\"Success\": false, \"Message\": \"{EscapeJson(ex.Message)}\"}}");
                }
                return 1;
            }
        }

        private static int RunFieldRva(string[] args)
        {
            string inputPath = null;
            string outputPePath = null;
            string outputMetaPath = null;
            bool allowTargetDeps = false;
            var allowedDepDirs = new List<string>();

            for (int i = 2; i < args.Length; i++)
            {
                if (args[i] == "--input" && i + 1 < args.Length)
                    inputPath = Path.GetFullPath(args[++i]);
                else if (args[i] == "--output-pe" && i + 1 < args.Length)
                    outputPePath = Path.GetFullPath(args[++i]);
                else if (args[i] == "--output-meta" && i + 1 < args.Length)
                    outputMetaPath = Path.GetFullPath(args[++i]);
                else if (args[i] == "--allow-target-deps")
                    allowTargetDeps = true;
                else if (args[i] == "--allowed-dep-dir" && i + 1 < args.Length)
                    allowedDepDirs.Add(Path.GetFullPath(args[++i]));
            }

            if (string.IsNullOrEmpty(inputPath) || !File.Exists(inputPath))
                return 1;

            SetupRestrictedResolver(inputPath, allowedDepDirs, allowTargetDeps);

            try
            {
                byte[] peImage = File.ReadAllBytes(inputPath);
                Assembly loadedAsm = Assembly.LoadFile(inputPath);
                using (var module = ModuleDefMD.Load(inputPath))
                {
                    var rvaResult = FieldRvaKiller.Execute(module, loadedAsm.ManifestModule, peImage);

                    if (rvaResult.RestoredFieldsCount > 0)
                    {
                        File.WriteAllBytes(outputPePath, peImage);
                    }

                    if (!string.IsNullOrEmpty(outputMetaPath))
                    {
                        File.WriteAllText(outputMetaPath,
                            $"{{\"Success\": true, \"RestoredCount\": {rvaResult.RestoredFieldsCount}, \"Message\": \"{EscapeJson(rvaResult.Message)}\"}}");
                    }
                    return 0;
                }
            }
            catch (Exception ex)
            {
                if (!string.IsNullOrEmpty(outputMetaPath))
                {
                    File.WriteAllText(outputMetaPath, $"{{\"Success\": false, \"Message\": \"{EscapeJson(ex.Message)}\"}}");
                }
                return 1;
            }
        }

        public static void SetupRestrictedResolver(string targetAssemblyPath, IEnumerable<string> allowedDirectories, bool allowTargetDir)
        {
            var allowedDirSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (allowedDirectories != null)
            {
                foreach (var dir in allowedDirectories)
                {
                    if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
                        allowedDirSet.Add(Path.GetFullPath(dir));
                }
            }

            string targetDir = Path.GetDirectoryName(Path.GetFullPath(targetAssemblyPath));
            var referencedAssemblyNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // Read AssemblyRefs from target module via dnlib (safe static read)
            try
            {
                using (var mod = ModuleDefMD.Load(targetAssemblyPath))
                {
                    foreach (var asmRef in mod.GetAssemblyRefs())
                    {
                        if (!string.IsNullOrEmpty(asmRef.Name.String))
                            referencedAssemblyNames.Add(asmRef.Name.String);
                    }
                }
            }
            catch { }

            AppDomain.CurrentDomain.AssemblyResolve += (sender, args) =>
            {
                try
                {
                    string simpleName = new AssemblyName(args.Name).Name;
                    if (string.IsNullOrEmpty(simpleName)) return null;

                    // Block system and core framework libraries from disk redirection
                    if (simpleName.Equals("mscorlib", StringComparison.OrdinalIgnoreCase) ||
                        simpleName.StartsWith("System.", StringComparison.OrdinalIgnoreCase) ||
                        simpleName.StartsWith("Microsoft.", StringComparison.OrdinalIgnoreCase) ||
                        simpleName.Equals("dnlib", StringComparison.OrdinalIgnoreCase) ||
                        simpleName.Equals("de4dot.blocks", StringComparison.OrdinalIgnoreCase) ||
                        simpleName.Equals("ConfuserExKillerRunner", StringComparison.OrdinalIgnoreCase))
                    {
                        return null;
                    }

                    // Only permit resolving if simpleName is explicitly listed in target's AssemblyRefs
                    if (!referencedAssemblyNames.Contains(simpleName))
                    {
                        Logger.LogWarning($"[WorkerHost] Blocked unauthorized dependency resolution: '{simpleName}' (not in target AssemblyRefs)");
                        return null;
                    }

                    // Search explicitly allowed directories first
                    foreach (var dir in allowedDirSet)
                    {
                        string candidateDll = Path.Combine(dir, simpleName + ".dll");
                        if (File.Exists(candidateDll))
                            return Assembly.LoadFrom(candidateDll);

                        string candidateExe = Path.Combine(dir, simpleName + ".exe");
                        if (File.Exists(candidateExe))
                            return Assembly.LoadFrom(candidateExe);
                    }

                    // Search target directory ONLY if explicitly authorized
                    if (allowTargetDir && !string.IsNullOrEmpty(targetDir))
                    {
                        string candidateDll = Path.Combine(targetDir, simpleName + ".dll");
                        if (File.Exists(candidateDll))
                            return Assembly.LoadFrom(candidateDll);

                        string candidateExe = Path.Combine(targetDir, simpleName + ".exe");
                        if (File.Exists(candidateExe))
                            return Assembly.LoadFrom(candidateExe);
                    }
                }
                catch (Exception ex)
                {
                    Logger.LogWarning($"[WorkerHost] Dependency resolution failed for '{args.Name}': {ex.Message}");
                }

                return null;
            };
        }

        private static void WriteAntiTamperMeta(string path, AntiTamperStatus status, bool modified, string message, List<string> sections)
        {
            if (string.IsNullOrEmpty(path)) return;

            var sb = new StringBuilder();
            sb.AppendLine("{");
            sb.AppendLine($"  \"Status\": \"{status}\",");
            sb.AppendLine($"  \"Modified\": {(modified ? "true" : "false")},");
            sb.AppendLine($"  \"Message\": \"{EscapeJson(message ?? string.Empty)}\",");
            sb.AppendLine("  \"DecryptedSections\": [");
            if (sections != null && sections.Count > 0)
            {
                for (int i = 0; i < sections.Count; i++)
                {
                    sb.Append($"    {{\"Section\": \"{EscapeJson(sections[i])}\"}}");
                    if (i < sections.Count - 1) sb.Append(",");
                    sb.AppendLine();
                }
            }
            sb.AppendLine("  ]");
            sb.AppendLine("}");

            File.WriteAllText(path, sb.ToString());
        }

        private static string EscapeJson(string s)
        {
            if (string.IsNullOrEmpty(s)) return string.Empty;
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", " ");
        }
    }
}
