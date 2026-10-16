using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using ConfuserExKillerRunner.Core;
using Tool;

namespace ConfuserExKillerRunner.Analysis
{
    public sealed class NetDetectScanResult
    {
        public bool Available { get; set; }
        public bool Detected { get; set; }
        public string PrimaryDetector { get; set; } = "None";
        public string Confidence { get; set; } = "None";
        public int VerdictScore { get; set; }
        public List<string> Protectors { get; set; } = new List<string>();
        public List<string> GenericTechniques { get; set; } = new List<string>();
        public string Summary { get; set; } = "";

        public bool IsKoiVMPresent => Protectors.Any(p => p.IndexOf("KoiVM", StringComparison.OrdinalIgnoreCase) >= 0) ||
                                     GenericTechniques.Any(t => t.IndexOf("KoiVM", StringComparison.OrdinalIgnoreCase) >= 0);

        public bool IsConfuserExPresent => Protectors.Any(p => p.IndexOf("ConfuserEx", StringComparison.OrdinalIgnoreCase) >= 0);

        public bool HasAntiTamper => GenericTechniques.Any(t => t.IndexOf("Anti-Tamper", StringComparison.OrdinalIgnoreCase) >= 0 || t.IndexOf("JIT Hooking", StringComparison.OrdinalIgnoreCase) >= 0);
        public bool HasConstants => GenericTechniques.Any(t => t.IndexOf("Constant", StringComparison.OrdinalIgnoreCase) >= 0);
        public bool HasControlFlow => GenericTechniques.Any(t => t.IndexOf("Control Flow", StringComparison.OrdinalIgnoreCase) >= 0);
    }

    public static class NetDetectIntegration
    {
        public static string ResolveScriptPath()
        {
            string appDir = AppDomain.CurrentDomain.BaseDirectory;
            string[] candidates = new[]
            {
                Path.Combine(Directory.GetCurrentDirectory(), "netdetect_cli.py"),
                Path.Combine(appDir, "netdetect_cli.py"),
                Path.Combine(appDir, "..", "..", "..", "netdetect_cli.py"),
                @"c:\Users\acer\claude\xp_src\netdetect_cli.py"
            };

            foreach (var candidate in candidates)
            {
                if (File.Exists(candidate))
                    return Path.GetFullPath(candidate);
            }

            return null;
        }

        public static NetDetectScanResult RunScan(string assemblyPath)
        {
            var result = new NetDetectScanResult { Available = false };
            string scriptPath = ResolveScriptPath();
            if (scriptPath == null)
                return result;

            string tempJson = Path.Combine(Path.GetTempPath(), $"netdetect_{Guid.NewGuid():N}.json");
            try
            {
                string args = $"\"{scriptPath}\" \"{assemblyPath}\" -j \"{tempJson}\"";
                var procResult = ProcessRunner.Run("python", args, Path.GetDirectoryName(scriptPath), timeoutMs: 60000);

                if (!File.Exists(tempJson))
                    return result;

                string jsonContent = File.ReadAllText(tempJson);
                result = ParseNetDetectJson(jsonContent);
                result.Available = true;
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"[NetDetect] Scan failed: {ex.Message}");
            }
            finally
            {
                try { if (File.Exists(tempJson)) File.Delete(tempJson); } catch { }
            }

            return result;
        }

        private static NetDetectScanResult ParseNetDetectJson(string json)
        {
            var result = new NetDetectScanResult { Available = true };

            // Lightweight regex-based parser to avoid external JSON library dependencies
            var detectedMatch = Regex.Match(json, "\"detected\"\\s*:\\s*(true|false)", RegexOptions.IgnoreCase);
            if (detectedMatch.Success)
                result.Detected = bool.Parse(detectedMatch.Groups[1].Value);

            var primaryMatch = Regex.Match(json, "\"primary_detector\"\\s*:\\s*\"([^\"]+)\"");
            if (primaryMatch.Success)
                result.PrimaryDetector = primaryMatch.Groups[1].Value;

            var confMatch = Regex.Match(json, "\"confidence\"\\s*:\\s*\"([^\"]+)\"");
            if (confMatch.Success)
                result.Confidence = confMatch.Groups[1].Value;

            var scoreMatch = Regex.Match(json, "\"verdict_score\"\\s*:\\s*(\\d+)");
            if (scoreMatch.Success)
                result.VerdictScore = int.Parse(scoreMatch.Groups[1].Value);

            var summaryMatch = Regex.Match(json, "\"summary\"\\s*:\\s*\"([^\"]+)\"");
            if (summaryMatch.Success)
                result.Summary = summaryMatch.Groups[1].Value;

            // Extract protectors
            var protectorMatches = Regex.Matches(json, "\"name\"\\s*:\\s*\"([^\"]+)\"");
            foreach (Match m in protectorMatches)
            {
                string name = m.Groups[1].Value;
                if (!result.Protectors.Contains(name) && name != ".text" && name != ".rsrc" && name != ".reloc")
                    result.Protectors.Add(name);
            }

            // Extract techniques
            var techniqueMatches = Regex.Matches(json, "\"technique\"\\s*:\\s*\"([^\"]+)\"");
            foreach (Match m in techniqueMatches)
            {
                string tech = m.Groups[1].Value;
                if (!result.GenericTechniques.Contains(tech))
                    result.GenericTechniques.Add(tech);
            }

            return result;
        }

        public static void PrintPreScanReport(NetDetectScanResult preScan)
        {
            if (!preScan.Available)
                return;

            Console.WriteLine();
            Console.WriteLine("---------------------------------------------------------------");
            Console.WriteLine("               NetDetect Pre-Deobfuscation Triage              ");
            Console.WriteLine("---------------------------------------------------------------");
            Console.WriteLine($"[*] Primary Verdict:        {preScan.PrimaryDetector} (Confidence: {preScan.Confidence})");
            Console.WriteLine($"[*] Obfuscation Score:      {preScan.VerdictScore}");
            if (preScan.Protectors.Count > 0)
                Console.WriteLine($"[*] Matched Protectors:     {string.Join(", ", preScan.Protectors)}");
            if (preScan.GenericTechniques.Count > 0)
                Console.WriteLine($"[*] Detected Techniques:    {string.Join("; ", preScan.GenericTechniques)}");

            if (preScan.IsKoiVMPresent)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine();
                Console.WriteLine("[!] ====================== CRITICAL NOTICE ======================");
                Console.WriteLine("[!] KoiVM Virtualization Detected!");
                Console.WriteLine("[!] Method bodies have been compiled to custom virtual bytecode.");
                Console.WriteLine("[!] Pure CIL deobfuscation cannot reconstruct KoiVM opcodes.");
                Console.WriteLine("[!] Dedicated devirtualization toolchain required for KoiVM bodies.");
                Console.WriteLine("[!] ==============================================================");
                Console.WriteLine();
                Console.ResetColor();
            }
            Console.WriteLine("---------------------------------------------------------------");
            Console.WriteLine();
        }

        public static void PrintComparisonReport(NetDetectScanResult preScan, NetDetectScanResult postScan)
        {
            if (!preScan.Available || !postScan.Available)
                return;

            Console.WriteLine();
            Console.WriteLine("===============================================================");
            Console.WriteLine("             NetDetect Obfuscation Reduction Audit             ");
            Console.WriteLine("===============================================================");
            Console.WriteLine($"[*] Pre-Scan Obfuscation Score:   {preScan.VerdictScore} ({preScan.PrimaryDetector})");
            Console.WriteLine($"[*] Post-Scan Obfuscation Score:  {postScan.VerdictScore} ({postScan.PrimaryDetector})");

            int reduction = preScan.VerdictScore - postScan.VerdictScore;
            double pct = preScan.VerdictScore > 0 ? (reduction * 100.0 / preScan.VerdictScore) : 0;
            Console.WriteLine($"[*] Score Delta:                  {(reduction <= 0 ? "+" : "-")}{Math.Abs(reduction)} ({(reduction >= 0 ? "-" : "+")}{Math.Abs(pct):F1}%)");
            Console.WriteLine($"[*] Final Verdict:                {(postScan.VerdictScore == 0 ? "[ CLEAN / UNOBFUSCATED ]" : postScan.Confidence + " " + postScan.PrimaryDetector)}");
            Console.WriteLine("===============================================================");
        }
    }
}
