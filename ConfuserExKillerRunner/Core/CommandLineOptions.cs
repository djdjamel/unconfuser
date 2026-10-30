using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace ConfuserExKillerRunner.Core
{
    public sealed class CommandLineOptions
    {
        public string AssemblyPath { get; set; }
        public bool AllowExecution { get; set; }
        public int WorkerTimeoutMs { get; set; } = 30000;
        public bool AllowTargetDeps { get; set; }
        public List<string> AllowedDepDirs { get; set; } = new List<string>();
        public string ExplicitDe4dotPath { get; set; }
        public bool SkipDe4dot { get; set; }
        public bool SkipNetDetect { get; set; }
        public string OutputPath { get; set; }
        public string JsonReportPath { get; set; }
        public bool StrictExitCodes { get; set; } = true;
        public bool Verbose { get; set; }
        public bool RestoreSemanticNames { get; set; }
        public bool ForcePromote { get; set; }
        public bool IsHelp { get; set; }

        public static CommandLineOptions Parse(string[] args, out string errorMessage)
        {
            errorMessage = null;
            var options = new CommandLineOptions();

            if (args == null || args.Length == 0 || args.Contains("-h") || args.Contains("--help"))
            {
                options.IsHelp = true;
                return options;
            }

            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];
                if (arg == "--allow-execution")
                {
                    options.AllowExecution = true;
                }
                else if (arg == "--worker-timeout" && i + 1 < args.Length && int.TryParse(args[i + 1], out int parsedTimeout))
                {
                    options.WorkerTimeoutMs = parsedTimeout;
                    i++;
                }
                else if (arg == "--allow-target-deps")
                {
                    options.AllowTargetDeps = true;
                }
                else if ((arg == "--dep-dir" || arg == "--allowed-dep-dir") && i + 1 < args.Length)
                {
                    options.AllowedDepDirs.Add(args[++i]);
                }
                else if (arg == "--no-de4dot")
                {
                    options.SkipDe4dot = true;
                }
                else if (arg == "--no-netdetect")
                {
                    options.SkipNetDetect = true;
                }
                else if (arg == "--verbose")
                {
                    options.Verbose = true;
                }
                else if ((arg == "--de4dot" || arg == "-d") && i + 1 < args.Length)
                {
                    options.ExplicitDe4dotPath = args[++i];
                }
                else if ((arg == "-o" || arg == "--output") && i + 1 < args.Length)
                {
                    options.OutputPath = args[++i];
                }
                else if ((arg == "--json-report" || arg == "--report-json" || arg == "--report" || arg == "-r" || arg == "--json" || arg == "-j") && i + 1 < args.Length)
                {
                    options.JsonReportPath = Path.GetFullPath(args[++i]);
                }
                else if (arg == "--strict-exit-codes")
                {
                    options.StrictExitCodes = true;
                }
                else if (arg == "--allow-partial-exit-zero" || arg == "--permissive-exit-codes")
                {
                    options.StrictExitCodes = false;
                }
                else if (arg == "--restore-names" || arg == "--semantic-names")
                {
                    options.RestoreSemanticNames = true;
                }
                else if (arg == "--force-promote" || arg == "--force")
                {
                    options.ForcePromote = true;
                }
                else if (!arg.StartsWith("-") && options.AssemblyPath == null)
                {
                    options.AssemblyPath = Path.GetFullPath(arg);
                }
            }

            if (string.IsNullOrEmpty(options.AssemblyPath))
            {
                errorMessage = "No target assembly specified.";
                return null;
            }

            if (!File.Exists(options.AssemblyPath))
            {
                errorMessage = $"File not found: {options.AssemblyPath}";
                return null;
            }

            return options;
        }

        public static void PrintUsage()
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
            Console.WriteLine("                          CAUTION: Only enable if target directory is trusted. Use --dep-dir for safe paths.");
            Console.WriteLine("  --dep-dir <path>        Add explicitly authorized directory for dependency resolution");
            Console.WriteLine("  -o, --output <path>     Specify custom destination path for final cleaned assembly");
            Console.WriteLine("  -d, --de4dot <path>     Specify explicit path to de4dot-cex executable");
            Console.WriteLine("  --no-de4dot             Skip de4dot external process pass");
            Console.WriteLine("  --no-netdetect          Skip NetDetect pre/post obfuscation audit");
            Console.WriteLine("  --json-report, --report-json <path>  Generate structured versioned JSON audit report");
            Console.WriteLine("  --strict-exit-codes     Return exit code 2 on any partial deobfuscation (default: enabled)");
            Console.WriteLine("  --allow-partial-exit-zero Return exit code 0 on partial deobfuscation (report status remains PARTIAL_SUCCESS)");
            Console.WriteLine("  --restore-names, --semantic-names   Restore semantic symbol names (Forms, Controls, Event Handlers, Resources)");
            Console.WriteLine("  --force-promote, --force            Promote candidate to output path even if external dependencies cause indeterminate status");
            Console.WriteLine("  --verbose               Enable verbose console output");
            Console.WriteLine("  -h, --help              Show this help message");
            Console.WriteLine();
            Console.WriteLine("Exit Codes:");
            Console.WriteLine("  0: Success - complete, verified deobfuscation (or --allow-partial-exit-zero on partial)");
            Console.WriteLine("  1: Fatal Error - corrupt assembly, structural audit failed, or unhandled exception");
            Console.WriteLine("  2: Partial Result - candidate unverified/partial (dynamic required, unsupported, unevaluated, indeterminate)");
        }
    }
}
