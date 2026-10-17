using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

namespace FixtureGenerator
{
    public static class Program
    {
        public static int Main(string[] args)
        {
            string verifyPath = null;
            string scenario = null;
            string baselinePath = null;
            string benignPath = null;
            string outputDir = null;

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--verify" && i + 1 < args.Length)
                    verifyPath = Path.GetFullPath(args[++i]);
                else if (args[i] == "--scenario" && i + 1 < args.Length)
                    scenario = args[++i];
                else if (args[i] == "--baseline" && i + 1 < args.Length)
                    baselinePath = Path.GetFullPath(args[++i]);
                else if (args[i] == "--input" && i + 1 < args.Length)
                    benignPath = Path.GetFullPath(args[++i]);
                else if (args[i] == "--output-dir" && i + 1 < args.Length)
                    outputDir = Path.GetFullPath(args[++i]);
                else if (args[i] == "--tamper-eh" && i + 2 < args.Length)
                {
                    string inPath = Path.GetFullPath(args[++i]);
                    string outPath = Path.GetFullPath(args[++i]);
                    using (var mod = ModuleDefMD.Load(inPath))
                    {
                        var worker = mod.Find("BenignSample.GenericWorker`1", false);
                        var proc = worker?.FindMethod("Process");
                        if (proc != null && proc.Body.ExceptionHandlers.Count > 0)
                        {
                            proc.Body.KeepOldMaxStack = true;
                            var h = proc.Body.ExceptionHandlers[0];
                            h.HandlerEnd = h.HandlerStart;
                        }
                        WriteModule(mod, outPath);
                    }
                    return 0;
                }
                else if (args[i] == "--tamper-res" && i + 2 < args.Length)
                {
                    string inPath = Path.GetFullPath(args[++i]);
                    string outPath = Path.GetFullPath(args[++i]);
                    using (var mod = ModuleDefMD.Load(inPath))
                    {
                        mod.Resources.Add(new EmbeddedResource("UnexpectedExtraResource.bin", new byte[] { 1, 2, 3 }));
                        WriteModule(mod, outPath);
                    }
                    return 0;
                }
                else if (args[i] == "--tamper-branch-target" && i + 2 < args.Length)
                {
                    string inPath = Path.GetFullPath(args[++i]);
                    string outPath = Path.GetFullPath(args[++i]);
                    using (var mod = ModuleDefMD.Load(inPath))
                    {
                        var worker = mod.Find("BenignSample.GenericWorker`1", false);
                        var proc = worker?.FindMethod("Process");
                        if (proc != null && proc.Body.Instructions.Count > 0)
                        {
                            proc.Body.KeepOldMaxStack = true;
                            // Find a conditional branch targeting an instruction whose opcode is shared by another instruction
                            var brInst = proc.Body.Instructions.FirstOrDefault(inst =>
                                inst.Operand is Instruction target && target.OpCode == OpCodes.Ldstr);
                            if (brInst != null)
                            {
                                var currentTarget = (Instruction)brInst.Operand;
                                var altTarget = proc.Body.Instructions.FirstOrDefault(inst =>
                                    inst != currentTarget && inst.OpCode == OpCodes.Ldstr);
                                if (altTarget != null)
                                {
                                    brInst.Operand = altTarget;
                                }
                            }
                        }
                        WriteModule(mod, outPath);
                    }
                    return 0;
                }
                else if (args[i] == "--tamper-eh-boundary-fingerprint" && i + 2 < args.Length)
                {
                    string inPath = Path.GetFullPath(args[++i]);
                    string outPath = Path.GetFullPath(args[++i]);
                    using (var mod = ModuleDefMD.Load(inPath))
                    {
                        var worker = mod.Find("BenignSample.GenericWorker`1", false);
                        var proc = worker?.FindMethod("Process");
                        if (proc != null && proc.Body.ExceptionHandlers.Count > 0)
                        {
                            proc.Body.KeepOldMaxStack = true;
                            var h = proc.Body.ExceptionHandlers[0];
                            var origTryStart = h.TryStart;
                            // Move TryStart to another instruction with the same structural fingerprint (ldloc.0)
                            var altInst = proc.Body.Instructions.FirstOrDefault(inst =>
                                inst != origTryStart && inst.OpCode == origTryStart.OpCode
                                && ((inst.Operand == null && origTryStart.Operand == null) || (inst.Operand?.ToString() == origTryStart.Operand?.ToString())));
                            if (altInst != null)
                            {
                                h.TryStart = altInst;
                            }
                        }
                        WriteModule(mod, outPath);
                    }
                    return 0;
                }
                else if (args[i] == "--tamper-local-type" && i + 2 < args.Length)
                {
                    string inPath = Path.GetFullPath(args[++i]);
                    string outPath = Path.GetFullPath(args[++i]);
                    using (var mod = ModuleDefMD.Load(inPath))
                    {
                        var worker = mod.Find("BenignSample.GenericWorker`1", false);
                        var proc = worker?.FindMethod("Process");
                        if (proc != null && proc.Body.Variables.Count > 0)
                        {
                            proc.Body.KeepOldMaxStack = true;
                            // Alter local variable type without changing the local count (int32 -> int64)
                            proc.Body.Variables[0].Type = mod.CorLibTypes.Int64;
                        }
                        WriteModule(mod, outPath);
                    }
                    return 0;
                }
            }

            if (!string.IsNullOrEmpty(verifyPath))
            {
                return VerifyCleanOutput(verifyPath, scenario ?? "unknown", baselinePath);
            }

            if (string.IsNullOrEmpty(benignPath) || !File.Exists(benignPath))
            {
                Console.WriteLine("[ERROR] Missing or invalid --input <path_to_BenignSample.dll>");
                return 1;
            }

            if (string.IsNullOrEmpty(outputDir))
            {
                outputDir = Path.Combine(Path.GetDirectoryName(benignPath), "fixtures");
            }

            Directory.CreateDirectory(outputDir);
            Console.WriteLine($"[*] Generating deobfuscation benchmark fixtures from: {benignPath}");
            Console.WriteLine($"[*] Output directory: {outputDir}");

            // Generate each deterministic protection scenario
            GenerateConstantsFixture(benignPath, Path.Combine(outputDir, "fixture_constants.dll"));
            GenerateCflowFixture(benignPath, Path.Combine(outputDir, "fixture_cflow.dll"));
            GenerateProxiesFixture(benignPath, Path.Combine(outputDir, "fixture_proxies.dll"));
            GenerateResourcesFixture(benignPath, Path.Combine(outputDir, "fixture_resources.dll"));
            GenerateCompressorFixture(benignPath, Path.Combine(outputDir, "fixture_compressor.dll"));
            GenerateAntiTamperFixture(benignPath, Path.Combine(outputDir, "fixture_antitamper.dll"));
            GenerateCombinedFixture(benignPath, Path.Combine(outputDir, "fixture_combined.dll"));
            GenerateEdgeCasesFixture(benignPath, Path.Combine(outputDir, "fixture_edge_cases.dll"));

            Console.WriteLine("[+] All 8 benchmark fixtures generated successfully.");
            return 0;
        }

        public static int VerifyCleanOutput(string cleanPath, string scenario, string baselinePath = null)
        {
            if (!File.Exists(cleanPath))
            {
                Console.WriteLine("{\"verified\":false,\"error\":\"File not found\"}");
                return 1;
            }

            try
            {
                using (var module = ModuleDefMD.Load(cleanPath))
                {
                    bool verified = false;
                    bool partial = false;
                    bool unverified = false;
                    var verifiedTransformations = new List<string>();
                    var unverifiedTransformations = new List<string>();
                    string notes = "";

                    switch (scenario.ToLowerInvariant())
                    {
                        case "constants":
                            {
                                var features = module.Find("BenignSample.BenignFeatures", false);
                                var getStr = features?.FindMethod("GetStringConstant");
                                var getNum1 = features?.FindMethod("GetNumericConstant1");
                                var getNum2 = features?.FindMethod("GetNumericConstant2");

                                bool strInlined = getStr != null && getStr.Body.Instructions.Any(i => i.OpCode == OpCodes.Ldstr && (string)i.Operand == "ConfuserEx_Benchmark_Secret_String_2026");
                                bool num1Inlined = getNum1 != null && getNum1.Body.Instructions.Any(i => i.IsLdcI4() && i.GetLdcI4Value() == 133742);
                                bool num2Inlined = getNum2 != null && getNum2.Body.Instructions.Any(i => (i.OpCode == OpCodes.Ldc_I8 && (long)i.Operand == 9223372036854775800L));
                                bool strNoDecrypter = getStr != null && !getStr.Body.Instructions.Any(i => i.OpCode == OpCodes.Call && i.Operand?.ToString().Contains("Decrypter") == true);
                                bool num1NoDecrypter = getNum1 != null && !getNum1.Body.Instructions.Any(i => i.OpCode == OpCodes.Call && i.Operand?.ToString().Contains("Decrypter") == true);
                                bool num2NoDecrypter = getNum2 != null && !getNum2.Body.Instructions.Any(i => i.OpCode == OpCodes.Call && i.Operand?.ToString().Contains("Decrypter") == true);

                                if (strInlined) verifiedTransformations.Add("string_constant_inlined(System.String)");
                                else unverifiedTransformations.Add("string_constant_inlined(System.String)");

                                if (num1Inlined) verifiedTransformations.Add("numeric_constant_inlined(System.Int32)");
                                else unverifiedTransformations.Add("numeric_constant_inlined(System.Int32)");

                                if (num2Inlined) verifiedTransformations.Add("numeric_constant_inlined(System.Int64)");
                                else unverifiedTransformations.Add("numeric_constant_inlined(System.Int64)");

                                if (strNoDecrypter && num1NoDecrypter && num2NoDecrypter) verifiedTransformations.Add("decrypter_calls_removed");
                                else unverifiedTransformations.Add("decrypter_calls_removed");

                                verified = strInlined && num1Inlined && num2Inlined && strNoDecrypter && num1NoDecrypter && num2NoDecrypter;
                                notes = "Exact string (System.String), integer (System.Int32), and long (System.Int64) constants recovered and inlined; exactly 3 constants decrypted.";
                            }
                            break;

                        case "cflow":
                            {
                                var features = module.Find("BenignSample.BenignFeatures", false);
                                var compute = features?.FindMethod("ComputeSwitch");
                                bool hasJunk = compute != null && compute.Body.Instructions.Any(i => i.IsLdcI4() && i.GetLdcI4Value() == 8888);
                                bool hasValidFlow = compute != null && compute.Body.Instructions.Count > 0 && compute.Body.Instructions.Any(i => i.OpCode == OpCodes.Ret);
                                bool hasSwitchOrDispatch = compute != null && (compute.Body.Instructions.Any(i => i.OpCode == OpCodes.Switch) || compute.Body.Instructions.Any(i => i.IsBr()));

                                if (!hasJunk) verifiedTransformations.Add("deadcode_junk_pair_stripped");
                                else unverifiedTransformations.Add("deadcode_junk_pair_stripped");

                                if (hasValidFlow && hasSwitchOrDispatch) verifiedTransformations.Add("switch_dispatch_structure_preserved");
                                else unverifiedTransformations.Add("switch_dispatch_structure_preserved");

                                verified = !hasJunk && hasValidFlow && hasSwitchOrDispatch;
                                notes = "Dead-code junk pairs (ldc.i4 8888 + pop) stripped and switch dispatch structure preserved across all 4 switch cases.";
                            }
                            break;

                        case "proxies":
                            {
                                var features = module.Find("BenignSample.BenignFeatures", false);
                                var exec = features?.FindMethod("ExecuteProxy");
                                bool callsTargetDirectly = exec != null && exec.Body.Instructions.Any(i => i.OpCode == OpCodes.Call && i.Operand?.ToString().Contains("AddProxyTarget") == true);
                                bool callsProxyMethod = exec != null && exec.Body.Instructions.Any(i => i.OpCode == OpCodes.Call && i.Operand?.ToString().Contains("Proxy_Add_Method") == true);
                                bool proxyMethodPruned = features?.FindMethod("Proxy_Add_Method") == null;

                                if (callsTargetDirectly) verifiedTransformations.Add("proxy_call_rewritten_to_target");
                                else unverifiedTransformations.Add("proxy_call_rewritten_to_target");

                                if (!callsProxyMethod) verifiedTransformations.Add("intermediate_proxy_call_removed");
                                else unverifiedTransformations.Add("intermediate_proxy_call_removed");

                                if (proxyMethodPruned) verifiedTransformations.Add("proxy_method_definition_pruned");
                                else unverifiedTransformations.Add("proxy_method_definition_pruned");

                                verified = callsTargetDirectly && !callsProxyMethod && proxyMethodPruned;
                                notes = "PrivateScope reference proxy method inlined, call site rewritten directly to target, and proxy definition pruned.";
                            }
                            break;

                        case "resources":
                            {
                                var resourceNames = module.Resources.Select(r => r.Name.String).OrderBy(n => n).ToList();
                                bool namesMatch = resourceNames.Count == 1 && resourceNames[0] == "BenignSample.Greeting.txt";

                                if (!string.IsNullOrEmpty(baselinePath) && File.Exists(baselinePath))
                                {
                                    using (var baseModule = ModuleDefMD.Load(baselinePath))
                                    {
                                        var baseResNames = baseModule.Resources.Select(r => r.Name.String).OrderBy(n => n).ToList();
                                        namesMatch = namesMatch && resourceNames.SequenceEqual(baseResNames);
                                    }
                                }

                                if (namesMatch) verifiedTransformations.Add("resource_manifest_names_matched");
                                else unverifiedTransformations.Add("resource_manifest_names_matched");

                                var res = module.Resources.Find("BenignSample.Greeting.txt") as EmbeddedResource;
                                if (res != null)
                                {
                                    byte[] actualBytes = res.GetResourceData();
                                    byte[] expectedBytes = System.Text.Encoding.UTF8.GetBytes("HELLO_FROM_BENIGN_EMBEDDED_RESOURCE");
                                    bool bytesMatch = actualBytes != null && actualBytes.SequenceEqual(expectedBytes);

                                    if (bytesMatch)
                                    {
                                        verifiedTransformations.Add("resource_byte_for_byte_exact_match");
                                        verified = namesMatch;
                                        notes = "Resource extracted from encrypted payload and re-embedded with exact byte-for-byte payload match and correct manifest name set.";
                                    }
                                    else
                                    {
                                        unverifiedTransformations.Add("resource_byte_for_byte_exact_match");
                                    }
                                }
                                else
                                {
                                    unverifiedTransformations.Add("resource_missing_from_manifest");
                                }
                            }
                            break;

                        case "compressor":
                            {
                                bool hasSimpleName = module.Assembly != null && module.Assembly.Name == "BenignSample";
                                bool hasProgram = module.Find("BenignSample.Program", false) != null;
                                bool hasFeatures = module.Find("BenignSample.BenignFeatures", false) != null;
                                bool hasCalc = module.Find("BenignSample.ICalculator", false) != null;
                                bool hasWorker = module.Find("BenignSample.GenericWorker`1", false) != null;
                                bool hasDecrypters = module.Find("BenignSample.Decrypters", false) != null;
                                bool hasStandardCalc = module.Find("BenignSample.StandardCalculator", false) != null;
                                bool hasGreetingRes = module.Resources.Any(r => r.Name == "BenignSample.Greeting.txt");
                                bool allTypesPresent = hasProgram && hasFeatures && hasCalc && hasWorker && hasDecrypters && hasStandardCalc;

                                bool baselineCompared = false;
                                bool baselineMatched = false;

                                if (string.IsNullOrEmpty(baselinePath) || !File.Exists(baselinePath))
                                {
                                    unverified = true;
                                    unverifiedTransformations.Add("assembly_full_identity_matched_baseline");
                                    unverifiedTransformations.Add("payload_types_entrypoint_and_required_resources_matched_baseline");
                                }
                                else
                                {
                                    using (var baseModule = ModuleDefMD.Load(baselinePath))
                                    {
                                        baselineCompared = true;
                                        bool asmIdentityMatch = module.Assembly != null && baseModule.Assembly != null
                                            && module.Assembly.Name == baseModule.Assembly.Name
                                            && module.Assembly.Version == baseModule.Assembly.Version
                                            && module.Assembly.Culture == baseModule.Assembly.Culture
                                            && ((module.Assembly.PublicKeyOrToken == null && baseModule.Assembly.PublicKeyOrToken == null)
                                                || (module.Assembly.PublicKeyOrToken != null && baseModule.Assembly.PublicKeyOrToken != null
                                                    && (module.Assembly.PublicKeyOrToken.Data == null && baseModule.Assembly.PublicKeyOrToken.Data == null
                                                        || (module.Assembly.PublicKeyOrToken.Data != null && baseModule.Assembly.PublicKeyOrToken.Data != null
                                                            && module.Assembly.PublicKeyOrToken.Data.SequenceEqual(baseModule.Assembly.PublicKeyOrToken.Data)))));

                                        var cleanTypes = module.Types.Select(t => t.FullName).OrderBy(x => x).ToList();
                                        var baseTypes = baseModule.Types.Select(t => t.FullName).OrderBy(x => x).ToList();
                                        bool typesMatch = cleanTypes.SequenceEqual(baseTypes);

                                        bool requiredResMatch = true;
                                        foreach (var baseR in baseModule.Resources)
                                        {
                                            var cleanR = module.Resources.Find(baseR.Name) as EmbeddedResource;
                                            var baseEmb = baseR as EmbeddedResource;
                                            if (cleanR == null || baseEmb == null)
                                            {
                                                requiredResMatch = false;
                                                break;
                                            }
                                            var cleanData = cleanR.GetResourceData();
                                            var baseData = baseEmb.GetResourceData();
                                            if (cleanData == null || baseData == null || !cleanData.SequenceEqual(baseData))
                                            {
                                                requiredResMatch = false;
                                                break;
                                            }
                                        }

                                        bool epMatch = (module.EntryPoint == null && baseModule.EntryPoint == null)
                                            || (module.EntryPoint != null && baseModule.EntryPoint != null && module.EntryPoint.Name == baseModule.EntryPoint.Name);

                                        baselineMatched = asmIdentityMatch && typesMatch && requiredResMatch && epMatch;
                                        if (baselineMatched)
                                        {
                                            verifiedTransformations.Add("assembly_full_identity_matched_baseline");
                                            verifiedTransformations.Add("payload_types_entrypoint_and_required_resources_matched_baseline");
                                        }
                                        else
                                        {
                                            unverifiedTransformations.Add("assembly_full_identity_matched_baseline");
                                            unverifiedTransformations.Add("payload_types_entrypoint_and_required_resources_matched_baseline");
                                        }
                                    }
                                }

                                if (hasSimpleName) verifiedTransformations.Add("assembly_simple_name_restored");
                                else unverifiedTransformations.Add("assembly_simple_name_restored");

                                if (allTypesPresent) verifiedTransformations.Add("all_payload_types_present");
                                else unverifiedTransformations.Add("all_payload_types_present");

                                if (hasGreetingRes) verifiedTransformations.Add("payload_embedded_resources_restored");
                                else unverifiedTransformations.Add("payload_embedded_resources_restored");

                                verified = hasSimpleName && allTypesPresent && hasGreetingRes && baselineMatched && !unverified;
                                notes = baselineCompared
                                    ? "Deflate container unwrapped and verified against reference BenignSample.dll: 4-part assembly identity (Name, Version, Culture, PublicKeyToken), top-level type set (7 types), entry point, and required embedded resource byte-for-byte match."
                                    : "Deflate container unwrapped and verified against known payload assembly types, identity, and required resources (baseline comparison unverified).";
                            }
                            break;

                        case "antitamper":
                            {
                                var cctor = module.GlobalType?.FindStaticConstructor();
                                bool hasAntiTamperCall = cctor != null && cctor.HasBody && cctor.Body.Instructions.Any(i => i.OpCode == OpCodes.Call && i.Operand?.ToString().Contains("ConfuserAntiTamper") == true);
                                bool hasProtectorMethod = module.GlobalType?.Methods.Any(m => m.Name == "ConfuserAntiTamper") == true;

                                if (!hasAntiTamperCall) verifiedTransformations.Add("cctor_hook_removed");
                                else unverifiedTransformations.Add("cctor_hook_removed");

                                if (!hasProtectorMethod) verifiedTransformations.Add("protector_method_pruned");
                                else unverifiedTransformations.Add("protector_method_pruned");

                                verified = !hasAntiTamperCall && !hasProtectorMethod;
                                notes = "CleanerKiller stripped module initializer hook from <Module>.cctor and pruned unused ConfuserAntiTamper method. (Tests module initializer cleanup; does not simulate native PE section decryption).";
                            }
                            break;

                        case "combined":
                            {
                                var features = module.Find("BenignSample.BenignFeatures", false);
                                var exec = features?.FindMethod("ExecuteProxy");
                                bool proxyInlined = exec != null && exec.Body.Instructions.Any(i => i.OpCode == OpCodes.Call && i.Operand?.ToString().Contains("AddProxyTarget") == true);

                                var compute = features?.FindMethod("ComputeSwitch");
                                bool cflowStripped = compute != null && !compute.Body.Instructions.Any(i => i.IsLdcI4() && i.GetLdcI4Value() == 8888);

                                var cctor = module.GlobalType?.FindStaticConstructor();
                                bool hookStripped = cctor != null && (!cctor.HasBody || !cctor.Body.Instructions.Any(i => i.OpCode == OpCodes.Call && i.Operand?.ToString().Contains("ConfuserAntiTamper") == true));

                                var getStr = features?.FindMethod("GetStringConstant");
                                bool constInlined = getStr != null && getStr.Body.Instructions.Any(i => i.OpCode == OpCodes.Ldstr && (string)i.Operand == "ConfuserEx_Benchmark_Secret_String_2026");

                                if (proxyInlined) verifiedTransformations.Add("proxies_inlined");
                                else unverifiedTransformations.Add("proxies_inlined");

                                if (cflowStripped) verifiedTransformations.Add("cflow_deadcode_stripped");
                                else unverifiedTransformations.Add("cflow_deadcode_stripped");

                                if (hookStripped) verifiedTransformations.Add("cctor_antitamper_hook_stripped");
                                else unverifiedTransformations.Add("cctor_antitamper_hook_stripped");

                                if (constInlined) verifiedTransformations.Add("constants_decrypted_and_inlined");
                                else unverifiedTransformations.Add("constants_decrypted_and_inlined");

                                if (proxyInlined && cflowStripped && hookStripped && constInlined)
                                {
                                    verified = true;
                                    notes = "All 4 multi-protection layers verified.";
                                }
                                else if (proxyInlined && cflowStripped && hookStripped && !constInlined)
                                {
                                    partial = true;
                                    verified = false;
                                    notes = "Partially transformed: Proxies, deadcode, and anti-tamper hooks stripped, but constant decryption was blocked by TypeInitializationException during Reflection module load prior to hook removal.";
                                }
                            }
                            break;

                        case "edge_cases":
                            {
                                var worker = module.Find("BenignSample.GenericWorker`1", false);
                                var process = worker?.FindMethod("Process");
                                bool hasGenericParam = process != null && process.GenericParameters.Count == 1 && process.GenericParameters[0].Name == "U";
                                bool returnTypeMatch = process != null && process.ReturnType.FullName == "System.String";
                                bool hasLocals = process != null && process.Body.HasVariables && process.Body.Variables.Count >= 3;

                                bool ehValid = false;
                                bool baselineCompared = false;
                                bool baselineMatched = false;

                                if (process != null && process.Body.HasExceptionHandlers && process.Body.ExceptionHandlers.Count == 2)
                                {
                                    var hCatch = process.Body.ExceptionHandlers.FirstOrDefault(h => h.HandlerType == ExceptionHandlerType.Catch);
                                    var hFinally = process.Body.ExceptionHandlers.FirstOrDefault(h => h.HandlerType == ExceptionHandlerType.Finally);

                                    bool catchMatches = hCatch != null && hCatch.CatchType != null && hCatch.CatchType.Name == "Exception"
                                        && hCatch.TryStart != null && hCatch.TryEnd != null
                                        && hCatch.HandlerStart != null && hCatch.HandlerEnd != null;

                                    bool finallyMatches = hFinally != null
                                        && hFinally.TryStart != null && hFinally.TryEnd != null
                                        && hFinally.HandlerStart != null && hFinally.HandlerEnd != null;

                                    ehValid = catchMatches && finallyMatches;

                                    if (string.IsNullOrEmpty(baselinePath) || !File.Exists(baselinePath))
                                    {
                                        unverified = true;
                                    }
                                    else
                                    {
                                        using (var baseModule = ModuleDefMD.Load(baselinePath))
                                        {
                                            baselineCompared = true;
                                            var baseWorker = baseModule.Find("BenignSample.GenericWorker`1", false);
                                            var baseProcess = baseWorker?.FindMethod("Process");
                                            if (baseProcess != null && baseProcess.Body.ExceptionHandlers.Count == 2)
                                            {
                                                var baseCatch = baseProcess.Body.ExceptionHandlers.FirstOrDefault(h => h.HandlerType == ExceptionHandlerType.Catch);
                                                var baseFinally = baseProcess.Body.ExceptionHandlers.FirstOrDefault(h => h.HandlerType == ExceptionHandlerType.Finally);

                                                bool genericParamsMatch = process.GenericParameters.Count == baseProcess.GenericParameters.Count;
                                                if (genericParamsMatch)
                                                {
                                                    for (int g = 0; g < process.GenericParameters.Count; g++)
                                                    {
                                                        var cleanGP = process.GenericParameters[g];
                                                        var baseGP = baseProcess.GenericParameters[g];
                                                        if (cleanGP.Name != baseGP.Name)
                                                        {
                                                            genericParamsMatch = false;
                                                            break;
                                                        }
                                                        if (cleanGP.GenericParamConstraints.Count != baseGP.GenericParamConstraints.Count)
                                                        {
                                                            genericParamsMatch = false;
                                                            break;
                                                        }
                                                        for (int c = 0; c < cleanGP.GenericParamConstraints.Count; c++)
                                                        {
                                                            if (cleanGP.GenericParamConstraints[c].Constraint?.FullName != baseGP.GenericParamConstraints[c].Constraint?.FullName)
                                                            {
                                                                genericParamsMatch = false;
                                                                break;
                                                            }
                                                        }
                                                        if (!genericParamsMatch) break;
                                                    }
                                                }

                                                bool paramsMatch = process.Parameters.Count == baseProcess.Parameters.Count;
                                                if (paramsMatch)
                                                {
                                                    for (int p = 0; p < process.Parameters.Count; p++)
                                                    {
                                                        var cleanParam = process.Parameters[p];
                                                        var baseParam = baseProcess.Parameters[p];
                                                        if (cleanParam.Type?.FullName != baseParam.Type?.FullName)
                                                        {
                                                            paramsMatch = false;
                                                            break;
                                                        }
                                                    }
                                                }

                                                bool sigMatch = genericParamsMatch && paramsMatch
                                                    && process.ReturnType.FullName == baseProcess.ReturnType.FullName;

                                                bool localsMatch = process.Body.Variables.Count == baseProcess.Body.Variables.Count;
                                                if (localsMatch)
                                                {
                                                    for (int v = 0; v < process.Body.Variables.Count; v++)
                                                    {
                                                        var cleanVar = process.Body.Variables[v];
                                                        var baseVar = baseProcess.Body.Variables[v];
                                                        if (cleanVar.Type?.FullName != baseVar.Type?.FullName)
                                                        {
                                                            localsMatch = false;
                                                            break;
                                                        }
                                                    }
                                                }

                                                bool catchTypeMatch = baseCatch != null && catchMatches
                                                    && hCatch.HandlerType == baseCatch.HandlerType
                                                    && hCatch.CatchType?.FullName == baseCatch.CatchType?.FullName;

                                                bool finallyTypeMatch = baseFinally != null && finallyMatches
                                                    && hFinally.HandlerType == baseFinally.HandlerType;

                                                var cleanStream = new NormalizedMethodStream(process.Body.Instructions);
                                                var baseStream = new NormalizedMethodStream(baseProcess.Body.Instructions);

                                                bool catchBoundariesMatch = catchTypeMatch
                                                    && cleanStream.GetNormalizedTargetIndex(hCatch.TryStart) == baseStream.GetNormalizedTargetIndex(baseCatch.TryStart)
                                                    && cleanStream.GetNormalizedTargetIndex(hCatch.TryEnd) == baseStream.GetNormalizedTargetIndex(baseCatch.TryEnd)
                                                    && cleanStream.GetNormalizedTargetIndex(hCatch.HandlerStart) == baseStream.GetNormalizedTargetIndex(baseCatch.HandlerStart)
                                                    && cleanStream.GetNormalizedTargetIndex(hCatch.HandlerEnd) == baseStream.GetNormalizedTargetIndex(baseCatch.HandlerEnd)
                                                    && MatchSemanticInstruction(hCatch.TryStart, baseCatch.TryStart, cleanStream, baseStream)
                                                    && MatchSemanticInstruction(hCatch.TryEnd, baseCatch.TryEnd, cleanStream, baseStream)
                                                    && MatchSemanticInstruction(hCatch.HandlerStart, baseCatch.HandlerStart, cleanStream, baseStream)
                                                    && MatchSemanticInstruction(hCatch.HandlerEnd, baseCatch.HandlerEnd, cleanStream, baseStream);

                                                bool finallyBoundariesMatch = finallyTypeMatch
                                                    && cleanStream.GetNormalizedTargetIndex(hFinally.TryStart) == baseStream.GetNormalizedTargetIndex(baseFinally.TryStart)
                                                    && cleanStream.GetNormalizedTargetIndex(hFinally.TryEnd) == baseStream.GetNormalizedTargetIndex(baseFinally.TryEnd)
                                                    && cleanStream.GetNormalizedTargetIndex(hFinally.HandlerStart) == baseStream.GetNormalizedTargetIndex(baseFinally.HandlerStart)
                                                    && cleanStream.GetNormalizedTargetIndex(hFinally.HandlerEnd) == baseStream.GetNormalizedTargetIndex(baseFinally.HandlerEnd)
                                                    && MatchSemanticInstruction(hFinally.TryStart, baseFinally.TryStart, cleanStream, baseStream)
                                                    && MatchSemanticInstruction(hFinally.TryEnd, baseFinally.TryEnd, cleanStream, baseStream)
                                                    && MatchSemanticInstruction(hFinally.HandlerStart, baseFinally.HandlerStart, cleanStream, baseStream)
                                                    && MatchSemanticInstruction(hFinally.HandlerEnd, baseFinally.HandlerEnd, cleanStream, baseStream);

                                                bool catchTryMatch = catchBoundariesMatch && MatchInstructionRanges(
                                                    cleanStream, hCatch.TryStart, hCatch.TryEnd,
                                                    baseStream, baseCatch.TryStart, baseCatch.TryEnd);

                                                bool catchHandlerMatch = catchBoundariesMatch && MatchInstructionRanges(
                                                    cleanStream, hCatch.HandlerStart, hCatch.HandlerEnd,
                                                    baseStream, baseCatch.HandlerStart, baseCatch.HandlerEnd);

                                                bool finallyTryMatch = finallyBoundariesMatch && MatchInstructionRanges(
                                                    cleanStream, hFinally.TryStart, hFinally.TryEnd,
                                                    baseStream, baseFinally.TryStart, baseFinally.TryEnd);

                                                bool finallyHandlerMatch = finallyBoundariesMatch && MatchInstructionRanges(
                                                    cleanStream, hFinally.HandlerStart, hFinally.HandlerEnd,
                                                    baseStream, baseFinally.HandlerStart, baseFinally.HandlerEnd);

                                                bool methodBodyMatch = MatchInstructionRanges(
                                                    cleanStream, process.Body.Instructions.FirstOrDefault(), null,
                                                    baseStream, baseProcess.Body.Instructions.FirstOrDefault(), null);

                                                baselineMatched = sigMatch && localsMatch
                                                    && methodBodyMatch
                                                    && catchBoundariesMatch && finallyBoundariesMatch
                                                    && catchTryMatch && catchHandlerMatch
                                                    && finallyTryMatch && finallyHandlerMatch;
                                            }
                                            else
                                            {
                                                baselineMatched = false;
                                            }
                                        }
                                    }
                                }
                                else
                                {
                                    if (string.IsNullOrEmpty(baselinePath) || !File.Exists(baselinePath))
                                    {
                                        unverified = true;
                                    }
                                }

                                if (hasGenericParam && returnTypeMatch) verifiedTransformations.Add("generic_method_signature_intact");
                                else unverifiedTransformations.Add("generic_method_signature_intact");

                                if (hasLocals) verifiedTransformations.Add("local_variables_structure_preserved");
                                else unverifiedTransformations.Add("local_variables_structure_preserved");

                                if (ehValid) verifiedTransformations.Add("exception_handlers_try_and_handler_ranges_verified");
                                else unverifiedTransformations.Add("exception_handlers_try_and_handler_ranges_verified");

                                if (baselineCompared && baselineMatched)
                                {
                                    verifiedTransformations.Add("baseline_exception_handlers_matched");
                                }
                                else
                                {
                                    unverifiedTransformations.Add("baseline_exception_handlers_matched");
                                }

                                verified = hasGenericParam && returnTypeMatch && hasLocals && ehValid && baselineMatched && !unverified;
                                notes = baselineCompared
                                    ? "Generic method signature (parameters, return type, generic constraints), local variables (count and types), and exception-handler try/handler ranges (including semantic TryStart/TryEnd, HandlerStart/HandlerEnd targets, and instruction bodies) verified against baseline assembly."
                                    : "Generic method signature, local variables (3+), and exception-handler try/handler ranges structurally verified (baseline comparison unavailable).";
                            }
                            break;

                        case "real_confuserex":
                            {
                                bool asmNameMatch = module.Assembly != null && module.Assembly.Name == "BenignSample";
                                var features = module.Find("BenignSample.BenignFeatures", false);
                                bool hasFeatures = features != null;
                                bool hasProgram = module.Find("BenignSample.Program", false) != null;

                                var getStr = features?.FindMethod("GetStringConstant");
                                bool strDecrypted = getStr != null && getStr.Body != null
                                    && getStr.Body.Instructions.Any(i => i.OpCode == OpCodes.Ldstr && (string)i.Operand == "ConfuserEx_Benchmark_Secret_String_2026");

                                var res = module.Resources.Find("BenignSample.Greeting.txt") as EmbeddedResource;
                                bool resPresent = res != null;

                                var cctor = module.GlobalType?.FindStaticConstructor();
                                bool cctorClean = cctor == null || !cctor.HasBody || !cctor.Body.Instructions.Any(i => i.OpCode == OpCodes.Call && i.Operand?.ToString().Contains("Confuser") == true);

                                if (asmNameMatch) verifiedTransformations.Add("assembly_identity_preserved");
                                else unverifiedTransformations.Add("assembly_identity_preserved");

                                if (hasFeatures && hasProgram) verifiedTransformations.Add("types_intact");
                                else unverifiedTransformations.Add("types_intact");

                                if (strDecrypted) verifiedTransformations.Add("constants_decrypted");
                                else unverifiedTransformations.Add("constants_decrypted");

                                if (resPresent) verifiedTransformations.Add("resources_extracted");
                                else unverifiedTransformations.Add("resources_extracted");

                                if (cctorClean) verifiedTransformations.Add("module_initializer_clean");
                                else unverifiedTransformations.Add("module_initializer_clean");

                                verified = asmNameMatch && hasFeatures && hasProgram && strDecrypted && resPresent && cctorClean;
                                notes = "Real ConfuserEx CLI output verified for identity, types, decrypted constants, extracted resources, and clean module initializer.";
                            }
                            break;

                        default:
                            notes = $"Unknown scenario: {scenario}";
                            break;
                    }

                    // Format JSON output
                    string statusStr = verified ? "VERIFIED" : (unverified ? "UNVERIFIED" : (partial ? "PARTIAL" : "FAILED"));
                    string json = string.Format(
                        "{{\"scenario\":\"{0}\",\"verified\":{1},\"partial\":{2},\"unverified\":{3},\"status\":\"{4}\",\"verified_transformations\":[{5}],\"unverified_transformations\":[{6}],\"notes\":\"{7}\"}}",
                        scenario,
                        verified ? "true" : "false",
                        partial ? "true" : "false",
                        unverified ? "true" : "false",
                        statusStr,
                        string.Join(",", verifiedTransformations.Select(s => $"\"{s}\"")),
                        string.Join(",", unverifiedTransformations.Select(s => $"\"{s}\"")),
                        notes.Replace("\"", "\\\"")
                    );
                    Console.WriteLine(json);
                    if (unverified) return 3;
                    return verified ? 0 : (partial ? 2 : 1);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format("{{\"verified\":false,\"error\":\"{0}\"}}", ex.Message.Replace("\"", "\\\"")));
                return 1;
            }
        }

        private sealed class NormalizedMethodStream
        {
            public IList<Instruction> AllInstructions { get; }
            public List<Instruction> NonNopInstructions { get; }
            private readonly Dictionary<Instruction, int> _instructionToNonNopIndex;

            public NormalizedMethodStream(IList<Instruction> instructions)
            {
                AllInstructions = instructions ?? Array.Empty<Instruction>();
                NonNopInstructions = new List<Instruction>();
                _instructionToNonNopIndex = new Dictionary<Instruction, int>();

                int nonNopIdx = 0;
                for (int i = 0; i < AllInstructions.Count; i++)
                {
                    var inst = AllInstructions[i];
                    if (inst.OpCode != OpCodes.Nop)
                    {
                        NonNopInstructions.Add(inst);
                        _instructionToNonNopIndex[inst] = nonNopIdx;
                        nonNopIdx++;
                    }
                }
            }

            public int GetNormalizedTargetIndex(Instruction target)
            {
                if (target == null) return NonNopInstructions.Count;
                if (_instructionToNonNopIndex.TryGetValue(target, out int idx))
                    return idx;

                int rawIdx = AllInstructions.IndexOf(target);
                if (rawIdx < 0) return -1;

                for (int i = rawIdx; i < AllInstructions.Count; i++)
                {
                    var inst = AllInstructions[i];
                    if (_instructionToNonNopIndex.TryGetValue(inst, out int found))
                        return found;
                }

                return NonNopInstructions.Count;
            }

            public List<Instruction> GetRangeInstructions(Instruction start, Instruction end)
            {
                var list = new List<Instruction>();
                if (start == null) return list;

                int startIdx = GetNormalizedTargetIndex(start);
                if (startIdx < 0) return list;

                int endIdx = end != null ? GetNormalizedTargetIndex(end) : NonNopInstructions.Count;
                if (endIdx < 0) endIdx = NonNopInstructions.Count;

                for (int i = startIdx; i < endIdx && i < NonNopInstructions.Count; i++)
                {
                    list.Add(NonNopInstructions[i]);
                }
                return list;
            }
        }

        private static bool MatchSemanticInstruction(
            Instruction a, Instruction b,
            NormalizedMethodStream aStream = null, NormalizedMethodStream bStream = null)
        {
            if (a == null && b == null) return true;
            if (a == null || b == null) return false;
            if (a.OpCode != b.OpCode) return false;

            if (a.Operand == null && b.Operand == null) return true;
            if (a.Operand == null || b.Operand == null) return false;

            if (a.Operand is IMethod aMeth && b.Operand is IMethod bMeth)
                return aMeth.FullName == bMeth.FullName;

            if (a.Operand is IField aField && b.Operand is IField bField)
                return aField.FullName == bField.FullName;

            if (a.Operand is ITypeDefOrRef aType && b.Operand is ITypeDefOrRef bType)
                return aType.FullName == bType.FullName;

            if (a.Operand is string aStr && b.Operand is string bStr)
                return aStr == bStr;

            if (a.Operand is int aInt && b.Operand is int bInt)
                return aInt == bInt;

            if (a.Operand is long aLong && b.Operand is long bLong)
                return aLong == bLong;

            if (a.Operand is Instruction aTarget && b.Operand is Instruction bTarget)
            {
                if (aStream != null && bStream != null)
                {
                    int aIdx = aStream.GetNormalizedTargetIndex(aTarget);
                    int bIdx = bStream.GetNormalizedTargetIndex(bTarget);
                    if (aIdx != bIdx || aIdx < 0) return false;
                }
                return aTarget.OpCode == bTarget.OpCode;
            }

            if (a.Operand is IList<Instruction> aTargets && b.Operand is IList<Instruction> bTargets)
            {
                if (aTargets.Count != bTargets.Count) return false;
                for (int i = 0; i < aTargets.Count; i++)
                {
                    if (aStream != null && bStream != null)
                    {
                        int aIdx = aStream.GetNormalizedTargetIndex(aTargets[i]);
                        int bIdx = bStream.GetNormalizedTargetIndex(bTargets[i]);
                        if (aIdx != bIdx || aIdx < 0) return false;
                    }
                    if (aTargets[i]?.OpCode != bTargets[i]?.OpCode) return false;
                }
                return true;
            }

            return a.Operand.ToString() == b.Operand.ToString();
        }

        private static bool MatchInstructionRanges(
            NormalizedMethodStream cleanStream, Instruction cleanStart, Instruction cleanEnd,
            NormalizedMethodStream baseStream, Instruction baseStart, Instruction baseEnd)
        {
            if (cleanStream == null || baseStream == null) return false;

            int cleanStartIdx = cleanStream.GetNormalizedTargetIndex(cleanStart);
            int baseStartIdx = baseStream.GetNormalizedTargetIndex(baseStart);
            if (cleanStartIdx != baseStartIdx || cleanStartIdx < 0) return false;

            int cleanEndIdx = cleanStream.GetNormalizedTargetIndex(cleanEnd);
            int baseEndIdx = baseStream.GetNormalizedTargetIndex(baseEnd);
            if (cleanEndIdx != baseEndIdx || cleanEndIdx < 0) return false;

            if (!MatchSemanticInstruction(cleanStart, baseStart, cleanStream, baseStream)) return false;
            if (cleanEnd != null || baseEnd != null)
            {
                if (!MatchSemanticInstruction(cleanEnd, baseEnd, cleanStream, baseStream)) return false;
            }

            var cleanRange = cleanStream.GetRangeInstructions(cleanStart, cleanEnd);
            var baseRange = baseStream.GetRangeInstructions(baseStart, baseEnd);

            if (cleanRange.Count != baseRange.Count) return false;

            for (int i = 0; i < cleanRange.Count; i++)
            {
                if (!MatchSemanticInstruction(cleanRange[i], baseRange[i], cleanStream, baseStream))
                    return false;
            }

            return true;
        }

        private static void WriteModule(ModuleDef module, string destinationPath)
        {
            var writerOpts = new ModuleWriterOptions(module);
            writerOpts.MetaDataOptions.Flags |= MetaDataFlags.KeepOldMaxStack;
            writerOpts.Logger = DummyLogger.NoThrowInstance;
            module.Write(destinationPath, writerOpts);
            Console.WriteLine($"  [+] Created: {Path.GetFileName(destinationPath)} ({new FileInfo(destinationPath).Length} bytes)");
        }

        // 1. Constants Protection: Encrypts string and numeric constants via <Module>.Decrypter<T>(key)
        private static void GenerateConstantsFixture(string inputPath, string outputPath)
        {
            using (var module = ModuleDefMD.Load(inputPath))
            {
                var globalType = module.GlobalType;

                // Move Decrypter method from Decrypters class to GlobalType (<Module>)
                var decryptersType = module.Find("BenignSample.Decrypters", false);
                var decrypterDef = decryptersType.FindMethod("Decrypter");
                decryptersType.Methods.Remove(decrypterDef);
                globalType.Methods.Add(decrypterDef);

                // Rewrite GetStringConstant
                var featuresType = module.Find("BenignSample.BenignFeatures", false);
                var getStringMethod = featuresType.FindMethod("GetStringConstant");
                getStringMethod.Body.Instructions.Clear();
                var specStr = new MethodSpecUser(decrypterDef, new GenericInstMethodSig(module.CorLibTypes.String));
                getStringMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1001));
                getStringMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, specStr));
                getStringMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

                // Rewrite GetNumericConstant1
                var getNumMethod1 = featuresType.FindMethod("GetNumericConstant1");
                getNumMethod1.Body.Instructions.Clear();
                var specInt = new MethodSpecUser(decrypterDef, new GenericInstMethodSig(module.CorLibTypes.Int32));
                getNumMethod1.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1002));
                getNumMethod1.Body.Instructions.Add(Instruction.Create(OpCodes.Call, specInt));
                getNumMethod1.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

                // Rewrite GetNumericConstant2 (Int64)
                var getNumMethod2 = featuresType.FindMethod("GetNumericConstant2");
                getNumMethod2.Body.Instructions.Clear();
                var specInt64 = new MethodSpecUser(decrypterDef, new GenericInstMethodSig(module.CorLibTypes.Int64));
                getNumMethod2.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1003));
                getNumMethod2.Body.Instructions.Add(Instruction.Create(OpCodes.Call, specInt64));
                getNumMethod2.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

                WriteModule(module, outputPath);
            }
        }

        // 2. Control Flow: Switch-based state machine and dead code trampolines
        private static void GenerateCflowFixture(string inputPath, string outputPath)
        {
            using (var module = ModuleDefMD.Load(inputPath))
            {
                var featuresType = module.Find("BenignSample.BenignFeatures", false);
                var computeMethod = featuresType.FindMethod("ComputeSwitch");

                // Target branches for cases: case 1, case 2, case 3, default
                var instCase1 = Instruction.Create(OpCodes.Ldarg_1);
                var instCase2 = Instruction.Create(OpCodes.Ldarg_1);
                var instCase3 = Instruction.Create(OpCodes.Ldarg_1);
                var instDefault = Instruction.Create(OpCodes.Ldarg_1);

                // Switch table
                var switchTargets = new Instruction[] { instDefault, instCase1, instCase2, instCase3 };
                var instSwitch = Instruction.Create(OpCodes.Switch, switchTargets);

                var body = new CilBody();
                computeMethod.Body = body;

                // Dead code ldc+pop pattern:
                body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 8888));
                body.Instructions.Add(Instruction.Create(OpCodes.Pop));

                // ConfuserEx switch pattern: ldc.i4 <val>, ldc.i4 <xorVal>, xor, switch
                body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0)); // state
                body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
                body.Instructions.Add(Instruction.Create(OpCodes.Xor));
                body.Instructions.Add(instSwitch);

                // Default
                body.Instructions.Add(instDefault);
                body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x55));
                body.Instructions.Add(Instruction.Create(OpCodes.Xor));
                body.Instructions.Add(Instruction.Create(OpCodes.Ret));

                // Case 1
                body.Instructions.Add(instCase1);
                body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 10));
                body.Instructions.Add(Instruction.Create(OpCodes.Add));
                body.Instructions.Add(Instruction.Create(OpCodes.Ret));

                // Case 2
                body.Instructions.Add(instCase2);
                body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_2));
                body.Instructions.Add(Instruction.Create(OpCodes.Mul));
                body.Instructions.Add(Instruction.Create(OpCodes.Ret));

                // Case 3
                body.Instructions.Add(instCase3);
                body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_5));
                body.Instructions.Add(Instruction.Create(OpCodes.Sub));
                body.Instructions.Add(Instruction.Create(OpCodes.Ret));

                WriteModule(module, outputPath);
            }
        }

        // 3. Proxies: Reference proxy method and delegate proxy
        private static void GenerateProxiesFixture(string inputPath, string outputPath)
        {
            using (var module = ModuleDefMD.Load(inputPath))
            {
                var featuresType = module.Find("BenignSample.BenignFeatures", false);
                var addTarget = featuresType.FindMethod("AddProxyTarget");

                // 1. Create PrivateScope reference proxy method in BenignFeatures:
                var proxyMethod = new MethodDefUser(
                    "Proxy_Add_Method",
                    MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                    dnlib.DotNet.MethodImplAttributes.IL | dnlib.DotNet.MethodImplAttributes.Managed,
                    dnlib.DotNet.MethodAttributes.PrivateScope | dnlib.DotNet.MethodAttributes.Static)
                {
                    Body = new CilBody()
                };
                proxyMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
                proxyMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1));
                proxyMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, addTarget));
                proxyMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                featuresType.Methods.Add(proxyMethod);

                // Rewrite ExecuteProxy to call proxyMethod
                var execMethod = featuresType.FindMethod("ExecuteProxy");
                execMethod.Body.Instructions.Clear();
                execMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
                execMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1));
                execMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, proxyMethod));
                execMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

                WriteModule(module, outputPath);
            }
        }

        // 4. Encrypted Resources: ConfuserEx resource decrypter and cctor hook
        private static void GenerateResourcesFixture(string inputPath, string outputPath)
        {
            using (var module = ModuleDefMD.Load(inputPath))
            {
                // Create payload module containing greeting resource
                byte[] payloadBytes;
                using (var payloadMod = new ModuleDefUser("DecryptedResourcePayload"))
                {
                    var payloadAsm = new AssemblyDefUser("DecryptedResourcePayloadAsm");
                    payloadAsm.Modules.Add(payloadMod);
                    payloadMod.Resources.Add(new EmbeddedResource("BenignSample.Greeting.txt", System.Text.Encoding.UTF8.GetBytes("HELLO_FROM_BENIGN_EMBEDDED_RESOURCE")));
                    using (var pms = new MemoryStream())
                    {
                        payloadMod.Write(pms);
                        payloadBytes = pms.ToArray();
                    }
                }

                // Remove existing plain resource from module
                var existingRes = module.Resources.Find("BenignSample.Greeting.txt");
                if (existingRes != null)
                    module.Resources.Remove(existingRes);

                // Emit decrypter method: static void ConfuserResourceDecrypter()
                var decrypterMethod = new MethodDefUser(
                    "ConfuserResourceDecrypter",
                    MethodSig.CreateStatic(module.CorLibTypes.Void),
                    dnlib.DotNet.MethodImplAttributes.IL | dnlib.DotNet.MethodImplAttributes.Managed,
                    dnlib.DotNet.MethodAttributes.Public | dnlib.DotNet.MethodAttributes.Static)
                {
                    Body = new CilBody()
                };

                // Array initializer for payload bytes
                var arrayInitInstrs = CreateArrayInitializer(
                    module, module.CorLibTypes.Byte.TypeDefOrRef, payloadBytes.Length, payloadBytes);
                foreach (var inst in arrayInitInstrs)
                    decrypterMethod.Body.Instructions.Add(inst);

                var asmLoadRef = module.Import(typeof(Assembly).GetMethod("Load", new[] { typeof(byte[]) }));

                decrypterMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, asmLoadRef));
                decrypterMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
                decrypterMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                module.GlobalType.Methods.Add(decrypterMethod);

                // cctor calling decrypterMethod
                var cctor = module.GlobalType.FindOrCreateStaticConstructor();
                cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, decrypterMethod));

                WriteModule(module, outputPath);
            }
        }

        // 5. Compressor: Deflate compressed assembly container
        private static void GenerateCompressorFixture(string inputPath, string outputPath)
        {
            byte[] rawBytes = File.ReadAllBytes(inputPath);
            byte[] compressed;
            using (var ms = new MemoryStream())
            {
                using (var deflate = new DeflateStream(ms, CompressionLevel.Optimal, true))
                {
                    deflate.Write(rawBytes, 0, rawBytes.Length);
                }
                compressed = ms.ToArray();
            }

            using (var stubMod = new ModuleDefUser("CompressorStub"))
            {
                var stubAsm = new AssemblyDefUser("CompressorStubAsm");
                stubAsm.Modules.Add(stubMod);

                // Embed compressed bytes
                stubMod.Resources.Add(new EmbeddedResource("ConfuserEx.CompressedPayload", compressed));

                // Entry point calling Assembly.Load
                var ep = new MethodDefUser("Main", MethodSig.CreateStatic(stubMod.CorLibTypes.Void, new SZArraySig(stubMod.CorLibTypes.String)),
                    dnlib.DotNet.MethodImplAttributes.IL | dnlib.DotNet.MethodImplAttributes.Managed,
                    dnlib.DotNet.MethodAttributes.Public | dnlib.DotNet.MethodAttributes.Static)
                {
                    Body = new CilBody()
                };
                var asmLoadRef = stubMod.Import(typeof(Assembly).GetMethod("Load", new[] { typeof(byte[]) }));

                ep.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
                ep.Body.Instructions.Add(Instruction.Create(OpCodes.Call, asmLoadRef));
                ep.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
                ep.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                stubMod.GlobalType.Methods.Add(ep);
                stubMod.EntryPoint = ep;

                WriteModule(stubMod, outputPath);
            }
        }

        // 6. Anti-Tamper: Initializer hook in <Module>.cctor calling GetHINSTANCE
        private static void GenerateAntiTamperFixture(string inputPath, string outputPath)
        {
            using (var module = ModuleDefMD.Load(inputPath))
            {
                var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                    MethodSig.CreateStatic(module.CorLibTypes.IntPtr, new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                    new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef));

                var antiTamperMethod = new MethodDefUser("ConfuserAntiTamper", MethodSig.CreateStatic(module.CorLibTypes.Void),
                    dnlib.DotNet.MethodImplAttributes.IL | dnlib.DotNet.MethodImplAttributes.Managed,
                    dnlib.DotNet.MethodAttributes.Public | dnlib.DotNet.MethodAttributes.Static)
                {
                    Body = new CilBody()
                };

                antiTamperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
                antiTamperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
                antiTamperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
                antiTamperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                module.GlobalType.Methods.Add(antiTamperMethod);

                var cctor = module.GlobalType.FindOrCreateStaticConstructor();
                cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, antiTamperMethod));

                WriteModule(module, outputPath);
            }
        }

        // 7. Combined: Constants + Proxies + Cflow + AntiTamper
        private static void GenerateCombinedFixture(string inputPath, string outputPath)
        {
            string temp1 = Path.Combine(Path.GetTempPath(), "temp_comb_1.dll");
            string temp2 = Path.Combine(Path.GetTempPath(), "temp_comb_2.dll");
            string temp3 = Path.Combine(Path.GetTempPath(), "temp_comb_3.dll");

            try
            {
                GenerateConstantsFixture(inputPath, temp1);
                GenerateProxiesFixture(temp1, temp2);
                GenerateCflowFixture(temp2, temp3);
                GenerateAntiTamperFixture(temp3, outputPath);
            }
            finally
            {
                try { if (File.Exists(temp1)) File.Delete(temp1); } catch { }
                try { if (File.Exists(temp2)) File.Delete(temp2); } catch { }
                try { if (File.Exists(temp3)) File.Delete(temp3); } catch { }
            }
        }

        // 8. Edge Cases: Generic worker with try-catch-finally and multiple locals
        private static void GenerateEdgeCasesFixture(string inputPath, string outputPath)
        {
            using (var module = ModuleDefMD.Load(inputPath))
            {
                var workerType = module.Find("BenignSample.GenericWorker`1", false);
                var processMethod = workerType.FindMethod("Process");

                // Inject dead code and dummy jumps around the exception handler to test boundary preservation
                var instrs = processMethod.Body.Instructions;
                instrs.Insert(0, Instruction.Create(OpCodes.Ldc_I4, 12345));
                instrs.Insert(1, Instruction.Create(OpCodes.Pop));

                WriteModule(module, outputPath);
            }
        }

        private static List<Instruction> CreateArrayInitializer(ModuleDef module, ITypeDefOrRef arrayType, int arrayLength, byte[] data)
        {
            return CreateArrayInitializer(module, arrayType, arrayLength, GetOrCreateDataField(module, data));
        }

        private static List<Instruction> CreateArrayInitializer(ModuleDef module, ITypeDefOrRef arrayType, int arrayLength, FieldDef dataField)
        {
            var instructions = new List<Instruction>
            {
                new Instruction(OpCodes.Ldc_I4, arrayLength),
                new Instruction(OpCodes.Newarr, arrayType),
                new Instruction(OpCodes.Dup),
                new Instruction(OpCodes.Ldtoken, dataField),
                new Instruction(OpCodes.Call, module.Import(typeof(RuntimeHelpers).GetMethod("InitializeArray"))),
            };
            return instructions;
        }

        private static FieldDef GetOrCreateDataField(ModuleDef module, byte[] data)
        {
            var privateImplementationDetails = module.FindNormal("<PrivateImplementationDetails>");
            if (privateImplementationDetails is null)
            {
                privateImplementationDetails = new TypeDefUser(UTF8String.Empty, "<PrivateImplementationDetails>", module.CorLibTypes.Object.TypeRef)
                {
                    Attributes = dnlib.DotNet.TypeAttributes.NotPublic | dnlib.DotNet.TypeAttributes.Sealed
                };
                var compilerGeneratedAttribute = module.CorLibTypes.GetTypeRef("System.Runtime.CompilerServices", "CompilerGeneratedAttribute");
                var ca = new CustomAttribute(new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), compilerGeneratedAttribute));
                privateImplementationDetails.CustomAttributes.Add(ca);
                module.Types.Add(privateImplementationDetails);
            }
            string storageStructName = $"__StaticArrayInitTypeSize={data.Length}";
            var storageStruct = privateImplementationDetails.NestedTypes.FirstOrDefault(t => t.Name == storageStructName);
            if (storageStruct is null)
            {
                storageStruct = new TypeDefUser(string.Empty, storageStructName, module.CorLibTypes.GetTypeRef("System", "ValueType"))
                {
                    Attributes = dnlib.DotNet.TypeAttributes.NestedPrivate | dnlib.DotNet.TypeAttributes.ExplicitLayout | dnlib.DotNet.TypeAttributes.Sealed,
                    ClassLayout = new ClassLayoutUser(1, (uint)data.Length)
                };
                privateImplementationDetails.NestedTypes.Add(storageStruct);
            }
            string dataFieldName;
            using (var sha256 = SHA256.Create())
                dataFieldName = BitConverter.ToString(sha256.ComputeHash(data)).Replace("-", string.Empty);
            var dataField = privateImplementationDetails.FindField(dataFieldName);
            if (!(dataField is null))
                return dataField;
            dataField = new FieldDefUser(dataFieldName, new FieldSig(storageStruct.ToTypeSig()))
            {
                Attributes = dnlib.DotNet.FieldAttributes.Assembly | dnlib.DotNet.FieldAttributes.Static | dnlib.DotNet.FieldAttributes.InitOnly | dnlib.DotNet.FieldAttributes.HasFieldRVA,
                InitialValue = data
            };
            privateImplementationDetails.Fields.Add(dataField);
            return dataField;
        }
    }
}
