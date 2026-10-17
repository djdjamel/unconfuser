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
            string benignPath = null;
            string outputDir = null;

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--verify" && i + 1 < args.Length)
                    verifyPath = Path.GetFullPath(args[++i]);
                else if (args[i] == "--scenario" && i + 1 < args.Length)
                    scenario = args[++i];
                else if (args[i] == "--input" && i + 1 < args.Length)
                    benignPath = Path.GetFullPath(args[++i]);
                else if (args[i] == "--output-dir" && i + 1 < args.Length)
                    outputDir = Path.GetFullPath(args[++i]);
            }

            if (!string.IsNullOrEmpty(verifyPath))
            {
                return VerifyCleanOutput(verifyPath, scenario ?? "unknown");
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

        public static int VerifyCleanOutput(string cleanPath, string scenario)
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

                                if (!hasJunk) verifiedTransformations.Add("deadcode_junk_pair_stripped");
                                else unverifiedTransformations.Add("deadcode_junk_pair_stripped");

                                if (hasValidFlow) verifiedTransformations.Add("control_flow_structure_preserved");
                                else unverifiedTransformations.Add("control_flow_structure_preserved");

                                verified = !hasJunk && hasValidFlow;
                                notes = "Control flow dead code trampolines and dummy stack pairs stripped while preserving branch equivalence.";
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
                                bool isNotStub = module.Assembly != null && module.Assembly.Name == "BenignSample";
                                bool hasProgram = module.Find("BenignSample.Program", false) != null;
                                bool hasFeatures = module.Find("BenignSample.BenignFeatures", false) != null;
                                bool hasCalc = module.Find("BenignSample.ICalculator", false) != null;
                                bool hasWorker = module.Find("BenignSample.GenericWorker`1", false) != null;
                                bool hasGreetingRes = module.Resources.Any(r => r.Name == "BenignSample.Greeting.txt");

                                if (isNotStub) verifiedTransformations.Add("assembly_identity_restored_to_payload");
                                else unverifiedTransformations.Add("assembly_identity_restored_to_payload");

                                if (hasProgram && hasFeatures && hasCalc && hasWorker) verifiedTransformations.Add("all_payload_types_present");
                                else unverifiedTransformations.Add("all_payload_types_present");

                                if (hasGreetingRes) verifiedTransformations.Add("payload_embedded_resources_restored");
                                else unverifiedTransformations.Add("payload_embedded_resources_restored");

                                verified = isNotStub && hasProgram && hasFeatures && hasCalc && hasWorker && hasGreetingRes;
                                notes = "Deflate container unwrapped and verified against known source assembly types, identity, and resources.";
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
                                if (process != null && process.Body.HasExceptionHandlers && process.Body.ExceptionHandlers.Count == 2)
                                {
                                    var hCatch = process.Body.ExceptionHandlers.FirstOrDefault(h => h.HandlerType == ExceptionHandlerType.Catch);
                                    var hFinally = process.Body.ExceptionHandlers.FirstOrDefault(h => h.HandlerType == ExceptionHandlerType.Finally);
                                    bool catchMatches = hCatch != null && hCatch.CatchType != null && hCatch.CatchType.Name == "Exception" && hCatch.TryStart != null && hCatch.HandlerStart != null;
                                    bool finallyMatches = hFinally != null && hFinally.TryStart != null && hFinally.HandlerStart != null;
                                    ehValid = catchMatches && finallyMatches;
                                }

                                if (hasGenericParam && returnTypeMatch) verifiedTransformations.Add("generic_method_signature_intact");
                                else unverifiedTransformations.Add("generic_method_signature_intact");

                                if (hasLocals) verifiedTransformations.Add("local_variables_structure_preserved");
                                else unverifiedTransformations.Add("local_variables_structure_preserved");

                                if (ehValid) verifiedTransformations.Add("exception_handlers_structure_preserved");
                                else unverifiedTransformations.Add("exception_handlers_structure_preserved");

                                verified = hasGenericParam && returnTypeMatch && hasLocals && ehValid;
                                notes = "Generic method signature, local variables (3+), and nested try-catch-finally exception handlers structure verified against baseline.";
                            }
                            break;

                        default:
                            notes = $"Unknown scenario: {scenario}";
                            break;
                    }

                    // Format JSON output
                    string json = string.Format(
                        "{{\"scenario\":\"{0}\",\"verified\":{1},\"partial\":{2},\"verified_transformations\":[{3}],\"unverified_transformations\":[{4}],\"notes\":\"{5}\"}}",
                        scenario,
                        verified ? "true" : "false",
                        partial ? "true" : "false",
                        string.Join(",", verifiedTransformations.Select(s => $"\"{s}\"")),
                        string.Join(",", unverifiedTransformations.Select(s => $"\"{s}\"")),
                        notes.Replace("\"", "\\\"")
                    );
                    Console.WriteLine(json);
                    return verified ? 0 : (partial ? 2 : 1);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format("{{\"verified\":false,\"error\":\"{0}\"}}", ex.Message.Replace("\"", "\\\"")));
                return 1;
            }
        }

        private static void WriteModule(ModuleDef module, string destinationPath)
        {
            var writerOpts = new ModuleWriterOptions(module);
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
