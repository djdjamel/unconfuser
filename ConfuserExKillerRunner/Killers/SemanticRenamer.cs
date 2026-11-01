using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Tool;

namespace ConfuserExKillerRunner.Killers
{
    public enum RenameConfidence
    {
        StrongReference,
        HighConfidence,
        Heuristic,
        Ambiguous
    }

    public sealed class RenameDecision
    {
        public string OriginalName { get; set; }
        public string NewName { get; set; }
        public string SymbolType { get; set; } // "Type", "Field", "Method", "Property", "Resource"
        public RenameConfidence Confidence { get; set; }
        public string Justification { get; set; }
        public bool Applied { get; set; }
        public string Evidence { get; set; }

        public override string ToString() =>
            $"[{Confidence}] {SymbolType} '{OriginalName}' -> '{NewName}' (Applied: {Applied}): {Justification}";
    }

    public sealed class SemanticRenamerResult
    {
        public int TypesRenamed { get; set; }
        public int FieldsRenamed { get; set; }
        public int MethodsRenamed { get; set; }
        public int PropertiesRenamed { get; set; }
        public int ResourcesRenamed { get; set; }
        public int UnprintableNormalized { get; set; }
        public string Message { get; set; }
        public List<RenameDecision> Decisions { get; set; } = new List<RenameDecision>();

        public string GenerateMappingReport()
        {
            var sb = new StringBuilder();
            sb.AppendLine("=================================================================================");
            sb.AppendLine("                           SEMANTIC RENAMING MAPPING REPORT                      ");
            sb.AppendLine("=================================================================================");
            sb.AppendLine($"Total Decisions: {Decisions.Count} (Applied: {Decisions.Count(d => d.Applied)}, Preserved/Ambiguous: {Decisions.Count(d => !d.Applied)})");
            sb.AppendLine($"Summary: {TypesRenamed} types, {FieldsRenamed} fields, {MethodsRenamed} methods, {PropertiesRenamed} properties, {ResourcesRenamed} resources renamed. {UnprintableNormalized} normalized.");
            sb.AppendLine(new string('-', 81));
            sb.AppendLine(string.Format("{0,-18} {1,-10} {2,-30} -> {3}", "Confidence", "Type", "Original Name", "New Name / Status"));
            sb.AppendLine(new string('-', 81));

            foreach (var d in Decisions)
            {
                string target = d.Applied ? d.NewName : $"(Preserved: {d.Justification})";
                string orig = d.OriginalName ?? "";
                if (orig.Length > 28) orig = orig.Substring(0, 25) + "...";
                sb.AppendLine(string.Format("{0,-18} {1,-10} {2,-30} -> {3}",
                    $"[{d.Confidence}]",
                    d.SymbolType,
                    orig,
                    target));
            }
            sb.AppendLine(new string('=', 81));
            return sb.ToString();
        }

        public void SaveMappingReport(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentNullException(nameof(filePath));

            string dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }
            File.WriteAllText(filePath, GenerateMappingReport(), Encoding.UTF8);
        }
    }

    /// <summary>
    /// Restores semantic symbol names for Forms, Controls, Handlers, and Resources
    /// from ECMA-335 metadata and WinForms / DevExpress initialization bytecode.
    /// Also normalizes any residual unprintable or Unicode-mangled identifiers.
    /// Protects reflection references, public APIs, and disambiguates resource associations.
    /// </summary>
    public static class SemanticRenamer
    {
        private static readonly Regex ValidIdentifierRegex = new Regex(@"^[A-Za-z_][A-Za-z0-9_]*$", RegexOptions.Compiled);
        private static readonly Regex DecodableRegex = new Regex(@"^_0[0-9a-fA-F]{3,}$", RegexOptions.Compiled);
        private static readonly Regex HexHashRegex = new Regex(@"^[0-9a-fA-F]{32}$", RegexOptions.Compiled);
        private static readonly Regex IdentifierTokenRegex = new Regex(@"([A-Z]+(?=[A-Z][a-z]|[0-9]|_|$)|[A-Z][a-z]+|[a-z]+|[0-9]+)", RegexOptions.Compiled);

        private static readonly HashSet<string> CommonAbbreviationWords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "http", "https", "sync", "async", "msg", "ptr", "id", "db", "fs", "io", "os", "ui", "ip",
            "tcp", "udp", "sctp", "rtp", "rtcp", "sftp", "scp", "ntp", "src", "dst", "cmd", "ctrl", "btn", "txt", "lbl", "pnl", "chk", "cmb",
            "pic", "lst", "grp", "dgv", "rgb", "rgba", "xml", "html", "json", "utf", "sql", "wcf", "wpf",
            "xaml", "sha", "md5", "aes", "des", "rsa", "gcm", "ecb", "cbc", "hmac", "url", "uri", "sdk", "api", "gui", "cli",
            "csv", "pdf", "zip", "gzip", "smtp", "tls", "ssl", "imap", "pop", "dns", "dhcp", "ftp",
            "ldap", "ssh", "guid", "uuid", "crud", "rest", "jwt", "auth", "cors", "xsrf", "csrf",
            "xpath", "attr", "prop", "elem", "param", "args", "temp", "tmp", "cfg", "config",
            "ctx", "env", "app", "svc", "mgr", "init", "impl", "repo", "prev", "next", "curr",
            "min", "max", "avg", "sum", "cnt", "num", "pos", "idx", "len", "buf", "str", "char",
            "int", "bool", "byte", "enum", "dict", "spec", "info", "desc", "err", "warn",
            "bgp", "mqtt", "grpc", "pe", "nt", "clr", "sz", "il", "md", "ldstr", "ldfld", "ldsfld", "stfld", "stsfld", "rt", "sb", "cf", "gc", "vm", "cls", "nls", "bsd", "bstr"
        };

        private static bool CanSegmentAllCapsAcronym(string tok)
        {
            if (string.IsNullOrEmpty(tok) || tok.Length <= 1) return false;
            string tokLower = tok.ToLowerInvariant();
            if (CommonAbbreviationWords.Contains(tokLower))
                return true;

            int n = tok.Length;
            bool[] dp = new bool[n + 1];
            dp[0] = true;
            for (int i = 0; i < n; i++)
            {
                if (!dp[i]) continue;
                for (int len = 2; len <= n - i; len++)
                {
                    string sub = tokLower.Substring(i, len);
                    if (CommonAbbreviationWords.Contains(sub))
                    {
                        dp[i + len] = true;
                    }
                }
            }
            return dp[n];
        }

        private static readonly HashSet<string> GenericResourceWords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "components", "componentResourceManager", "resources", "icon", "$this",
            "panel", "panel1", "panel2", "button", "button1", "button2",
            "label", "label1", "label2", "textbox", "textbox1", "textbox2",
            "timer", "timer1", "image", "imagelist", "imagelist1"
        };

        private sealed class ReflectionReferenceMap
        {
            public HashSet<string> StringLiterals { get; } = new HashSet<string>(StringComparer.Ordinal);
            public HashSet<string> ExplicitTypeNames { get; } = new HashSet<string>(StringComparer.Ordinal);
            public HashSet<string> ExplicitMemberNames { get; } = new HashSet<string>(StringComparer.Ordinal);
            public List<(Instruction Instruction, string TargetName)> TypeGetTypeCalls { get; } = new List<(Instruction, string)>();
            public bool HasUnresolvableDynamicReflection { get; set; }
            public bool HasUnresolvableModuleScopeReflection { get; set; }
            public HashSet<TypeDef> UnresolvableDynamicReflectionTypes { get; } = new HashSet<TypeDef>();
            public List<string> UnresolvedDynamicPatterns { get; } = new List<string>();
        }

        private static int GetStoreLocalIndex(Instruction ins)
        {
            if (ins == null) return -1;
            var op = ins.OpCode;
            if (op == OpCodes.Stloc_0) return 0;
            if (op == OpCodes.Stloc_1) return 1;
            if (op == OpCodes.Stloc_2) return 2;
            if (op == OpCodes.Stloc_3) return 3;
            if ((op == OpCodes.Stloc_S || op == OpCodes.Stloc) && ins.Operand is Local loc)
                return loc.Index;
            return -1;
        }

        private static int GetLoadLocalIndex(Instruction ins)
        {
            if (ins == null) return -1;
            var op = ins.OpCode;
            if (op == OpCodes.Ldloc_0) return 0;
            if (op == OpCodes.Ldloc_1) return 1;
            if (op == OpCodes.Ldloc_2) return 2;
            if (op == OpCodes.Ldloc_3) return 3;
            if ((op == OpCodes.Ldloc_S || op == OpCodes.Ldloc) && ins.Operand is Local loc)
                return loc.Index;
            return -1;
        }

        private static int GetArgIndex(Instruction ins)
        {
            if (ins == null) return -1;
            var op = ins.OpCode;
            if (op == OpCodes.Ldarg_0) return 0;
            if (op == OpCodes.Ldarg_1) return 1;
            if (op == OpCodes.Ldarg_2) return 2;
            if (op == OpCodes.Ldarg_3) return 3;
            if ((op == OpCodes.Ldarg || op == OpCodes.Ldarg_S) && ins.Operand is Parameter p)
                return p.Index;
            return -1;
        }

        private static int FindStackProducer(IList<Instruction> instrs, int beforeIdx, int targetDepth)
        {
            if (beforeIdx <= 0 || beforeIdx > instrs.Count) return -1;
            int currentDepth = targetDepth;

            for (int j = beforeIdx - 1; j >= 0; j--)
            {
                var ins = instrs[j];
                ins.CalculateStackUsage(out int pushes, out int pops);

                if (pushes > 0)
                {
                    if (currentDepth < pushes)
                    {
                        return j;
                    }
                    currentDepth = currentDepth - pushes + pops;
                }
                else
                {
                    currentDepth += pops;
                }

                if (currentDepth < 0) return -1;
            }

            return -1;
        }

        private static bool TryResolveStringValue(
            IList<Instruction> instrs,
            int producerIdx,
            Dictionary<int, string> unambiguousLocals,
            out string resolvedStr)
        {
            resolvedStr = null;
            if (producerIdx < 0 || producerIdx >= instrs.Count) return false;

            var ins = instrs[producerIdx];

            // 1. Direct ldstr
            if (ins.OpCode == OpCodes.Ldstr && ins.Operand is string s)
            {
                resolvedStr = s;
                return true;
            }

            // 2. Local variable with single unambiguous constant assignment
            int locIdx = GetLoadLocalIndex(ins);
            if (locIdx >= 0 && unambiguousLocals.TryGetValue(locIdx, out var locVal))
            {
                resolvedStr = locVal;
                return true;
            }

            // 3. Static constant field
            if (ins.OpCode == OpCodes.Ldsfld && ins.Operand is IField fld)
            {
                var fDef = fld as FieldDef ?? fld.ResolveFieldDef();
                if (fDef?.Constant?.Value is string fStr)
                {
                    resolvedStr = fStr;
                    return true;
                }
            }

            // 4. String.Concat(s1, s2)
            if (ins.OpCode == OpCodes.Call && ins.Operand is IMethod concatM &&
                concatM.DeclaringType?.FullName == "System.String" && concatM.Name == "Concat")
            {
                int numParams = concatM.MethodSig?.Params?.Count ?? 0;
                if (numParams == 2)
                {
                    int p1 = FindStackProducer(instrs, producerIdx, targetDepth: 1);
                    int p2 = FindStackProducer(instrs, producerIdx, targetDepth: 0);
                    if (p1 >= 0 && p2 >= 0 &&
                        TryResolveStringValue(instrs, p1, unambiguousLocals, out string s1) &&
                        TryResolveStringValue(instrs, p2, unambiguousLocals, out string s2))
                    {
                        resolvedStr = s1 + s2;
                        return true;
                    }
                }
            }

            return false;
        }

        private sealed class TargetTypeResolution
        {
            /// <summary>
            /// Exact target type when strictly demonstrable (e.g. typeof(Target), newobj Target, sealed type instance).
            /// </summary>
            public TypeDef ExactType { get; set; }

            /// <summary>
            /// Indicates whether the runtime type is provably exact.
            /// </summary>
            public bool IsExact { get; set; }

            /// <summary>
            /// Candidate target types in the module when the declared static type is extensible (interface, abstract class, non-sealed base class).
            /// </summary>
            public List<TypeDef> PotentialTypes { get; } = new List<TypeDef>();

            /// <summary>
            /// Indicates whether target resolution is unbounded or cannot be safely determined, requiring conservative module-scope fallback.
            /// </summary>
            public bool RequiresModuleScopeFallback { get; set; }

            /// <summary>
            /// Diagnostic description of the resolution outcome.
            /// </summary>
            public string Description { get; set; }
        }

        private static bool DerivesFrom(TypeDef type, TypeDef baseType)
        {
            if (type == null || baseType == null) return false;
            var curr = type.BaseType?.ResolveTypeDef();
            while (curr != null)
            {
                if (curr == baseType || curr.FullName == baseType.FullName)
                    return true;
                curr = curr.BaseType?.ResolveTypeDef();
            }
            return false;
        }

        private static bool ImplementsInterface(TypeDef type, TypeDef ifaceType)
        {
            if (type == null || ifaceType == null) return false;
            var visited = new HashSet<string>(StringComparer.Ordinal);
            var queue = new Queue<TypeDef>();
            queue.Enqueue(type);
            while (queue.Count > 0)
            {
                var curr = queue.Dequeue();
                if (curr == null || !visited.Add(curr.FullName)) continue;
                if (curr.HasInterfaces)
                {
                    foreach (var iface in curr.Interfaces)
                    {
                        var resolved = iface.Interface?.ResolveTypeDef();
                        if (resolved != null)
                        {
                            if (resolved == ifaceType || resolved.FullName == ifaceType.FullName)
                                return true;
                            queue.Enqueue(resolved);
                        }
                    }
                }
                var baseDef = curr.BaseType?.ResolveTypeDef();
                if (baseDef != null)
                    queue.Enqueue(baseDef);
            }
            return false;
        }

        private static TargetTypeResolution ResolveExtensibleTypeTargets(ModuleDef module, TypeDef resolved, string sourceKind)
        {
            if (resolved == null || resolved.FullName == "System.Object")
            {
                return new TargetTypeResolution
                {
                    RequiresModuleScopeFallback = true,
                    Description = $"{sourceKind} is System.Object or unresolvable; requires conservative module-scope protection."
                };
            }

            // Sealed classes or value types cannot be subclassed in CLR: runtime type is guaranteed to be exact
            if (resolved.IsSealed || resolved.IsValueType)
            {
                return new TargetTypeResolution
                {
                    IsExact = true,
                    ExactType = resolved,
                    Description = $"{sourceKind} '{resolved.FullName}' is sealed/value-type; runtime type is provably exact."
                };
            }

            var res = new TargetTypeResolution
            {
                IsExact = false
            };

            if (resolved.IsInterface)
            {
                foreach (var t in module.GetTypes())
                {
                    if (t.IsInterface || t.IsAbstract) continue;
                    if (ImplementsInterface(t, resolved))
                    {
                        res.PotentialTypes.Add(t);
                    }
                }
                res.PotentialTypes.Add(resolved);
                res.Description = $"{sourceKind} interface '{resolved.FullName}' targets {res.PotentialTypes.Count} implementing/interface types in module.";
            }
            else if (resolved.IsAbstract)
            {
                foreach (var t in module.GetTypes())
                {
                    if (t.IsInterface || t.IsAbstract) continue;
                    if (DerivesFrom(t, resolved))
                    {
                        res.PotentialTypes.Add(t);
                    }
                }
                res.PotentialTypes.Add(resolved);
                res.Description = $"{sourceKind} abstract class '{resolved.FullName}' targets {res.PotentialTypes.Count} derived/base types in module.";
            }
            else
            {
                // Non-sealed class: can be the base class itself or any derived class in the module
                res.PotentialTypes.Add(resolved);
                foreach (var t in module.GetTypes())
                {
                    if (t == resolved) continue;
                    if (DerivesFrom(t, resolved))
                    {
                        res.PotentialTypes.Add(t);
                    }
                }
                res.Description = $"{sourceKind} extensible base class '{resolved.FullName}' targets {res.PotentialTypes.Count} base/derived types in module.";
            }

            return res;
        }

        private static TargetTypeResolution TryResolveTargetType(
            ModuleDef module,
            TypeDef declaringType,
            MethodDef currentMethod,
            IList<Instruction> instrs,
            int typeProducerIdx)
        {
            if (typeProducerIdx < 0 || typeProducerIdx >= instrs.Count) return null;
            var ins = instrs[typeProducerIdx];

            // Case 1: typeof(Target) -> ldtoken Target + call Type.GetTypeFromHandle
            if (ins.OpCode == OpCodes.Call && ins.Operand is IMethod handleM &&
                handleM.DeclaringType?.FullName == "System.Type" && handleM.Name == "GetTypeFromHandle")
            {
                int tokenIdx = FindStackProducer(instrs, typeProducerIdx, targetDepth: 0);
                if (tokenIdx >= 0 && instrs[tokenIdx].OpCode == OpCodes.Ldtoken)
                {
                    if (instrs[tokenIdx].Operand is ITypeDefOrRef tdr)
                    {
                        var exactDef = tdr.ResolveTypeDef() ?? (tdr as TypeDef);
                        if (exactDef != null)
                        {
                            return new TargetTypeResolution
                            {
                                IsExact = true,
                                ExactType = exactDef,
                                Description = $"typeof({exactDef.FullName}) is provably exact."
                            };
                        }
                    }
                }
            }

            // Case 2: obj.GetType() -> callvirt Object.GetType()
            if (ins.OpCode == OpCodes.Callvirt && ins.Operand is IMethod objGetType &&
                objGetType.DeclaringType?.FullName == "System.Object" && objGetType.Name == "GetType")
            {
                int objIdx = FindStackProducer(instrs, typeProducerIdx, targetDepth: 0);
                if (objIdx >= 0)
                {
                    var objIns = instrs[objIdx];

                    // Direct instantiation via newobj on the evaluation stack guarantees exact runtime type
                    if (objIns.OpCode == OpCodes.Newobj && objIns.Operand is IMethod ctor)
                    {
                        var exactT = ctor.DeclaringType?.ResolveTypeDef() ?? (ctor.DeclaringType as TypeDef);
                        if (exactT != null)
                        {
                            return new TargetTypeResolution
                            {
                                IsExact = true,
                                ExactType = exactT,
                                Description = $"newobj {exactT.FullName} guarantees exact runtime type."
                            };
                        }
                    }

                    int argIdx = GetArgIndex(objIns);
                    if (argIdx >= 0)
                    {
                        if (argIdx == 0 && currentMethod.HasThis)
                        {
                            return ResolveExtensibleTypeTargets(module, declaringType, "Instance (this)");
                        }
                        if (argIdx < currentMethod.Parameters.Count)
                        {
                            var pType = currentMethod.Parameters[argIdx].Type?.ToTypeDefOrRef();
                            var resolved = pType?.ResolveTypeDef() ?? (pType as TypeDef);
                            return ResolveExtensibleTypeTargets(module, resolved, $"Parameter #{argIdx}");
                        }
                    }

                    int locIdx = GetLoadLocalIndex(objIns);
                    if (locIdx >= 0 && currentMethod.Body.Variables.Count > locIdx)
                    {
                        var locType = currentMethod.Body.Variables[locIdx].Type?.ToTypeDefOrRef();
                        var resolved = locType?.ResolveTypeDef() ?? (locType as TypeDef);
                        return ResolveExtensibleTypeTargets(module, resolved, $"Local variable #{locIdx}");
                    }

                    if ((objIns.OpCode == OpCodes.Ldfld || objIns.OpCode == OpCodes.Ldsfld) && objIns.Operand is IField fld)
                    {
                        var fType = fld.FieldSig?.Type?.ToTypeDefOrRef();
                        var resolved = fType?.ResolveTypeDef() ?? (fType as TypeDef);
                        return ResolveExtensibleTypeTargets(module, resolved, $"Field '{fld.Name}'");
                    }
                }
            }

            // Case 3: Type.GetType("MyNamespace.MyType")
            if (ins.OpCode == OpCodes.Call && ins.Operand is IMethod typeGetType &&
                typeGetType.DeclaringType?.FullName == "System.Type" && typeGetType.Name == "GetType")
            {
                int strIdx = FindStackProducer(instrs, typeProducerIdx, targetDepth: 0);
                if (strIdx >= 0 && instrs[strIdx].OpCode == OpCodes.Ldstr && instrs[strIdx].Operand is string tName)
                {
                    var exactDef = module.Find(tName, isReflectionName: true);
                    if (exactDef != null)
                    {
                        return new TargetTypeResolution
                        {
                            IsExact = true,
                            ExactType = exactDef,
                            Description = $"Type.GetType(\"{tName}\") is provably exact."
                        };
                    }
                }
            }

            // Case 4: direct ldtoken without GetTypeFromHandle
            if (ins.OpCode == OpCodes.Ldtoken && ins.Operand is ITypeDefOrRef rawTdr)
            {
                var exactDef = rawTdr.ResolveTypeDef() ?? (rawTdr as TypeDef);
                if (exactDef != null)
                {
                    return new TargetTypeResolution
                    {
                        IsExact = true,
                        ExactType = exactDef,
                        Description = $"Direct ldtoken for '{exactDef.FullName}' is provably exact."
                    };
                }
            }

            return null;
        }

        private static ReflectionReferenceMap BuildReflectionReferenceMap(ModuleDef module)
        {
            var map = new ReflectionReferenceMap();
            foreach (var type in module.GetTypes())
            {
                if (!type.HasMethods) continue;
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody || method.Body.Instructions == null) continue;
                    var instrs = method.Body.Instructions;

                    // Analyze local variables: detect locals with exactly one store of a constant string
                    var storeCounts = new Dictionary<int, int>();
                    var storeIndices = new Dictionary<int, int>();
                    for (int k = 0; k < instrs.Count; k++)
                    {
                        int locIdx = GetStoreLocalIndex(instrs[k]);
                        if (locIdx >= 0)
                        {
                            storeCounts[locIdx] = storeCounts.TryGetValue(locIdx, out int c) ? c + 1 : 1;
                            storeIndices[locIdx] = k;
                        }
                    }

                    var unambiguousLocals = new Dictionary<int, string>();
                    foreach (var kvp in storeCounts)
                    {
                        if (kvp.Value == 1)
                        {
                            int storeIdx = storeIndices[kvp.Key];
                            int valProducer = FindStackProducer(instrs, storeIdx, targetDepth: 0);
                            if (valProducer >= 0)
                            {
                                if (instrs[valProducer].OpCode == OpCodes.Ldstr && instrs[valProducer].Operand is string sVal)
                                {
                                    unambiguousLocals[kvp.Key] = sVal;
                                }
                                else if (instrs[valProducer].OpCode == OpCodes.Ldsfld && instrs[valProducer].Operand is IField fld)
                                {
                                    var fDef = fld as FieldDef ?? fld.ResolveFieldDef();
                                    if (fDef?.Constant?.Value is string fStr)
                                    {
                                        unambiguousLocals[kvp.Key] = fStr;
                                    }
                                }
                            }
                        }
                    }

                    for (int i = 0; i < instrs.Count; i++)
                    {
                        var ins = instrs[i];
                        if (ins.OpCode == OpCodes.Ldstr && ins.Operand is string s && !string.IsNullOrEmpty(s))
                        {
                            map.StringLiterals.Add(s);
                        }

                        if (ins.OpCode == OpCodes.Call || ins.OpCode == OpCodes.Callvirt)
                        {
                            if (ins.Operand is IMethod called)
                            {
                                string mName = called.Name;
                                string declType = called.DeclaringType?.FullName;
                                bool isTypeReflection = declType == "System.Type" ||
                                                        declType == "System.Reflection.TypeInfo" ||
                                                        declType == "System.Reflection.TypeExtensions" ||
                                                        declType == "System.Reflection.RuntimeReflectionExtensions";

                                if (isTypeReflection)
                                {
                                    if (mName == "GetType")
                                    {
                                        for (int j = i - 1; j >= Math.Max(0, i - 16); j--)
                                        {
                                            if (instrs[j].OpCode == OpCodes.Ldstr && instrs[j].Operand is string strVal)
                                            {
                                                map.ExplicitTypeNames.Add(strVal);
                                                map.TypeGetTypeCalls.Add((instrs[j], strVal));
                                                break;
                                            }
                                        }
                                    }
                                    else if (mName == "GetMethod" || mName == "GetProperty" || mName == "GetField" ||
                                             mName == "GetEvent" || mName == "GetMember" ||
                                             mName == "GetRuntimeMethod" || mName == "GetRuntimeProperty" ||
                                             mName == "GetRuntimeField" || mName == "GetRuntimeEvent")
                                    {
                                        MethodSig msig = called.MethodSig;
                                        int paramCount = msig?.Params?.Count ?? 0;
                                        int totalArgs = (msig != null && msig.HasThis ? 1 : 0) + paramCount;
                                        int nameStackDepth = totalArgs - 2;
                                        int typeStackDepth = totalArgs - 1;

                                        bool resolvedMember = false;
                                        if (nameStackDepth >= 0)
                                        {
                                            int nameProducer = FindStackProducer(instrs, i, nameStackDepth);
                                            if (nameProducer >= 0 && TryResolveStringValue(instrs, nameProducer, unambiguousLocals, out string sVal))
                                            {
                                                map.ExplicitMemberNames.Add(sVal);
                                                resolvedMember = true;
                                            }
                                        }

                                        TargetTypeResolution targetResolution = null;
                                        if (typeStackDepth >= 0)
                                        {
                                            int typeProducer = FindStackProducer(instrs, i, typeStackDepth);
                                            if (typeProducer >= 0)
                                            {
                                                targetResolution = TryResolveTargetType(module, type, method, instrs, typeProducer);
                                            }
                                        }

                                        if (!resolvedMember)
                                        {
                                            map.HasUnresolvableDynamicReflection = true;
                                            if (targetResolution != null)
                                            {
                                                if (targetResolution.RequiresModuleScopeFallback)
                                                {
                                                    map.HasUnresolvableModuleScopeReflection = true;
                                                    map.UnresolvedDynamicPatterns.Add($"Dynamic member reflection with unresolvable/unbounded target type in method '{type.FullName}::{method.Name}' ({targetResolution.Description}).");
                                                }
                                                else if (targetResolution.IsExact && targetResolution.ExactType != null)
                                                {
                                                    map.UnresolvableDynamicReflectionTypes.Add(targetResolution.ExactType);
                                                    map.UnresolvedDynamicPatterns.Add($"Dynamic member reflection on exact type '{targetResolution.ExactType.FullName}' in method '{type.FullName}::{method.Name}'.");
                                                }
                                                else if (!targetResolution.IsExact && targetResolution.PotentialTypes.Count > 0)
                                                {
                                                    foreach (var pt in targetResolution.PotentialTypes)
                                                    {
                                                        map.UnresolvableDynamicReflectionTypes.Add(pt);
                                                    }
                                                    map.UnresolvedDynamicPatterns.Add($"Dynamic member reflection on extensible hierarchy in method '{type.FullName}::{method.Name}' ({targetResolution.Description}).");
                                                }
                                                else
                                                {
                                                    map.HasUnresolvableModuleScopeReflection = true;
                                                    map.UnresolvedDynamicPatterns.Add($"Unresolvable target type for dynamic reflection in method '{type.FullName}::{method.Name}'.");
                                                }
                                            }
                                            else
                                            {
                                                // Target type cannot be determined statically: conservative module scope fallback
                                                map.HasUnresolvableModuleScopeReflection = true;
                                                map.UnresolvedDynamicPatterns.Add($"Unresolvable target type for dynamic reflection in method '{type.FullName}::{method.Name}'.");
                                            }
                                        }
                                    }
                                    else if (mName == "GetNestedType")
                                    {
                                        for (int j = i - 1; j >= Math.Max(0, i - 16); j--)
                                        {
                                            if (instrs[j].OpCode == OpCodes.Ldstr && instrs[j].Operand is string strVal)
                                            {
                                                map.ExplicitTypeNames.Add(strVal);
                                            }
                                        }
                                    }
                                }
                                else if ((declType == "System.Reflection.Assembly" || declType == "System.Reflection.Module") && mName == "GetType")
                                {
                                    for (int j = i - 1; j >= Math.Max(0, i - 16); j--)
                                    {
                                        if (instrs[j].OpCode == OpCodes.Ldstr && instrs[j].Operand is string strVal)
                                        {
                                            map.ExplicitTypeNames.Add(strVal);
                                            map.TypeGetTypeCalls.Add((instrs[j], strVal));
                                            break;
                                        }
                                    }
                                }
                                else if (declType == "System.Activator" && mName == "CreateInstance")
                                {
                                    for (int j = i - 1; j >= Math.Max(0, i - 16); j--)
                                    {
                                        if (instrs[j].OpCode == OpCodes.Ldstr && instrs[j].Operand is string strVal)
                                        {
                                            map.ExplicitTypeNames.Add(strVal);
                                        }
                                    }
                                }
                                else if (declType == "System.Enum" && (mName == "Parse" || mName == "TryParse"))
                                {
                                    for (int j = i - 1; j >= Math.Max(0, i - 16); j--)
                                    {
                                        if (instrs[j].OpCode == OpCodes.Ldstr && instrs[j].Operand is string strVal)
                                        {
                                            map.ExplicitMemberNames.Add(strVal);
                                        }
                                    }
                                }
                                else if ((declType == "System.Windows.Forms.ControlBindingsCollection" ||
                                          declType == "System.Windows.Forms.BindingsCollection") && mName == "Add")
                                {
                                    for (int j = i - 1; j >= Math.Max(0, i - 16); j--)
                                    {
                                        if (instrs[j].OpCode == OpCodes.Ldstr && instrs[j].Operand is string strVal)
                                        {
                                            map.ExplicitMemberNames.Add(strVal);
                                        }
                                    }
                                }
                                else if (mName.IndexOf("PropertyChanged", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                         mName == "RaisePropertyChanged" || mName == "NotifyPropertyChanged" || mName == "OnPropertyChanged")
                                {
                                    for (int j = i - 1; j >= Math.Max(0, i - 16); j--)
                                    {
                                        if (instrs[j].OpCode == OpCodes.Ldstr && instrs[j].Operand is string strVal)
                                        {
                                            map.ExplicitMemberNames.Add(strVal);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return map;
        }

        public static SemanticRenamerResult Execute(ModuleDef module, bool verbose = false)
        {
            if (module == null) throw new ArgumentNullException(nameof(module));

            var result = new SemanticRenamerResult();

            var usedFullNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var t in module.GetTypes())
            {
                if (!string.IsNullOrEmpty(t.FullName))
                    usedFullNames.Add(t.FullName);
            }

            // Build map of symbols referenced dynamically or via reflection
            var refMap = BuildReflectionReferenceMap(module);

            // Pass 1: Recover Form and UserControl type names & namespaces
            RenameFormsAndUserControls(module, usedFullNames, refMap, result, verbose);

            // Pass 1.5: Match unlinked/mangled resources against Form resource strings
            MatchAndRenameMangledResources(module, result, verbose);

            // Pass 2: Recover Control fields & event handler methods
            RenameControlFieldsAndEventHandlers(module, refMap, result, verbose);

            // Pass 3: Recover strongly-typed Properties.Resources classes and properties
            RenameStronglyTypedResources(module, usedFullNames, refMap, result, verbose);

            // Pass 4: Normalize any remaining unprintable / Unicode-mangled identifiers
            NormalizeRemainingMangledIdentifiers(module, usedFullNames, refMap, result, verbose);

            result.Message = $"Restored {result.TypesRenamed} types, {result.FieldsRenamed} fields, " +
                             $"{result.MethodsRenamed} methods, {result.PropertiesRenamed} properties, " +
                             $"{result.ResourcesRenamed} resources ({result.UnprintableNormalized} unprintable symbols normalized).";

            return result;
        }

        #region Pass 1: Forms & UserControls Renaming

        private static void RenameFormsAndUserControls(ModuleDef module, HashSet<string> usedFullNames, ReflectionReferenceMap refMap, SemanticRenamerResult result, bool verbose)
        {
            var manifestResourceNames = new HashSet<string>(module.Resources.Select(r => r.Name.String));

            // Map: TypeDef -> (Detected (Namespace, Name), Confidence, Justification)
            var candidates = new Dictionary<TypeDef, (string ns, string name, RenameConfidence confidence, string justification)>();

            foreach (var type in module.GetTypes())
            {
                if (type.IsGlobalModuleType || type.DeclaringType != null)
                    continue;

                if (IsResourceWrapperClass(type))
                    continue;

                // Safety rule: compiler-generated types must be preserved
                if (IsCompilerGenerated(type))
                    continue;

                // Safety rule: if the type name is already clean and non-obfuscated, preserve it!
                if (!IsObfuscatedOrGenericTypeName(type.Name))
                    continue;

                string discoveredName = null;
                string discoveredNamespace = null;
                RenameConfidence confidence = RenameConfidence.Heuristic;
                string justification = null;

                // Pattern 1: Look for self set_Name call in methods (e.g. InitializeComponent)
                // Strict check: type must derive from Form/Control AND called method must be Control.set_Name
                if (IsWinFormsControlOrForm(type))
                {
                    foreach (var method in type.Methods)
                    {
                        if (!method.HasBody || method.Body.Instructions == null)
                            continue;

                        var instrs = method.Body.Instructions;
                        for (int i = 2; i < instrs.Count; i++)
                        {
                            var ins = instrs[i];
                            if (ins.OpCode == OpCodes.Call || ins.OpCode == OpCodes.Callvirt)
                            {
                                if (ins.Operand is IMethod calledM && IsControlSetName(calledM))
                                {
                                    var p1 = instrs[i - 1];
                                    var p2 = instrs[i - 2];
                                    if (p2.OpCode == OpCodes.Ldarg_0 && p1.OpCode == OpCodes.Ldstr && p1.Operand is string strVal)
                                    {
                                        strVal = strVal.Trim();
                                        if (IsValidIdentifier(strVal))
                                        {
                                            discoveredName = strVal;
                                            confidence = RenameConfidence.StrongReference;
                                            justification = $"Proven by Control.set_Name call in method '{method.Name}'";
                                            break;
                                        }
                                    }
                                }
                            }
                        }

                        if (discoveredName != null)
                            break;
                    }
                }

                // Pattern 2: Check linked WinForm type in constructor:
                // e.g. this.winForm = typeof(OrderDetailsForm);
                if (discoveredName == null && IsWinFormsControlOrForm(type))
                {
                    var ctor = type.FindDefaultConstructor() ?? type.Methods.FirstOrDefault(m => m.IsConstructor);
                    if (ctor != null && ctor.HasBody)
                    {
                        foreach (var ins in ctor.Body.Instructions)
                        {
                            if (ins.OpCode == OpCodes.Ldtoken && ins.Operand is ITypeDefOrRef tokenType)
                            {
                                string tName = (string)tokenType.Name;
                                if (!string.IsNullOrEmpty(tName) && IsValidIdentifier(tName) &&
                                    (tName.EndsWith("Form", StringComparison.OrdinalIgnoreCase) ||
                                     tName.EndsWith("List", StringComparison.OrdinalIgnoreCase)))
                                {
                                    discoveredName = tName + "Control";
                                    discoveredNamespace = (string)tokenType.Namespace;
                                    confidence = RenameConfidence.HighConfidence;
                                    justification = $"Discovered from linked Form type token '{tName}' in constructor";
                                    break;
                                }
                            }
                        }
                    }
                }

                // Safety rule: if type is public and referenced by string literal without explicit Type.GetType call,
                // do not rename to avoid breaking dynamic reflection or serialization.
                if (discoveredName != null)
                {
                    if (type.IsPublic && (refMap.StringLiterals.Contains(type.Name.String) || refMap.StringLiterals.Contains(type.FullName)) &&
                        !refMap.ExplicitTypeNames.Contains(type.Name.String) && !refMap.ExplicitTypeNames.Contains(type.FullName))
                    {
                        result.Decisions.Add(new RenameDecision
                        {
                            OriginalName = type.FullName,
                            NewName = type.FullName,
                            SymbolType = "Type",
                            Confidence = RenameConfidence.Ambiguous,
                            Justification = "Type is public and its name appears in string literal without identifiable Type.GetType call; preserved to prevent breaking reflection or serialization.",
                            Applied = false
                        });
                        continue;
                    }

                    // Try to associate discoveredName with manifest resources to get proper namespace
                    string matchedResName = manifestResourceNames.FirstOrDefault(rn =>
                        rn.EndsWith("." + discoveredName + ".resources", StringComparison.OrdinalIgnoreCase) ||
                        rn.Equals(discoveredName + ".resources", StringComparison.OrdinalIgnoreCase));

                    if (matchedResName != null)
                    {
                        string withoutExt = matchedResName.Substring(0, matchedResName.Length - ".resources".Length);
                        int lastDot = withoutExt.LastIndexOf('.');
                        if (lastDot > 0)
                        {
                            discoveredNamespace = withoutExt.Substring(0, lastDot);
                            discoveredName = withoutExt.Substring(lastDot + 1);
                        }
                    }
                    else if (string.IsNullOrEmpty(discoveredNamespace))
                    {
                        discoveredNamespace = GetAssemblyRootNamespace(module);
                    }

                    candidates[type] = (discoveredNamespace, discoveredName, confidence, justification);
                }
            }

            // Apply discovered Form names
            foreach (var kvp in candidates)
            {
                var type = kvp.Key;
                var (targetNs, targetName, confidence, justification) = kvp.Value;

                // Ensure unique name
                string finalName = targetName;
                int suffix = 1;
                while (usedFullNames.Contains(string.IsNullOrEmpty(targetNs) ? finalName : targetNs + "." + finalName))
                {
                    if (type.Name == finalName && type.Namespace == targetNs)
                        break;
                    finalName = $"{targetName}_{suffix++}";
                }

                string oldFullName = type.FullName;
                string oldName = type.Name.String;

                type.Name = finalName;
                if (!string.IsNullOrEmpty(targetNs))
                    type.Namespace = targetNs;

                usedFullNames.Add(type.FullName);
                result.TypesRenamed++;

                // Synchronize any Type.GetType("OldName") string literals
                foreach (var call in refMap.TypeGetTypeCalls)
                {
                    if (call.TargetName == oldFullName || call.TargetName == oldName)
                    {
                        call.Instruction.Operand = type.FullName;
                    }
                }

                // Sync manifest resource if old name had a matching resource
                SyncResourceForType(module, type, oldFullName, oldName, result);

                result.Decisions.Add(new RenameDecision
                {
                    OriginalName = oldFullName,
                    NewName = type.FullName,
                    SymbolType = "Type",
                    Confidence = confidence,
                    Justification = justification,
                    Applied = true
                });

                if (verbose)
                    Tool.Logger.LogInfo($"[SemanticRenamer] Form Renamed: {oldFullName} -> {type.FullName}");
            }
        }

        private static void SyncResourceForType(ModuleDef module, TypeDef type, string oldFullName, string oldName, SemanticRenamerResult result)
        {
            string newResName = type.FullName + ".resources";

            // Check if resource already exists with new name
            if (module.Resources.Any(r => r.Name.Equals(newResName)))
                return;

            // Search for resource matching exactly oldFullName or oldName (never fuzzy Contains)
            var matchingResources = module.Resources.Where(r =>
                r.Name.Equals(oldFullName + ".resources") ||
                r.Name.Equals(oldName + ".resources")).ToList();

            if (matchingResources.Count == 1)
            {
                var oldRes = matchingResources[0];
                if (oldRes.Name != newResName)
                {
                    string oldResName = oldRes.Name.String;
                    oldRes.Name = newResName;
                    result.ResourcesRenamed++;

                    result.Decisions.Add(new RenameDecision
                    {
                        OriginalName = oldResName,
                        NewName = newResName,
                        SymbolType = "Resource",
                        Confidence = RenameConfidence.StrongReference,
                        Justification = $"Synchronized manifest resource for renamed form '{type.FullName}'",
                        Applied = true
                    });
                }
            }
            else if (matchingResources.Count > 1)
            {
                result.Decisions.Add(new RenameDecision
                {
                    OriginalName = oldFullName,
                    NewName = newResName,
                    SymbolType = "Resource",
                    Confidence = RenameConfidence.Ambiguous,
                    Justification = $"Multiple manifest resources match type '{type.FullName}'. Preserved without renaming.",
                    Applied = false
                });
            }
        }

        private static void MatchAndRenameMangledResources(ModuleDef module, SemanticRenamerResult result, bool verbose)
        {
            var mangledResources = module.Resources.OfType<EmbeddedResource>()
                .Where(r => r.Name.String.EndsWith(".resources") && IsMangledIdentifier(r.Name.String.Substring(0, r.Name.String.Length - 10)))
                .ToList();

            if (mangledResources.Count == 0) return;

            // Map each non-empty resource to (fullKeys, ctrlPrefixes), and collect empty resources
            var resourceKeysMap = new Dictionary<EmbeddedResource, (HashSet<string> fullKeys, HashSet<string> ctrlPrefixes)>();
            var emptyResources = new List<EmbeddedResource>();

            foreach (var res in mangledResources)
            {
                try
                {
                    var fullKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    var ctrlPrefixes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                    using (var stream = res.GetResourceStream())
                    using (var reader = new System.Resources.ResourceReader(stream))
                    {
                        var enumerator = reader.GetEnumerator();
                        while (enumerator.MoveNext())
                        {
                            if (enumerator.Key is string k)
                            {
                                fullKeys.Add(k);
                                int dotIdx = k.IndexOf('.');
                                if (dotIdx > 0)
                                {
                                    string prefix = k.Substring(0, dotIdx);
                                    if (!prefix.Equals("$this", StringComparison.OrdinalIgnoreCase))
                                        ctrlPrefixes.Add(prefix);
                                }
                                else
                                {
                                    ctrlPrefixes.Add(k);
                                }
                            }
                        }
                    }

                    if (fullKeys.Count > 0)
                        resourceKeysMap[res] = (fullKeys, ctrlPrefixes);
                    else
                        emptyResources.Add(res);
                }
                catch
                {
                    emptyResources.Add(res);
                }
            }

            // Identify all types that instantiate ComponentResourceManager or ResourceManager(typeof(T))
            var typesWithCrm = new HashSet<TypeDef>();
            foreach (var t in module.GetTypes())
            {
                if (t.IsGlobalModuleType || t.DeclaringType != null) continue;
                if (TypeInstantiatesComponentResourceManager(t))
                    typesWithCrm.Add(t);
            }

            // Phase A: Match non-empty mangled resources against candidate types using control prefixes and field names
            var candidateTypes = new List<(TypeDef Type, HashSet<string> Identifiers)>();
            foreach (var type in module.GetTypes())
            {
                if (type.IsGlobalModuleType || type.DeclaringType != null) continue;
                if (IsResourceWrapperClass(type)) continue;

                string expectedResName = type.FullName + ".resources";
                if (module.Resources.Any(r => r.Name.Equals(expectedResName)))
                    continue;

                var typeIdentifiers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                typeIdentifiers.Add(type.Name.String);

                foreach (var f in type.Fields)
                {
                    if (!string.IsNullOrEmpty(f.Name?.String))
                        typeIdentifiers.Add(f.Name.String);
                }

                foreach (var m in type.Methods)
                {
                    if (!m.HasBody || m.Body.Instructions == null) continue;
                    foreach (var ins in m.Body.Instructions)
                    {
                        if (ins.OpCode == OpCodes.Ldstr && ins.Operand is string s && !string.IsNullOrWhiteSpace(s))
                            typeIdentifiers.Add(s);
                    }
                }

                candidateTypes.Add((type, typeIdentifiers));
            }

            // Compute score matrix: scores[type][res] = (matches, nonGenericMatches)
            var scores = new Dictionary<TypeDef, Dictionary<EmbeddedResource, (int matches, int nonGeneric)>>();
            foreach (var (type, idents) in candidateTypes)
            {
                scores[type] = new Dictionary<EmbeddedResource, (int, int)>();
                foreach (var kvp in resourceKeysMap)
                {
                    var res = kvp.Key;
                    var (fullKeys, ctrlPrefixes) = kvp.Value;

                    int matches = 0;
                    int nonGeneric = 0;

                    foreach (var cp in ctrlPrefixes)
                    {
                        if (idents.Contains(cp))
                        {
                            matches++;
                            if (!GenericResourceWords.Contains(cp))
                                nonGeneric++;
                        }
                    }
                    foreach (var fk in fullKeys)
                    {
                        if (idents.Contains(fk))
                        {
                            matches++;
                            if (!GenericResourceWords.Contains(fk))
                                nonGeneric++;
                        }
                    }

                    if (matches > 0)
                    {
                        scores[type][res] = (matches, nonGeneric);
                    }
                }
            }

            // Two-way disambiguation matching
            var assignedResources = new HashSet<EmbeddedResource>();
            var assignedTypes = new HashSet<TypeDef>();

            foreach (var (type, _) in candidateTypes)
            {
                if (assignedTypes.Contains(type)) continue;

                var resScores = scores[type];
                if (resScores.Count == 0) continue;

                // Find top scoring resource for this type
                var sortedRes = resScores
                    .Where(kv => !assignedResources.Contains(kv.Key))
                    .OrderByDescending(kv => kv.Value.matches)
                    .ThenByDescending(kv => kv.Value.nonGeneric)
                    .ToList();

                if (sortedRes.Count == 0) continue;

                var bestPair = sortedRes[0];
                var bestRes = bestPair.Key;
                var (topMatches, topNonGeneric) = bestPair.Value;

                // Confidence threshold: at least 2 matches with 1 non-generic, or 1 distinctive match
                if (topMatches < 2 && (topNonGeneric < 1 || topMatches < 1))
                    continue;

                // Check tie for this type: if runner-up has same topMatches, it's ambiguous!
                if (sortedRes.Count > 1 && sortedRes[1].Value.matches == topMatches)
                {
                    result.Decisions.Add(new RenameDecision
                    {
                        OriginalName = bestRes.Name.String,
                        NewName = type.FullName + ".resources",
                        SymbolType = "Resource",
                        Confidence = RenameConfidence.Ambiguous,
                        Justification = $"Resource matching for type '{type.FullName}' is ambiguous: tied top score ({topMatches} matches) between multiple resources. Preserved without renaming.",
                        Applied = false
                    });
                    continue;
                }

                // Check tie in the reverse direction: is this bestRes also the unique top match for bestType?
                bool conflictFound = false;
                foreach (var (otherType, _) in candidateTypes)
                {
                    if (otherType == type || assignedTypes.Contains(otherType)) continue;
                    if (scores[otherType].TryGetValue(bestRes, out var otherScore))
                    {
                        if (otherScore.matches >= topMatches)
                        {
                            conflictFound = true;
                            break;
                        }
                    }
                }

                if (conflictFound)
                {
                    result.Decisions.Add(new RenameDecision
                    {
                        OriginalName = bestRes.Name.String,
                        NewName = type.FullName + ".resources",
                        SymbolType = "Resource",
                        Confidence = RenameConfidence.Ambiguous,
                        Justification = $"Resource '{bestRes.Name}' matches multiple types with equal or higher score ({topMatches} matches). Preserved without renaming.",
                        Applied = false
                    });
                    continue;
                }

                // Mutually unique best match with sufficient confidence!
                string expectedResName = type.FullName + ".resources";
                string oldResName = bestRes.Name.String;
                bestRes.Name = expectedResName;
                assignedResources.Add(bestRes);
                assignedTypes.Add(type);
                resourceKeysMap.Remove(bestRes);
                result.ResourcesRenamed++;

                result.Decisions.Add(new RenameDecision
                {
                    OriginalName = oldResName,
                    NewName = expectedResName,
                    SymbolType = "Resource",
                    Confidence = RenameConfidence.HighConfidence,
                    Justification = $"Matched {topMatches} unique control/key references with type '{type.FullName}'",
                    Applied = true
                });

                if (verbose)
                    Tool.Logger.LogInfo($"[SemanticRenamer] Synced mangled resource: {oldResName} -> {expectedResName} (matches: {topMatches})");
            }

            // Phase B: For any remaining forms/types that call ComponentResourceManager(typeof(T)) but still lack a resource stream,
            // associate an unused empty resource or create a minimal valid empty resource stream.
            foreach (var type in typesWithCrm)
            {
                string expectedResName = type.FullName + ".resources";
                if (module.Resources.Any(r => r.Name.Equals(expectedResName)))
                    continue;

                if (emptyResources.Count > 0)
                {
                    var emptyRes = emptyResources[0];
                    emptyResources.RemoveAt(0);
                    string oldResName = emptyRes.Name.String;
                    emptyRes.Name = expectedResName;
                    result.ResourcesRenamed++;

                    result.Decisions.Add(new RenameDecision
                    {
                        OriginalName = oldResName,
                        NewName = expectedResName,
                        SymbolType = "Resource",
                        Confidence = emptyResources.Count == 0 && typesWithCrm.Count == 1 ? RenameConfidence.HighConfidence : RenameConfidence.Heuristic,
                        Justification = $"Associated empty resource for CRM type '{type.FullName}'",
                        Applied = true
                    });

                    if (verbose)
                        Tool.Logger.LogInfo($"[SemanticRenamer] Associated empty resource for CRM type: {oldResName} -> {expectedResName}");
                }
                else
                {
                    using (var ms = new MemoryStream())
                    {
                        using (var writer = new System.Resources.ResourceWriter(ms))
                        {
                            writer.Generate();
                        }
                        var newRes = new EmbeddedResource(expectedResName, ms.ToArray());
                        module.Resources.Add(newRes);
                        result.ResourcesRenamed++;

                        result.Decisions.Add(new RenameDecision
                        {
                            OriginalName = "<None>",
                            NewName = expectedResName,
                            SymbolType = "Resource",
                            Confidence = RenameConfidence.Heuristic,
                            Justification = $"Created valid empty resource stream for CRM type '{type.FullName}' to prevent MissingManifestResourceException",
                            Applied = true
                        });

                        if (verbose)
                            Tool.Logger.LogInfo($"[SemanticRenamer] Created empty resource for CRM type: {expectedResName}");
                    }
                }
            }
        }

        private static bool TypeInstantiatesComponentResourceManager(TypeDef type)
        {
            if (type == null || !type.HasMethods) return false;
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
                        for (int j = Math.Max(0, i - 5); j < i; j++)
                        {
                            var prev = instrs[j];
                            if (prev.OpCode == OpCodes.Ldtoken && prev.Operand is ITypeDefOrRef tokenType &&
                                (tokenType.Name == type.Name || tokenType.FullName == type.FullName))
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            return false;
        }

        #endregion

        #region Pass 2: Controls & Event Handlers Renaming

        private static void RenameControlFieldsAndEventHandlers(ModuleDef module, ReflectionReferenceMap refMap, SemanticRenamerResult result, bool verbose)
        {
            foreach (var type in module.GetTypes())
            {
                if (type.IsGlobalModuleType)
                    continue;

                var fieldControlNames = new Dictionary<FieldDef, string>();

                foreach (var method in type.Methods)
                {
                    if (!method.HasBody || method.Body.Instructions == null)
                        continue;

                    var instrs = method.Body.Instructions;
                    for (int i = 0; i < instrs.Count; i++)
                    {
                        var ins = instrs[i];

                        // Pattern 1: ldarg.0; ldfld <field>; ldstr "btnSave"; callvirt set_Name
                        if (ins.OpCode == OpCodes.Callvirt || ins.OpCode == OpCodes.Call)
                        {
                            if (ins.Operand is IMethod calledM && IsControlSetName(calledM))
                            {
                                if (i >= 2 && instrs[i - 1].OpCode == OpCodes.Ldstr && instrs[i - 1].Operand is string ctrlName)
                                {
                                    ctrlName = ctrlName.Trim();
                                    if (IsValidIdentifier(ctrlName))
                                    {
                                        FieldDef targetField = null;
                                        if (instrs[i - 2].OpCode == OpCodes.Ldfld && instrs[i - 2].Operand is FieldDef fd1 && fd1.DeclaringType == type)
                                        {
                                            targetField = fd1;
                                        }
                                        else if (i >= 3 && instrs[i - 3].OpCode == OpCodes.Ldfld && instrs[i - 3].Operand is FieldDef fd2 && fd2.DeclaringType == type)
                                        {
                                            targetField = fd2;
                                        }

                                        if (targetField != null && !fieldControlNames.ContainsKey(targetField))
                                        {
                                            // Check reflection, compiler-generated, and public/family access protection
                                            if (!targetField.IsPublic && !targetField.IsFamily &&
                                                !IsCompilerGenerated(targetField) &&
                                                !refMap.ExplicitMemberNames.Contains(targetField.Name.String) &&
                                                !refMap.StringLiterals.Contains(targetField.Name.String))
                                            {
                                                fieldControlNames[targetField] = ctrlName;
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Pattern 2: Event Subscription
                        // ldftn <Method>; newobj EventHandler; callvirt add_<Event>
                        if (ins.OpCode == OpCodes.Callvirt || ins.OpCode == OpCodes.Call)
                        {
                            if (ins.Operand is IMethod addEventMethod && addEventMethod.Name.StartsWith("add_"))
                            {
                                string eventName = addEventMethod.Name.Substring(4); // e.g. "Click"
                                if (i >= 2 && (instrs[i - 1].OpCode == OpCodes.Newobj) &&
                                    (instrs[i - 2].OpCode == OpCodes.Ldftn) &&
                                    instrs[i - 2].Operand is MethodDef handlerMethod && handlerMethod.DeclaringType == type)
                                {
                                    // Protect public, protected, virtual, override, interface, P/Invoke, compiler generated, and reflection methods
                                    if (handlerMethod.IsPublic || handlerMethod.IsFamily || handlerMethod.IsVirtual || handlerMethod.HasOverrides ||
                                        handlerMethod.Overrides.Count > 0 || handlerMethod.IsPinvokeImpl ||
                                        IsCompilerGenerated(handlerMethod) ||
                                        refMap.ExplicitMemberNames.Contains(handlerMethod.Name.String) ||
                                        refMap.StringLiterals.Contains(handlerMethod.Name.String))
                                    {
                                        continue;
                                    }

                                    FieldDef eventControlField = null;
                                    for (int j = i - 3; j >= Math.Max(0, i - 6); j--)
                                    {
                                        if (instrs[j].OpCode == OpCodes.Ldfld && instrs[j].Operand is FieldDef fd && fd.DeclaringType == type)
                                        {
                                            eventControlField = fd;
                                            break;
                                        }
                                    }

                                    string prefix = null;
                                    if (eventControlField != null)
                                    {
                                        fieldControlNames.TryGetValue(eventControlField, out prefix);
                                        if (string.IsNullOrEmpty(prefix))
                                            prefix = eventControlField.Name.String;
                                    }
                                    else
                                    {
                                        prefix = type.Name.String;
                                    }

                                    if (!string.IsNullOrEmpty(prefix) && IsValidIdentifier(prefix) && IsObfuscatedOrGenericMethodName(handlerMethod.Name))
                                    {
                                        string newHandlerName = $"{prefix}_{eventName}";
                                        if (IsValidIdentifier(newHandlerName) && !type.Methods.Any(m => m.Name == newHandlerName))
                                        {
                                            string oldMName = handlerMethod.Name.String;
                                            handlerMethod.Name = newHandlerName;
                                            result.MethodsRenamed++;

                                            result.Decisions.Add(new RenameDecision
                                            {
                                                OriginalName = oldMName,
                                                NewName = newHandlerName,
                                                SymbolType = "Method",
                                                Confidence = RenameConfidence.StrongReference,
                                                Justification = $"Restored event handler name from event '{eventName}' on control '{prefix}'",
                                                Applied = true
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Apply field renames
                var usedFieldNames = new HashSet<string>(type.Fields.Select(f => f.Name.String), StringComparer.Ordinal);
                foreach (var kvp in fieldControlNames)
                {
                    var field = kvp.Key;
                    string targetName = kvp.Value;

                    if (field.Name == targetName)
                        continue;

                    if (IsObfuscatedOrGenericFieldName(field.Name))
                    {
                        string finalFieldName = targetName;
                        int suffix = 1;
                        while (usedFieldNames.Contains(finalFieldName))
                        {
                            finalFieldName = $"{targetName}_{suffix++}";
                        }

                        string oldFieldName = field.Name.String;
                        usedFieldNames.Remove(field.Name.String);
                        field.Name = finalFieldName;
                        usedFieldNames.Add(finalFieldName);
                        result.FieldsRenamed++;

                        result.Decisions.Add(new RenameDecision
                        {
                            OriginalName = oldFieldName,
                            NewName = finalFieldName,
                            SymbolType = "Field",
                            Confidence = RenameConfidence.StrongReference,
                            Justification = $"Restored control field name from set_Name '{targetName}'",
                            Applied = true
                        });
                    }
                }
            }
        }

        #endregion

        #region Pass 3: Properties.Resources Renaming

        private static bool IsResourceWrapperClass(TypeDef type)
        {
            if (type.IsGlobalModuleType || type.DeclaringType != null)
                return false;

            foreach (var f in type.Fields)
            {
                if (f.IsStatic && f.FieldType.FullName == "System.Resources.ResourceManager")
                    return true;
            }

            foreach (var p in type.Properties)
            {
                if (p.PropertySig?.RetType?.FullName == "System.Resources.ResourceManager")
                    return true;
            }

            return false;
        }

        private static void RenameStronglyTypedResources(ModuleDef module, HashSet<string> usedFullNames, ReflectionReferenceMap refMap, SemanticRenamerResult result, bool verbose)
        {
            var resourceClasses = new List<TypeDef>();
            foreach (var type in module.GetTypes())
            {
                if (IsResourceWrapperClass(type))
                    resourceClasses.Add(type);
            }

            if (resourceClasses.Count == 0)
                return;

            resourceClasses.Sort((a, b) =>
            {
                int aDrawings = a.Properties.Count(p => p.PropertySig?.RetType?.FullName?.StartsWith("System.Drawing") == true);
                int bDrawings = b.Properties.Count(p => p.PropertySig?.RetType?.FullName?.StartsWith("System.Drawing") == true);
                if (aDrawings != bDrawings)
                    return bDrawings.CompareTo(aDrawings);
                return b.Properties.Count.CompareTo(a.Properties.Count);
            });

            string rootNs = GetAssemblyRootNamespace(module);
            string propNs = string.IsNullOrEmpty(rootNs) ? "Properties" : rootNs + ".Properties";
            bool resourcesAssigned = false;

            foreach (var type in resourceClasses)
            {
                string oldFullName = type.FullName;
                string oldName = type.Name.String;

                string preferredName;
                if (!resourcesAssigned)
                {
                    preferredName = "Resources";
                    resourcesAssigned = true;
                }
                else
                {
                    preferredName = "Messages";
                }

                string finalName = preferredName;
                string targetFullName = string.IsNullOrEmpty(propNs) ? finalName : propNs + "." + finalName;
                int suffix = 2;
                while (usedFullNames.Contains(targetFullName))
                {
                    if (type.FullName.Equals(targetFullName, StringComparison.OrdinalIgnoreCase))
                        break;
                    finalName = $"{preferredName}_{suffix++}";
                    targetFullName = string.IsNullOrEmpty(propNs) ? finalName : propNs + "." + finalName;
                }

                if (IsObfuscatedOrGenericTypeName(type.Name) || type.Name != finalName || type.Namespace != propNs)
                {
                    usedFullNames.Remove(type.FullName);
                    type.Name = finalName;
                    type.Namespace = propNs;
                    usedFullNames.Add(type.FullName);
                    result.TypesRenamed++;

                    result.Decisions.Add(new RenameDecision
                    {
                        OriginalName = oldFullName,
                        NewName = type.FullName,
                        SymbolType = "Type",
                        Confidence = RenameConfidence.StrongReference,
                        Justification = $"Restored strongly-typed resource wrapper class '{type.FullName}'",
                        Applied = true
                    });

                    if (verbose)
                        Tool.Logger.LogInfo($"[SemanticRenamer] Resource Wrapper: {oldFullName} -> {type.FullName}");
                }

                // Sync manifest resource and update ldstr in methods atomically
                SyncResourceAndLdstr(module, type, oldFullName, oldName, result, verbose);

                // Rename properties
                RenameResourceProperties(type, refMap, result);
            }
        }

        private static void SyncResourceAndLdstr(ModuleDef module, TypeDef type, string oldFullName, string oldName, SemanticRenamerResult result, bool verbose)
        {
            string expectedResName = type.FullName + ".resources";

            var rmBaseNameInstructions = new List<Instruction>();
            string oldBaseName = null;

            foreach (var m in type.Methods)
            {
                if (!m.HasBody || m.Body.Instructions == null) continue;
                var instrs = m.Body.Instructions;
                for (int i = 0; i < instrs.Count; i++)
                {
                    var ins = instrs[i];
                    if (ins.OpCode == OpCodes.Newobj && ins.Operand is IMethod ctor &&
                        ctor.DeclaringType?.FullName == "System.Resources.ResourceManager")
                    {
                        for (int j = i - 1; j >= Math.Max(0, i - 6); j--)
                        {
                            if (instrs[j].OpCode == OpCodes.Ldstr && instrs[j].Operand is string s && !string.IsNullOrEmpty(s))
                            {
                                rmBaseNameInstructions.Add(instrs[j]);
                                if (oldBaseName == null)
                                    oldBaseName = s;
                                break;
                            }
                        }
                    }
                }
            }

            if (oldBaseName == null)
            {
                foreach (var m in type.Methods)
                {
                    if (!m.HasBody || m.Body.Instructions == null) continue;
                    foreach (var ins in m.Body.Instructions)
                    {
                        if (ins.OpCode == OpCodes.Ldstr && ins.Operand is string s && !string.IsNullOrEmpty(s))
                        {
                            if (module.Resources.Any(r => r.Name.Equals(s + ".resources") || r.Name.Equals(s)))
                            {
                                oldBaseName = s;
                                rmBaseNameInstructions.Add(ins);
                                break;
                            }
                        }
                    }
                    if (oldBaseName != null) break;
                }
            }

            EmbeddedResource matchedRes = null;
            if (oldBaseName != null)
            {
                matchedRes = module.Resources.OfType<EmbeddedResource>()
                    .FirstOrDefault(r => r.Name.Equals(oldBaseName + ".resources") || r.Name.Equals(oldBaseName));
            }

            if (matchedRes == null)
            {
                var candidateResources = module.Resources.OfType<EmbeddedResource>()
                    .Where(r => r.Name.Equals(oldFullName + ".resources") ||
                                r.Name.Equals(oldName + ".resources")).ToList();
                if (candidateResources.Count == 1)
                {
                    matchedRes = candidateResources[0];
                }
                else if (candidateResources.Count > 1)
                {
                    result.Decisions.Add(new RenameDecision
                    {
                        OriginalName = oldFullName,
                        NewName = expectedResName,
                        SymbolType = "Resource",
                        Confidence = RenameConfidence.Ambiguous,
                        Justification = $"Multiple manifest resources match strongly-typed resource '{type.FullName}'. Preserved without renaming.",
                        Applied = false
                    });
                }
            }

            if (matchedRes == null)
            {
                var typeKeys = new HashSet<string>(StringComparer.Ordinal);
                foreach (var p in type.Properties)
                {
                    var getter = p.GetMethod;
                    if (getter != null && getter.HasBody && getter.Body.Instructions != null)
                    {
                        foreach (var ins in getter.Body.Instructions)
                        {
                            if (ins.OpCode == OpCodes.Ldstr && ins.Operand is string k && !string.IsNullOrEmpty(k))
                                typeKeys.Add(k);
                        }
                    }
                }

                if (typeKeys.Count > 0)
                {
                    EmbeddedResource bestRes = null;
                    int maxMatches = 0;
                    foreach (var res in module.Resources.OfType<EmbeddedResource>())
                    {
                        try
                        {
                            int matches = 0;
                            using (var stream = res.GetResourceStream())
                            using (var reader = new System.Resources.ResourceReader(stream))
                            {
                                var en = reader.GetEnumerator();
                                while (en.MoveNext())
                                {
                                    if (en.Key is string rk && typeKeys.Contains(rk))
                                        matches++;
                                }
                            }
                            if (matches > maxMatches)
                            {
                                maxMatches = matches;
                                bestRes = res;
                            }
                        }
                        catch { }
                    }

                    if (bestRes != null && maxMatches > 0)
                        matchedRes = bestRes;
                }
            }

            string matchedOldName = matchedRes?.Name.String;
            if (matchedRes != null && matchedRes.Name != expectedResName)
            {
                if (!module.Resources.Any(r => r.Name.Equals(expectedResName) && r != matchedRes))
                {
                    try
                    {
                        matchedRes.Name = expectedResName;
                        result.ResourcesRenamed++;

                        result.Decisions.Add(new RenameDecision
                        {
                            OriginalName = matchedOldName,
                            NewName = expectedResName,
                            SymbolType = "Resource",
                            Confidence = RenameConfidence.StrongReference,
                            Justification = $"Synchronized strongly typed manifest resource '{matchedOldName}' -> '{expectedResName}'",
                            Applied = true
                        });

                        if (verbose)
                            Tool.Logger.LogInfo($"[SemanticRenamer] Synced resource: {matchedOldName} -> {expectedResName}");
                    }
                    catch
                    {
                        matchedRes.Name = matchedOldName;
                        throw;
                    }
                }
            }

            // Update all ldstr instructions that pass baseName or reference oldBaseName
            foreach (var ins in rmBaseNameInstructions)
            {
                ins.Operand = type.FullName;
            }

            foreach (var m in type.Methods)
            {
                if (!m.HasBody || m.Body.Instructions == null) continue;
                foreach (var ins in m.Body.Instructions)
                {
                    if (ins.OpCode == OpCodes.Ldstr && ins.Operand is string s)
                    {
                        if ((oldBaseName != null && s == oldBaseName) ||
                            (matchedOldName != null && (s + ".resources" == matchedOldName || s == matchedOldName)))
                        {
                            ins.Operand = type.FullName;
                        }
                    }
                }
            }
        }

        private static void RenameResourceProperties(TypeDef type, ReflectionReferenceMap refMap, SemanticRenamerResult result)
        {
            var usedPropNames = new HashSet<string>(StringComparer.Ordinal);

            // First pass: rename ResourceManager and Culture properties if present
            foreach (var prop in type.Properties)
            {
                if (prop.PropertySig?.RetType?.FullName == "System.Resources.ResourceManager")
                {
                    usedPropNames.Add("ResourceManager");
                    if (prop.Name != "ResourceManager")
                    {
                        prop.Name = "ResourceManager";
                        if (prop.GetMethod != null) prop.GetMethod.Name = "get_ResourceManager";
                        result.PropertiesRenamed++;
                    }
                }
                else if (prop.PropertySig?.RetType?.FullName == "System.Globalization.CultureInfo")
                {
                    usedPropNames.Add("Culture");
                    if (prop.Name != "Culture")
                    {
                        prop.Name = "Culture";
                        if (prop.GetMethod != null) prop.GetMethod.Name = "get_Culture";
                        if (prop.SetMethod != null) prop.SetMethod.Name = "set_Culture";
                        result.PropertiesRenamed++;
                    }
                }
            }

            // Second pass: rename data properties based on ldstr resource key
            foreach (var prop in type.Properties)
            {
                if (prop.Name == "ResourceManager" || prop.Name == "Culture")
                    continue;

                // Protect property if accessed via reflection GetProperty(...)
                if (refMap.ExplicitMemberNames.Contains(prop.Name.String))
                {
                    result.Decisions.Add(new RenameDecision
                    {
                        OriginalName = prop.Name.String,
                        NewName = prop.Name.String,
                        SymbolType = "Property",
                        Confidence = RenameConfidence.Ambiguous,
                        Justification = $"Property '{prop.Name}' is accessed via reflection; preserved.",
                        Applied = false
                    });
                    continue;
                }

                var getter = prop.GetMethod;
                if (getter == null || !getter.HasBody || getter.Body.Instructions == null)
                    continue;

                string resourceKey = null;
                foreach (var ins in getter.Body.Instructions)
                {
                    if (ins.OpCode == OpCodes.Ldstr && ins.Operand is string key && !string.IsNullOrEmpty(key))
                    {
                        resourceKey = key;
                        break;
                    }
                }

                if (!string.IsNullOrEmpty(resourceKey))
                {
                    string validPropName = SanitizeIdentifier(resourceKey);
                    string finalPropName = validPropName;
                    int suffix = 2;
                    while (usedPropNames.Contains(finalPropName))
                    {
                        if (prop.Name == finalPropName) break;
                        finalPropName = $"{validPropName}_{suffix++}";
                    }

                    usedPropNames.Add(finalPropName);

                    if (prop.Name != finalPropName)
                    {
                        string oldPropName = prop.Name.String;
                        prop.Name = finalPropName;
                        getter.Name = "get_" + finalPropName;
                        result.PropertiesRenamed++;
                        result.MethodsRenamed++;

                        result.Decisions.Add(new RenameDecision
                        {
                            OriginalName = oldPropName,
                            NewName = finalPropName,
                            SymbolType = "Property",
                            Confidence = RenameConfidence.StrongReference,
                            Justification = $"Restored resource property name from resource key '{resourceKey}'",
                            Applied = true
                        });
                    }
                }
            }
        }

        #endregion

        #region Pass 4: Unprintable / Mangled Normalization

        private static void NormalizeRemainingMangledIdentifiers(ModuleDef module, HashSet<string> usedFullNames, ReflectionReferenceMap refMap, SemanticRenamerResult result, bool verbose)
        {
            foreach (var type in module.GetTypes())
            {
                if (type.IsGlobalModuleType)
                    continue;

                // API & Member Protection: Do NOT normalize public types, nested public types, protected types, compiler generated, or reflection-targeted
                if (type.IsPublic || type.IsNestedPublic || type.IsNestedFamily || type.IsNestedFamilyOrAssembly)
                    continue;

                if (IsCompilerGenerated(type))
                    continue;

                if (refMap.ExplicitTypeNames.Contains(type.Name.String) || refMap.ExplicitTypeNames.Contains(type.FullName))
                    continue;

                // Safety rule: if type or module contains unresolvable dynamic reflection, preserve methods and fields conservatively
                if (refMap.HasUnresolvableModuleScopeReflection || refMap.UnresolvableDynamicReflectionTypes.Contains(type))
                {
                    result.Decisions.Add(new RenameDecision
                    {
                        OriginalName = type.FullName,
                        NewName = type.FullName,
                        SymbolType = "Type",
                        Confidence = RenameConfidence.Ambiguous,
                        Justification = refMap.HasUnresolvableModuleScopeReflection
                            ? $"Module contains unresolvable dynamic reflection call with unknown target type; type '{type.FullName}' members preserved conservatively."
                            : $"Type '{type.FullName}' contains unresolvable dynamic reflection call; members preserved conservatively.",
                        Applied = false
                    });
                    continue;
                }

                // Normalize Type name
                if (IsMangledIdentifier(type.Name.String))
                {
                    string candidate = $"Class_{type.Rid}";
                    string candidateFull = string.IsNullOrEmpty(type.Namespace) ? candidate : type.Namespace + "." + candidate;
                    int sfx = 2;
                    while (usedFullNames.Contains(candidateFull))
                    {
                        candidate = $"Class_{type.Rid}_{sfx++}";
                        candidateFull = string.IsNullOrEmpty(type.Namespace) ? candidate : type.Namespace + "." + candidate;
                    }

                    string oldFullName = type.FullName;
                    string oldName = type.Name.String;
                    usedFullNames.Remove(type.FullName);
                    type.Name = candidate;
                    usedFullNames.Add(type.FullName);
                    result.UnprintableNormalized++;

                    // Update reflection Type.GetType calls
                    foreach (var call in refMap.TypeGetTypeCalls)
                    {
                        if (call.TargetName == oldFullName || call.TargetName == oldName)
                        {
                            call.Instruction.Operand = type.FullName;
                        }
                    }

                    result.Decisions.Add(new RenameDecision
                    {
                        OriginalName = oldFullName,
                        NewName = type.FullName,
                        SymbolType = "Type",
                        Confidence = RenameConfidence.Heuristic,
                        Justification = "Normalized unprintable Unicode identifier to safe metadata name",
                        Applied = true
                    });
                }

                // Normalize Fields
                foreach (var field in type.Fields)
                {
                    if (field.IsPublic || field.IsFamily || field.IsFamilyOrAssembly)
                        continue;
                    if (field.IsSpecialName || field.IsRuntimeSpecialName)
                        continue;
                    if (IsCompilerGenerated(field))
                        continue;
                    if (refMap.ExplicitMemberNames.Contains(field.Name.String))
                        continue;
                    if (IsSerializationMember(field))
                        continue;

                    if (IsMangledIdentifier(field.Name.String))
                    {
                        string oldFName = field.Name.String;
                        field.Name = $"field_{field.Rid}";
                        result.UnprintableNormalized++;

                        result.Decisions.Add(new RenameDecision
                        {
                            OriginalName = oldFName,
                            NewName = field.Name.String,
                            SymbolType = "Field",
                            Confidence = RenameConfidence.Heuristic,
                            Justification = "Normalized unprintable field identifier",
                            Applied = true
                        });
                    }
                }

                // Normalize Methods
                foreach (var method in type.Methods)
                {
                    if (method.IsConstructor || method.IsStaticConstructor || method.IsRuntimeSpecialName ||
                        method.Name == "Invoke" || method.Name == "BeginInvoke" || method.Name == "EndInvoke")
                        continue;

                    // Preserve public, protected, virtual, override, interface, PInvoke, compiler-generated, reflection
                    if (method.IsPublic || method.IsFamily || method.IsFamilyOrAssembly)
                        continue;
                    if (method.IsVirtual || method.IsAbstract || method.HasOverrides || method.Overrides.Count > 0)
                        continue;
                    if (method.IsPinvokeImpl || method.IsNative)
                        continue;
                    if (IsCompilerGenerated(method))
                        continue;
                    if (refMap.ExplicitMemberNames.Contains(method.Name.String))
                        continue;

                    if ((method.Name.StartsWith("get_") || method.Name.StartsWith("set_")) &&
                        refMap.ExplicitMemberNames.Contains(method.Name.String.Substring(4)))
                    {
                        continue;
                    }

                    if (IsMangledIdentifier(method.Name.String))
                    {
                        string oldMName = method.Name.String;
                        if (method.IsGetter)
                            method.Name = $"get_Prop_{method.Rid}";
                        else if (method.IsSetter)
                            method.Name = $"set_Prop_{method.Rid}";
                        else
                            method.Name = $"Method_{method.Rid}";

                        result.UnprintableNormalized++;

                        result.Decisions.Add(new RenameDecision
                        {
                            OriginalName = oldMName,
                            NewName = method.Name.String,
                            SymbolType = "Method",
                            Confidence = RenameConfidence.Heuristic,
                            Justification = "Normalized unprintable method identifier",
                            Applied = true
                        });
                    }

                    // Normalize Parameters
                    if (method.Parameters != null)
                    {
                        foreach (var param in method.Parameters)
                        {
                            if (param.Name != null && IsMangledIdentifier(param.Name))
                            {
                                param.Name = $"p_{param.Index}";
                                result.UnprintableNormalized++;
                            }
                        }
                    }
                }

                // Normalize Properties
                foreach (var prop in type.Properties)
                {
                    if (prop.IsSpecialName) continue;
                    if (IsCompilerGenerated(prop)) continue;
                    if (refMap.ExplicitMemberNames.Contains(prop.Name.String))
                        continue;

                    var getter = prop.GetMethod;
                    var setter = prop.SetMethod;
                    if ((getter != null && (getter.IsPublic || getter.IsFamily)) ||
                        (setter != null && (setter.IsPublic || setter.IsFamily)))
                        continue;

                    if (IsMangledIdentifier(prop.Name.String))
                    {
                        string oldPName = prop.Name.String;
                        prop.Name = $"Property_{prop.Rid}";
                        result.UnprintableNormalized++;

                        result.Decisions.Add(new RenameDecision
                        {
                            OriginalName = oldPName,
                            NewName = prop.Name.String,
                            SymbolType = "Property",
                            Confidence = RenameConfidence.Heuristic,
                            Justification = "Normalized unprintable property identifier",
                            Applied = true
                        });
                    }
                }

                // Normalize Events
                foreach (var ev in type.Events)
                {
                    if (ev.IsSpecialName) continue;
                    if (IsCompilerGenerated(ev)) continue;
                    if (refMap.ExplicitMemberNames.Contains(ev.Name.String))
                        continue;

                    var addM = ev.AddMethod;
                    if (addM != null && (addM.IsPublic || addM.IsFamily))
                        continue;

                    if (IsMangledIdentifier(ev.Name.String))
                    {
                        string oldEName = ev.Name.String;
                        ev.Name = $"Event_{ev.Rid}";
                        result.UnprintableNormalized++;

                        result.Decisions.Add(new RenameDecision
                        {
                            OriginalName = oldEName,
                            NewName = ev.Name.String,
                            SymbolType = "Event",
                            Confidence = RenameConfidence.Heuristic,
                            Justification = "Normalized unprintable event identifier",
                            Applied = true
                        });
                    }
                }
            }
        }

        #endregion

        #region Helpers

        public static bool IsCompilerGeneratedIdentifier(string name)
        {
            if (string.IsNullOrEmpty(name)) return false;
            if (name.StartsWith("<PrivateImplementationDetails>", StringComparison.Ordinal)) return true;
            if (name.StartsWith("__StaticArrayInitTypeSize", StringComparison.Ordinal)) return true;
            if (name.StartsWith("<>c", StringComparison.Ordinal)) return true;
            if (name.StartsWith("<>z__", StringComparison.Ordinal)) return true;
            if (name.StartsWith("CS$<>", StringComparison.Ordinal)) return true;
            if (name.StartsWith("$ArrayType$", StringComparison.Ordinal)) return true;
            if (name.StartsWith("<") && name.Contains(">")) return true;
            return false;
        }

        public static bool IsCompilerGenerated(IHasCustomAttribute member)
        {
            if (member == null) return false;
            if (member is IMemberDef md && IsCompilerGeneratedIdentifier(md.Name))
                return true;
            if (member.HasCustomAttributes)
            {
                foreach (var ca in member.CustomAttributes)
                {
                    string fn = ca.TypeFullName;
                    if (fn == "System.Runtime.CompilerServices.CompilerGeneratedAttribute" ||
                        fn == "System.Runtime.CompilerServices.AsyncStateMachineAttribute" ||
                        fn == "System.Runtime.CompilerServices.IteratorStateMachineAttribute")
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        public static bool IsWinFormsControlOrForm(ITypeDefOrRef type)
        {
            if (type == null) return false;
            var curr = type;
            int depth = 0;
            while (curr != null && depth++ < 20)
            {
                string fn = curr.FullName;
                if (fn == "System.Windows.Forms.Control" ||
                    fn == "System.Windows.Forms.Form" ||
                    fn == "System.Windows.Forms.UserControl" ||
                    fn == "System.Windows.Forms.ContainerControl" ||
                    fn.StartsWith("DevExpress.XtraEditors.XtraForm") ||
                    fn.StartsWith("DevExpress.XtraEditors.XtraUserControl") ||
                    fn.StartsWith("DevExpress.XtraBars.Ribbon.RibbonForm"))
                {
                    return true;
                }
                if (fn == "System.Object") break;

                var td = curr.ResolveTypeDef();
                if (td == null) break;
                curr = td.BaseType;
            }
            return false;
        }

        public static bool IsControlSetName(IMethod method)
        {
            if (method == null || method.Name != "set_Name") return false;
            var dt = method.DeclaringType;
            if (dt == null) return false;
            string fn = dt.FullName;
            if (fn == "System.Windows.Forms.Control" ||
                fn == "System.Windows.Forms.Form" ||
                fn == "System.Windows.Forms.UserControl" ||
                fn.StartsWith("DevExpress.XtraEditors.XtraForm") ||
                fn.StartsWith("DevExpress.XtraEditors.XtraUserControl") ||
                fn.StartsWith("DevExpress.XtraBars.Ribbon.RibbonForm"))
            {
                return true;
            }
            return IsWinFormsControlOrForm(dt);
        }

        private static bool IsSerializationMember(IHasCustomAttribute member)
        {
            if (member == null || !member.HasCustomAttributes) return false;
            foreach (var ca in member.CustomAttributes)
            {
                string fn = ca.TypeFullName;
                if (fn == "System.Runtime.Serialization.DataMemberAttribute" ||
                    fn == "System.Xml.Serialization.XmlElementAttribute" ||
                    fn == "System.Xml.Serialization.XmlAttributeAttribute" ||
                    fn.EndsWith(".JsonPropertyAttribute"))
                {
                    return true;
                }
            }
            return false;
        }

        private static bool IsVowel(char c)
        {
            char lower = char.ToLowerInvariant(c);
            return lower == 'a' || lower == 'e' || lower == 'i' || lower == 'o' || lower == 'u' || lower == 'y';
        }

        private static double ComputeShannonEntropy(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0.0;
            var counts = new Dictionary<char, int>();
            foreach (char c in s)
            {
                counts[c] = counts.TryGetValue(c, out int cnt) ? cnt + 1 : 1;
            }
            double entropy = 0.0;
            double len = s.Length;
            foreach (var kvp in counts)
            {
                double p = kvp.Value / len;
                entropy -= p * Math.Log(p, 2.0);
            }
            return entropy;
        }

        public static bool IsHighEntropyOrRandomAscii(string name)
        {
            if (string.IsNullOrEmpty(name)) return false;
            if (IsCompilerGeneratedIdentifier(name)) return false;

            // ConfuserEx Decodable mode: e.g. _0001, _00a4
            if (DecodableRegex.IsMatch(name)) return true;

            // ConfuserEx MD5 Hash mode: 32-hex character identifier
            if (HexHashRegex.IsMatch(name)) return true;

            // Only inspect identifiers of sufficient length
            if (name.Length < 8) return false;

            // Must be standard alphanumeric + underscore
            if (!ValidIdentifierRegex.IsMatch(name)) return false;

            double entropy = ComputeShannonEntropy(name);

            int vowels = 0;
            int maxLowercaseRun = 0;
            int currentLowercaseRun = 0;
            int upperCount = 0;
            int lowerCount = 0;

            for (int i = 0; i < name.Length; i++)
            {
                char c = name[i];
                if (char.IsLetter(c))
                {
                    if (char.IsUpper(c))
                    {
                        upperCount++;
                        currentLowercaseRun = 0;
                    }
                    else
                    {
                        lowerCount++;
                        currentLowercaseRun++;
                        if (currentLowercaseRun > maxLowercaseRun)
                            maxLowercaseRun = currentLowercaseRun;
                    }

                    if (IsVowel(c))
                    {
                        vowels++;
                    }
                }
            }

            // Pure uppercase constants (e.g. MAX_BUFFER_SIZE) or pure lowercase are not ConfuserEx random letters
            if (upperCount == 0 || lowerCount == 0) return false;

            // ConfuserEx random letters mode requires high Shannon entropy (typically >= 2.8 bits per symbol)
            if (entropy < 2.8) return false;

            // ConfuserEx alternating single-character casing (e.g. aBcDeFgH) where lowercase runs never exceed 1
            if (upperCount >= 3 && lowerCount >= 3 && maxLowercaseRun <= 1)
                return true;

            // Token-based structural decomposition (CamelCase / PascalCase / acronyms)
            var matches = IdentifierTokenRegex.Matches(name);
            if (matches.Count > 0)
            {
                int meaningfulTokens = 0;
                int junkTokens = 0;
                int singleLetterTokens = 0;
                int solidWords = 0;

                bool hasUnverifiedAllCapsCluster = false;
                foreach (Match m in matches)
                {
                    string tok = m.Value;
                    bool hasVowel = false;
                    for (int k = 0; k < tok.Length; k++)
                    {
                        if (IsVowel(tok[k])) { hasVowel = true; break; }
                    }

                    bool isAllUpper = tok.Length >= 2 && tok.All(char.IsUpper);
                    bool isAbbrev = CommonAbbreviationWords.Contains(tok);
                    bool isDigit = char.IsDigit(tok[0]);

                    bool isAllUpperAcronym = false;
                    if (isAllUpper)
                    {
                        if (CanSegmentAllCapsAcronym(tok))
                        {
                            isAllUpperAcronym = true;
                        }
                        else
                        {
                            // Unsegmented all-caps token (e.g. KPX, QXZ, ZQX, KPXQTZVRM, ABCDWXYZ)
                            int consRun = 0;
                            int maxCons = 0;
                            for (int ci = 0; ci < tok.Length; ci++)
                            {
                                if (!IsVowel(tok[ci]))
                                {
                                    consRun++;
                                    if (consRun > maxCons) maxCons = consRun;
                                }
                                else
                                {
                                    consRun = 0;
                                }
                            }
                            if (maxCons >= 5 || (!hasVowel && tok.Length >= 3))
                            {
                                hasUnverifiedAllCapsCluster = true;
                            }
                            else if (hasVowel && maxCons < 4)
                            {
                                isAllUpperAcronym = true;
                            }
                        }
                    }

                    if (tok.Length == 1 && char.IsLetter(tok[0]))
                    {
                        singleLetterTokens++;
                    }

                    if (hasVowel || isAllUpperAcronym || isAbbrev || isDigit)
                    {
                        meaningfulTokens++;
                        if (hasVowel && tok.Length >= 4)
                        {
                            solidWords++;
                        }
                    }
                    else
                    {
                        junkTokens++;
                    }
                }

                if (hasUnverifiedAllCapsCluster)
                    return true;

                // If EVERY token is meaningful/valid, the identifier is strictly legitimate
                if (junkTokens == 0)
                    return false;

                // If majority of tokens are short junk fragments without vowels or multiple unverified consonant clusters
                // (e.g. KpxQtzProcessor with 2 junk vs 1 meaningful, or KpxQtzVrmProcessor with 3 junk vs 1 meaningful)
                if (junkTokens >= 2 && junkTokens > meaningfulTokens)
                    return true;

                if (junkTokens >= 3)
                    return true;
            }

            // ConfuserEx random letters without vowels in mixed-case string containing junk tokens
            if (vowels == 0 && upperCount >= 2 && lowerCount >= 2)
                return true;

            // Consonant cluster detection strictly WITHIN an individual token (NEVER crossing token boundaries)
            foreach (Match m in matches)
            {
                string tok = m.Value;
                int tokConsRun = 0;
                bool hasLowerInTok = false;
                bool hasUpperInTok = false;
                for (int i = 0; i < tok.Length; i++)
                {
                    char c = tok[i];
                    if (char.IsLetter(c))
                    {
                        if (!IsVowel(c))
                        {
                            tokConsRun++;
                            if (char.IsLower(c)) hasLowerInTok = true;
                            if (char.IsUpper(c)) hasUpperInTok = true;

                            // Mixed-case consonant cluster of >= 5 in a single token
                            if (tokConsRun >= 5 && hasLowerInTok && hasUpperInTok)
                                return true;
                        }
                        else
                        {
                            tokConsRun = 0;
                            hasLowerInTok = false;
                            hasUpperInTok = false;
                        }
                    }
                    else
                    {
                        tokConsRun = 0;
                        hasLowerInTok = false;
                        hasUpperInTok = false;
                    }
                }
            }

            return false;
        }

        public static bool IsMangledIdentifier(string name)
        {
            if (string.IsNullOrEmpty(name)) return false;
            if (IsCompilerGeneratedIdentifier(name)) return false;

            foreach (char c in name)
            {
                int code = (int)c;
                // Zero-width and formatting unicode characters (ConfuserEx Unicode mode)
                if (code >= 0x2000 && code <= 0x206F) return true;
                if (code >= 0xFE00 && code <= 0xFEFF) return true;
                if (char.IsControl(c) || char.GetUnicodeCategory(c) == UnicodeCategory.Format) return true;

                // ConfuserEx unprintable/ASCII scrambled chars (strictly excluding <, >, and $)
                if (c == '#' || c == '%' || c == '\'' || c == '\\' || c == '/' ||
                    c == '{' || c == '}' || c == '~' || c == '!' || c == '^' || c == '?' ||
                    c == '*' || c == '|' || c == ';' || c == '=')
                    return true;
            }

            // ConfuserEx Decodable, MD5 hash, and high-entropy / Letters modes
            if (IsHighEntropyOrRandomAscii(name))
                return true;

            return false;
        }

        public static bool IsValidIdentifier(string name)
        {
            if (string.IsNullOrEmpty(name)) return false;
            return ValidIdentifierRegex.IsMatch(name) && !IsMangledIdentifier(name);
        }

        public static string SanitizeIdentifier(string name)
        {
            if (string.IsNullOrEmpty(name)) return "Item";

            var sb = new StringBuilder();
            if (char.IsDigit(name[0]))
                sb.Append('_');

            foreach (char c in name)
            {
                if (char.IsLetterOrDigit(c) || c == '_')
                    sb.Append(c);
                else
                    sb.Append('_');
            }

            string result = sb.ToString();
            return IsValidIdentifier(result) ? result : "_" + result;
        }

        private static bool IsObfuscatedOrGenericTypeName(string name)
        {
            if (string.IsNullOrEmpty(name)) return true;
            if (IsMangledIdentifier(name)) return true;
            if (name.StartsWith("Class", StringComparison.OrdinalIgnoreCase) && int.TryParse(name.Substring(5), out _)) return true;
            if (name.StartsWith("Form", StringComparison.OrdinalIgnoreCase) && int.TryParse(name.Substring(4), out _)) return true;
            if (name.StartsWith("Struct", StringComparison.OrdinalIgnoreCase) && int.TryParse(name.Substring(6), out _)) return true;
            return false;
        }

        private static bool IsObfuscatedOrGenericFieldName(string name)
        {
            if (string.IsNullOrEmpty(name)) return true;
            if (IsMangledIdentifier(name)) return true;
            if (name.StartsWith("field_", StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private static bool IsObfuscatedOrGenericMethodName(string name)
        {
            if (string.IsNullOrEmpty(name)) return true;
            if (IsMangledIdentifier(name)) return true;
            if (name.StartsWith("method_", StringComparison.OrdinalIgnoreCase)) return true;
            if (name.StartsWith("smethod_", StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private static string GetAssemblyRootNamespace(ModuleDef module)
        {
            string asmName = module.Assembly?.Name?.String;
            if (!string.IsNullOrEmpty(asmName))
                return asmName;

            var firstWithNs = module.GetTypes().FirstOrDefault(t => !string.IsNullOrEmpty(t.Namespace));
            return firstWithNs?.Namespace?.String ?? "DeobfuscatedApp";
        }

        #endregion
    }
}
