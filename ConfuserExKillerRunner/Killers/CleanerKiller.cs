using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Tool;

namespace ConfuserExKillerRunner.Killers
{
    public sealed class CleanerResult
    {
        public int StrippedHooksCount { get; set; }
        public int RemovedMethodsCount { get; set; }
        public List<string> StrippedDetails { get; set; } = new List<string>();
    }

    public static class CleanerKiller
    {
        public static CleanerResult StripProtectorHooks(ModuleDef module)
        {
            if (module == null) throw new ArgumentNullException(nameof(module));

            var result = new CleanerResult();
            var cctor = module.GlobalType?.FindStaticConstructor();
            if (cctor == null || !cctor.HasBody)
                return result;

            var methodsToRemove = new HashSet<MethodDef>();
            var instructions = cctor.Body.Instructions;

            for (int i = 0; i < instructions.Count; i++)
            {
                var inst = instructions[i];
                if (inst.OpCode != OpCodes.Call && inst.OpCode != OpCodes.Callvirt)
                    continue;

                if (!(inst.Operand is IMethod calledMethod))
                    continue;

                var methodDef = calledMethod.ResolveMethodDef();
                if (methodDef == null || !methodDef.HasBody)
                    continue;

                // Check if target method is a known ConfuserEx protector initializer
                string hookType = ClassifyProtectorMethod(methodDef);
                if (hookType != null)
                {
                    inst.OpCode = OpCodes.Nop;
                    inst.Operand = null;
                    methodsToRemove.Add(methodDef);
                    result.StrippedHooksCount++;
                    result.StrippedDetails.Add($"{hookType} hook removed from <Module>.cctor: {methodDef.Name}");
                    Logger.LogInfo($"[CleanerKiller] Nulled {hookType} initializer call to {methodDef.Name} in <Module>.cctor");
                }
            }

            // Remove identified protector methods from <Module>
            if (module.GlobalType != null)
            {
                foreach (var m in methodsToRemove)
                {
                    var declType = m.DeclaringType;
                    if (declType != null && declType.Methods.Contains(m))
                    {
                        declType.Methods.Remove(m);
                        result.RemovedMethodsCount++;
                        Logger.LogInfo($"[CleanerKiller] Removed protector method {m.Name} from {declType.Name}");
                    }
                }

                // Check and remove unused native P/Invokes in <Module>
                var pinvokesToRemove = new List<MethodDef>();
                foreach (var m in module.GlobalType.Methods)
                {
                    if (m.IsPinvokeImpl && m.ImplMap != null)
                    {
                        string fn = m.ImplMap.Name?.String ?? m.Name.String;
                        if (IsProtectorPinvoke(fn))
                        {
                            // Check if any other method still calls this pinvoke
                            if (!IsReferencedInModule(module, m))
                                pinvokesToRemove.Add(m);
                        }
                    }
                }

                foreach (var p in pinvokesToRemove)
                {
                    module.GlobalType.Methods.Remove(p);
                    result.RemovedMethodsCount++;
                    Logger.LogInfo($"[CleanerKiller] Removed unused protector P/Invoke: {p.Name} ({p.ImplMap?.Name})");
                }
            }

            return result;
        }

        private static string ClassifyProtectorMethod(MethodDef method)
        {
            if (method.DeclaringType != null && !method.DeclaringType.IsGlobalModuleType)
                return null;

            bool hasVirtualProtect = false;
            bool hasDebuggerCheck = false;
            bool hasSectionLoop = false;
            bool hasHINSTANCE = false;

            foreach (var inst in method.Body.Instructions)
            {
                if (inst.Operand is IMethod called)
                {
                    string fullName = called.FullName;
                    if (fullName.IndexOf("GetHINSTANCE", StringComparison.OrdinalIgnoreCase) >= 0)
                        hasHINSTANCE = true;
                    if (fullName.IndexOf("IsAttached", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        fullName.IndexOf("CheckRemoteDebuggerPresent", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        fullName.IndexOf("IsDebuggerPresent", StringComparison.OrdinalIgnoreCase) >= 0)
                        hasDebuggerCheck = true;
                    if (fullName.IndexOf("VirtualProtect", StringComparison.OrdinalIgnoreCase) >= 0)
                        hasVirtualProtect = true;
                }

                if (inst.OpCode == OpCodes.Ldfld || inst.OpCode == OpCodes.Stfld)
                {
                    if (inst.Operand is IField field && field.Name.String.IndexOf("VirtualAddress", StringComparison.OrdinalIgnoreCase) >= 0)
                        hasSectionLoop = true;
                }
            }

            if (hasHINSTANCE || (hasVirtualProtect && hasSectionLoop))
                return "Anti-Tamper";
            if (hasDebuggerCheck)
                return "Anti-Debug";
            if (hasVirtualProtect)
                return "Anti-Dump";

            return null;
        }

        private static bool IsProtectorPinvoke(string name)
        {
            if (string.IsNullOrEmpty(name)) return false;
            return string.Equals(name, "VirtualProtect", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "IsDebuggerPresent", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "CheckRemoteDebuggerPresent", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "OutputDebugStringA", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "OutputDebugStringW", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsReferencedInModule(ModuleDef module, MethodDef target)
        {
            foreach (var type in module.GetTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody || method == target) continue;
                    foreach (var inst in method.Body.Instructions)
                    {
                        if (inst.Operand is IMethod called && called.ResolveMethodDef() == target)
                            return true;
                    }
                }
            }
            return false;
        }
    }
}
