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
        public static CleanerResult StripProtectorHooks(ModuleDef module, bool resourcesDecrypted = false, bool constantsDecrypted = false, bool antiTamperDecrypted = false)
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
                string hookType = ClassifyProtectorMethod(methodDef, resourcesDecrypted, constantsDecrypted, antiTamperDecrypted);
                if (hookType != null)
                {
                    inst.OpCode = OpCodes.Nop;
                    inst.Operand = null;

                    // Clean up preceding argument push instructions if the stripped method consumed parameters
                    int paramsCount = methodDef.Parameters?.Count ?? 0;
                    for (int p = 1; p <= paramsCount && (i - p) >= 0; p++)
                    {
                        var prev = instructions[i - p];
                        if (prev.OpCode == OpCodes.Ldnull || prev.OpCode == OpCodes.Ldarg_0 ||
                            prev.OpCode == OpCodes.Ldc_I4 || prev.OpCode == OpCodes.Ldc_I4_0 ||
                            prev.OpCode == OpCodes.Ldtoken)
                        {
                            prev.OpCode = OpCodes.Nop;
                            prev.Operand = null;
                        }
                    }

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
                        if (!IsReferencedInModule(module, m))
                        {
                            declType.Methods.Remove(m);
                            result.RemovedMethodsCount++;
                            Logger.LogInfo($"[CleanerKiller] Removed unused protector method {m.Name} from {declType.Name}");
                        }
                        else
                        {
                            Logger.LogWarning($"[CleanerKiller] Retaining protector method {m.Name} in {declType.Name}: live references remain in module.");
                        }
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

        private static string ClassifyProtectorMethod(MethodDef method, bool resourcesDecrypted, bool constantsDecrypted, bool antiTamperDecrypted)
        {
            if (method.DeclaringType != null && !method.DeclaringType.IsGlobalModuleType)
                return null;

            bool hasVirtualProtect = false;
            bool hasDebuggerCheck = false;
            bool hasSectionLoop = false;
            bool hasResourceResolve = false;
            bool hasInitializeArray = false;

            foreach (var inst in method.Body.Instructions)
            {
                if (inst.Operand is IMethod called)
                {
                    string fullName = called.FullName;
                    if (fullName.IndexOf("IsAttached", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        fullName.IndexOf("CheckRemoteDebuggerPresent", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        fullName.IndexOf("IsDebuggerPresent", StringComparison.OrdinalIgnoreCase) >= 0)
                        hasDebuggerCheck = true;
                    if (fullName.IndexOf("VirtualProtect", StringComparison.OrdinalIgnoreCase) >= 0)
                        hasVirtualProtect = true;
                    if (fullName.IndexOf("add_ResourceResolve", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        fullName.IndexOf("add_AssemblyResolve", StringComparison.OrdinalIgnoreCase) >= 0)
                        hasResourceResolve = true;
                    if (fullName.IndexOf("InitializeArray", StringComparison.OrdinalIgnoreCase) >= 0)
                        hasInitializeArray = true;
                }

                if (inst.OpCode == OpCodes.Ldfld || inst.OpCode == OpCodes.Stfld)
                {
                    if (inst.Operand is IField field && field.Name.String.IndexOf("VirtualAddress", StringComparison.OrdinalIgnoreCase) >= 0)
                        hasSectionLoop = true;
                }
            }

            if (hasVirtualProtect && hasSectionLoop)
            {
                if (antiTamperDecrypted)
                    return "Anti-Tamper";

                Logger.LogWarning($"[CleanerKiller] Retaining Anti-Tamper hook in <Module>.cctor: Anti-Tamper sections have not been confirmed as decrypted (execution disabled or decryption unconfirmed).");
                return null;
            }
            if (IsExactStubProtectorCall(method))
            {
                return "Protector-Stub";
            }
            if (hasDebuggerCheck)
                return "Anti-Debug";
            if (hasVirtualProtect)
                return "Anti-Dump";
            if (hasResourceResolve && resourcesDecrypted)
                return "Resource-Resolver";
            if (hasInitializeArray && constantsDecrypted && method.Parameters.Count == 0 && IsConfuserConstantBufferInitializer(method))
                return "Constant-Buffer";

            return null;
        }

        internal static bool IsExactStubProtectorCall(MethodDef method)
        {
            if (method == null || !method.HasBody || method.Body.Instructions == null)
                return false;

            if (!method.IsStatic)
                return false;

            if (method.DeclaringType != null && !method.DeclaringType.IsGlobalModuleType)
                return false;

            // Stubs must have no exception handlers and no local variables
            if (method.Body.HasExceptionHandlers || method.Body.Variables.Count > 0)
                return false;

            var nonNops = method.Body.Instructions.Where(i => i.OpCode != OpCodes.Nop).ToList();

            // Canonical 4-instruction void stub: ldnull/ldarg -> call Marshal.GetHINSTANCE -> pop -> ret
            if (nonNops.Count == 4)
            {
                if (method.ReturnType == null || method.ReturnType.ElementType != ElementType.Void)
                    return false;

                if (!IsValidModuleLoadInstruction(nonNops[0], method))
                    return false;

                if (nonNops[1].OpCode != OpCodes.Call)
                    return false;
                if (!(nonNops[1].Operand is IMethod called && IsMarshalGetHINSTANCE(called)))
                    return false;

                if (nonNops[2].OpCode != OpCodes.Pop)
                    return false;

                if (nonNops[3].OpCode != OpCodes.Ret)
                    return false;

                return true;
            }

            // Canonical 3-instruction IntPtr stub: ldnull/ldarg -> call Marshal.GetHINSTANCE -> ret
            if (nonNops.Count == 3)
            {
                if (method.ReturnType == null || (method.ReturnType.ElementType != ElementType.I && method.ReturnType.TypeName != "IntPtr"))
                    return false;

                if (!IsValidModuleLoadInstruction(nonNops[0], method))
                    return false;

                if (nonNops[1].OpCode != OpCodes.Call)
                    return false;
                if (!(nonNops[1].Operand is IMethod called && IsMarshalGetHINSTANCE(called)))
                    return false;

                if (nonNops[2].OpCode != OpCodes.Ret)
                    return false;

                return true;
            }

            return false;
        }

        internal static bool IsMarshalGetHINSTANCE(IMethod called)
        {
            if (called == null || called.Name != "GetHINSTANCE")
                return false;

            var decl = called.DeclaringType;
            if (decl == null || decl.Name != "Marshal" || decl.Namespace != "System.Runtime.InteropServices")
                return false;

            // Verify resolving scope / assembly
            string asmName = decl.DefinitionAssembly?.Name?.String;
            if (string.IsNullOrEmpty(asmName) && decl.Scope != null)
            {
                asmName = decl.Scope.ScopeName;
                if (asmName != null && asmName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                    asmName = asmName.Substring(0, asmName.Length - 4);
            }

            if (!string.IsNullOrEmpty(asmName))
            {
                bool isFrameworkAssembly =
                    asmName.Equals("mscorlib", StringComparison.OrdinalIgnoreCase) ||
                    asmName.Equals("System.Runtime.InteropServices", StringComparison.OrdinalIgnoreCase) ||
                    asmName.Equals("System.Runtime", StringComparison.OrdinalIgnoreCase) ||
                    asmName.Equals("netstandard", StringComparison.OrdinalIgnoreCase);

                if (!isFrameworkAssembly)
                    return false;
            }
            else
            {
                // If declaring type is defined in the current module (TypeDef) or has ModuleDef scope,
                // it is an internal application type and not the framework BCL Marshal class.
                if (decl is TypeDef || (decl is TypeRef tr && tr.ResolutionScope is ModuleDef))
                    return false;
            }

            var sig = called.MethodSig;
            if (sig == null || sig.HasThis)
                return false;

            if (sig.Params.Count != 1)
                return false;

            var p0 = sig.Params[0];
            if (p0 == null || p0.TypeName != "Module" || p0.Namespace != "System.Reflection")
                return false;

            if (sig.RetType == null)
                return false;

            if (sig.RetType.ElementType != ElementType.I && sig.RetType.TypeName != "IntPtr")
                return false;

            return true;
        }

        private static bool IsValidModuleLoadInstruction(Instruction inst, MethodDef method)
        {
            if (inst == null)
                return false;

            if (inst.OpCode == OpCodes.Ldnull)
            {
                return method.Parameters.Count == 0;
            }

            if (inst.OpCode == OpCodes.Ldarg_0)
            {
                return method.Parameters.Count == 1 &&
                       method.Parameters[0].Type != null &&
                       method.Parameters[0].Type.TypeName == "Module" &&
                       method.Parameters[0].Type.Namespace == "System.Reflection";
            }

            if (inst.OpCode == OpCodes.Ldarg)
            {
                if (inst.Operand is Parameter p && p.Index == 0)
                {
                    return method.Parameters.Count == 1 &&
                           method.Parameters[0].Type != null &&
                           method.Parameters[0].Type.TypeName == "Module" &&
                           method.Parameters[0].Type.Namespace == "System.Reflection";
                }
            }

            return false;
        }

        private static bool IsConfuserConstantBufferInitializer(MethodDef method)
        {
            // Verify method initializes a static byte/int array from a private implementation field in <Module>
            bool loadsFieldToken = false;
            foreach (var inst in method.Body.Instructions)
            {
                if (inst.OpCode == OpCodes.Ldtoken && inst.Operand is IField field)
                {
                    var fd = field.ResolveFieldDef();
                    if (fd != null && fd.DeclaringType != null && fd.DeclaringType.IsGlobalModuleType && fd.HasFieldRVA)
                        loadsFieldToken = true;
                }
            }
            return loadsFieldToken;
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

        internal static bool IsReferencedInModule(ModuleDef module, MethodDef target)
        {
            if (module == null || target == null) return false;
            foreach (var type in module.GetTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody || method == target) continue;
                    foreach (var inst in method.Body.Instructions)
                    {
                        if (inst.Operand is IMethod called && (called.ResolveMethodDef() == target || called == target))
                            return true;
                        if (inst.Operand is MethodDef md && md == target)
                            return true;
                    }
                }
            }
            return false;
        }
    }
}
