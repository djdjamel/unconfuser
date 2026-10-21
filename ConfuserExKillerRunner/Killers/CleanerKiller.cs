using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.PE;
using Tool;
using ConfuserExKillerRunner.Analysis;
using ConfuserExKillerRunner.Core;

namespace ConfuserExKillerRunner.Killers
{
    public sealed class CleanerResult
    {
        public int StrippedHooksCount { get; set; }
        public int RemovedMethodsCount { get; set; }
        public List<string> StrippedDetails { get; set; } = new List<string>();
        public List<string> RetainedHooksDetails { get; set; } = new List<string>();
        public List<HookTraceRecord> HookRecords { get; set; } = new List<HookTraceRecord>();
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

            // Collect all branch targets within <Module>..cctor to protect control-flow targets
            var branchTargets = new HashSet<Instruction>();
            foreach (var ins in instructions)
            {
                if (ins == null) continue;
                if (ins.Operand is Instruction singleTarget)
                {
                    if (singleTarget != null) branchTargets.Add(singleTarget);
                }
                else if (ins.Operand is IList<Instruction> switchTargets)
                {
                    foreach (var st in switchTargets)
                        if (st != null) branchTargets.Add(st);
                }
                else if (ins.Operand is Instruction[] switchArray)
                {
                    foreach (var st in switchArray)
                        if (st != null) branchTargets.Add(st);
                }
            }

            // Collect all exception handler boundaries within <Module>..cctor
            var ehBoundaries = new HashSet<Instruction>();
            if (cctor.Body.HasExceptionHandlers)
            {
                foreach (var eh in cctor.Body.ExceptionHandlers)
                {
                    if (eh.TryStart != null) ehBoundaries.Add(eh.TryStart);
                    if (eh.TryEnd != null) ehBoundaries.Add(eh.TryEnd);
                    if (eh.HandlerStart != null) ehBoundaries.Add(eh.HandlerStart);
                    if (eh.HandlerEnd != null) ehBoundaries.Add(eh.HandlerEnd);
                    if (eh.FilterStart != null) ehBoundaries.Add(eh.FilterStart);
                }
            }

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
                string hookType = ClassifyProtectorMethod(methodDef, resourcesDecrypted, constantsDecrypted, antiTamperDecrypted, result);
                if (hookType != null)
                {
                    string hookId = $"Hook_{hookType}_{methodDef.Name}";
                    int paramsCount = methodDef.Parameters?.Count ?? 0;
                    if (calledMethod.MethodSig != null && calledMethod.MethodSig.HasThis)
                        paramsCount++;

                    // Verify that all arguments consumed by the hook call can be unambiguously identified,
                    // do not conflict with branch targets or EH boundaries, and do not involve complex multi-instruction sequences.
                    if (!TryIdentifyArgumentProducers(cctor, i, paramsCount, branchTargets, ehBoundaries, out var toNeutralize))
                    {
                        string msg = $"Retaining {hookType} hook {methodDef.Name} in <Module>.cctor: argument producers cannot be safely or unambiguously identified.";
                        Logger.LogWarning($"[CleanerKiller] {msg}");
                        result.RetainedHooksDetails.Add(msg);
                        result.HookRecords.Add(new HookTraceRecord
                        {
                            HookId = hookId,
                            HookType = hookType,
                            DeclaringType = cctor.DeclaringType?.FullName ?? "<Module>",
                            MethodName = methodDef.Name?.String ?? string.Empty,
                            Action = "Retained",
                            Reason = msg,
                            Confidence = "HIGH"
                        });
                        continue;
                    }

                    // If the hook method returns a non-void value (such as IntPtr), find and verify its consumer (e.g. pop)
                    bool returnsValue = methodDef.ReturnType != null && methodDef.ReturnType.ElementType != ElementType.Void;
                    if (returnsValue)
                    {
                        if (!TryIdentifyReturnConsumer(cctor, i, branchTargets, ehBoundaries, out var consumerPop))
                        {
                            string msg = $"Retaining {hookType} hook {methodDef.Name} in <Module>.cctor: non-void return value consumer cannot be safely or unambiguously identified.";
                            Logger.LogWarning($"[CleanerKiller] {msg}");
                            result.RetainedHooksDetails.Add(msg);
                            result.HookRecords.Add(new HookTraceRecord
                            {
                                HookId = hookId,
                                HookType = hookType,
                                DeclaringType = cctor.DeclaringType?.FullName ?? "<Module>",
                                MethodName = methodDef.Name?.String ?? string.Empty,
                                Action = "Retained",
                                Reason = msg,
                                Confidence = "HIGH"
                            });
                            continue;
                        }
                        toNeutralize.Add(consumerPop);
                    }

                    // Save in-place snapshot of original opcodes and operands
                    var originalStates = toNeutralize.Select(n => (Instruction: n, OpCode: n.OpCode, Operand: n.Operand)).ToList();

                    // Apply transformation in place: nop call, producers, and consumer
                    foreach (var n in toNeutralize)
                    {
                        n.OpCode = OpCodes.Nop;
                        n.Operand = null;
                    }

                    // Atomic post-strip audit: ensure <Module>..cctor remains structurally valid
                    var auditReport = new AuditReport { CanLoad = true };
                    QualityAuditor.AuditMethod(cctor, auditReport);
                    if (!auditReport.StructuralAuditPassed)
                    {
                        // In-place rollback: restore original opcodes and operands directly on existing instruction objects
                        foreach (var s in originalStates)
                        {
                            s.Instruction.OpCode = s.OpCode;
                            s.Instruction.Operand = s.Operand;
                        }

                        string rollbackMsg = $"Rollback in <Module>.cctor: stripping hook {methodDef.Name} failed structural IL audit ({string.Join("; ", auditReport.Errors)}). Original IL restored.";
                        Logger.LogWarning($"[CleanerKiller] {rollbackMsg}");
                        result.RetainedHooksDetails.Add(rollbackMsg);
                        result.HookRecords.Add(new HookTraceRecord
                        {
                            HookId = hookId,
                            HookType = hookType,
                            DeclaringType = cctor.DeclaringType?.FullName ?? "<Module>",
                            MethodName = methodDef.Name?.String ?? string.Empty,
                            Action = "Retained",
                            Reason = rollbackMsg,
                            Confidence = "HIGH"
                        });
                        continue;
                    }

                    methodsToRemove.Add(methodDef);
                    result.StrippedHooksCount++;
                    result.StrippedDetails.Add($"{hookType} hook removed from <Module>.cctor: {methodDef.Name}");
                    result.HookRecords.Add(new HookTraceRecord
                    {
                        HookId = hookId,
                        HookType = hookType,
                        DeclaringType = cctor.DeclaringType?.FullName ?? "<Module>",
                        MethodName = methodDef.Name?.String ?? string.Empty,
                        Action = "Stripped",
                        Reason = $"Safely stripped {hookType} initializer call to {methodDef.Name} and {toNeutralize.Count - 1} related instruction(s) in <Module>.cctor",
                        Confidence = "HIGH"
                    });
                    Logger.LogInfo($"[CleanerKiller] Safely stripped {hookType} initializer call to {methodDef.Name} and {toNeutralize.Count - 1} related instruction(s) in <Module>.cctor");
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
                            string msg = $"Retaining protector method {m.Name} in {declType.Name}: live references remain in module.";
                            Logger.LogWarning($"[CleanerKiller] {msg}");
                            result.RetainedHooksDetails.Add(msg);
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

        private static string ClassifyProtectorMethod(MethodDef method, bool resourcesDecrypted, bool constantsDecrypted, bool antiTamperDecrypted, CleanerResult result = null)
        {
            if (method.DeclaringType != null && !method.DeclaringType.IsGlobalModuleType)
                return null;
            if (!method.HasBody || method.Body.Instructions == null || method.Body.Instructions.Count == 0)
                return null;

            bool hasVirtualProtect = false;
            bool hasDebuggerCheck = false;
            bool hasSectionField = false;
            bool hasResourceResolve = false;
            bool hasInitializeArray = false;
            bool hasPointerConversion = false;
            bool hasPointerIndirection = false;
            bool hasPointerWrite = false;
            bool hasCipherArithmetic = false;
            bool hasBackwardBranch = false;
            bool hasPeHeaderOffset = false;

            var instructions = method.Body.Instructions;
            for (int idx = 0; idx < instructions.Count; idx++)
            {
                var inst = instructions[idx];
                if (inst.Operand is IMethod called)
                {
                    string fullName = called.FullName;
                    if (fullName.IndexOf("IsAttached", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        fullName.IndexOf("CheckRemoteDebuggerPresent", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        fullName.IndexOf("IsDebuggerPresent", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        fullName.IndexOf("OutputDebugString", StringComparison.OrdinalIgnoreCase) >= 0)
                        hasDebuggerCheck = true;
                    if (fullName.IndexOf("VirtualProtect", StringComparison.OrdinalIgnoreCase) >= 0)
                        hasVirtualProtect = true;
                    if (fullName.IndexOf("add_ResourceResolve", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        fullName.IndexOf("add_AssemblyResolve", StringComparison.OrdinalIgnoreCase) >= 0)
                        hasResourceResolve = true;
                    if (fullName.IndexOf("InitializeArray", StringComparison.OrdinalIgnoreCase) >= 0)
                        hasInitializeArray = true;
                    if (fullName.IndexOf("ZeroMemory", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        fullName.IndexOf("memset", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        hasPointerWrite = true;
                    }
                }

                if (inst.OpCode == OpCodes.Ldfld || inst.OpCode == OpCodes.Stfld || inst.OpCode == OpCodes.Ldflda)
                {
                    if (inst.Operand is IField field)
                    {
                        string fName = field.Name?.String ?? string.Empty;
                        if (fName.IndexOf("VirtualAddress", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            fName.IndexOf("PointerToRawData", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            fName.IndexOf("SizeOfRawData", StringComparison.OrdinalIgnoreCase) >= 0)
                            hasSectionField = true;
                    }
                }

                if ((inst.OpCode == OpCodes.Ldc_I4 && inst.Operand is int iVal && iVal == 0x3c) ||
                    (inst.OpCode == OpCodes.Ldc_I4_S && inst.Operand is sbyte sbVal && sbVal == 0x3c) ||
                    (inst.OpCode == OpCodes.Ldc_I4_S && inst.Operand is byte bVal && bVal == 0x3c))
                {
                    hasPeHeaderOffset = true;
                }

                var code = inst.OpCode.Code;
                if (code == Code.Conv_U || code == Code.Conv_I || code == Code.Conv_U4 || code == Code.Conv_U8 || code == Code.Conv_I4 || code == Code.Conv_I8)
                    hasPointerConversion = true;

                if (code == Code.Ldind_I1 || code == Code.Ldind_U1 || code == Code.Ldind_I2 || code == Code.Ldind_U2 ||
                    code == Code.Ldind_I4 || code == Code.Ldind_U4 || code == Code.Ldind_I8 || code == Code.Ldind_I ||
                    code == Code.Ldind_R4 || code == Code.Ldind_R8 || code == Code.Localloc)
                    hasPointerIndirection = true;

                if (code == Code.Stind_I1 || code == Code.Stind_I2 || code == Code.Stind_I4 || code == Code.Stind_I8 ||
                    code == Code.Stind_I || code == Code.Stind_R4 || code == Code.Stind_R8 || code == Code.Cpblk)
                {
                    hasPointerWrite = true;
                }

                if (code == Code.Initblk)
                {
                    hasPointerWrite = true;
                }

                if (code == Code.Xor || code == Code.Not || code == Code.Shl || code == Code.Shr || code == Code.Shr_Un)
                {
                    hasCipherArithmetic = true;
                }

                if (inst.Operand is Instruction targetInst)
                {
                    int targetIdx = instructions.IndexOf(targetInst);
                    if (targetIdx >= 0 && targetIdx <= idx)
                        hasBackwardBranch = true;
                }
                else if (inst.Operand is IList<Instruction> switchTargets)
                {
                    foreach (var st in switchTargets)
                    {
                        int targetIdx = instructions.IndexOf(st);
                        if (targetIdx >= 0 && targetIdx <= idx)
                            hasBackwardBranch = true;
                    }
                }
            }

            // 1. Anti-Tamper: calls VirtualProtect and exhibits section fields or pointer decryption characteristics
            bool isAntiTamper = hasVirtualProtect && (
                hasSectionField ||
                (hasPointerWrite && hasCipherArithmetic) ||
                ((hasPointerConversion || hasPointerIndirection) && hasBackwardBranch && hasCipherArithmetic) ||
                (hasPeHeaderOffset && hasCipherArithmetic)
            );

            if (isAntiTamper)
            {
                if (antiTamperDecrypted)
                    return "Anti-Tamper";

                string msg = "Retaining Anti-Tamper hook in <Module>.cctor: Anti-Tamper sections have not been confirmed as decrypted (execution disabled or decryption unconfirmed).";
                Logger.LogWarning($"[CleanerKiller] {msg}");
                result?.RetainedHooksDetails.Add(msg);
                result?.HookRecords.Add(new HookTraceRecord
                {
                    HookId = $"Hook_Anti-Tamper_{method.Name}",
                    HookType = "Anti-Tamper",
                    DeclaringType = method.DeclaringType?.FullName ?? "<Module>",
                    MethodName = method.Name?.String ?? string.Empty,
                    Action = "Retained",
                    Reason = msg,
                    Confidence = "HIGH"
                });
                return null;
            }

            // 2. Canonical Stub calls
            if (IsExactStubProtectorCall(method))
            {
                return "Protector-Stub";
            }

            // 3. Anti-Dump: calls VirtualProtect to wipe/zero headers without decryption cipher arithmetic, debugger checks, or section metadata fields.
            // MUST explicitly exhibit proven PE header zeroing/wiping behavior (e.g. stind/initblk with 0 or ZeroMemory/memset structurally linked to the module base or PE header pointer).
            // Merely reading an offset 0x3c, or calling VirtualProtect with an unlinked memory zeroing, is ambiguous and must NOT classify as Anti-Dump.
            bool isAntiDump = hasVirtualProtect &&
                              !hasCipherArithmetic &&
                              !hasDebuggerCheck &&
                              !hasSectionField &&
                              HasLinkedPeHeaderZeroing(method);

            if (isAntiDump)
            {
                return "Anti-Dump";
            }

            // 4. Ambiguous VirtualProtect hook: If a method calls VirtualProtect but cannot be unambiguously classified as pure Anti-Dump,
            // never strip it via fallback! Retain it to safeguard against undetected Anti-Tamper or runtime requirements.
            if (hasVirtualProtect)
            {
                string msg = $"Retaining hook {method.Name} in <Module>.cctor: ambiguous classification (calls VirtualProtect but does not match pure Anti-Dump with verified PE header zeroing).";
                Logger.LogWarning($"[CleanerKiller] {msg}");
                result?.RetainedHooksDetails.Add(msg);
                result?.HookRecords.Add(new HookTraceRecord
                {
                    HookId = $"Hook_Ambiguous-VirtualProtect_{method.Name}",
                    HookType = "Ambiguous-VirtualProtect",
                    DeclaringType = method.DeclaringType?.FullName ?? "<Module>",
                    MethodName = method.Name?.String ?? string.Empty,
                    Action = "Retained",
                    Reason = msg,
                    Confidence = "MEDIUM"
                });
                return null;
            }

            // 5. Anti-Debug: debugger checks without VirtualProtect or pointer decryption
            if (hasDebuggerCheck)
            {
                if (hasPointerWrite || hasCipherArithmetic)
                {
                    string msg = $"Retaining hook {method.Name} in <Module>.cctor: ambiguous Anti-Debug hook containing memory writes or cipher operations.";
                    Logger.LogWarning($"[CleanerKiller] {msg}");
                    result?.RetainedHooksDetails.Add(msg);
                    result?.HookRecords.Add(new HookTraceRecord
                    {
                        HookId = $"Hook_Anti-Debug_{method.Name}",
                        HookType = "Anti-Debug",
                        DeclaringType = method.DeclaringType?.FullName ?? "<Module>",
                        MethodName = method.Name?.String ?? string.Empty,
                        Action = "Retained",
                        Reason = msg,
                        Confidence = "MEDIUM"
                    });
                    return null;
                }
                return "Anti-Debug";
            }

            // 6. Resource Resolver
            if (hasResourceResolve)
            {
                if (resourcesDecrypted && IsConfuserResourceResolver(method))
                    return "Resource-Resolver";

                if (!resourcesDecrypted)
                {
                    string msg = $"Retaining Resource-Resolver hook {method.Name} in <Module>.cctor: resources have not been decrypted.";
                    Logger.LogWarning($"[CleanerKiller] {msg}");
                    result?.RetainedHooksDetails.Add(msg);
                    result?.HookRecords.Add(new HookTraceRecord
                    {
                        HookId = $"Hook_Resource-Resolver_{method.Name}",
                        HookType = "Resource-Resolver",
                        DeclaringType = method.DeclaringType?.FullName ?? "<Module>",
                        MethodName = method.Name?.String ?? string.Empty,
                        Action = "Retained",
                        Reason = msg,
                        Confidence = "HIGH"
                    });
                    return null;
                }
            }

            // 7. Constant Buffer Initializer
            if (hasInitializeArray && method.Parameters.Count == 0 && IsConfuserConstantBufferInitializer(method))
            {
                if (constantsDecrypted)
                    return "Constant-Buffer";

                string msg = $"Retaining Constant-Buffer hook {method.Name} in <Module>.cctor: constants have not been fully decrypted.";
                Logger.LogWarning($"[CleanerKiller] {msg}");
                result?.RetainedHooksDetails.Add(msg);
                result?.HookRecords.Add(new HookTraceRecord
                {
                    HookId = $"Hook_Constant-Buffer_{method.Name}",
                    HookType = "Constant-Buffer",
                    DeclaringType = method.DeclaringType?.FullName ?? "<Module>",
                    MethodName = method.Name?.String ?? string.Empty,
                    Action = "Retained",
                    Reason = msg,
                    Confidence = "HIGH"
                });
                return null;
            }

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

        private static bool IsConfuserResourceResolver(MethodDef method)
        {
            if (method == null || !method.HasBody || method.Body.Instructions == null)
                return false;

            if (method.DeclaringType != null && !method.DeclaringType.IsGlobalModuleType)
                return false;

            if (method.Parameters.Count > 1)
                return false;

            if (method.Parameters.Count == 1 && method.Parameters[0].Type != null &&
                method.Parameters[0].Type.TypeName != "Module")
                return false;

            if (method.ReturnType != null && method.ReturnType.ElementType != ElementType.Void)
                return false;

            // Reject if the method references or calls user application types/methods
            foreach (var inst in method.Body.Instructions)
            {
                if (inst.OpCode == OpCodes.Ldftn && inst.Operand is IMethod handler)
                {
                    var hDef = handler.ResolveMethodDef() ?? (handler as MethodDef);
                    if (hDef != null && hDef.DeclaringType != null && !hDef.DeclaringType.IsGlobalModuleType)
                    {
                        // Handler belongs to a user class -> legitimate user resolver
                        return false;
                    }
                }
                else if (inst.Operand is IMethod called)
                {
                    var decl = called.DeclaringType;
                    bool isGlobal = decl != null && ((decl is TypeDef td && td.IsGlobalModuleType) || string.Equals(decl.TypeName, "<Module>", StringComparison.Ordinal));
                    if (decl != null && !isGlobal && method.Module != null &&
                        decl.DefinitionAssembly == method.Module.Assembly)
                    {
                        // Calls a method on an application type in current assembly
                        return false;
                    }
                }
            }

            return true;
        }

        private static bool IsConfuserConstantBufferInitializer(MethodDef method)
        {
            if (method == null || !method.HasBody || method.Body.Instructions == null)
                return false;

            if (method.DeclaringType != null && !method.DeclaringType.IsGlobalModuleType)
                return false;

            if (method.Parameters.Count > 0)
                return false;

            if (method.ReturnType != null && method.ReturnType.ElementType != ElementType.Void)
                return false;

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
                else if (inst.Operand is IMethod called)
                {
                    var decl = called.DeclaringType;
                    bool isGlobal = decl != null && ((decl is TypeDef td && td.IsGlobalModuleType) || string.Equals(decl.TypeName, "<Module>", StringComparison.Ordinal));
                    if (decl != null && !isGlobal && method.Module != null &&
                        decl.DefinitionAssembly == method.Module.Assembly)
                    {
                        // Calls application logic
                        return false;
                    }
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

        private enum PeSymbolicKind
        {
            None = 0,
            ModuleBase = 1,        // Proven origin from Marshal.GetHINSTANCE(...) (offset 0 from base)
            PeHeaderOffset = 2,    // Constant 0x3C / 60 (e_lfanew)
            PeHeaderField = 3,     // Field specifically loaded from ModuleBase + 0x3C (IMAGE_DOS_HEADER.e_lfanew)
            PeDerivedAddress = 4,  // Derived pointer to PE header space with cumulative offset from ModuleBase
            NtDerivedAddress = 5,  // Derived pointer to PE NT headers with cumulative offset from IMAGE_NT_HEADERS
            Zero = 6,              // Integer 0, null, or zeroed value
            NumericOffset = 7      // Demonstrated numeric integer displacement
        }

        private readonly struct PeSymbolicSlot : IEquatable<PeSymbolicSlot>
        {
            public readonly PeSymbolicKind Kind;
            public readonly int? ConcreteValue;

            public PeSymbolicSlot(PeSymbolicKind kind, int? concreteValue = null)
            {
                Kind = kind;
                ConcreteValue = concreteValue;
            }

            public static readonly PeSymbolicSlot None = new(PeSymbolicKind.None);
            public static readonly PeSymbolicSlot ModuleBase = new(PeSymbolicKind.ModuleBase, 0);
            public static readonly PeSymbolicSlot PeHeaderOffset = new(PeSymbolicKind.PeHeaderOffset, 0x3C);
            public static readonly PeSymbolicSlot PeHeaderField = new(PeSymbolicKind.PeHeaderField);
            public static readonly PeSymbolicSlot Zero = new(PeSymbolicKind.Zero, 0);
            public static readonly PeSymbolicSlot NumericOffset = new(PeSymbolicKind.NumericOffset);

            public bool Equals(PeSymbolicSlot other) => Kind == other.Kind && ConcreteValue == other.ConcreteValue;
            public override bool Equals(object obj) => obj is PeSymbolicSlot other && Equals(other);
            public override int GetHashCode()
            {
                unchecked
                {
                    return ((int)Kind * 397) ^ (ConcreteValue.HasValue ? ConcreteValue.Value : -1);
                }
            }
            public static bool operator ==(PeSymbolicSlot left, PeSymbolicSlot right) => left.Equals(right);
            public static bool operator !=(PeSymbolicSlot left, PeSymbolicSlot right) => !left.Equals(right);
        }

        // In the Windows PE format (ECMA-335 / Microsoft PE/COFF specification), the initial headers
        // (IMAGE_DOS_HEADER, MS-DOS stub, IMAGE_NT_HEADERS, and Section Table) are mapped by the OS loader
        // in the image's first page (typically bounded by SectionAlignment / SizeOfHeaders, nominally 0x1000 = 4096 bytes).
        // This displacement bound is used by the analyzer as a safe upper envelope for legitimate PE header structures.
        // It does not serve as a universal guarantee for non-standard PE files, but ensures that displacements
        // escaping beyond the first page cannot be misclassified as header manipulations.
        private const int MaxPeHeaderDisplacement = 0x1000;

        private static bool IsNumeric(PeSymbolicSlot v)
        {
            return v.Kind == PeSymbolicKind.NumericOffset || v.Kind == PeSymbolicKind.Zero || v.Kind == PeSymbolicKind.PeHeaderOffset;
        }

        private static bool IsAlignmentMask(int mask)
        {
            return mask == -2 || mask == -4 || mask == -8 || mask == -16 || mask == -32 || mask == -64;
        }

        private static bool IsPeTarget(PeSymbolicSlot addr)
        {
            return addr.Kind == PeSymbolicKind.ModuleBase ||
                   addr.Kind == PeSymbolicKind.PeDerivedAddress ||
                   addr.Kind == PeSymbolicKind.NtDerivedAddress;
        }

        private static PeSymbolicSlot CreateNumericSlot(int val)
        {
            if (val == 0)
                return PeSymbolicSlot.Zero;
            if (val == 0x3C || val == 60)
                return PeSymbolicSlot.PeHeaderOffset;
            return new PeSymbolicSlot(PeSymbolicKind.NumericOffset, val);
        }

        private sealed class PeSymbolicState
        {
            public readonly PeSymbolicSlot[] Locals;
            public readonly PeSymbolicSlot[] Stack;

            public PeSymbolicState(int localCount, PeSymbolicSlot[] stack)
            {
                Locals = new PeSymbolicSlot[localCount];
                for (int i = 0; i < localCount; i++) Locals[i] = PeSymbolicSlot.None;
                Stack = stack ?? Array.Empty<PeSymbolicSlot>();
            }

            public PeSymbolicState(PeSymbolicSlot[] locals, PeSymbolicSlot[] stack)
            {
                Locals = locals;
                Stack = stack ?? Array.Empty<PeSymbolicSlot>();
            }

            public PeSymbolicState Clone()
            {
                var newLocals = new PeSymbolicSlot[Locals.Length];
                Array.Copy(Locals, newLocals, Locals.Length);
                var newStack = new PeSymbolicSlot[Stack.Length];
                Array.Copy(Stack, newStack, Stack.Length);
                return new PeSymbolicState(newLocals, newStack);
            }

            public bool MergeFrom(PeSymbolicState incoming, out bool incompatible)
            {
                incompatible = false;
                if (incoming == null) return false;

                // Check stack compatibility:
                // Under ECMA-335 (Partition I, §12.3.2.1), stack depth must be invariant across all paths reaching an instruction.
                // If stack heights differ, control flow is either malformed or states cannot be soundly unified.
                if (Stack.Length != incoming.Stack.Length)
                {
                    incompatible = true;
                    return false;
                }

                if (Locals.Length != incoming.Locals.Length)
                {
                    incompatible = true;
                    return false;
                }

                bool changed = false;

                for (int i = 0; i < Locals.Length; i++)
                {
                    var merged = MergeValue(Locals[i], incoming.Locals[i]);
                    if (merged != Locals[i])
                    {
                        Locals[i] = merged;
                        changed = true;
                    }
                }

                for (int i = 0; i < Stack.Length; i++)
                {
                    var merged = MergeValue(Stack[i], incoming.Stack[i]);
                    if (merged != Stack[i])
                    {
                        Stack[i] = merged;
                        changed = true;
                    }
                }

                return changed;
            }

            private static PeSymbolicSlot MergeValue(PeSymbolicSlot a, PeSymbolicSlot b)
            {
                // Sound conservative join:
                // If both agree on kind and value, preserve it.
                if (a == b) return a;

                // If both are numeric, preserve numeric offset without concrete value
                if (IsNumeric(a) && IsNumeric(b))
                {
                    return PeSymbolicSlot.NumericOffset;
                }

                return PeSymbolicSlot.None;
            }
        }

        internal static bool HasLinkedPeHeaderZeroing(MethodDef method)
        {
            if (method == null || !method.HasBody || method.Body.Instructions == null)
                return false;

            var instructions = method.Body.Instructions;
            if (instructions.Count == 0)
                return false;

            // Strict provenance requirement: If Marshal.GetHINSTANCE is never called in this method,
            // module base provenance cannot be established.
            bool hasGetHinstance = false;
            foreach (var inst in instructions)
            {
                if ((inst.OpCode == OpCodes.Call || inst.OpCode == OpCodes.Callvirt) &&
                    inst.Operand is IMethod called && IsMarshalGetHINSTANCE(called))
                {
                    hasGetHinstance = true;
                    break;
                }
            }

            if (!hasGetHinstance)
                return false;

            try
            {
                int varCount = method.Body.Variables?.Count ?? 0;
                var instToIndex = new Dictionary<Instruction, int>(instructions.Count);
                for (int i = 0; i < instructions.Count; i++)
                    instToIndex[instructions[i]] = i;

                var entryStates = new PeSymbolicState[instructions.Count];
                entryStates[0] = new PeSymbolicState(varCount, Array.Empty<PeSymbolicSlot>());

                var worklist = new Queue<int>();
                var inWorklist = new bool[instructions.Count];
                worklist.Enqueue(0);
                inWorklist[0] = true;

                bool zeroingDetected = false;

                while (worklist.Count > 0)
                {
                    int i = worklist.Dequeue();
                    inWorklist[i] = false;

                    var inst = instructions[i];
                    var state = entryStates[i];
                    if (state == null) continue;

                    var curStack = new List<PeSymbolicSlot>(state.Stack);
                    var curLocals = new PeSymbolicSlot[state.Locals.Length];
                    Array.Copy(state.Locals, curLocals, curLocals.Length);

                    ExecuteSymbolicInstruction(inst, curStack, curLocals, ref zeroingDetected, method.Module);

                    var successors = GetSuccessorIndices(inst, i, instructions.Count, instToIndex);
                    if (successors.Count == 0) continue;

                    var outState = new PeSymbolicState(curLocals, curStack.ToArray());
                    foreach (var sIdx in successors)
                    {
                        if (entryStates[sIdx] == null)
                        {
                            entryStates[sIdx] = outState.Clone();
                            if (!inWorklist[sIdx])
                            {
                                worklist.Enqueue(sIdx);
                                inWorklist[sIdx] = true;
                            }
                        }
                        else
                        {
                            if (entryStates[sIdx].MergeFrom(outState, out bool incompatible))
                            {
                                if (!inWorklist[sIdx])
                                {
                                    worklist.Enqueue(sIdx);
                                    inWorklist[sIdx] = true;
                                }
                            }

                            if (incompatible)
                            {
                                Logger.LogWarning($"[CleanerKiller] Incompatible stack or local state when merging into instruction IL_{instructions[sIdx].Offset:X4} in {method.Name}. Inconclusive analysis: safely retaining hook.");
                                return false;
                            }
                        }
                    }
                }

                return zeroingDetected;
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"[CleanerKiller] Symbolic evaluation error in {method.Name}: {ex.Message}. Falling back to safe hook retention.");
                return false;
            }
        }

        private static void ExecuteSymbolicInstruction(
            Instruction inst,
            List<PeSymbolicSlot> stack,
            PeSymbolicSlot[] locals,
            ref bool zeroingDetected,
            ModuleDef module)
        {
            var op = inst.OpCode;
            var code = op.Code;

            // 1. Marshal.GetHINSTANCE: proven origin of ModuleBase
            if ((code == Code.Call || code == Code.Callvirt) &&
                inst.Operand is IMethod called && IsMarshalGetHINSTANCE(called))
            {
                inst.CalculateStackUsage(out int pushes, out int pops);
                for (int p = 0; p < pops; p++) PopStack(stack);
                PushStack(stack, PeSymbolicSlot.ModuleBase);
                return;
            }

            // 2. Type conversions / casts that preserve pointer tag
            if (code == Code.Conv_I || code == Code.Conv_U || code == Code.Conv_I4 || code == Code.Conv_U4 ||
                code == Code.Conv_I8 || code == Code.Conv_U8 ||
                ((code == Code.Call || code == Code.Callvirt) && inst.Operand?.ToString().Contains("op_Explicit") == true))
            {
                var val = PopStack(stack);
                PushStack(stack, val);
                return;
            }

            // 3. Constants: ldc.i4, ldc.i8, ldnull
            if (inst.IsLdcI4())
            {
                int val = inst.GetLdcI4Value();
                PushStack(stack, CreateNumericSlot(val));
                return;
            }

            if (code == Code.Ldc_I8)
            {
                if (inst.Operand is long lv)
                {
                    if (lv >= int.MinValue && lv <= int.MaxValue)
                        PushStack(stack, CreateNumericSlot((int)lv));
                    else
                        PushStack(stack, new PeSymbolicSlot(PeSymbolicKind.NumericOffset, null));
                }
                else
                {
                    PushStack(stack, PeSymbolicSlot.NumericOffset);
                }
                return;
            }

            if (code == Code.Ldnull)
            {
                PushStack(stack, PeSymbolicSlot.Zero);
                return;
            }

            // 4. Local variable load
            if (code == Code.Ldloc || code == Code.Ldloc_S ||
                code == Code.Ldloc_0 || code == Code.Ldloc_1 || code == Code.Ldloc_2 || code == Code.Ldloc_3)
            {
                if (TryGetVariableIndex(inst, out int idx) && idx >= 0 && idx < locals.Length)
                    PushStack(stack, locals[idx]);
                else
                    PushStack(stack, PeSymbolicSlot.None);
                return;
            }

            // 5. Local variable store
            if (code == Code.Stloc || code == Code.Stloc_S ||
                code == Code.Stloc_0 || code == Code.Stloc_1 || code == Code.Stloc_2 || code == Code.Stloc_3)
            {
                var val = PopStack(stack);
                if (TryGetVariableIndex(inst, out int idx) && idx >= 0 && idx < locals.Length)
                    locals[idx] = val;
                return;
            }

            // 6. Local variable address (Ldloca)
            if (code == Code.Ldloca || code == Code.Ldloca_S)
            {
                PushStack(stack, PeSymbolicSlot.None);
                return;
            }

            // 7. Pointer arithmetic: Add
            if (code == Code.Add || code == Code.Add_Ovf || code == Code.Add_Ovf_Un)
            {
                var b = PopStack(stack);
                var a = PopStack(stack);
                PushStack(stack, CombineAdd(a, b));
                return;
            }

            // 8. Pointer arithmetic: Sub
            if (code == Code.Sub || code == Code.Sub_Ovf || code == Code.Sub_Ovf_Un)
            {
                var b = PopStack(stack);
                var a = PopStack(stack);
                PushStack(stack, CombineSub(a, b));
                return;
            }

            // 9. Bitwise And (pointer alignment or mask)
            if (code == Code.And)
            {
                var b = PopStack(stack);
                var a = PopStack(stack);
                PushStack(stack, CombineAnd(a, b));
                return;
            }

            // 10. Additional numeric arithmetic / bitwise operations
            if (code == Code.Mul || code == Code.Mul_Ovf || code == Code.Mul_Ovf_Un)
            {
                var b = PopStack(stack);
                var a = PopStack(stack);
                if (a.Kind == PeSymbolicKind.Zero || b.Kind == PeSymbolicKind.Zero)
                {
                    PushStack(stack, PeSymbolicSlot.Zero);
                }
                else if (IsNumeric(a) && IsNumeric(b))
                {
                    if (a.ConcreteValue.HasValue && b.ConcreteValue.HasValue)
                        PushStack(stack, CreateNumericSlot(unchecked(a.ConcreteValue.Value * b.ConcreteValue.Value)));
                    else
                        PushStack(stack, PeSymbolicSlot.NumericOffset);
                }
                else
                {
                    PushStack(stack, PeSymbolicSlot.None);
                }
                return;
            }

            if (code == Code.Or)
            {
                var b = PopStack(stack);
                var a = PopStack(stack);
                if (IsNumeric(a) && IsNumeric(b))
                {
                    if (a.ConcreteValue.HasValue && b.ConcreteValue.HasValue)
                        PushStack(stack, CreateNumericSlot(a.ConcreteValue.Value | b.ConcreteValue.Value));
                    else
                        PushStack(stack, PeSymbolicSlot.NumericOffset);
                }
                else
                {
                    PushStack(stack, PeSymbolicSlot.None);
                }
                return;
            }

            if (code == Code.Xor)
            {
                var b = PopStack(stack);
                var a = PopStack(stack);
                if (a.Kind == PeSymbolicKind.Zero && b.Kind == PeSymbolicKind.Zero)
                {
                    PushStack(stack, PeSymbolicSlot.Zero);
                }
                else if (IsNumeric(a) && IsNumeric(b))
                {
                    if (a.ConcreteValue.HasValue && b.ConcreteValue.HasValue)
                        PushStack(stack, CreateNumericSlot(a.ConcreteValue.Value ^ b.ConcreteValue.Value));
                    else
                        PushStack(stack, PeSymbolicSlot.NumericOffset);
                }
                else
                {
                    // CRITICAL: Two unknown/abstract values (None) are NOT proven to be equal at runtime.
                    // Xor of unknown operands strictly evaluates to None (never assumed to be Zero).
                    PushStack(stack, PeSymbolicSlot.None);
                }
                return;
            }

            if (code == Code.Shl || code == Code.Shr || code == Code.Shr_Un)
            {
                var b = PopStack(stack);
                var a = PopStack(stack);
                if (a.Kind == PeSymbolicKind.Zero)
                {
                    PushStack(stack, PeSymbolicSlot.Zero);
                }
                else if (IsNumeric(a) && IsNumeric(b))
                {
                    if (a.ConcreteValue.HasValue && b.ConcreteValue.HasValue)
                    {
                        int shift = b.ConcreteValue.Value & 0x1F;
                        int res = code == Code.Shl ? (a.ConcreteValue.Value << shift) :
                                  code == Code.Shr ? (a.ConcreteValue.Value >> shift) :
                                  (int)((uint)a.ConcreteValue.Value >> shift);
                        PushStack(stack, CreateNumericSlot(res));
                    }
                    else
                    {
                        PushStack(stack, PeSymbolicSlot.NumericOffset);
                    }
                }
                else
                {
                    PushStack(stack, PeSymbolicSlot.None);
                }
                return;
            }

            if (code == Code.Neg)
            {
                var a = PopStack(stack);
                if (a.Kind == PeSymbolicKind.Zero)
                    PushStack(stack, PeSymbolicSlot.Zero);
                else if (IsNumeric(a))
                {
                    if (a.ConcreteValue.HasValue)
                        PushStack(stack, CreateNumericSlot(unchecked(-a.ConcreteValue.Value)));
                    else
                        PushStack(stack, PeSymbolicSlot.NumericOffset);
                }
                else
                    PushStack(stack, PeSymbolicSlot.None);
                return;
            }

            if (code == Code.Not)
            {
                var a = PopStack(stack);
                if (IsNumeric(a))
                {
                    if (a.ConcreteValue.HasValue)
                        PushStack(stack, CreateNumericSlot(~a.ConcreteValue.Value));
                    else
                        PushStack(stack, PeSymbolicSlot.NumericOffset);
                }
                else
                    PushStack(stack, PeSymbolicSlot.None);
                return;
            }

            // 11. Pointer dereference (ldind)
            if (code == Code.Ldind_I || code == Code.Ldind_I1 || code == Code.Ldind_I2 || code == Code.Ldind_I4 ||
                code == Code.Ldind_I8 || code == Code.Ldind_U1 || code == Code.Ldind_U2 || code == Code.Ldind_U4)
            {
                var addr = PopStack(stack);
                PushStack(stack, EvaluateLdind(addr, code, module));
                return;
            }

            // 12. Pointer write (stind): Check for zeroing of PE address or ModuleBase
            if (code == Code.Stind_I || code == Code.Stind_I1 || code == Code.Stind_I2 || code == Code.Stind_I4 || code == Code.Stind_I8)
            {
                var val = PopStack(stack);
                var addr = PopStack(stack);
                if (IsPeTarget(addr) && val.Kind == PeSymbolicKind.Zero)
                {
                    zeroingDetected = true;
                }
                return;
            }

            // 13. Block write (initblk)
            if (code == Code.Initblk)
            {
                var size = PopStack(stack);
                var val = PopStack(stack);
                var addr = PopStack(stack);
                if (IsPeTarget(addr) && val.Kind == PeSymbolicKind.Zero)
                {
                    zeroingDetected = true;
                }
                return;
            }

            // 14. Method calls (RtlZeroMemory, memset, etc.)
            if ((code == Code.Call || code == Code.Callvirt) && inst.Operand is IMethod calledFn)
            {
                string fn = calledFn.Name;
                if (fn.IndexOf("ZeroMemory", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    var count = PopStack(stack);
                    var dest = PopStack(stack);
                    if (IsPeTarget(dest))
                        zeroingDetected = true;
                    return;
                }
                if (fn.IndexOf("memset", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    var count = PopStack(stack);
                    var c = PopStack(stack);
                    var dest = PopStack(stack);
                    if (IsPeTarget(dest) && c.Kind == PeSymbolicKind.Zero)
                    {
                        zeroingDetected = true;
                    }
                    PushStack(stack, dest);
                    return;
                }
            }

            // 15. Dup & Pop
            if (code == Code.Dup)
            {
                var val = PopStack(stack);
                PushStack(stack, val);
                PushStack(stack, val);
                return;
            }
            if (code == Code.Pop)
            {
                PopStack(stack);
                return;
            }

            // 16. Fallback for all other instructions
            inst.CalculateStackUsage(out int pushesCount, out int popsCount);
            for (int p = 0; p < popsCount; p++) PopStack(stack);
            for (int p = 0; p < pushesCount; p++) PushStack(stack, PeSymbolicSlot.None);
        }

        private static PeSymbolicSlot CombineAdd(PeSymbolicSlot a, PeSymbolicSlot b)
        {
            // Obvious arithmetic identity: X + 0 == X, 0 + X == X
            if (b.Kind == PeSymbolicKind.Zero)
            {
                return a;
            }
            if (a.Kind == PeSymbolicKind.Zero)
            {
                return b;
            }

            // 1. Proven ModuleBase + 0x3C -> PeDerivedAddress with cumulative displacement 0x3C
            if ((a.Kind == PeSymbolicKind.ModuleBase && b.Kind == PeSymbolicKind.PeHeaderOffset) ||
                (b.Kind == PeSymbolicKind.ModuleBase && a.Kind == PeSymbolicKind.PeHeaderOffset))
            {
                return new PeSymbolicSlot(PeSymbolicKind.PeDerivedAddress, 0x3C);
            }

            // 2. Proven ModuleBase + PeHeaderField (specifically e_lfanew read from ModuleBase + 0x3C)
            // Points to IMAGE_NT_HEADERS with relative cumulative displacement 0 from NT headers.
            if ((a.Kind == PeSymbolicKind.ModuleBase && b.Kind == PeSymbolicKind.PeHeaderField) ||
                (b.Kind == PeSymbolicKind.ModuleBase && a.Kind == PeSymbolicKind.PeHeaderField))
            {
                return new PeSymbolicSlot(PeSymbolicKind.NtDerivedAddress, 0);
            }

            // 3. ModuleBase + Numeric displacement
            if (a.Kind == PeSymbolicKind.ModuleBase && IsNumeric(b))
            {
                if (b.ConcreteValue.HasValue)
                {
                    int offset = b.ConcreteValue.Value;
                    if (offset >= 0 && offset <= MaxPeHeaderDisplacement)
                        return new PeSymbolicSlot(PeSymbolicKind.PeDerivedAddress, offset);
                }
                return PeSymbolicSlot.None;
            }
            if (b.Kind == PeSymbolicKind.ModuleBase && IsNumeric(a))
            {
                if (a.ConcreteValue.HasValue)
                {
                    int offset = a.ConcreteValue.Value;
                    if (offset >= 0 && offset <= MaxPeHeaderDisplacement)
                        return new PeSymbolicSlot(PeSymbolicKind.PeDerivedAddress, offset);
                }
                return PeSymbolicSlot.None;
            }

            // 4. Cumulative offset calculation from already derived PE DOS/stub address:
            // CRITICAL: The cumulative displacement from ModuleBase MUST be tracked and bounded
            // within the PE header space (0 <= offset <= MaxPeHeaderDisplacement).
            // If the position becomes unknown or exceeds bounds, provenance is lost!
            if (a.Kind == PeSymbolicKind.PeDerivedAddress && IsNumeric(b))
            {
                if (a.ConcreteValue.HasValue && b.ConcreteValue.HasValue)
                {
                    long cum = (long)a.ConcreteValue.Value + b.ConcreteValue.Value;
                    if (cum >= 0 && cum <= MaxPeHeaderDisplacement)
                        return new PeSymbolicSlot(PeSymbolicKind.PeDerivedAddress, (int)cum);
                }
                return PeSymbolicSlot.None;
            }
            if (b.Kind == PeSymbolicKind.PeDerivedAddress && IsNumeric(a))
            {
                if (b.ConcreteValue.HasValue && a.ConcreteValue.HasValue)
                {
                    long cum = (long)b.ConcreteValue.Value + a.ConcreteValue.Value;
                    if (cum >= 0 && cum <= MaxPeHeaderDisplacement)
                        return new PeSymbolicSlot(PeSymbolicKind.PeDerivedAddress, (int)cum);
                }
                return PeSymbolicSlot.None;
            }

            // 5. Cumulative offset calculation from NT headers:
            // CRITICAL: Displacement from IMAGE_NT_HEADERS must remain within header bounds (|offset| <= MaxPeHeaderDisplacement).
            if (a.Kind == PeSymbolicKind.NtDerivedAddress && IsNumeric(b))
            {
                if (a.ConcreteValue.HasValue && b.ConcreteValue.HasValue)
                {
                    long cum = (long)a.ConcreteValue.Value + b.ConcreteValue.Value;
                    if (Math.Abs(cum) <= MaxPeHeaderDisplacement)
                        return new PeSymbolicSlot(PeSymbolicKind.NtDerivedAddress, (int)cum);
                }
                return PeSymbolicSlot.None;
            }
            if (b.Kind == PeSymbolicKind.NtDerivedAddress && IsNumeric(a))
            {
                if (b.ConcreteValue.HasValue && a.ConcreteValue.HasValue)
                {
                    long cum = (long)b.ConcreteValue.Value + a.ConcreteValue.Value;
                    if (Math.Abs(cum) <= MaxPeHeaderDisplacement)
                        return new PeSymbolicSlot(PeSymbolicKind.NtDerivedAddress, (int)cum);
                }
                return PeSymbolicSlot.None;
            }

            // 6. Numeric + Numeric -> Numeric
            if (IsNumeric(a) && IsNumeric(b))
            {
                if (a.ConcreteValue.HasValue && b.ConcreteValue.HasValue)
                {
                    return CreateNumericSlot(unchecked(a.ConcreteValue.Value + b.ConcreteValue.Value));
                }
                return PeSymbolicSlot.NumericOffset;
            }

            return PeSymbolicSlot.None;
        }

        private static PeSymbolicSlot CombineSub(PeSymbolicSlot a, PeSymbolicSlot b)
        {
            // Obvious arithmetic identity: X - 0 == X
            if (b.Kind == PeSymbolicKind.Zero)
            {
                return a;
            }

            // 1. PeDerivedAddress - NumericOffset
            // Tracks cumulative displacement from ModuleBase. Must remain in [0, MaxPeHeaderDisplacement].
            if (a.Kind == PeSymbolicKind.PeDerivedAddress && IsNumeric(b))
            {
                if (a.ConcreteValue.HasValue && b.ConcreteValue.HasValue)
                {
                    long cum = (long)a.ConcreteValue.Value - b.ConcreteValue.Value;
                    if (cum >= 0 && cum <= MaxPeHeaderDisplacement)
                        return new PeSymbolicSlot(PeSymbolicKind.PeDerivedAddress, (int)cum);
                }
                return PeSymbolicSlot.None;
            }

            // 2. NtDerivedAddress - NumericOffset
            // Tracks cumulative displacement from NT headers. Must remain bounded.
            if (a.Kind == PeSymbolicKind.NtDerivedAddress && IsNumeric(b))
            {
                if (a.ConcreteValue.HasValue && b.ConcreteValue.HasValue)
                {
                    long cum = (long)a.ConcreteValue.Value - b.ConcreteValue.Value;
                    if (Math.Abs(cum) <= MaxPeHeaderDisplacement)
                        return new PeSymbolicSlot(PeSymbolicKind.NtDerivedAddress, (int)cum);
                }
                return PeSymbolicSlot.None;
            }

            // 3. Numeric - Numeric -> Numeric
            if (IsNumeric(a) && IsNumeric(b))
            {
                if (a.ConcreteValue.HasValue && b.ConcreteValue.HasValue)
                {
                    return CreateNumericSlot(unchecked(a.ConcreteValue.Value - b.ConcreteValue.Value));
                }
                return PeSymbolicSlot.NumericOffset;
            }

            return PeSymbolicSlot.None;
        }

        private static PeSymbolicSlot CombineAnd(PeSymbolicSlot a, PeSymbolicSlot b)
        {
            // Obvious arithmetic identity: anything & 0 == 0
            if (a.Kind == PeSymbolicKind.Zero || b.Kind == PeSymbolicKind.Zero)
            {
                return PeSymbolicSlot.Zero;
            }

            // ModuleBase & AlignmentMask -> ModuleBase
            if (a.Kind == PeSymbolicKind.ModuleBase && b.ConcreteValue.HasValue && IsAlignmentMask(b.ConcreteValue.Value))
            {
                return PeSymbolicSlot.ModuleBase;
            }
            if (b.Kind == PeSymbolicKind.ModuleBase && a.ConcreteValue.HasValue && IsAlignmentMask(a.ConcreteValue.Value))
            {
                return PeSymbolicSlot.ModuleBase;
            }

            // Pointer alignment: PeDerivedAddress & AlignmentMask
            // CRITICAL: Only legitimate pointer alignment masks (-2, -4, -8, -16, -32, -64) preserve provenance!
            if (a.Kind == PeSymbolicKind.PeDerivedAddress && b.ConcreteValue.HasValue && IsAlignmentMask(b.ConcreteValue.Value))
            {
                if (a.ConcreteValue.HasValue)
                {
                    int masked = a.ConcreteValue.Value & b.ConcreteValue.Value;
                    if (masked >= 0 && masked <= MaxPeHeaderDisplacement)
                        return new PeSymbolicSlot(PeSymbolicKind.PeDerivedAddress, masked);
                }
                return PeSymbolicSlot.None;
            }
            if (b.Kind == PeSymbolicKind.PeDerivedAddress && a.ConcreteValue.HasValue && IsAlignmentMask(a.ConcreteValue.Value))
            {
                if (b.ConcreteValue.HasValue)
                {
                    int masked = b.ConcreteValue.Value & a.ConcreteValue.Value;
                    if (masked >= 0 && masked <= MaxPeHeaderDisplacement)
                        return new PeSymbolicSlot(PeSymbolicKind.PeDerivedAddress, masked);
                }
                return PeSymbolicSlot.None;
            }

            // Pointer alignment: NtDerivedAddress & AlignmentMask
            if (a.Kind == PeSymbolicKind.NtDerivedAddress && b.ConcreteValue.HasValue && IsAlignmentMask(b.ConcreteValue.Value))
            {
                if (a.ConcreteValue.HasValue)
                {
                    int masked = a.ConcreteValue.Value & b.ConcreteValue.Value;
                    if (Math.Abs(masked) <= MaxPeHeaderDisplacement)
                        return new PeSymbolicSlot(PeSymbolicKind.NtDerivedAddress, masked);
                }
                return PeSymbolicSlot.None;
            }
            if (b.Kind == PeSymbolicKind.NtDerivedAddress && a.ConcreteValue.HasValue && IsAlignmentMask(a.ConcreteValue.Value))
            {
                if (b.ConcreteValue.HasValue)
                {
                    int masked = b.ConcreteValue.Value & a.ConcreteValue.Value;
                    if (Math.Abs(masked) <= MaxPeHeaderDisplacement)
                        return new PeSymbolicSlot(PeSymbolicKind.NtDerivedAddress, masked);
                }
                return PeSymbolicSlot.None;
            }

            // Numeric & Numeric
            if (IsNumeric(a) && IsNumeric(b))
            {
                if (a.ConcreteValue.HasValue && b.ConcreteValue.HasValue)
                {
                    return CreateNumericSlot(a.ConcreteValue.Value & b.ConcreteValue.Value);
                }
                return PeSymbolicSlot.NumericOffset;
            }

            return PeSymbolicSlot.None;
        }

        private static bool IsGuaranteed32BitModule(ModuleDef module)
        {
            if (module == null)
                return false;

            // 64-bit architectures
            if (module.IsAMD64 || module.IsARM64 || module.IsIA64)
                return false;

            if (module.Machine == Machine.AMD64 ||
                module.Machine == Machine.ARM64 ||
                module.Machine == Machine.IA64)
            {
                return false;
            }

            // Must be a recognized 32-bit machine (e.g. I386 / ARMNT)
            if (module.Machine != Machine.I386 && module.Machine != Machine.ARMNT)
                return false;

            // If a file path is available on disk, also check full PE/COR20 header architecture info
            if (!string.IsNullOrEmpty(module.Location) && File.Exists(module.Location))
            {
                try
                {
                    var arch = ArchitectureDetector.Detect(module.Location);
                    if (arch.Architecture == TargetArchitecture.X86Required)
                        return true;
                    if (arch.Architecture == TargetArchitecture.X64 ||
                        arch.Architecture == TargetArchitecture.AnyCPU ||
                        arch.Architecture == TargetArchitecture.Unknown)
                    {
                        return false;
                    }
                }
                catch
                {
                    // Fall back to module metadata inspection below
                }
            }

            // For in-memory / metadata modules:
            // 1. If 32-bit execution is explicitly required, OS loader guarantees 32-bit execution (WoW64 or 32-bit OS),
            //    so native int (IntPtr) is guaranteed to be 4 bytes.
            if (module.Is32BitRequired)
                return true;

            // 2. If the module is not IL-only (mixed-mode / contains native x86 code), it cannot execute as 64-bit.
            if (!module.IsILOnly)
                return true;

            // 3. IL-only AnyCPU (even with 32BitPreferred) or unconfigured module:
            //    Runtime bitness is ambiguous (executes as 64-bit on 64-bit OS / 64-bit CLR hosts).
            //    Conservatively reject ldind.i as proof of a 4-byte read.
            return false;
        }

        private static PeSymbolicSlot EvaluateLdind(PeSymbolicSlot addr, Code code, ModuleDef module)
        {
            // In the PE specification, offset 0x3C (IMAGE_DOS_HEADER.e_lfanew) specifically holds
            // the 4-byte (32-bit) relative file offset to IMAGE_NT_HEADERS.
            // Full 32-bit integer reads (ldind.i4, ldind.u4) directly at (ModuleBase + 0x3C)
            // qualify as a proven e_lfanew field regardless of platform architecture.
            // Native int reads (ldind.i) are only 4 bytes if the analyzed target module is guaranteed
            // to execute as 32-bit (e.g. x86 required or 32-bit mixed mode). On 64-bit or ambiguous/unknown
            // architectures (e.g. AnyCPU, x64), ldind.i loads 8 bytes or an indeterminate size and
            // cannot be accepted as proof of reading 32-bit e_lfanew.
            // Narrow partial reads (ldind.u1, ldind.i1, ldind.u2, ldind.i2) or reads at any other offset
            // produce None.
            bool is32BitRead = code == Code.Ldind_I4 || code == Code.Ldind_U4;
            if (!is32BitRead && code == Code.Ldind_I)
            {
                is32BitRead = IsGuaranteed32BitModule(module);
            }

            if (is32BitRead &&
                addr.Kind == PeSymbolicKind.PeDerivedAddress &&
                addr.ConcreteValue.HasValue &&
                addr.ConcreteValue.Value == 0x3C)
            {
                return PeSymbolicSlot.PeHeaderField;
            }
            return PeSymbolicSlot.None;
        }

        private static PeSymbolicSlot PopStack(List<PeSymbolicSlot> stack)
        {
            if (stack != null && stack.Count > 0)
            {
                var tag = stack[stack.Count - 1];
                stack.RemoveAt(stack.Count - 1);
                return tag;
            }
            return PeSymbolicSlot.None;
        }

        private static void PushStack(List<PeSymbolicSlot> stack, PeSymbolicSlot tag)
        {
            stack?.Add(tag);
        }

        private static List<int> GetSuccessorIndices(Instruction inst, int i, int count, Dictionary<Instruction, int> instToIndex)
        {
            var list = new List<int>(2);
            var flow = inst.OpCode.FlowControl;

            if (flow == FlowControl.Branch)
            {
                if (inst.Operand is Instruction target && instToIndex.TryGetValue(target, out int tIdx))
                    list.Add(tIdx);
            }
            else if (flow == FlowControl.Cond_Branch)
            {
                if (inst.Operand is Instruction target && instToIndex.TryGetValue(target, out int tIdx))
                    list.Add(tIdx);
                else if (inst.Operand is Instruction[] targets)
                {
                    foreach (var t in targets)
                    {
                        if (instToIndex.TryGetValue(t, out int idx))
                            list.Add(idx);
                    }
                }
                if (i + 1 < count)
                    list.Add(i + 1);
            }
            else if (flow == FlowControl.Return || flow == FlowControl.Throw)
            {
                // No successors
            }
            else
            {
                if (i + 1 < count)
                    list.Add(i + 1);
            }

            return list;
        }

        private static bool TryGetVariableIndex(Instruction inst, out int index)
        {
            index = -1;
            if (inst == null) return false;

            if (inst.OpCode == OpCodes.Ldloc_0 || inst.OpCode == OpCodes.Stloc_0 ||
                (inst.OpCode == OpCodes.Ldloca_S && inst.Operand is Local l0 && l0.Index == 0))
            {
                index = 0;
                return true;
            }
            if (inst.OpCode == OpCodes.Ldloc_1 || inst.OpCode == OpCodes.Stloc_1 ||
                (inst.OpCode == OpCodes.Ldloca_S && inst.Operand is Local l1 && l1.Index == 1))
            {
                index = 1;
                return true;
            }
            if (inst.OpCode == OpCodes.Ldloc_2 || inst.OpCode == OpCodes.Stloc_2 ||
                (inst.OpCode == OpCodes.Ldloca_S && inst.Operand is Local l2 && l2.Index == 2))
            {
                index = 2;
                return true;
            }
            if (inst.OpCode == OpCodes.Ldloc_3 || inst.OpCode == OpCodes.Stloc_3 ||
                (inst.OpCode == OpCodes.Ldloca_S && inst.Operand is Local l3 && l3.Index == 3))
            {
                index = 3;
                return true;
            }

            if (inst.Operand is Local loc)
            {
                index = loc.Index;
                return true;
            }

            if (inst.Operand is int intIdx)
            {
                index = intIdx;
                return true;
            }

            return false;
        }

        private static bool TryIdentifyArgumentProducers(
            MethodDef cctor,
            int callIndex,
            int expectedParams,
            HashSet<Instruction> branchTargets,
            HashSet<Instruction> ehBoundaries,
            out List<Instruction> instructionsToNeutralize)
        {
            instructionsToNeutralize = new List<Instruction>();
            var instructions = cctor.Body.Instructions;
            var callInst = instructions[callIndex];

            // The call instruction itself cannot be a branch target or EH boundary
            if (branchTargets.Contains(callInst) || ehBoundaries.Contains(callInst))
                return false;

            instructionsToNeutralize.Add(callInst);

            if (expectedParams == 0)
                return true;

            int needed = expectedParams;
            int curr = callIndex - 1;

            while (needed > 0 && curr >= 0)
            {
                var prev = instructions[curr];

                // Skip existing nops
                if (prev.OpCode == OpCodes.Nop)
                {
                    curr--;
                    continue;
                }

                // Must not be a branch target or EH boundary
                if (branchTargets.Contains(prev) || ehBoundaries.Contains(prev))
                    return false;

                // An argument must be produced by an unambiguous, single-instruction pure push.
                // If an argument is produced by multiple instructions, a field access (ldfld/ldsfld),
                // a method call (call/callvirt), or any unsupported sequence, refuse!
                if (IsPureSingleArgumentProducer(prev))
                {
                    instructionsToNeutralize.Add(prev);
                    needed--;
                    curr--;
                }
                else
                {
                    // Unsupported producer (call, field load, binary op, multi-instruction, etc.)
                    return false;
                }
            }

            if (needed > 0)
                return false;

            // Verify exception handlers: no instruction to neutralize may cross an EH boundary or be inside an EH clause
            // if the call instruction is not inside the exact same clause
            if (cctor.Body.HasExceptionHandlers)
            {
                foreach (var eh in cctor.Body.ExceptionHandlers)
                {
                    bool callInTry = IsInstructionInClause(instructions, eh.TryStart, eh.TryEnd, callInst);
                    bool callInHandler = IsInstructionInClause(instructions, eh.HandlerStart, eh.HandlerEnd, callInst);

                    foreach (var inst in instructionsToNeutralize)
                    {
                        bool instInTry = IsInstructionInClause(instructions, eh.TryStart, eh.TryEnd, inst);
                        bool instInHandler = IsInstructionInClause(instructions, eh.HandlerStart, eh.HandlerEnd, inst);

                        if (instInTry != callInTry || instInHandler != callInHandler)
                            return false;
                    }
                }
            }

            return true;
        }

        private static bool TryIdentifyReturnConsumer(
            MethodDef cctor,
            int callIndex,
            HashSet<Instruction> branchTargets,
            HashSet<Instruction> ehBoundaries,
            out Instruction consumerInst)
        {
            consumerInst = null;
            var instructions = cctor.Body.Instructions;
            var callInst = instructions[callIndex];

            int nextIdx = callIndex + 1;
            while (nextIdx < instructions.Count && instructions[nextIdx].OpCode == OpCodes.Nop)
                nextIdx++;

            if (nextIdx >= instructions.Count)
                return false;

            var candidate = instructions[nextIdx];
            if (candidate.OpCode != OpCodes.Pop)
                return false;

            if (branchTargets.Contains(candidate) || ehBoundaries.Contains(candidate))
                return false;

            if (cctor.Body.HasExceptionHandlers)
            {
                foreach (var eh in cctor.Body.ExceptionHandlers)
                {
                    bool callInTry = IsInstructionInClause(instructions, eh.TryStart, eh.TryEnd, callInst);
                    bool callInHandler = IsInstructionInClause(instructions, eh.HandlerStart, eh.HandlerEnd, callInst);

                    bool popInTry = IsInstructionInClause(instructions, eh.TryStart, eh.TryEnd, candidate);
                    bool popInHandler = IsInstructionInClause(instructions, eh.HandlerStart, eh.HandlerEnd, candidate);

                    if (callInTry != popInTry || callInHandler != popInHandler)
                        return false;
                }
            }

            consumerInst = candidate;
            return true;
        }

        private static bool IsPureSingleArgumentProducer(Instruction inst)
        {
            if (inst == null) return false;

            // Reject all field loads (ldfld, ldsfld, ldflda, ldsflda)
            if (inst.OpCode == OpCodes.Ldfld || inst.OpCode == OpCodes.Ldsfld ||
                inst.OpCode == OpCodes.Ldflda || inst.OpCode == OpCodes.Ldsflda)
                return false;

            // Reject all calls
            if (inst.OpCode == OpCodes.Call || inst.OpCode == OpCodes.Callvirt || inst.OpCode == OpCodes.Calli)
                return false;

            // Check stack usage: must have pops == 0 and pushes == 1
            inst.CalculateStackUsage(out int pushes, out int pops);
            if (pops != 0 || pushes != 1)
                return false;

            // Allowed pure push opcodes:
            // Constants & literals
            if (inst.OpCode == OpCodes.Ldnull) return true;
            if (inst.OpCode == OpCodes.Ldc_I4 || inst.OpCode == OpCodes.Ldc_I4_S ||
                inst.OpCode == OpCodes.Ldc_I4_0 || inst.OpCode == OpCodes.Ldc_I4_1 ||
                inst.OpCode == OpCodes.Ldc_I4_2 || inst.OpCode == OpCodes.Ldc_I4_3 ||
                inst.OpCode == OpCodes.Ldc_I4_4 || inst.OpCode == OpCodes.Ldc_I4_5 ||
                inst.OpCode == OpCodes.Ldc_I4_6 || inst.OpCode == OpCodes.Ldc_I4_7 ||
                inst.OpCode == OpCodes.Ldc_I4_8 || inst.OpCode == OpCodes.Ldc_I4_M1)
                return true;
            if (inst.OpCode == OpCodes.Ldc_I8 || inst.OpCode == OpCodes.Ldc_R4 || inst.OpCode == OpCodes.Ldc_R8)
                return true;
            if (inst.OpCode == OpCodes.Ldstr) return true;
            if (inst.OpCode == OpCodes.Ldtoken) return true;

            // Arguments and locals
            if (inst.OpCode == OpCodes.Ldarg || inst.OpCode == OpCodes.Ldarg_S ||
                inst.OpCode == OpCodes.Ldarg_0 || inst.OpCode == OpCodes.Ldarg_1 ||
                inst.OpCode == OpCodes.Ldarg_2 || inst.OpCode == OpCodes.Ldarg_3)
                return true;
            if (inst.OpCode == OpCodes.Ldloc || inst.OpCode == OpCodes.Ldloc_S ||
                inst.OpCode == OpCodes.Ldloc_0 || inst.OpCode == OpCodes.Ldloc_1 ||
                inst.OpCode == OpCodes.Ldloc_2 || inst.OpCode == OpCodes.Ldloc_3)
                return true;

            return false;
        }

        private static bool IsInstructionInClause(IList<Instruction> instructions, Instruction start, Instruction end, Instruction target)
        {
            if (start == null || target == null) return false;
            int s = instructions.IndexOf(start);
            int t = instructions.IndexOf(target);
            if (s < 0 || t < 0) return false;
            if (end == null)
            {
                return t >= s;
            }
            int e = instructions.IndexOf(end);
            if (e < 0) return false;
            return t >= s && t < e;
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
