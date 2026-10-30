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
        public int StrippedAttributesCount { get; set; }
        public bool AntiIldasmStripped { get; set; }
        public bool AntiDebugStripped { get; set; }
        public List<string> StrippedDetails { get; set; } = new List<string>();
        public List<string> RetainedHooksDetails { get; set; } = new List<string>();
        public List<HookTraceRecord> HookRecords { get; set; } = new List<HookTraceRecord>();
    }

    public static class CleanerKiller
    {
        public static bool StripAntiIldasm(ModuleDef module)
        {
            if (module == null) return false;
            bool stripped = false;
            if (module.Assembly != null && module.Assembly.HasCustomAttributes)
            {
                for (int i = module.Assembly.CustomAttributes.Count - 1; i >= 0; i--)
                {
                    var ca = module.Assembly.CustomAttributes[i];
                    if (ca?.TypeFullName != null && ca.TypeFullName.IndexOf("SuppressIldasmAttribute", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        module.Assembly.CustomAttributes.RemoveAt(i);
                        stripped = true;
                    }
                }
            }
            if (module.HasCustomAttributes)
            {
                for (int i = module.CustomAttributes.Count - 1; i >= 0; i--)
                {
                    var ca = module.CustomAttributes[i];
                    if (ca?.TypeFullName != null && ca.TypeFullName.IndexOf("SuppressIldasmAttribute", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        module.CustomAttributes.RemoveAt(i);
                        stripped = true;
                    }
                }
            }
            return stripped;
        }

        public static CleanerResult StripProtectorHooks(ModuleDef module, bool resourcesDecrypted = false, bool constantsDecrypted = false, bool antiTamperDecrypted = false)
        {
            if (module == null) throw new ArgumentNullException(nameof(module));

            var result = new CleanerResult();

            if (StripAntiIldasm(module))
            {
                result.AntiIldasmStripped = true;
                result.StrippedAttributesCount++;
                result.StrippedDetails.Add("Stripped SuppressIldasmAttribute from assembly/module custom attributes");
            }

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
                    if (hookType == "Anti-Debug") result.AntiDebugStripped = true;
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

            // Collect any subsidiary delegate methods referenced by methodsToRemove (e.g. smethod_1 watchdog thread)
            var subsidiaryMethods = new List<MethodDef>();
            foreach (var m in methodsToRemove)
            {
                if (m.HasBody && m.Body.Instructions != null)
                {
                    foreach (var ins in m.Body.Instructions)
                    {
                        if (ins.OpCode == OpCodes.Ldftn && ins.Operand is IMethod called)
                        {
                            var targetDef = called.ResolveMethodDef() ?? (called as MethodDef);
                            if (targetDef != null && targetDef.DeclaringType != null && targetDef.DeclaringType.IsGlobalModuleType && !methodsToRemove.Contains(targetDef))
                            {
                                subsidiaryMethods.Add(targetDef);
                            }
                        }
                    }
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
                        if (!IsReferencedInModule(module, m, methodsToRemove))
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

                foreach (var sub in subsidiaryMethods)
                {
                    var declType = sub.DeclaringType;
                    if (declType != null && declType.Methods.Contains(sub))
                    {
                        if (!IsReferencedInModule(module, sub, methodsToRemove))
                        {
                            declType.Methods.Remove(sub);
                            result.RemovedMethodsCount++;
                            Logger.LogInfo($"[CleanerKiller] Removed unused subsidiary protector method {sub.Name} from {declType.Name}");
                        }
                        else
                        {
                            string msg = $"Retaining subsidiary method {sub.Name} in {declType.Name}: live references remain outside stripped hooks.";
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
                            // Check if any other method still calls this pinvoke, and never remove public P/Invokes
                            if (!m.IsPublic && !IsReferencedInModule(module, m, methodsToRemove))
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

        /// <summary>
        /// Strictly determines whether a call instruction targets a positively identified ConfuserEx protector hook.
        /// Unresolved external references, non-global types, or methods without positive structural protector patterns
        /// are NEVER classified as protector calls.
        /// </summary>
        public static bool IsRecognizedProtectorCall(Instruction inst, out MethodDef targetMethodDef, out string hookType)
        {
            targetMethodDef = null;
            hookType = null;
            if (inst == null || (inst.OpCode != OpCodes.Call && inst.OpCode != OpCodes.Callvirt))
                return false;

            if (!(inst.Operand is IMethod calledMethod))
                return false;

            // Rule 1: Target must be resolvable. Unresolved MemberRef or external reference MUST NEVER be neutralized.
            targetMethodDef = calledMethod.ResolveMethodDef() ?? (calledMethod as MethodDef);
            if (targetMethodDef == null)
                return false;

            // Rule 2: ConfuserEx protector methods are defined on the global <Module> type.
            if (targetMethodDef.DeclaringType == null || !targetMethodDef.DeclaringType.IsGlobalModuleType)
                return false;

            // Rule 3: Positive identification required. Method names alone are NEVER sufficient proof.
            if (IsExactStubProtectorCall(targetMethodDef))
            {
                hookType = "Protector-Stub";
                return true;
            }

            // Positive structural classification (Anti-Dump, Anti-Tamper, Anti-Debug, Resource-Resolver, Constant-Buffer)
            string classification = ClassifyProtectorMethod(targetMethodDef, resourcesDecrypted: true, constantsDecrypted: true, antiTamperDecrypted: true);
            if (!string.IsNullOrEmpty(classification))
            {
                hookType = classification;
                return true;
            }

            return false;
        }

        public static void SanitizeModuleStaticConstructor(MethodDef cctor, CleanerResult result = null)
        {
            if (cctor == null || !cctor.HasBody || cctor.Body.Instructions == null || cctor.Body.Instructions.Count == 0)
                return;

            // If the constructor is already structurally valid across all CFG paths, do not touch anything.
            if (QualityAuditor.IsMethodStructurallyValid(cctor, out _))
                return;

            var instructions = cctor.Body.Instructions;

            // Find only calls that are positively verified ConfuserEx protector hooks.
            // Never touch user methods, instance methods, or unresolved MemberRefs!
            var candidateCalls = new List<(Instruction CallInst, MethodDef TargetDef, string HookType)>();
            for (int i = 0; i < instructions.Count; i++)
            {
                var inst = instructions[i];
                if (IsRecognizedProtectorCall(inst, out var targetDef, out var hookType))
                {
                    candidateCalls.Add((inst, targetDef, hookType));
                }
            }

            // Rule: If no positively identified protector calls exist, retain all instructions intact!
            // Do NOT guess or blindly sanitize unknown application initializers.
            if (candidateCalls.Count == 0)
            {
                Logger.LogWarning("[CleanerKiller] <Module>.cctor is structurally invalid, but contains no recognized ConfuserEx protector hooks. Preserving all instructions to prevent breaking application logic.");
                return;
            }

            // Snapshot original opcodes and operands for strict atomic rollback
            var backup = instructions.Select(ins => (Inst: ins, Op: ins.OpCode, Opnd: ins.Operand)).ToList();

            // Attempt 1: Neutralize only the positively identified protector calls
            foreach (var cand in candidateCalls)
            {
                cand.CallInst.OpCode = OpCodes.Nop;
                cand.CallInst.Operand = null;
            }

            if (QualityAuditor.IsMethodStructurallyValid(cctor, out _))
            {
                if (result != null)
                    result.StrippedHooksCount += candidateCalls.Count;
                string msg = $"Sanitized {candidateCalls.Count} recognized protector hook call(s) ({string.Join(", ", candidateCalls.Select(c => c.HookType))}) in <Module>.cctor";
                Logger.LogInfo($"[CleanerKiller] {msg}");
                result?.StrippedDetails.Add(msg);
                return;
            }

            // Attempt 2: If neutralizing all together didn't achieve validity, try each recognized hook individually
            foreach (var b in backup)
            {
                b.Inst.OpCode = b.Op;
                b.Inst.Operand = b.Opnd;
            }

            for (int i = 0; i < candidateCalls.Count; i++)
            {
                var cand = candidateCalls[i];
                cand.CallInst.OpCode = OpCodes.Nop;
                cand.CallInst.Operand = null;

                if (QualityAuditor.IsMethodStructurallyValid(cctor, out _))
                {
                    if (result != null)
                        result.StrippedHooksCount++;
                    string msg = $"Sanitized recognized {cand.HookType} hook call to {cand.TargetDef.Name} in <Module>.cctor";
                    Logger.LogInfo($"[CleanerKiller] {msg}");
                    result?.StrippedDetails.Add(msg);
                    return;
                }

                // Restore
                cand.CallInst.OpCode = backup.First(b => b.Inst == cand.CallInst).Op;
                cand.CallInst.Operand = backup.First(b => b.Inst == cand.CallInst).Opnd;
            }

            // Strict Rollback: If no recognized hook neutralization rendered the constructor structurally valid,
            // restore everything and retain the original method body.
            foreach (var b in backup)
            {
                b.Inst.OpCode = b.Op;
                b.Inst.Operand = b.Opnd;
            }

            Logger.LogWarning("[CleanerKiller] Rollback in <Module>.cctor: neutralization of recognized protector hooks did not resolve structural defects. Original instructions restored.");
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
                    string pinvokeName = null;
                    var calledDef = called.ResolveMethodDef() ?? (called as MethodDef);
                    if (calledDef != null && calledDef.IsPinvokeImpl && calledDef.ImplMap != null)
                    {
                        pinvokeName = calledDef.ImplMap.Name?.String ?? calledDef.Name?.String;
                    }

                    if (fullName.IndexOf("IsAttached", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        fullName.IndexOf("IsLogging", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        fullName.IndexOf("CheckRemoteDebuggerPresent", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        fullName.IndexOf("IsDebuggerPresent", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        fullName.IndexOf("OutputDebugString", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        fullName.IndexOf("FailFast", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        string.Equals(pinvokeName, "IsDebuggerPresent", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(pinvokeName, "CheckRemoteDebuggerPresent", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(pinvokeName, "OutputDebugStringA", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(pinvokeName, "OutputDebugStringW", StringComparison.OrdinalIgnoreCase))
                        hasDebuggerCheck = true;
                    if (fullName.IndexOf("VirtualProtect", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        string.Equals(pinvokeName, "VirtualProtect", StringComparison.OrdinalIgnoreCase))
                        hasVirtualProtect = true;
                    if (fullName.IndexOf("add_ResourceResolve", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        fullName.IndexOf("add_AssemblyResolve", StringComparison.OrdinalIgnoreCase) >= 0)
                        hasResourceResolve = true;
                    if (fullName.IndexOf("InitializeArray", StringComparison.OrdinalIgnoreCase) >= 0)
                        hasInitializeArray = true;
                    if (fullName.IndexOf("ZeroMemory", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        fullName.IndexOf("memset", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        string.Equals(pinvokeName, "RtlZeroMemory", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(pinvokeName, "ZeroMemory", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(pinvokeName, "memset", StringComparison.OrdinalIgnoreCase))
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

                if (inst.OpCode == OpCodes.Ldstr && inst.Operand is string sVal)
                {
                    if (sVal.IndexOf("ENABLE_PROFILING", StringComparison.OrdinalIgnoreCase) >= 0)
                        hasDebuggerCheck = true;
                }

                if (inst.OpCode == OpCodes.Ldftn && inst.Operand is IMethod delegatedMethod)
                {
                    var delDef = delegatedMethod.ResolveMethodDef() ?? (delegatedMethod as MethodDef);
                    if (delDef != null && delDef.HasBody && delDef.DeclaringType != null && delDef.DeclaringType.IsGlobalModuleType)
                    {
                        if (IsConfuserAntiDebugMethod(delDef))
                            hasDebuggerCheck = true;
                    }
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

            // 1. Anti-Dump: calls VirtualProtect to wipe/zero headers without decryption cipher arithmetic, debugger checks, or section metadata fields.
            // MUST explicitly exhibit proven PE header zeroing/wiping behavior (e.g. stind/initblk with 0 or ZeroMemory/memset structurally linked to the module base or PE header pointer).
            bool isAntiDump = hasVirtualProtect &&
                              !hasCipherArithmetic &&
                              !hasDebuggerCheck &&
                              !hasSectionField &&
                              HasLinkedPeHeaderZeroing(method);

            if (isAntiDump)
            {
                return "Anti-Dump";
            }

            // 2. Anti-Tamper: calls VirtualProtect and exhibits section fields or pointer decryption characteristics
            bool isAntiTamper = hasVirtualProtect && (
                hasSectionField ||
                (hasPointerWrite && hasCipherArithmetic) ||
                ((hasPointerConversion || hasPointerIndirection) && hasBackwardBranch && hasCipherArithmetic) ||
                (hasPeHeaderOffset && (hasCipherArithmetic || hasPointerWrite || hasPointerIndirection || hasPointerConversion))
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

            // 3. Canonical Stub calls
            if (IsExactStubProtectorCall(method))
            {
                return "Protector-Stub";
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

                // Check signature: ConfuserEx Anti-Debug hook takes 0 parameters and returns void
                if (method.Parameters.Count > 0 || (method.ReturnType != null && method.ReturnType.ElementType != ElementType.Void))
                {
                    string msg = $"Retaining method {method.Name} in <Module>.cctor: signature has parameters or non-void return type (application diagnostic).";
                    Logger.LogWarning($"[CleanerKiller] {msg}");
                    result?.RetainedHooksDetails.Add(msg);
                    result?.HookRecords.Add(new HookTraceRecord
                    {
                        HookId = $"Hook_Diagnostic_{method.Name}",
                        HookType = "Application-Diagnostic",
                        DeclaringType = method.DeclaringType?.FullName ?? "<Module>",
                        MethodName = method.Name?.String ?? string.Empty,
                        Action = "Retained",
                        Reason = msg,
                        Confidence = "HIGH"
                    });
                    return null;
                }

                // Check for confirmed ConfuserEx Anti-Debug behavior: termination (FailFast/Kill/ExitProcess) or watchdog thread
                bool hasTerminationOrWatchdog = HasAntiDebugTerminationOrWatchdog(method);
                if (!hasTerminationOrWatchdog)
                {
                    string msg = $"Retaining method {method.Name} in <Module>.cctor: contains debugger check but lacks confirmed ConfuserEx termination (FailFast/Kill) or watchdog thread pattern (application diagnostic).";
                    Logger.LogWarning($"[CleanerKiller] {msg}");
                    result?.RetainedHooksDetails.Add(msg);
                    result?.HookRecords.Add(new HookTraceRecord
                    {
                        HookId = $"Hook_Diagnostic_{method.Name}",
                        HookType = "Application-Diagnostic",
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

        private static bool HasAntiDebugTerminationOrWatchdog(MethodDef method)
        {
            if (method == null || !method.HasBody || method.Body.Instructions == null)
                return false;

            bool hasTerminateCall = false;
            bool hasWatchdogThread = false;

            foreach (var inst in method.Body.Instructions)
            {
                if (inst.OpCode == OpCodes.Ldstr && inst.Operand is string s)
                {
                    if (s.IndexOf("ENABLE_PROFILING", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        s.IndexOf("COR_ENABLE_PROFILING", StringComparison.OrdinalIgnoreCase) >= 0)
                        return true;
                }

                if (inst.Operand is IMethod called)
                {
                    string fn = called.FullName;
                    string pinvokeName = null;
                    var calledDef = called.ResolveMethodDef() ?? (called as MethodDef);
                    if (calledDef != null && calledDef.IsPinvokeImpl && calledDef.ImplMap != null)
                        pinvokeName = calledDef.ImplMap.Name?.String ?? calledDef.Name?.String;

                    if (fn.IndexOf("FailFast", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        fn.IndexOf("Kill", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        string.Equals(pinvokeName, "ExitProcess", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(pinvokeName, "TerminateProcess", StringComparison.OrdinalIgnoreCase))
                    {
                        hasTerminateCall = true;
                    }

                    if (fn.IndexOf("Thread::Start", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        hasWatchdogThread = true;
                    }
                }

                if (inst.OpCode == OpCodes.Ldftn && inst.Operand is IMethod delegated)
                {
                    var delDef = delegated.ResolveMethodDef() ?? (delegated as MethodDef);
                    if (delDef != null && delDef.HasBody && delDef.DeclaringType != null && delDef.DeclaringType.IsGlobalModuleType)
                    {
                        if (HasAntiDebugTerminationOrWatchdog(delDef))
                            hasWatchdogThread = true;
                    }
                }
            }

            return hasTerminateCall || hasWatchdogThread;
        }

        private static bool IsConfuserAntiDebugMethod(MethodDef method)
        {
            if (method == null || !method.HasBody || method.Body.Instructions == null)
                return false;

            foreach (var inst in method.Body.Instructions)
            {
                if (inst.OpCode == OpCodes.Ldstr && inst.Operand is string s &&
                    s.IndexOf("ENABLE_PROFILING", StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;

                if (inst.Operand is IMethod called)
                {
                    string fn = called.FullName;
                    if (fn.IndexOf("IsAttached", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        fn.IndexOf("IsLogging", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        fn.IndexOf("FailFast", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        fn.IndexOf("IsDebuggerPresent", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        fn.IndexOf("CheckRemoteDebuggerPresent", StringComparison.OrdinalIgnoreCase) >= 0)
                        return true;
                }
            }

            return false;
        }

        internal const int MaxPeHeaderDisplacement = PeSymbolicEvaluator.MaxPeHeaderDisplacement;
        internal static bool IsNumeric(PeSymbolicSlot v) => PeSymbolicEvaluator.IsNumeric(v);
        internal static bool IsAlignmentMask(long mask) => PeSymbolicEvaluator.IsAlignmentMask(mask);
        internal static bool IsPeTarget(PeSymbolicSlot addr) => PeSymbolicEvaluator.IsPeTarget(addr);
        internal static PeSymbolicSlot CreateNumericSlot(long val, IntegerWidth width = IntegerWidth.Bit32) => PeSymbolicEvaluator.CreateNumericSlot(val, width);
        internal static bool HasLinkedPeHeaderZeroing(MethodDef method) => PeSymbolicEvaluator.HasLinkedPeHeaderZeroing(method);
        internal static void ExecuteSymbolicInstruction(Instruction inst, List<PeSymbolicSlot> stack, PeSymbolicSlot[] locals, ref bool zeroingDetected, ModuleDef module) => PeSymbolicEvaluator.ExecuteSymbolicInstruction(inst, stack, locals, ref zeroingDetected, module);
        internal static PeSymbolicSlot CombineAdd(PeSymbolicSlot a, PeSymbolicSlot b) => PeSymbolicEvaluator.CombineAdd(a, b);
        internal static PeSymbolicSlot CombineSub(PeSymbolicSlot a, PeSymbolicSlot b) => PeSymbolicEvaluator.CombineSub(a, b);
        internal static PeSymbolicSlot CombineAnd(PeSymbolicSlot a, PeSymbolicSlot b) => PeSymbolicEvaluator.CombineAnd(a, b);


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

        internal static bool IsReferencedInModule(ModuleDef module, MethodDef target, IEnumerable<MethodDef> excludedMethods = null)
        {
            if (module == null || target == null) return false;

            // Rule 1: A public method on a normal (non-global) type or unmanaged export can be invoked from outside the module
            if (target.IsPublic && (target.DeclaringType == null || !target.DeclaringType.IsGlobalModuleType))
                return true;

            // Rule 2: Module or Assembly entry point can never be deleted
            if (module.EntryPoint == target || (module.Assembly?.ManifestModule != null && module.Assembly.ManifestModule.EntryPoint == target))
                return true;

            var excluded = excludedMethods != null ? new HashSet<MethodDef>(excludedMethods) : new HashSet<MethodDef>();
            excluded.Add(target);

            foreach (var type in module.GetTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody || method.Body.Instructions == null || excluded.Contains(method))
                        continue;

                    foreach (var inst in method.Body.Instructions)
                    {
                        // Check direct and indirect calls (call, callvirt, ldftn, ldvirtftn)
                        if (inst.Operand is IMethod called)
                        {
                            var resolved = called.ResolveMethodDef() ?? (called as MethodDef);
                            if (resolved == target || called == target)
                                return true;
                        }
                        else if (inst.Operand is MethodDef md && md == target)
                        {
                            return true;
                        }

                        // Check ldtoken Method
                        if (inst.OpCode == OpCodes.Ldtoken && inst.Operand is IMethod tokenMethod)
                        {
                            var resolved = tokenMethod.ResolveMethodDef() ?? (tokenMethod as MethodDef);
                            if (resolved == target || tokenMethod == target)
                                return true;
                        }

                        // Check reflection string literals loading target method name (e.g. Type.GetMethod("methodName"))
                        if (inst.OpCode == OpCodes.Ldstr && inst.Operand is string s && s == target.Name.String)
                        {
                            return true;
                        }
                    }
                }
            }
            return false;
        }
    }
}
