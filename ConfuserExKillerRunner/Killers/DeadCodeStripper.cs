using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Tool;

namespace ConfuserExKillerRunner.Killers
{
    public sealed class DeadCodeStripperResult
    {
        public int JunkPairsStripped { get; set; }
        public int TrampolinesFlattened { get; set; }
        public int JumpChainsCollapsed { get; set; }
        public int NopsRemoved { get; set; }
        public int MethodsOptimized { get; set; }
        public string Message { get; set; }
    }

    public static class DeadCodeStripper
    {
        public static DeadCodeStripperResult Execute(ModuleDef module)
        {
            if (module == null) throw new ArgumentNullException(nameof(module));

            var result = new DeadCodeStripperResult();

            foreach (var type in module.GetTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody || method.Body.Instructions == null || method.Body.Instructions.Count < 2)
                        continue;

                    var originalBody = ConfuserExKillerRunner.Core.MethodBodyCloner.Clone(method.Body);
                    try
                    {
                        bool methodModified = false;
                        var instrs = method.Body.Instructions;

                        // Pass 1: Eliminate junk stack pairs (ldc.i4; pop and dup; pop)
                        var protectedTargets = GetProtectedTargets(method);
                        var branchTargets = GetBranchTargets(instrs);

                        for (int i = 0; i < instrs.Count - 1; i++)
                        {
                            var first = instrs[i];
                            var second = instrs[i + 1];

                            if (second.OpCode == OpCodes.Pop)
                            {
                                if (first.IsLdcI4() || first.OpCode == OpCodes.Dup)
                                {
                                    // Verify second instruction is not a jump or handler target
                                    if (!protectedTargets.Contains(second) && !branchTargets.Contains(second))
                                    {
                                        first.OpCode = OpCodes.Nop;
                                        first.Operand = null;
                                        second.OpCode = OpCodes.Nop;
                                        second.Operand = null;
                                        result.JunkPairsStripped++;
                                        methodModified = true;
                                        i++; // Skip pop
                                    }
                                }
                            }
                        }

                        // Pass 2: Trampoline flattening & jump-to-jump collapsing
                        for (int i = 0; i < instrs.Count; i++)
                        {
                            var instr = instrs[i];

                            // 2A: Detect unconditional branch to immediate next non-nop instruction
                            if (instr.OpCode == OpCodes.Br || instr.OpCode == OpCodes.Br_S)
                            {
                                if (instr.Operand is Instruction target)
                                {
                                    Instruction nextExecutable = null;
                                    for (int j = i + 1; j < instrs.Count; j++)
                                    {
                                        if (instrs[j].OpCode != OpCodes.Nop)
                                        {
                                            nextExecutable = instrs[j];
                                            break;
                                        }
                                    }

                                    if (target == nextExecutable)
                                    {
                                        instr.OpCode = OpCodes.Nop;
                                        instr.Operand = null;
                                        result.TrampolinesFlattened++;
                                        methodModified = true;
                                    }
                                }
                            }

                            // 2B: Collapse jump chains (br -> br -> ... -> target)
                            if (instr.Operand is Instruction singleTarget)
                            {
                                Instruction current = singleTarget;
                                int depth = 0;
                                while (depth < 30 && current != null &&
                                       (current.OpCode == OpCodes.Br || current.OpCode == OpCodes.Br_S) &&
                                       current.Operand is Instruction next && next != current)
                                {
                                    current = next;
                                    depth++;
                                }

                                if (current != singleTarget)
                                {
                                    instr.Operand = current;
                                    result.JumpChainsCollapsed++;
                                    methodModified = true;
                                }
                            }
                            else if (instr.Operand is Instruction[] switchTargets)
                            {
                                for (int s = 0; s < switchTargets.Length; s++)
                                {
                                    Instruction current = switchTargets[s];
                                    int depth = 0;
                                    while (depth < 30 && current != null &&
                                           (current.OpCode == OpCodes.Br || current.OpCode == OpCodes.Br_S) &&
                                           current.Operand is Instruction next && next != current)
                                    {
                                        current = next;
                                        depth++;
                                    }

                                    if (current != switchTargets[s])
                                    {
                                        switchTargets[s] = current;
                                        result.JumpChainsCollapsed++;
                                        methodModified = true;
                                    }
                                }
                            }
                        }

                        // Pass 3: Redirect branch/handler targets jumping to NOPs and remove unreferenced NOPs
                        if (methodModified)
                        {
                            RedirectNopTargets(method);
                            int removed = RemoveUnreferencedNops(method);
                            result.NopsRemoved += removed;

                            method.Body.SimplifyBranches();
                            method.Body.OptimizeBranches();

                            if (!ConfuserExKillerRunner.Analysis.QualityAuditor.IsMethodStructurallyValid(method, out var errors))
                            {
                                method.Body = originalBody;
                                Logger.LogWarning($"[DeadCodeStripper] Structural invariant violation in {method.FullName}: {string.Join("; ", errors)}. Rolled back.");
                                continue;
                            }

                            result.MethodsOptimized++;
                        }
                    }
                    catch (Exception ex)
                    {
                        // Rollback on any unexpected exception to preserve IL integrity
                        method.Body = originalBody;
                        Logger.LogWarning($"[DeadCodeStripper] Optimization rollback in {method.FullName}: {ex.Message}");
                    }
                }
            }

            result.Message = $"Optimized {result.MethodsOptimized} methods (stripped {result.JunkPairsStripped} junk pairs, " +
                             $"flattened {result.TrampolinesFlattened} trampolines, collapsed {result.JumpChainsCollapsed} jump chains, " +
                             $"removed {result.NopsRemoved} NOPs)";
            Logger.LogInfo($"[DeadCodeStripper] {result.Message}");

            return result;
        }

        private static HashSet<Instruction> GetProtectedTargets(MethodDef method)
        {
            var protectedTargets = new HashSet<Instruction>();
            if (method.Body.HasExceptionHandlers)
            {
                foreach (var eh in method.Body.ExceptionHandlers)
                {
                    if (eh.TryStart != null) protectedTargets.Add(eh.TryStart);
                    if (eh.TryEnd != null) protectedTargets.Add(eh.TryEnd);
                    if (eh.HandlerStart != null) protectedTargets.Add(eh.HandlerStart);
                    if (eh.HandlerEnd != null) protectedTargets.Add(eh.HandlerEnd);
                    if (eh.FilterStart != null) protectedTargets.Add(eh.FilterStart);
                }
            }
            return protectedTargets;
        }

        private static HashSet<Instruction> GetBranchTargets(IList<Instruction> instrs)
        {
            var targets = new HashSet<Instruction>();
            foreach (var inst in instrs)
            {
                if (inst.Operand is Instruction target)
                {
                    targets.Add(target);
                }
                else if (inst.Operand is Instruction[] switchTargets)
                {
                    foreach (var st in switchTargets)
                    {
                        if (st != null)
                            targets.Add(st);
                    }
                }
            }
            return targets;
        }

        private static void RedirectNopTargets(MethodDef method)
        {
            var instrs = method.Body.Instructions;
            var nopTargetMap = new Dictionary<Instruction, Instruction>();

            for (int i = 0; i < instrs.Count; i++)
            {
                if (instrs[i].OpCode == OpCodes.Nop)
                {
                    Instruction nextValid = null;
                    for (int j = i + 1; j < instrs.Count; j++)
                    {
                        if (instrs[j].OpCode != OpCodes.Nop)
                        {
                            nextValid = instrs[j];
                            break;
                        }
                    }

                    if (nextValid != null)
                        nopTargetMap[instrs[i]] = nextValid;
                }
            }

            if (nopTargetMap.Count == 0)
                return;

            // Retarget branch instructions
            foreach (var inst in instrs)
            {
                if (inst.Operand is Instruction target && nopTargetMap.TryGetValue(target, out var newTarget))
                {
                    inst.Operand = newTarget;
                }
                else if (inst.Operand is Instruction[] switchTargets)
                {
                    for (int s = 0; s < switchTargets.Length; s++)
                    {
                        if (switchTargets[s] != null && nopTargetMap.TryGetValue(switchTargets[s], out var stTarget))
                            switchTargets[s] = stTarget;
                    }
                }
            }

            // Retarget exception handlers
            if (method.Body.HasExceptionHandlers)
            {
                foreach (var eh in method.Body.ExceptionHandlers)
                {
                    if (eh.TryStart != null && nopTargetMap.TryGetValue(eh.TryStart, out var newTryStart))
                        eh.TryStart = newTryStart;
                    if (eh.TryEnd != null && nopTargetMap.TryGetValue(eh.TryEnd, out var newTryEnd))
                        eh.TryEnd = newTryEnd;
                    if (eh.HandlerStart != null && nopTargetMap.TryGetValue(eh.HandlerStart, out var newHandlerStart))
                        eh.HandlerStart = newHandlerStart;
                    if (eh.HandlerEnd != null && nopTargetMap.TryGetValue(eh.HandlerEnd, out var newHandlerEnd))
                        eh.HandlerEnd = newHandlerEnd;
                    if (eh.FilterStart != null && nopTargetMap.TryGetValue(eh.FilterStart, out var newFilterStart))
                        eh.FilterStart = newFilterStart;
                }
            }
        }

        private static int RemoveUnreferencedNops(MethodDef method)
        {
            var instrs = method.Body.Instructions;
            var protectedTargets = GetProtectedTargets(method);
            var branchTargets = GetBranchTargets(instrs);

            int removed = 0;
            for (int i = instrs.Count - 1; i >= 0; i--)
            {
                if (instrs[i].OpCode == OpCodes.Nop)
                {
                    if (!protectedTargets.Contains(instrs[i]) && !branchTargets.Contains(instrs[i]))
                    {
                        instrs.RemoveAt(i);
                        removed++;
                    }
                }
            }

            return removed;
        }
    }
}
