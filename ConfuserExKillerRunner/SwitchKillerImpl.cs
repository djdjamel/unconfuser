using System;
using System.Collections.Generic;
using System.Linq;
using de4dot.blocks;
using de4dot.blocks.cflow;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

namespace ConfuserExKillerRunner
{
    public static class SwitchKillerImpl
    {
        public static int Execute(ModuleDef module)
        {
            var methods = new List<MethodDef>();
            foreach (var type in module.GetTypes())
                CollectMethods(type, methods);

            var deobfuscator = new BlocksCflowDeobfuscator();

            // Pass 1: cflow deobfuscation
            RunCflow(methods, deobfuscator);

            // Pass 2: remove ldc+pop and dup+pop patterns
            RemoveNopPatterns(methods);

            // Pass 3: cflow again
            RunCflow(methods, deobfuscator);

            // Pass 4: resolve simple switch (ldc xor switch)
            ResolveSimpleSwitch(methods);

            // Pass 5: cflow again
            RunCflow(methods, deobfuscator);

            // Pass 6: fix conditional branches
            FixConditionalBranches(methods);

            // Pass 7: cflow again
            RunCflow(methods, deobfuscator);

            // Pass 8: resolve complex switch patterns
            int count = ResolveComplexSwitch(methods, deobfuscator);

            // Pass 9: final cflow
            RunCflow(methods, deobfuscator);

            return count;
        }

        static void CollectMethods(TypeDef type, List<MethodDef> methods)
        {
            if (type.HasMethods)
                foreach (var m in type.Methods)
                    if (m.HasBody) methods.Add(m);
            if (type.HasNestedTypes)
                foreach (var nested in type.NestedTypes)
                    CollectMethods(nested, methods);
        }

        private static HashSet<Instruction> CollectBranchTargets(CilBody body)
        {
            var targets = new HashSet<Instruction>();
            foreach (var inst in body.Instructions)
            {
                if (inst.Operand is Instruction singleTarget && singleTarget != null)
                    targets.Add(singleTarget);
                else if (inst.Operand is IList<Instruction> multiTargets)
                {
                    foreach (var t in multiTargets)
                        if (t != null) targets.Add(t);
                }
            }
            if (body.HasExceptionHandlers)
            {
                foreach (var eh in body.ExceptionHandlers)
                {
                    if (eh.TryStart != null) targets.Add(eh.TryStart);
                    if (eh.TryEnd != null) targets.Add(eh.TryEnd);
                    if (eh.HandlerStart != null) targets.Add(eh.HandlerStart);
                    if (eh.HandlerEnd != null) targets.Add(eh.HandlerEnd);
                    if (eh.FilterStart != null) targets.Add(eh.FilterStart);
                }
            }
            return targets;
        }

        internal static void RunCflow(List<MethodDef> methods, BlocksCflowDeobfuscator deobfuscator)
        {
            foreach (var method in methods)
            {
                if (!method.HasBody) continue;
                var origBody = ConfuserExKillerRunner.Core.MethodBodyCloner.Clone(method.Body);
                try
                {
                    var blocks = new Blocks(method);
                    deobfuscator.Initialize(blocks);
                    deobfuscator.Deobfuscate();
                    blocks.RepartitionBlocks();
                    blocks.GetCode(out var instrs, out var handlers);
                    DotNetUtils.RestoreBody(method, instrs, handlers);

                    if (!ConfuserExKillerRunner.Analysis.QualityAuditor.IsMethodStructurallyValid(method, out var errors))
                    {
                        method.Body = origBody;
                        Tool.Logger.LogWarning($"[0x{method.MDToken.Raw:X8}] RunCflow produced invalid body in {method}: {string.Join("; ", errors)}. Rolled back.");
                    }
                }
                catch (Exception ex)
                {
                    method.Body = origBody;
                    Tool.Logger.LogWarning($"[0x{method.MDToken.Raw:X8}] RunCflow failed on {method}: {ex.Message}. Rolled back.");
                }
            }
        }

        internal static void RemoveNopPatterns(List<MethodDef> methods)
        {
            foreach (var method in methods)
            {
                if (!method.HasBody || method.Body.Instructions == null || method.Body.Instructions.Count < 2)
                    continue;

                var origBody = ConfuserExKillerRunner.Core.MethodBodyCloner.Clone(method.Body);
                try
                {
                    var instrs = method.Body.Instructions;
                    var branchTargets = CollectBranchTargets(method.Body);

                    // Collect exception handler boundaries explicitly
                    var ehBoundaries = new HashSet<Instruction>();
                    if (method.Body.HasExceptionHandlers)
                    {
                        foreach (var eh in method.Body.ExceptionHandlers)
                        {
                            if (eh.TryStart != null) ehBoundaries.Add(eh.TryStart);
                            if (eh.TryEnd != null) ehBoundaries.Add(eh.TryEnd);
                            if (eh.HandlerStart != null) ehBoundaries.Add(eh.HandlerStart);
                            if (eh.HandlerEnd != null) ehBoundaries.Add(eh.HandlerEnd);
                            if (eh.FilterStart != null) ehBoundaries.Add(eh.FilterStart);
                        }
                    }

                    // Build incoming branches map for each target instruction (supporting both single targets and switch multi-targets)
                    var incomingBranches = new Dictionary<Instruction, List<int>>();
                    for (int k = 0; k < instrs.Count; k++)
                    {
                        var inst = instrs[k];
                        if (inst.Operand is Instruction singleTarget && singleTarget != null)
                        {
                            if (!incomingBranches.TryGetValue(singleTarget, out var list))
                            {
                                list = new List<int>();
                                incomingBranches[singleTarget] = list;
                            }
                            list.Add(k);
                        }
                        else if (inst.Operand is IList<Instruction> multiTargets)
                        {
                            foreach (var t in multiTargets)
                            {
                                if (t != null)
                                {
                                    if (!incomingBranches.TryGetValue(t, out var list))
                                    {
                                        list = new List<int>();
                                        incomingBranches[t] = list;
                                    }
                                    list.Add(k);
                                }
                            }
                        }
                    }

                    bool modified = false;
                    for (int j = 0; j < instrs.Count; j++)
                    {
                        // ldc.i4 + pop
                        if (instrs[j].IsLdcI4() && j + 1 < instrs.Count && instrs[j + 1].OpCode == OpCodes.Pop)
                        {
                            var ldcInst = instrs[j];
                            var popInst = instrs[j + 1];

                            // Reject if either instruction is a protected exception boundary
                            if (ehBoundaries.Contains(ldcInst) || ehBoundaries.Contains(popInst))
                                continue;

                            // Reject if ldc is targeted by any branch
                            if (branchTargets.Contains(ldcInst))
                                continue;

                            // If pop is targeted by branches, verify that EVERY incoming branch is a valid pairing:
                            // a branch from an instruction whose preceding instruction is ldc.i4 (not targeted).
                            bool canRemove = true;
                            var matchingBranches = new List<int>();
                            if (incomingBranches.TryGetValue(popInst, out var branches))
                            {
                                foreach (int brIdx in branches)
                                {
                                    var brInst = instrs[brIdx];
                                    if ((brInst.OpCode == OpCodes.Br || brInst.OpCode == OpCodes.Br_S)
                                        && brIdx - 1 >= 0
                                        && instrs[brIdx - 1].IsLdcI4()
                                        && !branchTargets.Contains(instrs[brIdx - 1])
                                        && !ehBoundaries.Contains(instrs[brIdx - 1]))
                                    {
                                        matchingBranches.Add(brIdx - 1);
                                    }
                                    else
                                    {
                                        canRemove = false;
                                        break;
                                    }
                                }
                            }
                            else if (branchTargets.Contains(popInst))
                            {
                                canRemove = false;
                            }

                            if (canRemove)
                            {
                                ldcInst.OpCode = OpCodes.Nop;
                                ldcInst.Operand = null;
                                popInst.OpCode = OpCodes.Nop;
                                popInst.Operand = null;
                                foreach (int prevIdx in matchingBranches)
                                {
                                    instrs[prevIdx].OpCode = OpCodes.Nop;
                                    instrs[prevIdx].Operand = null;
                                }
                                modified = true;
                            }
                        }
                        // dup + pop
                        if (j < instrs.Count && instrs[j].OpCode == OpCodes.Dup && j + 1 < instrs.Count && instrs[j + 1].OpCode == OpCodes.Pop)
                        {
                            var dupInst = instrs[j];
                            var popInst = instrs[j + 1];

                            // Reject if either instruction is a protected exception boundary
                            if (ehBoundaries.Contains(dupInst) || ehBoundaries.Contains(popInst))
                                continue;

                            // Reject if dup is targeted by any branch
                            if (branchTargets.Contains(dupInst))
                                continue;

                            bool canRemove = true;
                            var matchingBranches = new List<int>();
                            if (incomingBranches.TryGetValue(popInst, out var branches))
                            {
                                foreach (int brIdx in branches)
                                {
                                    var brInst = instrs[brIdx];
                                    if ((brInst.OpCode == OpCodes.Br || brInst.OpCode == OpCodes.Br_S)
                                        && brIdx - 1 >= 0
                                        && instrs[brIdx - 1].OpCode == OpCodes.Dup
                                        && !branchTargets.Contains(instrs[brIdx - 1])
                                        && !ehBoundaries.Contains(instrs[brIdx - 1]))
                                    {
                                        matchingBranches.Add(brIdx - 1);
                                    }
                                    else
                                    {
                                        canRemove = false;
                                        break;
                                    }
                                }
                            }
                            else if (branchTargets.Contains(popInst))
                            {
                                canRemove = false;
                            }

                            if (canRemove)
                            {
                                dupInst.OpCode = OpCodes.Nop;
                                dupInst.Operand = null;
                                popInst.OpCode = OpCodes.Nop;
                                popInst.Operand = null;
                                foreach (int prevIdx in matchingBranches)
                                {
                                    instrs[prevIdx].OpCode = OpCodes.Nop;
                                    instrs[prevIdx].Operand = null;
                                }
                                modified = true;
                            }
                        }
                    }

                    if (!modified)
                        continue;

                    if (!ConfuserExKillerRunner.Analysis.QualityAuditor.IsMethodStructurallyValid(method, out var errors))
                    {
                        method.Body = origBody;
                        Tool.Logger.LogWarning($"[0x{method.MDToken.Raw:X8}] RemoveNopPatterns produced invalid body in {method}: {string.Join("; ", errors)}. Rolled back.");
                    }
                }
                catch (Exception ex)
                {
                    method.Body = origBody;
                    Tool.Logger.LogWarning($"[0x{method.MDToken.Raw:X8}] RemoveNopPatterns failed on {method}: {ex.Message}. Rolled back.");
                }
            }
        }

        internal static void ResolveSimpleSwitch(List<MethodDef> methods)
        {
            foreach (var method in methods)
            {
                if (!method.HasBody) continue;
                var origBody = ConfuserExKillerRunner.Core.MethodBodyCloner.Clone(method.Body);
                try
                {
                    var instrs = method.Body.Instructions;
                    var instToIndex = new Dictionary<Instruction, int>();
                    for (int i = 0; i < instrs.Count; i++)
                        instToIndex[instrs[i]] = i;

                    var switchInstrs = new List<Instruction>();
                    var ldcValues = new List<int>();
                    var xorValues = new List<int>();

                    for (int j = 0; j < instrs.Count; j++)
                    {
                        if (j + 3 < instrs.Count && instrs[j].IsLdcI4() && instrs[j + 1].IsLdcI4()
                            && instrs[j + 2].OpCode == OpCodes.Xor && instrs[j + 3].OpCode == OpCodes.Switch)
                        {
                            ldcValues.Add(instrs[j].GetLdcI4Value());
                            xorValues.Add(instrs[j + 1].GetLdcI4Value());
                            switchInstrs.Add(instrs[j + 3]);
                        }
                    }

                    if (switchInstrs.Count == 0) continue;

                    bool modified = false;
                    for (int j = 0; j < instrs.Count; j++)
                    {
                        if (j + 1 < instrs.Count && instrs[j].IsLdcI4() && instrs[j + 1].IsBr())
                        {
                            if (instrs[j + 1].Operand is Instruction target && target != null)
                            {
                                for (int k = 0; k < switchInstrs.Count; k++)
                                {
                                    if (!instToIndex.TryGetValue(switchInstrs[k], out int si))
                                        continue;

                                    if (si >= 3 && instrs[si - 3] == target)
                                    {
                                        if ((uint)xorValues[k] == 0)
                                            continue;

                                        int val = instrs[j].GetLdcI4Value();
                                        uint idx = (uint)(val ^ ldcValues[k]) % (uint)xorValues[k];
                                        var targets = switchInstrs[k].Operand as Instruction[];
                                        if (targets == null || idx >= targets.Length || targets[(int)idx] == null)
                                            continue;

                                        instrs[j].OpCode = OpCodes.Ldc_I4;
                                        instrs[j].Operand = (int)(uint)(val ^ ldcValues[k]);
                                        instrs[j + 1].Operand = targets[(int)idx];
                                        modified = true;
                                        j++;
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    if (!modified)
                        continue;

                    method.Body.SimplifyBranches();
                    method.Body.OptimizeBranches();

                    if (!ConfuserExKillerRunner.Analysis.QualityAuditor.IsMethodStructurallyValid(method, out var errors))
                    {
                        method.Body = origBody;
                        Tool.Logger.LogWarning($"[0x{method.MDToken.Raw:X8}] ResolveSimpleSwitch produced invalid body in {method}: {string.Join("; ", errors)}. Rolled back.");
                    }
                }
                catch (Exception ex)
                {
                    method.Body = origBody;
                    Tool.Logger.LogWarning($"[0x{method.MDToken.Raw:X8}] ResolveSimpleSwitch failed on {method}: {ex.Message}. Rolled back.");
                }
            }
        }

        static void FixConditionalBranches(List<MethodDef> methods)
        {
            foreach (var method in methods)
            {
                if (!method.HasBody) continue;
                var origBody = ConfuserExKillerRunner.Core.MethodBodyCloner.Clone(method.Body);
                try
                {
                    var instrs = method.Body.Instructions;
                    var done = new Dictionary<Instruction, Instruction>();
                    for (int j = 0; j < instrs.Count; j++)
                    {
                        if (!instrs[j].IsConditionalBranch()) continue;
                        if (j + 1 >= instrs.Count) continue;
                        var condInstr = instrs[j];
                        var nextInstr = instrs[j + 1];
                        if (nextInstr == null) continue;

                        for (int k = 0; k < instrs.Count; k++)
                        {
                            if (!instrs[k].IsBr()) continue;
                            var brTarget = instrs[k].Operand as Instruction;
                            if (brTarget != condInstr) continue;
                            if (done.ContainsKey(brTarget)) continue;
                            instrs[k].OpCode = condInstr.GetOpCode();
                            instrs[k].Operand = condInstr.GetOperand();
                            instrs.Insert(k + 1, OpCodes.Br.ToInstruction(nextInstr));
                            if (k < j) j++;
                            k++;
                            done.Add(brTarget, instrs[k]);
                        }
                    }

                    if (done.Count == 0)
                        continue;

                    method.Body.SimplifyBranches();
                    method.Body.OptimizeBranches();

                    if (!ConfuserExKillerRunner.Analysis.QualityAuditor.IsMethodStructurallyValid(method, out var errors))
                    {
                        method.Body = origBody;
                        Tool.Logger.LogWarning($"[0x{method.MDToken.Raw:X8}] FixConditionalBranches produced invalid body in {method}: {string.Join("; ", errors)}. Rolled back.");
                    }
                }
                catch (Exception ex)
                {
                    method.Body = origBody;
                    Tool.Logger.LogWarning($"[0x{method.MDToken.Raw:X8}] FixConditionalBranches failed on {method}: {ex.Message}. Rolled back.");
                }
            }
        }

        class ComplexDispatcher
        {
            public int HeaderIndex;
            public int PatternSize; // 6 (local) or 4 (no-local)
            public int IntValue;
            public int ForRem;
            public Instruction SwitchInstr;
            public Local LocalVar; // null if no-local
            public HashSet<Instruction> HeaderInstructions = new HashSet<Instruction>();
        }

        class ResolvedTransition
        {
            public ComplexDispatcher Dispatcher;
            public int TransitionIndex; // i
            public int Value;
            public Instruction BranchInst;
            public Instruction Destination;
        }

        internal static int ResolveComplexSwitch(List<MethodDef> methods, BlocksCflowDeobfuscator deobfuscator)
        {
            int total = 0;
            foreach (var method in methods)
            {
                if (!method.HasBody) continue;
                var origBody = ConfuserExKillerRunner.Core.MethodBodyCloner.Clone(method.Body);

                try
                {
                    var instrs = method.Body.Instructions;
                    var instToIndex = new Dictionary<Instruction, int>();
                    for (int i = 0; i < instrs.Count; i++)
                        instToIndex[instrs[i]] = i;

                    int methodTotal = 0;

                    // 1. First pattern: ldc xor dup stloc ldc rem switch (7-instruction pattern with local)
                    var localDispatchers = new List<ComplexDispatcher>();
                    for (int j = 0; j + 6 < instrs.Count; j++)
                    {
                        if (instrs[j].IsLdcI4() && instrs[j + 1].OpCode == OpCodes.Xor
                            && instrs[j + 4].IsLdcI4()
                            && instrs[j + 6].OpCode == OpCodes.Switch
                            && instrs[j + 3].IsStloc())
                        {
                            var d = new ComplexDispatcher
                            {
                                HeaderIndex = j,
                                PatternSize = 6,
                                IntValue = instrs[j].GetLdcI4Value(),
                                ForRem = instrs[j + 4].GetLdcI4Value(),
                                SwitchInstr = instrs[j + 6],
                                LocalVar = instrs[j + 3].GetLocal(method.Body.Variables)
                            };
                            for (int k = 0; k < 6; k++)
                                d.HeaderInstructions.Add(instrs[j + k]);
                            localDispatchers.Add(d);
                        }
                    }

                    if (localDispatchers.Count > 0)
                    {
                        var state = new SwitchState(instrs, method, localDispatchers, instToIndex);
                        state.Parse(0, 0u);
                        methodTotal += state.Apply();
                    }

                    // 2. Second pattern: ldc xor ldc [rem_un] switch (5-instruction pattern without local)
                    var noLocalDispatchers = new List<ComplexDispatcher>();
                    for (int j = 0; j + 4 < instrs.Count; j++)
                    {
                        if (instrs[j].IsLdcI4() && instrs[j + 1].OpCode == OpCodes.Xor
                            && instrs[j + 2].IsLdcI4() && instrs[j + 4].OpCode == OpCodes.Switch)
                        {
                            var d = new ComplexDispatcher
                            {
                                HeaderIndex = j,
                                PatternSize = 4,
                                IntValue = instrs[j].GetLdcI4Value(),
                                ForRem = instrs[j + 2].GetLdcI4Value(),
                                SwitchInstr = instrs[j + 4],
                                LocalVar = null
                            };
                            for (int k = 0; k < 4; k++)
                                d.HeaderInstructions.Add(instrs[j + k]);
                            noLocalDispatchers.Add(d);
                        }
                    }

                    if (noLocalDispatchers.Count > 0)
                    {
                        var state = new SwitchStateNoLocal(instrs, method, noLocalDispatchers, instToIndex);
                        state.Parse(0);
                        methodTotal += state.Apply(4);
                    }

                    if (methodTotal == 0)
                        continue;

                    var blocks = new Blocks(method);
                    deobfuscator.Initialize(blocks);
                    deobfuscator.Deobfuscate();
                    blocks.RepartitionBlocks();
                    blocks.GetCode(out var list, out var handlers);
                    DotNetUtils.RestoreBody(method, list, handlers);
                    method.Body.SimplifyBranches();
                    method.Body.OptimizeBranches();

                    if (!ConfuserExKillerRunner.Analysis.QualityAuditor.IsMethodStructurallyValid(method, out var errors))
                    {
                        method.Body = origBody;
                        Tool.Logger.LogWarning($"[0x{method.MDToken.Raw:X8}] ResolveComplexSwitch produced invalid body in {method}: {string.Join("; ", errors)}. Rolled back.");
                        continue;
                    }

                    total += methodTotal;
                }
                catch (Exception ex)
                {
                    method.Body = origBody;
                    Tool.Logger.LogWarning($"[0x{method.MDToken.Raw:X8}] ResolveComplexSwitch failed on {method}: {ex.Message}. Rolled back.");
                }
            }
            return total;
        }

        // Helper state classes for complex switch resolution (iterative stack-based parsing)
        class SwitchState
        {
            readonly IList<Instruction> instrs;
            readonly MethodDef method;
            readonly List<ComplexDispatcher> dispatchers;
            readonly Dictionary<Instruction, int> instToIndex;
            internal List<ResolvedTransition> resolvedTransitions = new List<ResolvedTransition>();
            HashSet<int> removedIdxSet = new HashSet<int>();
            HashSet<Instruction> brInstrs = new HashSet<Instruction>();
            HashSet<Instruction> realBrInstrs = new HashSet<Instruction>();
            HashSet<Instruction> condInstrs = new HashSet<Instruction>();
            Dictionary<Instruction, int> localValues = new Dictionary<Instruction, int>();

            internal SwitchState(IList<Instruction> instrs, MethodDef method,
                List<ComplexDispatcher> dispatchers, Dictionary<Instruction, int> instToIndex)
            {
                this.instrs = instrs;
                this.method = method;
                this.dispatchers = dispatchers;
                this.instToIndex = instToIndex;
            }

            internal void Parse(int startIdx, uint startLocalVal)
            {
                var workStack = new Stack<(int idx, uint localVal)>();
                var visited = new HashSet<(int idx, uint localVal)>();

                workStack.Push((startIdx, startLocalVal));

                if (method.Body.HasExceptionHandlers)
                {
                    foreach (var eh in method.Body.ExceptionHandlers)
                    {
                        if (eh.HandlerStart != null && instToIndex.TryGetValue(eh.HandlerStart, out int hIdx))
                            workStack.Push((hIdx, 0u));
                        if (eh.FilterStart != null && instToIndex.TryGetValue(eh.FilterStart, out int fIdx))
                            workStack.Push((fIdx, 0u));
                    }
                }

                while (workStack.Count > 0)
                {
                    var (idx, localVal) = workStack.Pop();
                    if (!visited.Add((idx, localVal)))
                        continue;

                    for (int i = idx; i < instrs.Count; i++)
                    {
                        if (removedIdxSet.Contains(i)) continue;

                        var inst = instrs[i];
                        if (inst.IsBr())
                        {
                            if (inst.Operand is Instruction t && t != null && instToIndex.TryGetValue(t, out int tIdx))
                            {
                                if (!brInstrs.Contains(t) && realBrInstrs.Add(t))
                                {
                                    workStack.Push((tIdx, localVal));
                                }
                            }
                            break;
                        }

                        if (inst.IsConditionalBranch() || inst.IsLeave())
                        {
                            if (inst.Operand is Instruction t && t != null && instToIndex.TryGetValue(t, out int tIdx))
                            {
                                if (condInstrs.Add(t))
                                {
                                    workStack.Push((tIdx, localVal));
                                    if (i + 1 < instrs.Count)
                                        workStack.Push((i + 1, localVal));
                                }
                            }
                            continue;
                        }

                        if (inst.OpCode == OpCodes.Ret) break;

                        if (inst.IsLdcI4() && i + 1 < instrs.Count && instrs[i + 1].IsStloc())
                        {
                            var stlocLocal = instrs[i + 1].GetLocal(method.Body.Variables);
                            if (dispatchers.Any(d => d.LocalVar == stlocLocal))
                            {
                                localVal = (uint)inst.GetLdcI4Value();
                                continue;
                            }
                        }

                        if (inst.IsLdcI4() || (inst.IsLdloc() && dispatchers.Any(d => d.LocalVar == inst.GetLocal(method.Body.Variables))))
                        {
                            uint num = inst.IsLdcI4() ? (uint)inst.GetLdcI4Value() : localVal;
                            int n2 = i + 1;
                            if (i + 1 < instrs.Count && instrs[i + 1].IsBr() && instrs[i + 1].Operand is Instruction brTarget && brTarget != null)
                            {
                                if (instToIndex.TryGetValue(brTarget, out int bIdx))
                                    n2 = bIdx;
                            }

                            if (n2 < instrs.Count && (instrs[n2].IsLdcI4() || (instrs[n2].IsLdloc() && dispatchers.Any(d => d.LocalVar == instrs[n2].GetLocal(method.Body.Variables)))))
                            {
                                uint num3 = instrs[n2].IsLdcI4() ? (uint)instrs[n2].GetLdcI4Value() : localVal;
                                TryResolve(i, n2, num, num3, ref localVal, workStack);
                            }
                        }
                        else if (inst.OpCode == OpCodes.Switch)
                        {
                            if (!IsKnownSwitch(inst))
                            {
                                if (inst.Operand is Instruction[] targets)
                                {
                                    foreach (var t in targets)
                                    {
                                        if (t != null && instToIndex.TryGetValue(t, out int tIdx))
                                            workStack.Push((tIdx, localVal));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            bool IsKnownSwitch(Instruction sw)
            {
                foreach (var d in dispatchers)
                    if (d.SwitchInstr == sw) return true;
                return false;
            }

            void TryResolve(int i, int n2, uint num, uint num3, ref uint localVal, Stack<(int idx, uint localVal)> workStack)
            {
                if (n2 + 3 >= instrs.Count) return;
                bool mulXor = (instrs[n2 + 1].OpCode == OpCodes.Mul && instrs[n2 + 2].IsLdcI4())
                           || (instrs[n2 + 1].IsLdcI4() && instrs[n2 + 2].OpCode == OpCodes.Mul)
                           || instrs[n2 + 1].OpCode == OpCodes.Xor;
                if (!mulXor) return;
                if (instrs[n2 + 3].OpCode != OpCodes.Xor && instrs[n2 + 1].OpCode != OpCodes.Xor) return;
                uint num4 = 0;
                if (instrs[n2 + 1].OpCode == OpCodes.Mul && instrs[n2 + 2].IsLdcI4()) num4 = (uint)instrs[n2 + 2].GetLdcI4Value();
                if (instrs[n2 + 1].IsLdcI4() && instrs[n2 + 2].OpCode == OpCodes.Mul) num4 = (uint)instrs[n2 + 1].GetLdcI4Value();

                for (int j = 0; j < dispatchers.Count; j++)
                {
                    var d = dispatchers[j];
                    Instruction brInst = null;
                    if (n2 + 4 < instrs.Count && instrs[n2 + 4].IsBr())
                        brInst = instrs[n2 + 4];

                    bool match = (brInst != null && brInst.Operand as Instruction == instrs[d.HeaderIndex])
                              || n2 + 4 == d.HeaderIndex
                              || (instrs[n2 + 1].OpCode == OpCodes.Xor && n2 == d.HeaderIndex);
                    if (!match) continue;

                    uint num5 = instrs[n2 + 1].OpCode == OpCodes.Xor ? (num ^ num3)
                              : (instrs[n2 + 1].IsLdcI4() ? (num4 * num3 ^ num) : (num * num3 ^ num4));
                    if (instrs[n2 + 1].OpCode != OpCodes.Xor) localVal = num5 ^ (uint)d.IntValue;
                    else localVal = num5;
                    if ((uint)d.ForRem == 0) continue;
                    uint idx = localVal % (uint)d.ForRem;
                    var arr = d.SwitchInstr.Operand as Instruction[];
                    if (arr == null || idx >= arr.Length) continue;
                    var dest = arr[(int)idx];
                    if (dest == null) continue;

                    if (removedIdxSet.Contains(i)) return;
                    removedIdxSet.Add(i);

                    var trans = new ResolvedTransition
                    {
                        Dispatcher = d,
                        TransitionIndex = i,
                        Value = (int)idx,
                        BranchInst = brInst,
                        Destination = dest
                    };
                    resolvedTransitions.Add(trans);

                    if (!localValues.TryGetValue(dest, out int prevVal) || prevVal != (int)localVal)
                    {
                        brInstrs.Add(dest);
                        localValues[dest] = (int)localVal;
                        if (instToIndex.TryGetValue(dest, out int destIdx))
                            workStack.Push((destIdx, localVal));
                    }
                    break;
                }
            }

            internal int Apply()
            {
                if (resolvedTransitions.Count == 0) return 0;

                foreach (var d in dispatchers)
                {
                    bool hasEhTargeting = false;
                    if (method.Body.HasExceptionHandlers)
                    {
                        foreach (var eh in method.Body.ExceptionHandlers)
                        {
                            if (d.HeaderInstructions.Contains(eh.TryStart) || d.HeaderInstructions.Contains(eh.TryEnd) ||
                                d.HeaderInstructions.Contains(eh.HandlerStart) || d.HeaderInstructions.Contains(eh.HandlerEnd) ||
                                d.HeaderInstructions.Contains(eh.FilterStart))
                            {
                                hasEhTargeting = true;
                                break;
                            }
                        }
                    }

                    if (!hasEhTargeting)
                    {
                        for (int j = 0; j < d.PatternSize; j++)
                        {
                            instrs[d.HeaderIndex + j].OpCode = OpCodes.Nop;
                            instrs[d.HeaderIndex + j].Operand = null;
                        }
                    }
                }

                foreach (var trans in resolvedTransitions)
                {
                    int i = trans.TransitionIndex;
                    instrs[i].OpCode = OpCodes.Ldc_I4;
                    instrs[i].Operand = trans.Value;
                    if (i + 1 < instrs.Count && !instrs[i + 1].IsBr())
                    {
                        for (int k = 0; k < 4 && i + k + 1 < instrs.Count; k++)
                        {
                            instrs[i + k + 1].OpCode = OpCodes.Nop;
                            instrs[i + k + 1].Operand = null;
                        }
                    }
                }

                return resolvedTransitions.Count;
            }
        }

        class SwitchStateNoLocal
        {
            readonly IList<Instruction> instrs;
            readonly MethodDef method;
            readonly List<ComplexDispatcher> dispatchers;
            readonly Dictionary<Instruction, int> instToIndex;
            internal List<ResolvedTransition> resolvedTransitions = new List<ResolvedTransition>();
            HashSet<int> removedIdxSet = new HashSet<int>();
            HashSet<Instruction> brInstrs = new HashSet<Instruction>();
            HashSet<Instruction> realBrInstrs = new HashSet<Instruction>();
            HashSet<Instruction> condInstrs = new HashSet<Instruction>();

            internal SwitchStateNoLocal(IList<Instruction> instrs, MethodDef method,
                List<ComplexDispatcher> dispatchers, Dictionary<Instruction, int> instToIndex)
            {
                this.instrs = instrs;
                this.method = method;
                this.dispatchers = dispatchers;
                this.instToIndex = instToIndex;
            }

            internal void Parse(int startIdx)
            {
                var workStack = new Stack<int>();
                var visited = new HashSet<int>();

                workStack.Push(startIdx);

                if (method.Body.HasExceptionHandlers)
                {
                    foreach (var eh in method.Body.ExceptionHandlers)
                    {
                        if (eh.HandlerStart != null && instToIndex.TryGetValue(eh.HandlerStart, out int hIdx))
                            workStack.Push(hIdx);
                        if (eh.FilterStart != null && instToIndex.TryGetValue(eh.FilterStart, out int fIdx))
                            workStack.Push(fIdx);
                    }
                }

                while (workStack.Count > 0)
                {
                    int idx = workStack.Pop();
                    if (!visited.Add(idx)) continue;

                    for (int i = idx; i < instrs.Count; i++)
                    {
                        if (removedIdxSet.Contains(i)) continue;

                        var inst = instrs[i];
                        if (inst.IsBr())
                        {
                            if (inst.Operand is Instruction t && t != null && instToIndex.TryGetValue(t, out int tIdx))
                            {
                                if (!brInstrs.Contains(t) && realBrInstrs.Add(t))
                                    workStack.Push(tIdx);
                            }
                            break;
                        }

                        if (inst.IsConditionalBranch() || inst.IsLeave())
                        {
                            if (inst.Operand is Instruction t && t != null && instToIndex.TryGetValue(t, out int tIdx))
                            {
                                if (condInstrs.Add(t))
                                {
                                    workStack.Push(tIdx);
                                    if (i + 1 < instrs.Count) workStack.Push(i + 1);
                                }
                            }
                            continue;
                        }

                        if (inst.OpCode == OpCodes.Ret) break;

                        if (!inst.IsLdcI4())
                        {
                            if (inst.OpCode == OpCodes.Switch) TrySwitch(inst, workStack);
                            continue;
                        }

                        uint num = (uint)inst.GetLdcI4Value();
                        int n2 = i + 1;
                        if (i + 1 < instrs.Count && instrs[i + 1].IsBr() && instrs[i + 1].Operand is Instruction brTarget && brTarget != null)
                        {
                            if (instToIndex.TryGetValue(brTarget, out int bIdx))
                                n2 = bIdx;
                        }

                        if (n2 >= instrs.Count || !instrs[n2].IsLdcI4()) continue;
                        uint num3 = (uint)instrs[n2].GetLdcI4Value();
                        TryResolve(i, n2, num, num3, workStack);
                    }
                }
            }

            void TrySwitch(Instruction sw, Stack<int> workStack)
            {
                bool known = dispatchers.Any(d => d.SwitchInstr == sw);
                if (!known && sw.Operand is Instruction[] targets)
                {
                    foreach (var t in targets)
                    {
                        if (t != null && instToIndex.TryGetValue(t, out int tIdx))
                            workStack.Push(tIdx);
                    }
                }
            }

            void TryResolve(int i, int n2, uint num, uint num3, Stack<int> workStack)
            {
                if (n2 + 3 >= instrs.Count) return;
                bool mulXor = (instrs[n2 + 1].OpCode == OpCodes.Mul && instrs[n2 + 2].IsLdcI4())
                           || (instrs[n2 + 1].IsLdcI4() && instrs[n2 + 2].OpCode == OpCodes.Mul)
                           || instrs[n2 + 1].OpCode == OpCodes.Xor;
                if (!mulXor) return;
                if (instrs[n2 + 3].OpCode != OpCodes.Xor && instrs[n2 + 1].OpCode != OpCodes.Xor) return;
                uint num4 = 0;
                if (instrs[n2 + 1].OpCode == OpCodes.Mul && instrs[n2 + 2].IsLdcI4()) num4 = (uint)instrs[n2 + 2].GetLdcI4Value();
                if (instrs[n2 + 1].IsLdcI4() && instrs[n2 + 2].OpCode == OpCodes.Mul) num4 = (uint)instrs[n2 + 1].GetLdcI4Value();

                for (int j = 0; j < dispatchers.Count; j++)
                {
                    var d = dispatchers[j];
                    Instruction brInst = null;
                    if (n2 + 4 < instrs.Count && instrs[n2 + 4].IsBr())
                        brInst = instrs[n2 + 4];

                    bool match = (brInst != null && brInst.Operand as Instruction == instrs[d.HeaderIndex])
                              || n2 + 4 == d.HeaderIndex
                              || (instrs[n2 + 1].OpCode == OpCodes.Xor && n2 == d.HeaderIndex);
                    if (!match) continue;

                    uint num5 = instrs[n2 + 1].OpCode == OpCodes.Xor ? (num ^ num3)
                              : (instrs[n2 + 1].IsLdcI4() ? (num4 * num3 ^ num) : (num * num3 ^ num4));
                    uint num6 = instrs[n2 + 1].OpCode != OpCodes.Xor ? (num5 ^ (uint)d.IntValue) : num5;
                    if ((uint)d.ForRem == 0) continue;
                    uint idx = num6 % (uint)d.ForRem;
                    var arr = d.SwitchInstr.Operand as Instruction[];
                    if (arr == null || idx >= arr.Length) continue;
                    var dest = arr[(int)idx];
                    if (dest == null) continue;

                    if (removedIdxSet.Contains(i)) return;
                    removedIdxSet.Add(i);

                    var trans = new ResolvedTransition
                    {
                        Dispatcher = d,
                        TransitionIndex = i,
                        Value = (int)idx,
                        BranchInst = brInst,
                        Destination = dest
                    };
                    resolvedTransitions.Add(trans);

                    if (brInstrs.Add(dest))
                    {
                        if (instToIndex.TryGetValue(dest, out int destIdx))
                            workStack.Push(destIdx);
                    }
                    break;
                }
            }

            internal int Apply(int patternSize)
            {
                if (resolvedTransitions.Count == 0) return 0;

                foreach (var d in dispatchers)
                {
                    bool hasEhTargeting = false;
                    if (method.Body.HasExceptionHandlers)
                    {
                        foreach (var eh in method.Body.ExceptionHandlers)
                        {
                            if (d.HeaderInstructions.Contains(eh.TryStart) || d.HeaderInstructions.Contains(eh.TryEnd) ||
                                d.HeaderInstructions.Contains(eh.HandlerStart) || d.HeaderInstructions.Contains(eh.HandlerEnd) ||
                                d.HeaderInstructions.Contains(eh.FilterStart))
                            {
                                hasEhTargeting = true;
                                break;
                            }
                        }
                    }

                    if (!hasEhTargeting)
                    {
                        for (int j = 0; j < d.PatternSize; j++)
                        {
                            instrs[d.HeaderIndex + j].OpCode = OpCodes.Nop;
                            instrs[d.HeaderIndex + j].Operand = null;
                        }
                    }
                }

                foreach (var trans in resolvedTransitions)
                {
                    int i = trans.TransitionIndex;
                    instrs[i].OpCode = OpCodes.Ldc_I4;
                    instrs[i].Operand = trans.Value;
                    if (i + 1 < instrs.Count && !instrs[i + 1].IsBr())
                    {
                        for (int k = 0; k < 4 && i + k + 1 < instrs.Count; k++)
                        {
                            instrs[i + k + 1].OpCode = OpCodes.Nop;
                            instrs[i + k + 1].Operand = null;
                        }
                    }
                }

                return resolvedTransitions.Count;
            }
        }
    }
}
