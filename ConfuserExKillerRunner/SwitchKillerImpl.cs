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

        static void RunCflow(List<MethodDef> methods, BlocksCflowDeobfuscator deobfuscator)
        {
            foreach (var method in methods)
            {
                if (!method.HasBody) continue;
                var origInstrs = method.Body.Instructions.ToList();
                var origHandlers = method.Body.ExceptionHandlers.ToList();
                try
                {
                    var blocks = new Blocks(method);
                    deobfuscator.Initialize(blocks);
                    deobfuscator.Deobfuscate();
                    blocks.RepartitionBlocks();
                    blocks.GetCode(out var instrs, out var handlers);
                    DotNetUtils.RestoreBody(method, instrs, handlers);
                }
                catch (Exception ex)
                {
                    method.Body.Instructions.Clear();
                    foreach (var inst in origInstrs) method.Body.Instructions.Add(inst);
                    method.Body.ExceptionHandlers.Clear();
                    foreach (var h in origHandlers) method.Body.ExceptionHandlers.Add(h);
                    Tool.Logger.LogWarning($"[0x{method.MDToken.Raw:X8}] RunCflow failed on {method}: {ex.Message}. Rolled back.");
                }
            }
        }

        static void RemoveNopPatterns(List<MethodDef> methods)
        {
            foreach (var method in methods)
            {
                var instrs = method.Body.Instructions;
                for (int j = 0; j < instrs.Count; j++)
                {
                    // ldc.i4 + pop
                    if (instrs[j].IsLdcI4() && j + 1 < instrs.Count && instrs[j + 1].OpCode == OpCodes.Pop)
                    {
                        instrs[j].OpCode = OpCodes.Nop;
                        instrs[j + 1].OpCode = OpCodes.Nop;
                        for (int k = 0; k < instrs.Count; k++)
                            if ((instrs[k].OpCode == OpCodes.Br || instrs[k].OpCode == OpCodes.Br_S)
                                && instrs[k].Operand is Instruction target && target == instrs[j + 1]
                                && k - 1 >= 0 && instrs[k - 1].IsLdcI4())
                                instrs[k - 1].OpCode = OpCodes.Nop;
                    }
                    // dup + pop
                    if (j < instrs.Count && instrs[j].OpCode == OpCodes.Dup && j + 1 < instrs.Count && instrs[j + 1].OpCode == OpCodes.Pop)
                    {
                        instrs[j].OpCode = OpCodes.Nop;
                        instrs[j + 1].OpCode = OpCodes.Nop;
                        for (int k = 0; k < instrs.Count; k++)
                            if ((instrs[k].OpCode == OpCodes.Br || instrs[k].OpCode == OpCodes.Br_S)
                                && instrs[k].Operand is Instruction target && target == instrs[j + 1]
                                && k - 1 >= 0 && instrs[k - 1].OpCode == OpCodes.Dup)
                                instrs[k - 1].OpCode = OpCodes.Nop;
                    }
                }
            }
        }

        static void ResolveSimpleSwitch(List<MethodDef> methods)
        {
            foreach (var method in methods)
            {
                var instrs = method.Body.Instructions;
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

                for (int j = 0; j < instrs.Count; j++)
                {
                    if (j + 1 < instrs.Count && instrs[j].IsLdcI4() && instrs[j + 1].IsBr())
                    {
                        var target = instrs[j + 1].Operand as Instruction;
                        for (int k = 0; k < switchInstrs.Count; k++)
                        {
                            // find the ldc that precedes this switch
                            int si = instrs.IndexOf(switchInstrs[k]);
                            if (si >= 3 && instrs[si - 3] == target)
                            {
                                if ((uint)xorValues[k] == 0)
                                    continue;

                                int val = instrs[j].GetLdcI4Value();
                                uint idx = (uint)(val ^ ldcValues[k]) % (uint)xorValues[k];
                                var targets = switchInstrs[k].Operand as Instruction[];
                                if (targets == null || idx >= targets.Length)
                                    continue;

                                instrs[j].OpCode = OpCodes.Ldc_I4;
                                instrs[j].Operand = (int)(uint)(val ^ ldcValues[k]);
                                instrs[j + 1].Operand = targets[(int)idx];
                                j++;
                                break;
                            }
                        }
                    }
                }

                method.Body.SimplifyBranches();
                method.Body.OptimizeBranches();
            }
        }

        static void FixConditionalBranches(List<MethodDef> methods)
        {
            foreach (var method in methods)
            {
                var instrs = method.Body.Instructions;
                var done = new Dictionary<Instruction, Instruction>();
                for (int j = 0; j < instrs.Count; j++)
                {
                    if (!instrs[j].IsConditionalBranch()) continue;
                    var condInstr = instrs[j];
                    for (int k = 0; k < instrs.Count; k++)
                    {
                        if (!instrs[k].IsBr()) continue;
                        var brTarget = instrs[k].Operand as Instruction;
                        if (brTarget != condInstr) continue;
                        if (done.ContainsKey(brTarget)) continue;
                        instrs[k].OpCode = condInstr.GetOpCode();
                        instrs[k].Operand = condInstr.GetOperand();
                        instrs.Insert(k + 1, OpCodes.Br.ToInstruction(instrs[j + 1]));
                        k++;
                        done.Add(brTarget, instrs[k]);
                    }
                }
                method.Body.SimplifyBranches();
                method.Body.OptimizeBranches();
            }
        }

        static int ResolveComplexSwitch(List<MethodDef> methods, BlocksCflowDeobfuscator deobfuscator)
        {
            int total = 0;
            foreach (var method in methods)
            {
                if (!method.HasBody) continue;
                var origInstrs = method.Body.Instructions.ToList();
                var origHandlers = method.Body.ExceptionHandlers.ToList();

                try
                {
                    var instrs = method.Body.Instructions;
                    var toberemoved   = new List<int>();
                    var intValues     = new List<int>();
                    var forRem        = new List<int>();
                    var switchInstrs  = new List<Instruction>();
                    Local localVar    = null;

                    for (int j = 0; j + 6 < instrs.Count; j++)
                    {
                        if (instrs[j].IsLdcI4() && instrs[j + 1].OpCode == OpCodes.Xor
                            && instrs[j + 4].IsLdcI4()
                            && instrs[j + 6].OpCode == OpCodes.Switch
                            && instrs[j + 3].IsStloc())
                        {
                            toberemoved.Add(j);
                            intValues.Add(instrs[j].GetLdcI4Value());
                            localVar = instrs[j + 3].GetLocal(method.Body.Variables);
                            forRem.Add(instrs[j + 4].GetLdcI4Value());
                            switchInstrs.Add(instrs[j + 6]);
                        }
                    }

                    if (switchInstrs.Count > 0)
                    {
                        var state = new SwitchState(instrs, method, toberemoved, intValues, forRem, switchInstrs, localVar);
                        state.Parse(0, 0u);
                        total += state.Apply();
                    }

                    // Second pattern: ldc xor ldc [rem_un] switch (4-instr variant)
                    toberemoved.Clear(); intValues.Clear(); forRem.Clear(); switchInstrs.Clear();
                    for (int j = 0; j + 4 < instrs.Count; j++)
                    {
                        if (instrs[j].IsLdcI4() && instrs[j + 1].OpCode == OpCodes.Xor
                            && instrs[j + 2].IsLdcI4() && instrs[j + 4].OpCode == OpCodes.Switch)
                        {
                            toberemoved.Add(j);
                            intValues.Add(instrs[j].GetLdcI4Value());
                            forRem.Add(instrs[j + 2].GetLdcI4Value());
                            switchInstrs.Add(instrs[j + 4]);
                        }
                    }

                    if (switchInstrs.Count > 0)
                    {
                        var state = new SwitchStateNoLocal(instrs, method, toberemoved, intValues, forRem, switchInstrs);
                        state.Parse(0);
                        total += state.Apply(4);
                    }

                    var blocks = new Blocks(method);
                    deobfuscator.Initialize(blocks);
                    deobfuscator.Deobfuscate();
                    blocks.RepartitionBlocks();
                    blocks.GetCode(out var list, out var handlers);
                    DotNetUtils.RestoreBody(method, list, handlers);
                    method.Body.SimplifyBranches();
                    method.Body.OptimizeBranches();
                }
                catch (Exception ex)
                {
                    method.Body.Instructions.Clear();
                    foreach (var inst in origInstrs) method.Body.Instructions.Add(inst);
                    method.Body.ExceptionHandlers.Clear();
                    foreach (var h in origHandlers) method.Body.ExceptionHandlers.Add(h);
                    Tool.Logger.LogWarning($"[0x{method.MDToken.Raw:X8}] ResolveComplexSwitch failed on {method}: {ex.Message}. Rolled back.");
                }
            }
            return total;
        }

        // Helper state classes for complex switch resolution
        class SwitchState
        {
            readonly IList<Instruction> instrs;
            readonly MethodDef method;
            readonly List<int> toberemoved, intValues, forRem;
            readonly List<Instruction> switchInstrs;
            readonly Local localVar;
            internal List<int> removedIdx = new List<int>();
            internal List<int> removedVals = new List<int>();
            List<Instruction> brInstrs = new List<Instruction>();
            List<Instruction> realBrInstrs = new List<Instruction>();
            List<Instruction> condInstrs = new List<Instruction>();
            List<int> localValues = new List<int>();

            internal SwitchState(IList<Instruction> instrs, MethodDef method,
                List<int> toberemoved, List<int> intValues, List<int> forRem,
                List<Instruction> switchInstrs, Local localVar)
            {
                this.instrs = instrs; this.method = method;
                this.toberemoved = toberemoved; this.intValues = intValues;
                this.forRem = forRem; this.switchInstrs = switchInstrs; this.localVar = localVar;
            }

            internal void Parse(int idx, uint localVal)
            {
                for (int i = idx; i < instrs.Count; i++)
                {
                    if (removedIdx.Contains(i)) continue;
                    if (instrs[i].IsBr())
                    {
                        var t = instrs[i].Operand as Instruction;
                        if (!brInstrs.Contains(t) && !realBrInstrs.Contains(t))
                        { realBrInstrs.Add(t); Parse(instrs.IndexOf(t), localVal); }
                        break;
                    }
                    if (instrs[i].IsConditionalBranch() || instrs[i].IsLeave())
                    {
                        var t = instrs[i].Operand as Instruction;
                        if (!condInstrs.Contains(t))
                        {
                            condInstrs.Add(t);
                            Parse(instrs.IndexOf(t), localVal);
                            if (i + 1 < instrs.Count) Parse(i + 1, localVal);
                        }
                        continue;
                    }
                    if (instrs[i].OpCode == OpCodes.Ret) break;
                    if (instrs[i].IsLdcI4() && i + 1 < instrs.Count && instrs[i + 1].IsStloc()
                        && instrs[i + 1].GetLocal(method.Body.Variables) == localVar)
                    { localVal = (uint)instrs[i].GetLdcI4Value(); continue; }
                    if (instrs[i].IsLdcI4() || (instrs[i].IsLdloc() && instrs[i].GetLocal(method.Body.Variables) == localVar))
                    {
                        uint num = instrs[i].IsLdcI4() ? (uint)instrs[i].GetLdcI4Value() : localVal;
                        int n2 = i + 1;
                        if (instrs[i + 1].IsBr()) n2 = instrs.IndexOf(instrs[i + 1].Operand as Instruction);
                        if (n2 < instrs.Count && (instrs[n2].IsLdcI4() || (instrs[n2].IsLdloc() && instrs[n2].GetLocal(method.Body.Variables) == localVar)))
                        {
                            uint num3 = instrs[n2].IsLdcI4() ? (uint)instrs[n2].GetLdcI4Value() : localVal;
                            TryResolve(i, n2, num, num3, ref localVal);
                        }
                    }
                    else if (instrs[i].OpCode == OpCodes.Switch)
                    {
                        if (i < 6 || !IsKnownSwitch(i))
                        { foreach (var t in (Instruction[])instrs[i].Operand) Parse(instrs.IndexOf(t), localVal); }
                    }
                }
            }

            bool IsKnownSwitch(int i)
            { foreach (var r in toberemoved) if (i - 6 == r) return true; return false; }

            void TryResolve(int i, int n2, uint num, uint num3, ref uint localVal)
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
                for (int j = 0; j < toberemoved.Count; j++)
                {
                    bool match = (n2 + 4 < instrs.Count && instrs[n2 + 4].IsBr() && instrs[n2 + 4].Operand as Instruction == instrs[toberemoved[j]])
                              || n2 + 4 == toberemoved[j]
                              || (instrs[n2 + 1].OpCode == OpCodes.Xor && n2 == toberemoved[j]);
                    if (!match) continue;
                    uint num5 = instrs[n2 + 1].OpCode == OpCodes.Xor ? (num ^ num3)
                              : (instrs[n2 + 1].IsLdcI4() ? (num4 * num3 ^ num) : (num * num3 ^ num4));
                    if (instrs[n2 + 1].OpCode != OpCodes.Xor) localVal = num5 ^ (uint)intValues[j];
                    else localVal = num5;
                    uint idx = localVal % (uint)forRem[j];
                    var arr = switchInstrs[j].Operand as Instruction[];
                    var dest = arr[(int)idx];
                    if (removedIdx.Contains(i)) return;
                    removedIdx.Add(i); removedVals.Add((int)idx);
                    int bi = brInstrs.IndexOf(dest);
                    bool go = bi == -1 || localValues[bi] != (int)localVal;
                    if (go) { brInstrs.Add(dest); localValues.Add((int)localVal); Parse(instrs.IndexOf(dest), localVal); }
                    break;
                }
            }

            internal int Apply()
            {
                if (removedIdx.Count == 0) return 0;
                foreach (int r in toberemoved)
                    for (int j = 0; j < 6; j++)
                    { instrs[r + j].OpCode = OpCodes.Nop; instrs[r + j].Operand = null; }
                for (int j = 0; j < removedIdx.Count; j++)
                {
                    instrs[removedIdx[j]].OpCode = OpCodes.Ldc_I4;
                    instrs[removedIdx[j]].Operand = removedVals[j];
                    if (!instrs[removedIdx[j] + 1].IsBr())
                        for (int k = 0; k < 4; k++)
                        { instrs[removedIdx[j] + k + 1].OpCode = OpCodes.Nop; instrs[removedIdx[j] + k + 1].Operand = null; }
                }
                return removedIdx.Count;
            }
        }

        class SwitchStateNoLocal
        {
            readonly IList<Instruction> instrs;
            readonly MethodDef method;
            readonly List<int> toberemoved, intValues, forRem;
            readonly List<Instruction> switchInstrs;
            List<int> removedIdx = new List<int>();
            List<int> removedVals = new List<int>();
            List<Instruction> brInstrs = new List<Instruction>();
            List<Instruction> realBrInstrs = new List<Instruction>();
            List<Instruction> condInstrs = new List<Instruction>();

            internal SwitchStateNoLocal(IList<Instruction> instrs, MethodDef method,
                List<int> toberemoved, List<int> intValues, List<int> forRem, List<Instruction> switchInstrs)
            {
                this.instrs = instrs; this.method = method;
                this.toberemoved = toberemoved; this.intValues = intValues;
                this.forRem = forRem; this.switchInstrs = switchInstrs;
            }

            internal void Parse(int idx)
            {
                for (int i = idx; i < instrs.Count; i++)
                {
                    if (removedIdx.Contains(i)) continue;
                    if (instrs[i].IsBr())
                    {
                        var t = instrs[i].Operand as Instruction;
                        if (!brInstrs.Contains(t) && !realBrInstrs.Contains(t))
                        { realBrInstrs.Add(t); Parse(instrs.IndexOf(t)); }
                        break;
                    }
                    if (instrs[i].IsConditionalBranch() || instrs[i].IsLeave())
                    {
                        var t = instrs[i].Operand as Instruction;
                        if (!condInstrs.Contains(t))
                        { condInstrs.Add(t); Parse(instrs.IndexOf(t)); if (i + 1 < instrs.Count) Parse(i + 1); }
                        continue;
                    }
                    if (instrs[i].OpCode == OpCodes.Ret) break;
                    if (!instrs[i].IsLdcI4()) { if (instrs[i].OpCode == OpCodes.Switch) TrySwitch(i); continue; }
                    uint num = (uint)instrs[i].GetLdcI4Value();
                    int n2 = i + 1;
                    if (instrs[i + 1].IsBr()) n2 = instrs.IndexOf(instrs[i + 1].Operand as Instruction);
                    if (n2 >= instrs.Count || !instrs[n2].IsLdcI4()) continue;
                    uint num3 = (uint)instrs[n2].GetLdcI4Value();
                    TryResolve(i, n2, num, num3);
                }
            }

            void TrySwitch(int i)
            {
                bool known = false;
                for (int j = 0; j < toberemoved.Count; j++) if (i - 4 == toberemoved[j]) { known = true; break; }
                if (!known) foreach (var t in (Instruction[])instrs[i].Operand) Parse(instrs.IndexOf(t));
            }

            void TryResolve(int i, int n2, uint num, uint num3)
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
                for (int j = 0; j < toberemoved.Count; j++)
                {
                    bool match = (n2 + 4 < instrs.Count && instrs[n2 + 4].IsBr() && instrs[n2 + 4].Operand as Instruction == instrs[toberemoved[j]])
                              || n2 + 4 == toberemoved[j]
                              || (instrs[n2 + 1].OpCode == OpCodes.Xor && n2 == toberemoved[j]);
                    if (!match) continue;
                    uint num5 = instrs[n2 + 1].OpCode == OpCodes.Xor ? (num ^ num3)
                              : (instrs[n2 + 1].IsLdcI4() ? (num4 * num3 ^ num) : (num * num3 ^ num4));
                    uint num6 = instrs[n2 + 1].OpCode != OpCodes.Xor ? (num5 ^ (uint)intValues[j]) : num5;
                    uint idx = num6 % (uint)forRem[j];
                    var dest = ((Instruction[])switchInstrs[j].Operand)[(int)idx];
                    if (removedIdx.Contains(i)) return;
                    removedIdx.Add(i); removedVals.Add((int)idx);
                    if (brInstrs.IndexOf(dest) == -1) { brInstrs.Add(dest); Parse(instrs.IndexOf(dest)); }
                    break;
                }
            }

            internal int Apply(int patternSize)
            {
                if (removedIdx.Count == 0) return 0;
                foreach (int r in toberemoved)
                    for (int j = 0; j < patternSize; j++)
                    { instrs[r + j].OpCode = OpCodes.Nop; instrs[r + j].Operand = null; }
                for (int j = 0; j < removedIdx.Count; j++)
                {
                    instrs[removedIdx[j]].OpCode = OpCodes.Ldc_I4;
                    instrs[removedIdx[j]].Operand = removedVals[j];
                    if (!instrs[removedIdx[j] + 1].IsBr())
                        for (int k = 0; k < 4; k++)
                        { instrs[removedIdx[j] + k + 1].OpCode = OpCodes.Nop; instrs[removedIdx[j] + k + 1].Operand = null; }
                }
                return removedIdx.Count;
            }
        }
    }
}
