using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Tool;

namespace ConfuserExKillerRunner.Killers
{
    public sealed class PredicateKillerResult
    {
        public int ConstantsFolded { get; set; }
        public int IdentitiesSimplified { get; set; }
        public int BranchesResolved { get; set; }
        public int MethodsOptimized { get; set; }
        public string Message { get; set; }
    }

    public static class PredicateKiller
    {
        public static PredicateKillerResult Execute(ModuleDef module)
        {
            if (module == null) throw new ArgumentNullException(nameof(module));

            var result = new PredicateKillerResult();

            foreach (var type in module.GetTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody || method.Body.Instructions == null || method.Body.Instructions.Count < 2)
                        continue;

                    var originalBody = ConfuserExKillerRunner.Core.MethodBodyCloner.Clone(method.Body);
                    try
                    {
                        bool modified = false;
                        bool passChanged;
                        int iterations = 0;
                        int methodConstantsFolded = 0;
                        int methodIdentitiesSimplified = 0;
                        int methodBranchesResolved = 0;

                        // Iterative simplification loop (folds constants then evaluates branches)
                        do
                        {
                            passChanged = false;
                            iterations++;

                            var branchTargets = CollectBranchTargets(method.Body);

                            var instIndex = new Dictionary<Instruction, int>();
                            for (int k = 0; k < method.Body.Instructions.Count; k++)
                                instIndex[method.Body.Instructions[k]] = k;

                            int foldedConsts = FoldConstants(method.Body, branchTargets, instIndex);
                            if (foldedConsts > 0)
                            {
                                methodConstantsFolded += foldedConsts;
                                passChanged = true;
                                modified = true;
                            }

                            int simplifiedIdents = FoldAlgebraicIdentities(method, branchTargets, instIndex);
                            if (simplifiedIdents > 0)
                            {
                                methodIdentitiesSimplified += simplifiedIdents;
                                passChanged = true;
                                modified = true;
                            }

                            int resolvedBranches = EvaluateConstantBranches(method.Body, branchTargets, instIndex);
                            if (resolvedBranches > 0)
                            {
                                methodBranchesResolved += resolvedBranches;
                                passChanged = true;
                                modified = true;
                            }

                        } while (passChanged && iterations < 10);

                        if (modified)
                        {
                            method.Body.SimplifyBranches();
                            method.Body.OptimizeBranches();

                            if (!ConfuserExKillerRunner.Analysis.QualityAuditor.IsMethodStructurallyValid(method, out var errors))
                            {
                                method.Body = originalBody;
                                Logger.LogWarning($"[PredicateKiller] Structural invariant violation in {method.FullName}: {string.Join("; ", errors)}. Rolled back.");
                                continue;
                            }

                            result.MethodsOptimized++;
                            // Commit counters only after method transformation successfully completes and passes audit
                            result.ConstantsFolded += methodConstantsFolded;
                            result.IdentitiesSimplified += methodIdentitiesSimplified;
                            result.BranchesResolved += methodBranchesResolved;
                        }
                    }
                    catch (Exception ex)
                    {
                        method.Body = originalBody;
                        Logger.LogWarning($"[PredicateKiller] Simplification rollback in {method.FullName}: {ex.Message}");
                    }
                }
            }

            result.Message = $"Optimized {result.MethodsOptimized} methods (folded {result.ConstantsFolded} constants, " +
                             $"simplified {result.IdentitiesSimplified} algebraic identities, resolved {result.BranchesResolved} constant branches)";
            Logger.LogInfo($"[PredicateKiller] {result.Message}");

            return result;
        }

        private static HashSet<Instruction> CollectBranchTargets(CilBody body)
        {
            var targets = new HashSet<Instruction>();
            foreach (var inst in body.Instructions)
            {
                if (inst.Operand is Instruction singleTarget && singleTarget != null)
                {
                    targets.Add(singleTarget);
                }
                else if (inst.Operand is IList<Instruction> multiTargets)
                {
                    foreach (var t in multiTargets)
                    {
                        if (t != null) targets.Add(t);
                    }
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

        private static bool CanSafelyTransformRange(IList<Instruction> instrs, int startIdx, int endIdx, HashSet<Instruction> branchTargets, CilBody body, Dictionary<Instruction, int> instIndex)
        {
            if (startIdx < 0 || endIdx >= instrs.Count || startIdx > endIdx)
                return false;

            // Ensure no instruction in [startIdx, endIdx] is a branch target or EH boundary
            for (int k = startIdx; k <= endIdx; k++)
            {
                if (branchTargets.Contains(instrs[k]))
                    return false;
            }

            // Ensure the entire range [startIdx, endIdx] does not cross exception handler boundaries
            if (body.HasExceptionHandlers)
            {
                foreach (var eh in body.ExceptionHandlers)
                {
                    if (eh.TryStart != null && instIndex.TryGetValue(eh.TryStart, out int tryStartIdx))
                    {
                        int tryEndIdx = (eh.TryEnd != null && instIndex.TryGetValue(eh.TryEnd, out int tEnd)) ? tEnd : instrs.Count;
                        bool startInTry = startIdx >= tryStartIdx && startIdx < tryEndIdx;
                        bool endInTry = endIdx >= tryStartIdx && endIdx < tryEndIdx;
                        if (startInTry != endInTry) return false;
                    }

                    if (eh.HandlerStart != null && instIndex.TryGetValue(eh.HandlerStart, out int hStartIdx))
                    {
                        int hEndIdx = (eh.HandlerEnd != null && instIndex.TryGetValue(eh.HandlerEnd, out int hEnd)) ? hEnd : instrs.Count;
                        bool startInHandler = startIdx >= hStartIdx && startIdx < hEndIdx;
                        bool endInHandler = endIdx >= hStartIdx && endIdx < hEndIdx;
                        if (startInHandler != endInHandler) return false;
                    }

                    if (eh.FilterStart != null && instIndex.TryGetValue(eh.FilterStart, out int fStartIdx))
                    {
                        int fEndIdx = (eh.HandlerStart != null && instIndex.TryGetValue(eh.HandlerStart, out int fEnd)) ? fEnd : instrs.Count;
                        bool startInFilter = startIdx >= fStartIdx && startIdx < fEndIdx;
                        bool endInFilter = endIdx >= fStartIdx && endIdx < fEndIdx;
                        if (startInFilter != endInFilter) return false;
                    }
                }
            }

            return true;
        }

        private static int FoldConstants(CilBody body, HashSet<Instruction> branchTargets, Dictionary<Instruction, int> instIndex)
        {
            var instrs = body.Instructions;
            int folded = 0;

            for (int i = 0; i < instrs.Count; i++)
            {
                var instr = instrs[i];
                if (instr.OpCode == OpCodes.Nop) continue;

                // Unary operations: ldc.i4 -> neg / not
                if (instr.OpCode == OpCodes.Neg || instr.OpCode == OpCodes.Not)
                {
                    int prevIdx = FindPreviousNonNop(instrs, i);
                    if (prevIdx >= 0 && instrs[prevIdx].IsLdcI4())
                    {
                        if (!CanSafelyTransformRange(instrs, prevIdx, i, branchTargets, body, instIndex))
                            continue;

                        int val = instrs[prevIdx].GetLdcI4Value();
                        int result = (instr.OpCode == OpCodes.Neg) ? -val : ~val;

                        instrs[prevIdx].OpCode = OpCodes.Nop;
                        instrs[prevIdx].Operand = null;
                        instr.OpCode = OpCodes.Ldc_I4;
                        instr.Operand = result;
                        folded++;
                        continue;
                    }
                }

                // Binary arithmetic / bitwise operations
                if (IsBinaryArithmetic(instr.OpCode))
                {
                    int rightIdx = FindPreviousNonNop(instrs, i);
                    if (rightIdx >= 0 && instrs[rightIdx].IsLdcI4())
                    {
                        int leftIdx = FindPreviousNonNop(instrs, rightIdx);
                        if (leftIdx >= 0 && instrs[leftIdx].IsLdcI4())
                        {
                            if (!CanSafelyTransformRange(instrs, leftIdx, i, branchTargets, body, instIndex))
                                continue;

                            int a = instrs[leftIdx].GetLdcI4Value();
                            int b = instrs[rightIdx].GetLdcI4Value();

                            if (TryEvaluateBinary(instr.OpCode, a, b, out int res))
                            {
                                instrs[leftIdx].OpCode = OpCodes.Nop;
                                instrs[leftIdx].Operand = null;
                                instrs[rightIdx].OpCode = OpCodes.Nop;
                                instrs[rightIdx].Operand = null;

                                instr.OpCode = OpCodes.Ldc_I4;
                                instr.Operand = res;
                                folded++;
                            }
                        }
                    }
                }
            }

            return folded;
        }

        private enum StackType
        {
            Unknown,
            Int32,
            Int64
        }

        private static StackType InferStackTypeBefore(IList<Instruction> instrs, int index, MethodDef method)
        {
            int p = FindPreviousNonNop(instrs, index);
            if (p < 0) return StackType.Unknown;
            var inst = instrs[p];

            if (inst.OpCode == OpCodes.Ldc_I8)
                return StackType.Int64;

            if (inst.IsLdcI4() || inst.OpCode == OpCodes.Ldc_I4 || inst.OpCode == OpCodes.Ldc_I4_S)
                return StackType.Int32;

            if (inst.IsLdloc() && method?.Body?.Variables != null)
            {
                var local = inst.GetLocal(method.Body.Variables);
                if (local?.Type != null)
                {
                    var et = local.Type.GetElementType();
                    if (et == ElementType.I8 || et == ElementType.U8)
                        return StackType.Int64;
                    if (et == ElementType.I4 || et == ElementType.U4 ||
                        et == ElementType.I1 || et == ElementType.U1 ||
                        et == ElementType.I2 || et == ElementType.U2 ||
                        et == ElementType.Boolean || et == ElementType.Char)
                        return StackType.Int32;
                }
            }

            if (inst.IsLdarg() && method?.Parameters != null)
            {
                var param = inst.GetParameter(method.Parameters);
                if (param?.Type != null)
                {
                    var et = param.Type.GetElementType();
                    if (et == ElementType.I8 || et == ElementType.U8)
                        return StackType.Int64;
                    if (et == ElementType.I4 || et == ElementType.U4 ||
                        et == ElementType.I1 || et == ElementType.U1 ||
                        et == ElementType.I2 || et == ElementType.U2 ||
                        et == ElementType.Boolean || et == ElementType.Char)
                        return StackType.Int32;
                }
            }

            if (inst.OpCode == OpCodes.Ldsfld || inst.OpCode == OpCodes.Ldfld)
            {
                if (inst.Operand is IField field && field.FieldSig?.Type != null)
                {
                    var et = field.FieldSig.Type.GetElementType();
                    if (et == ElementType.I8 || et == ElementType.U8)
                        return StackType.Int64;
                    if (et == ElementType.I4 || et == ElementType.U4 ||
                        et == ElementType.I1 || et == ElementType.U1 ||
                        et == ElementType.I2 || et == ElementType.U2 ||
                        et == ElementType.Boolean || et == ElementType.Char)
                        return StackType.Int32;
                }
            }

            if (inst.OpCode == OpCodes.Call || inst.OpCode == OpCodes.Callvirt)
            {
                if (inst.Operand is IMethod callTarget && callTarget.MethodSig?.RetType != null)
                {
                    var et = callTarget.MethodSig.RetType.GetElementType();
                    if (et == ElementType.I8 || et == ElementType.U8)
                        return StackType.Int64;
                    if (et == ElementType.I4 || et == ElementType.U4 ||
                        et == ElementType.I1 || et == ElementType.U1 ||
                        et == ElementType.I2 || et == ElementType.U2 ||
                        et == ElementType.Boolean)
                        return StackType.Int32;
                }
            }

            if (inst.OpCode == OpCodes.Conv_I8 || inst.OpCode == OpCodes.Conv_U8)
                return StackType.Int64;

            if (inst.OpCode == OpCodes.Conv_I4 || inst.OpCode == OpCodes.Conv_U4 ||
                inst.OpCode == OpCodes.Conv_I1 || inst.OpCode == OpCodes.Conv_U1 ||
                inst.OpCode == OpCodes.Conv_I2 || inst.OpCode == OpCodes.Conv_U2)
                return StackType.Int32;

            return StackType.Unknown;
        }

        private static int FoldAlgebraicIdentities(MethodDef method, HashSet<Instruction> branchTargets, Dictionary<Instruction, int> instIndex)
        {
            var body = method.Body;
            var instrs = body.Instructions;
            int simplified = 0;

            for (int i = 0; i < instrs.Count; i++)
            {
                var instr = instrs[i];
                if (instr.OpCode == OpCodes.Nop) continue;

                // Identity: dup; xor => pop; ldc.i4.0 (for 32-bit) or pop; ldc.i8 0 (for 64-bit)
                if (instr.OpCode == OpCodes.Xor)
                {
                    int prevIdx = FindPreviousNonNop(instrs, i);
                    if (prevIdx >= 0 && instrs[prevIdx].OpCode == OpCodes.Dup)
                    {
                        if (!CanSafelyTransformRange(instrs, prevIdx, i, branchTargets, body, instIndex))
                            continue;

                        var stackType = InferStackTypeBefore(instrs, prevIdx, method);
                        if (stackType == StackType.Int64)
                        {
                            instrs[prevIdx].OpCode = OpCodes.Pop;
                            instr.OpCode = OpCodes.Ldc_I8;
                            instr.Operand = 0L;
                            simplified++;
                            continue;
                        }
                        else if (stackType == StackType.Int32)
                        {
                            instrs[prevIdx].OpCode = OpCodes.Pop;
                            instr.OpCode = OpCodes.Ldc_I4_0;
                            instr.Operand = null;
                            simplified++;
                            continue;
                        }
                        // Ambiguous or unknown type: preserve original code to prevent type safety violation
                        continue;
                    }
                }

                // Identity: (x * (x + 1)) % 2 == 0 or (x * (x + 1)) & 1 == 0
                // Pattern: dup; ldc.i4.1; add; mul; ldc.i4.2; rem (or ldc.i4.1; and)
                if ((instr.OpCode == OpCodes.Rem || instr.OpCode == OpCodes.Rem_Un || instr.OpCode == OpCodes.And))
                {
                    int p1 = FindPreviousNonNop(instrs, i); // divisor / mask
                    if (p1 >= 0 && instrs[p1].IsLdcI4())
                    {
                        int divisor = instrs[p1].GetLdcI4Value();
                        bool matchesModulo = (instr.OpCode == OpCodes.And && divisor == 1) ||
                                             ((instr.OpCode == OpCodes.Rem || instr.OpCode == OpCodes.Rem_Un) && divisor == 2);

                        if (matchesModulo)
                        {
                            int p2 = FindPreviousNonNop(instrs, p1); // mul
                            if (p2 >= 0 && instrs[p2].OpCode == OpCodes.Mul) // non-overflow mul only
                            {
                                int p3 = FindPreviousNonNop(instrs, p2); // add
                                if (p3 >= 0 && instrs[p3].OpCode == OpCodes.Add) // non-overflow add only
                                {
                                    int p4 = FindPreviousNonNop(instrs, p3); // ldc.i4.1
                                    if (p4 >= 0 && instrs[p4].IsLdcI4() && instrs[p4].GetLdcI4Value() == 1)
                                    {
                                        int p5 = FindPreviousNonNop(instrs, p4); // dup
                                        if (p5 >= 0 && instrs[p5].OpCode == OpCodes.Dup)
                                        {
                                            if (!CanSafelyTransformRange(instrs, p5, i, branchTargets, body, instIndex))
                                                continue;

                                            // Strictly verify that x is a 32-bit integer
                                            var stackType = InferStackTypeBefore(instrs, p5, method);
                                            if (stackType != StackType.Int32)
                                                continue;

                                            // Product of consecutive numbers is always even; mod 2 or & 1 is strictly 0!
                                            instrs[p5].OpCode = OpCodes.Pop;
                                            instrs[p4].OpCode = OpCodes.Nop;
                                            instrs[p4].Operand = null;
                                            instrs[p3].OpCode = OpCodes.Nop;
                                            instrs[p3].Operand = null;
                                            instrs[p2].OpCode = OpCodes.Nop;
                                            instrs[p2].Operand = null;
                                            instrs[p1].OpCode = OpCodes.Nop;
                                            instrs[p1].Operand = null;

                                            instr.OpCode = OpCodes.Ldc_I4_0;
                                            instr.Operand = null;
                                            simplified++;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            return simplified;
        }

        private static int EvaluateConstantBranches(CilBody body, HashSet<Instruction> branchTargets, Dictionary<Instruction, int> instIndex)
        {
            var instrs = body.Instructions;
            int resolved = 0;

            for (int i = 0; i < instrs.Count; i++)
            {
                var instr = instrs[i];
                if (instr.OpCode == OpCodes.Nop) continue;

                // 1) Single-operand conditional branches: brtrue, brfalse
                if (instr.OpCode == OpCodes.Brtrue || instr.OpCode == OpCodes.Brtrue_S ||
                    instr.OpCode == OpCodes.Brfalse || instr.OpCode == OpCodes.Brfalse_S)
                {
                    int prevIdx = FindPreviousNonNop(instrs, i);
                    if (prevIdx >= 0 && instrs[prevIdx].IsLdcI4())
                    {
                        if (!CanSafelyTransformRange(instrs, prevIdx, i, branchTargets, body, instIndex))
                            continue;

                        int val = instrs[prevIdx].GetLdcI4Value();
                        bool isTrueBranch = (instr.OpCode == OpCodes.Brtrue || instr.OpCode == OpCodes.Brtrue_S);
                        bool conditionMet = isTrueBranch ? (val != 0) : (val == 0);

                        instrs[prevIdx].OpCode = OpCodes.Nop;
                        instrs[prevIdx].Operand = null;

                        if (conditionMet)
                        {
                            instr.OpCode = OpCodes.Br;
                        }
                        else
                        {
                            instr.OpCode = OpCodes.Nop;
                            instr.Operand = null;
                        }
                        resolved++;
                        continue;
                    }
                }

                // 2) Two-operand conditional branches: beq, bne.un, bge, bgt, ble, blt
                if (IsTwoOperandBranch(instr.OpCode))
                {
                    int rightIdx = FindPreviousNonNop(instrs, i);
                    if (rightIdx >= 0 && instrs[rightIdx].IsLdcI4())
                    {
                        int leftIdx = FindPreviousNonNop(instrs, rightIdx);
                        if (leftIdx >= 0 && instrs[leftIdx].IsLdcI4())
                        {
                            if (!CanSafelyTransformRange(instrs, leftIdx, i, branchTargets, body, instIndex))
                                continue;

                            int a = instrs[leftIdx].GetLdcI4Value();
                            int b = instrs[rightIdx].GetLdcI4Value();

                            bool conditionMet = EvaluateTwoOperandCondition(instr.OpCode, a, b);

                            instrs[leftIdx].OpCode = OpCodes.Nop;
                            instrs[leftIdx].Operand = null;
                            instrs[rightIdx].OpCode = OpCodes.Nop;
                            instrs[rightIdx].Operand = null;

                            if (conditionMet)
                            {
                                instr.OpCode = OpCodes.Br;
                            }
                            else
                            {
                                instr.OpCode = OpCodes.Nop;
                                instr.Operand = null;
                            }
                            resolved++;
                        }
                    }
                }
            }

            return resolved;
        }

        private static bool IsBinaryArithmetic(OpCode op)
        {
            return op == OpCodes.Add || op == OpCodes.Sub || op == OpCodes.Mul ||
                   op == OpCodes.Div || op == OpCodes.Div_Un || op == OpCodes.Rem || op == OpCodes.Rem_Un ||
                   op == OpCodes.Xor || op == OpCodes.And || op == OpCodes.Or ||
                   op == OpCodes.Shl || op == OpCodes.Shr || op == OpCodes.Shr_Un;
        }

        internal static bool TryEvaluateBinary(OpCode op, int a, int b, out int result)
        {
            result = 0;
            try
            {
                if (op == OpCodes.Add) { result = a + b; return true; }
                if (op == OpCodes.Sub) { result = a - b; return true; }
                if (op == OpCodes.Mul) { result = a * b; return true; }
                if (op == OpCodes.Div && b != 0) { result = a / b; return true; }
                if (op == OpCodes.Div_Un && b != 0) { result = (int)((uint)a / (uint)b); return true; }
                if (op == OpCodes.Rem && b != 0) { result = a % b; return true; }
                if (op == OpCodes.Rem_Un && b != 0) { result = (int)((uint)a % (uint)b); return true; }
                if (op == OpCodes.Xor) { result = a ^ b; return true; }
                if (op == OpCodes.And) { result = a & b; return true; }
                if (op == OpCodes.Or) { result = a | b; return true; }
                if (op == OpCodes.Shl) { result = a << (b & 31); return true; }
                if (op == OpCodes.Shr) { result = a >> (b & 31); return true; }
                if (op == OpCodes.Shr_Un) { result = (int)((uint)a >> (b & 31)); return true; }
            }
            catch { }
            return false;
        }

        private static bool IsTwoOperandBranch(OpCode op)
        {
            return op == OpCodes.Beq || op == OpCodes.Beq_S ||
                   op == OpCodes.Bne_Un || op == OpCodes.Bne_Un_S ||
                   op == OpCodes.Bge || op == OpCodes.Bge_S ||
                   op == OpCodes.Bge_Un || op == OpCodes.Bge_Un_S ||
                   op == OpCodes.Bgt || op == OpCodes.Bgt_S ||
                   op == OpCodes.Bgt_Un || op == OpCodes.Bgt_Un_S ||
                   op == OpCodes.Ble || op == OpCodes.Ble_S ||
                   op == OpCodes.Ble_Un || op == OpCodes.Ble_Un_S ||
                   op == OpCodes.Blt || op == OpCodes.Blt_S ||
                   op == OpCodes.Blt_Un || op == OpCodes.Blt_Un_S;
        }

        internal static bool EvaluateTwoOperandCondition(OpCode op, int a, int b)
        {
            if (op == OpCodes.Beq || op == OpCodes.Beq_S) return a == b;
            if (op == OpCodes.Bne_Un || op == OpCodes.Bne_Un_S) return a != b;
            if (op == OpCodes.Bge || op == OpCodes.Bge_S) return a >= b;
            if (op == OpCodes.Bgt || op == OpCodes.Bgt_S) return a > b;
            if (op == OpCodes.Ble || op == OpCodes.Ble_S) return a <= b;
            if (op == OpCodes.Blt || op == OpCodes.Blt_S) return a < b;
            if (op == OpCodes.Bge_Un || op == OpCodes.Bge_Un_S) return (uint)a >= (uint)b;
            if (op == OpCodes.Bgt_Un || op == OpCodes.Bgt_Un_S) return (uint)a > (uint)b;
            if (op == OpCodes.Ble_Un || op == OpCodes.Ble_Un_S) return (uint)a <= (uint)b;
            if (op == OpCodes.Blt_Un || op == OpCodes.Blt_Un_S) return (uint)a < (uint)b;
            return false;
        }

        private static int FindPreviousNonNop(IList<Instruction> instrs, int currentIndex)
        {
            for (int i = currentIndex - 1; i >= 0; i--)
            {
                if (instrs[i].OpCode != OpCodes.Nop)
                    return i;
            }
            return -1;
        }
    }
}
