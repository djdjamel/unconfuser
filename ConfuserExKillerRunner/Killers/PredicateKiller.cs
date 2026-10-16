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

                            int foldedConsts = FoldConstants(method.Body.Instructions);
                            if (foldedConsts > 0)
                            {
                                methodConstantsFolded += foldedConsts;
                                passChanged = true;
                                modified = true;
                            }

                            int simplifiedIdents = FoldAlgebraicIdentities(method.Body.Instructions);
                            if (simplifiedIdents > 0)
                            {
                                methodIdentitiesSimplified += simplifiedIdents;
                                passChanged = true;
                                modified = true;
                            }

                            int resolvedBranches = EvaluateConstantBranches(method.Body.Instructions);
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
                            result.MethodsOptimized++;
                        }

                        // Commit counters only after method transformation successfully completes
                        result.ConstantsFolded += methodConstantsFolded;
                        result.IdentitiesSimplified += methodIdentitiesSimplified;
                        result.BranchesResolved += methodBranchesResolved;
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

        private static int FoldConstants(IList<Instruction> instrs)
        {
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

        private static int FoldAlgebraicIdentities(IList<Instruction> instrs)
        {
            int simplified = 0;

            for (int i = 0; i < instrs.Count; i++)
            {
                var instr = instrs[i];
                if (instr.OpCode == OpCodes.Nop) continue;

                // Identity: dup; xor => pop; ldc.i4.0 (x ^ x == 0)
                if (instr.OpCode == OpCodes.Xor)
                {
                    int prevIdx = FindPreviousNonNop(instrs, i);
                    if (prevIdx >= 0 && instrs[prevIdx].OpCode == OpCodes.Dup)
                    {
                        instrs[prevIdx].OpCode = OpCodes.Pop;
                        instr.OpCode = OpCodes.Ldc_I4_0;
                        simplified++;
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
                            if (p2 >= 0 && instrs[p2].OpCode == OpCodes.Mul)
                            {
                                int p3 = FindPreviousNonNop(instrs, p2); // add
                                if (p3 >= 0 && instrs[p3].OpCode == OpCodes.Add)
                                {
                                    int p4 = FindPreviousNonNop(instrs, p3); // ldc.i4.1
                                    if (p4 >= 0 && instrs[p4].IsLdcI4() && instrs[p4].GetLdcI4Value() == 1)
                                    {
                                        int p5 = FindPreviousNonNop(instrs, p4); // dup
                                        if (p5 >= 0 && instrs[p5].OpCode == OpCodes.Dup)
                                        {
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

        private static int EvaluateConstantBranches(IList<Instruction> instrs)
        {
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
