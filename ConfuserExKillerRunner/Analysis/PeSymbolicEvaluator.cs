using System;
using System.Collections.Generic;
using System.IO;
using ConfuserExKillerRunner.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.PE;
using Tool;

namespace ConfuserExKillerRunner.Analysis
{
    public enum IntegerWidth
    {
        Unknown = 0,
        Bit32 = 1,
        Bit64 = 2,
        Native = 3
    }

    public enum PeSymbolicKind
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

    public readonly struct PeSymbolicSlot : IEquatable<PeSymbolicSlot>
    {
        public readonly PeSymbolicKind Kind;
        public readonly long? ConcreteValue;
        public readonly IntegerWidth Width;

        public PeSymbolicSlot(PeSymbolicKind kind, long? concreteValue = null, IntegerWidth width = IntegerWidth.Unknown)
        {
            Kind = kind;
            ConcreteValue = concreteValue;
            Width = width;
        }

        public static readonly PeSymbolicSlot None = new(PeSymbolicKind.None);
        public static readonly PeSymbolicSlot ModuleBase = new(PeSymbolicKind.ModuleBase, null, IntegerWidth.Native);
        public static readonly PeSymbolicSlot PeHeaderOffset = new(PeSymbolicKind.PeHeaderOffset, 0x3CL, IntegerWidth.Bit32);
        public static readonly PeSymbolicSlot PeHeaderField = new(PeSymbolicKind.PeHeaderField);
        public static readonly PeSymbolicSlot Zero = new(PeSymbolicKind.Zero, 0L, IntegerWidth.Bit32);
        public static readonly PeSymbolicSlot Zero64 = new(PeSymbolicKind.Zero, 0L, IntegerWidth.Bit64);
        public static readonly PeSymbolicSlot NumericOffset = new(PeSymbolicKind.NumericOffset);

        public bool Equals(PeSymbolicSlot other) => Kind == other.Kind && ConcreteValue == other.ConcreteValue && Width == other.Width;
        public override bool Equals(object obj) => obj is PeSymbolicSlot other && Equals(other);
        public override int GetHashCode()
        {
            unchecked
            {
                int hash = (int)Kind * 397;
                hash = (hash * 397) ^ (ConcreteValue.HasValue ? ConcreteValue.Value.GetHashCode() : -1);
                hash = (hash * 397) ^ (int)Width;
                return hash;
            }
        }
        public static bool operator ==(PeSymbolicSlot left, PeSymbolicSlot right) => left.Equals(right);
        public static bool operator !=(PeSymbolicSlot left, PeSymbolicSlot right) => !left.Equals(right);
    }

    public static class PeSymbolicEvaluator
    {
        // In the Windows PE format (ECMA-335 / Microsoft PE/COFF specification), the initial headers
        // (IMAGE_DOS_HEADER, MS-DOS stub, IMAGE_NT_HEADERS, and Section Table) are mapped by the OS loader
        // in the image's first page (typically bounded by SectionAlignment / SizeOfHeaders, nominally 0x1000 = 4096 bytes).
        // This displacement bound is used by the analyzer as a safe upper envelope for legitimate PE header structures.
        // It does not serve as a universal guarantee for non-standard PE files, but ensures that displacements
        // escaping beyond the first page cannot be misclassified as header manipulations.
        public const int MaxPeHeaderDisplacement = 0x1000;

        public static bool IsNumeric(PeSymbolicSlot v)
        {
            return v.Kind == PeSymbolicKind.NumericOffset || v.Kind == PeSymbolicKind.Zero || v.Kind == PeSymbolicKind.PeHeaderOffset;
        }

        public static bool IsAlignmentMask(long mask)
        {
            return mask == -2L || mask == -4L || mask == -8L || mask == -16L || mask == -32L || mask == -64L ||
                   mask == 0xFFFFFFFEL || mask == 0xFFFFFFFCL || mask == 0xFFFFFFF8L || mask == 0xFFFFFFF0L || mask == 0xFFFFFFE0L || mask == 0xFFFFFFC0L ||
                   mask == unchecked((long)0xFFFFFFFFFFFFFFFEL) || mask == unchecked((long)0xFFFFFFFFFFFFFFFCL) ||
                   mask == unchecked((long)0xFFFFFFFFFFFFFFF8L) || mask == unchecked((long)0xFFFFFFFFFFFFFFF0L) ||
                   mask == unchecked((long)0xFFFFFFFFFFFFFFE0L) || mask == unchecked((long)0xFFFFFFFFFFFFFFC0L);
        }

        public static bool IsPeTarget(PeSymbolicSlot addr)
        {
            return addr.Kind == PeSymbolicKind.ModuleBase ||
                   addr.Kind == PeSymbolicKind.PeDerivedAddress ||
                   addr.Kind == PeSymbolicKind.NtDerivedAddress;
        }

        public static PeSymbolicSlot CreateNumericSlot(long val, IntegerWidth width = IntegerWidth.Bit32)
        {
            if (val == 0)
                return width == IntegerWidth.Bit64 ? PeSymbolicSlot.Zero64 : PeSymbolicSlot.Zero;
            if (val == 0x3C && (width == IntegerWidth.Bit32 || width == IntegerWidth.Unknown))
                return PeSymbolicSlot.PeHeaderOffset;
            return new PeSymbolicSlot(PeSymbolicKind.NumericOffset, val, width);
        }

        public sealed class PeSymbolicState
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

        public static bool HasLinkedPeHeaderZeroing(MethodDef method)
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
                                Logger.LogWarning($"[PeSymbolicEvaluator] Incompatible stack or local state when merging into instruction IL_{instructions[sIdx].Offset:X4} in {method.Name}. Inconclusive analysis: safely retaining hook.");
                                return false;
                            }
                        }
                    }
                }

                return zeroingDetected;
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"[PeSymbolicEvaluator] Symbolic evaluation error in {method.Name}: {ex.Message}. Falling back to safe hook retention.");
                return false;
            }
        }

        public static void ExecuteSymbolicInstruction(
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

            // 2. Type conversions / casts
            if (code == Code.Conv_I || code == Code.Conv_U || code == Code.Conv_I4 || code == Code.Conv_U4 ||
                code == Code.Conv_I8 || code == Code.Conv_U8 ||
                ((code == Code.Call || code == Code.Callvirt) && inst.Operand?.ToString().Contains("op_Explicit") == true))
            {
                var val = PopStack(stack);
                if (val.Kind == PeSymbolicKind.None)
                {
                    PushStack(stack, PeSymbolicSlot.None);
                    return;
                }

                if (code == Code.Conv_I4)
                {
                    if (val.ConcreteValue.HasValue)
                    {
                        long res = (int)val.ConcreteValue.Value;
                        PushStack(stack, CreateNumericSlot(res, IntegerWidth.Bit32));
                    }
                    else
                    {
                        PushStack(stack, new PeSymbolicSlot(val.Kind, null, IntegerWidth.Bit32));
                    }
                    return;
                }
                if (code == Code.Conv_U4)
                {
                    if (val.ConcreteValue.HasValue)
                    {
                        long res = (long)(uint)val.ConcreteValue.Value;
                        PushStack(stack, CreateNumericSlot(res, IntegerWidth.Bit32));
                    }
                    else
                    {
                        PushStack(stack, new PeSymbolicSlot(val.Kind, null, IntegerWidth.Bit32));
                    }
                    return;
                }
                if (code == Code.Conv_I8)
                {
                    if (val.ConcreteValue.HasValue)
                    {
                        long res;
                        if (val.Width == IntegerWidth.Bit32)
                            res = (int)val.ConcreteValue.Value; // sign-extended
                        else
                            res = val.ConcreteValue.Value;
                        PushStack(stack, CreateNumericSlot(res, IntegerWidth.Bit64));
                    }
                    else
                    {
                        PushStack(stack, new PeSymbolicSlot(val.Kind, null, IntegerWidth.Bit64));
                    }
                    return;
                }
                if (code == Code.Conv_U8)
                {
                    if (val.ConcreteValue.HasValue)
                    {
                        ulong uVal;
                        if (val.Width == IntegerWidth.Bit32)
                            uVal = (uint)val.ConcreteValue.Value; // zero-extended
                        else
                            uVal = (ulong)val.ConcreteValue.Value;
                        PushStack(stack, CreateNumericSlot((long)uVal, IntegerWidth.Bit64));
                    }
                    else
                    {
                        PushStack(stack, new PeSymbolicSlot(val.Kind, null, IntegerWidth.Bit64));
                    }
                    return;
                }
                if (code == Code.Conv_I)
                {
                    bool is32 = IsGuaranteed32BitModule(module);
                    bool is64 = IsGuaranteed64BitModule(module);
                    if (val.ConcreteValue.HasValue)
                    {
                        if (is32)
                            PushStack(stack, CreateNumericSlot((int)val.ConcreteValue.Value, IntegerWidth.Bit32));
                        else if (is64)
                            PushStack(stack, CreateNumericSlot(val.ConcreteValue.Value, IntegerWidth.Bit64));
                        else
                            PushStack(stack, new PeSymbolicSlot(val.Kind == PeSymbolicKind.Zero ? PeSymbolicKind.Zero : PeSymbolicKind.NumericOffset, null, IntegerWidth.Native));
                    }
                    else
                    {
                        PushStack(stack, new PeSymbolicSlot(val.Kind, null, IntegerWidth.Native));
                    }
                    return;
                }
                if (code == Code.Conv_U)
                {
                    bool is32 = IsGuaranteed32BitModule(module);
                    bool is64 = IsGuaranteed64BitModule(module);
                    if (val.ConcreteValue.HasValue)
                    {
                        if (is32)
                            PushStack(stack, CreateNumericSlot((long)(uint)val.ConcreteValue.Value, IntegerWidth.Bit32));
                        else if (is64)
                            PushStack(stack, CreateNumericSlot(val.ConcreteValue.Value, IntegerWidth.Bit64));
                        else
                            PushStack(stack, new PeSymbolicSlot(val.Kind == PeSymbolicKind.Zero ? PeSymbolicKind.Zero : PeSymbolicKind.NumericOffset, null, IntegerWidth.Native));
                    }
                    else
                    {
                        PushStack(stack, new PeSymbolicSlot(val.Kind, null, IntegerWidth.Native));
                    }
                    return;
                }

                // General op_Explicit: preserve tag
                PushStack(stack, val);
                return;
            }

            // 3. Constants: ldc.i4, ldc.i8, ldnull
            if (inst.IsLdcI4())
            {
                int val = inst.GetLdcI4Value();
                PushStack(stack, CreateNumericSlot(val, IntegerWidth.Bit32));
                return;
            }

            if (code == Code.Ldc_I8)
            {
                if (inst.Operand is long lv)
                {
                    PushStack(stack, CreateNumericSlot(lv, IntegerWidth.Bit64));
                }
                else
                {
                    PushStack(stack, new PeSymbolicSlot(PeSymbolicKind.NumericOffset, null, IntegerWidth.Bit64));
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
                IntegerWidth width = (a.Width == IntegerWidth.Bit64 || b.Width == IntegerWidth.Bit64) ? IntegerWidth.Bit64 :
                                     (a.Width == IntegerWidth.Native || b.Width == IntegerWidth.Native) ? IntegerWidth.Native : IntegerWidth.Bit32;

                if (a.Kind == PeSymbolicKind.Zero || b.Kind == PeSymbolicKind.Zero ||
                    (a.ConcreteValue.HasValue && a.ConcreteValue.Value == 0) ||
                    (b.ConcreteValue.HasValue && b.ConcreteValue.Value == 0))
                {
                    PushStack(stack, width == IntegerWidth.Bit64 ? PeSymbolicSlot.Zero64 : PeSymbolicSlot.Zero);
                }
                else if (IsNumeric(a) && IsNumeric(b))
                {
                    if (a.ConcreteValue.HasValue && b.ConcreteValue.HasValue)
                    {
                        try
                        {
                            long res;
                            if (code == Code.Mul)
                            {
                                if (width == IntegerWidth.Bit64)
                                    res = unchecked(a.ConcreteValue.Value * b.ConcreteValue.Value);
                                else
                                    res = (long)unchecked((int)a.ConcreteValue.Value * (int)b.ConcreteValue.Value);
                            }
                            else if (code == Code.Mul_Ovf)
                            {
                                if (width == IntegerWidth.Bit64)
                                    res = checked(a.ConcreteValue.Value * b.ConcreteValue.Value);
                                else
                                    res = checked((int)a.ConcreteValue.Value * (int)b.ConcreteValue.Value);
                            }
                            else // Mul_Ovf_Un
                            {
                                if (width == IntegerWidth.Bit64)
                                    res = (long)checked((ulong)a.ConcreteValue.Value * (ulong)b.ConcreteValue.Value);
                                else
                                    res = (long)checked((uint)a.ConcreteValue.Value * (uint)b.ConcreteValue.Value);
                            }
                            PushStack(stack, CreateNumericSlot(res, width));
                        }
                        catch (OverflowException)
                        {
                            PushStack(stack, PeSymbolicSlot.None);
                        }
                    }
                    else
                    {
                        PushStack(stack, new PeSymbolicSlot(PeSymbolicKind.NumericOffset, null, width));
                    }
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
                    IntegerWidth width = (a.Width == IntegerWidth.Bit64 || b.Width == IntegerWidth.Bit64) ? IntegerWidth.Bit64 :
                                         (a.Width == IntegerWidth.Native || b.Width == IntegerWidth.Native) ? IntegerWidth.Native : IntegerWidth.Bit32;
                    if (a.ConcreteValue.HasValue && b.ConcreteValue.HasValue)
                        PushStack(stack, CreateNumericSlot(a.ConcreteValue.Value | b.ConcreteValue.Value, width));
                    else
                        PushStack(stack, new PeSymbolicSlot(PeSymbolicKind.NumericOffset, null, width));
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
                IntegerWidth width = (a.Width == IntegerWidth.Bit64 || b.Width == IntegerWidth.Bit64) ? IntegerWidth.Bit64 :
                                     (a.Width == IntegerWidth.Native || b.Width == IntegerWidth.Native) ? IntegerWidth.Native : IntegerWidth.Bit32;

                if (a.Kind == PeSymbolicKind.Zero && b.Kind == PeSymbolicKind.Zero)
                {
                    PushStack(stack, width == IntegerWidth.Bit64 ? PeSymbolicSlot.Zero64 : PeSymbolicSlot.Zero);
                }
                else if (IsNumeric(a) && IsNumeric(b))
                {
                    if (a.ConcreteValue.HasValue && b.ConcreteValue.HasValue)
                        PushStack(stack, CreateNumericSlot(a.ConcreteValue.Value ^ b.ConcreteValue.Value, width));
                    else
                        PushStack(stack, new PeSymbolicSlot(PeSymbolicKind.NumericOffset, null, width));
                }
                else
                {
                    PushStack(stack, PeSymbolicSlot.None);
                }
                return;
            }

            if (code == Code.Shl || code == Code.Shr || code == Code.Shr_Un)
            {
                var b = PopStack(stack);
                var a = PopStack(stack);
                if (a.Kind == PeSymbolicKind.Zero || (a.ConcreteValue.HasValue && a.ConcreteValue.Value == 0))
                {
                    PushStack(stack, a.Width == IntegerWidth.Bit64 ? PeSymbolicSlot.Zero64 : PeSymbolicSlot.Zero);
                }
                else if (IsNumeric(a) && IsNumeric(b))
                {
                    if (a.ConcreteValue.HasValue && b.ConcreteValue.HasValue)
                    {
                        if (a.Width == IntegerWidth.Bit64)
                            {
                            int shift = (int)(b.ConcreteValue.Value & 0x3F);
                            long res;
                            if (code == Code.Shl)
                                res = a.ConcreteValue.Value << shift;
                            else if (code == Code.Shr)
                                res = a.ConcreteValue.Value >> shift;
                            else // Shr_Un
                                res = (long)((ulong)a.ConcreteValue.Value >> shift);
                            PushStack(stack, CreateNumericSlot(res, IntegerWidth.Bit64));
                        }
                        else
                        {
                            int shift = (int)(b.ConcreteValue.Value & 0x1F);
                            int a32 = (int)a.ConcreteValue.Value;
                            long res;
                            if (code == Code.Shl)
                                res = a32 << shift;
                            else if (code == Code.Shr)
                                res = a32 >> shift;
                            else // Shr_Un
                                res = (long)((uint)a32 >> shift);
                            PushStack(stack, CreateNumericSlot(res, IntegerWidth.Bit32));
                        }
                    }
                    else
                    {
                        PushStack(stack, new PeSymbolicSlot(PeSymbolicKind.NumericOffset, null, a.Width));
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
                    PushStack(stack, a);
                else if (IsNumeric(a))
                {
                    if (a.ConcreteValue.HasValue)
                    {
                        long res = a.Width == IntegerWidth.Bit64 ? unchecked(-a.ConcreteValue.Value) :
                                   (long)unchecked(-(int)a.ConcreteValue.Value);
                        PushStack(stack, CreateNumericSlot(res, a.Width));
                    }
                    else
                        PushStack(stack, new PeSymbolicSlot(PeSymbolicKind.NumericOffset, null, a.Width));
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
                    {
                        long res = a.Width == IntegerWidth.Bit64 ? ~a.ConcreteValue.Value :
                                   (long)~(int)a.ConcreteValue.Value;
                        PushStack(stack, CreateNumericSlot(res, a.Width));
                    }
                    else
                        PushStack(stack, new PeSymbolicSlot(PeSymbolicKind.NumericOffset, null, a.Width));
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

        public static PeSymbolicSlot CombineAdd(PeSymbolicSlot a, PeSymbolicSlot b)
        {
            // Obvious arithmetic identity: X + 0 == X, 0 + X == X
            if (b.Kind == PeSymbolicKind.Zero || (b.Kind == PeSymbolicKind.NumericOffset && b.ConcreteValue.HasValue && b.ConcreteValue.Value == 0))
            {
                return a;
            }
            if (a.Kind == PeSymbolicKind.Zero || (a.Kind == PeSymbolicKind.NumericOffset && a.ConcreteValue.HasValue && a.ConcreteValue.Value == 0))
            {
                return b;
            }

            // 1. Proven ModuleBase + 0x3C -> PeDerivedAddress with cumulative displacement 0x3C
            if ((a.Kind == PeSymbolicKind.ModuleBase && b.Kind == PeSymbolicKind.PeHeaderOffset) ||
                (b.Kind == PeSymbolicKind.ModuleBase && a.Kind == PeSymbolicKind.PeHeaderOffset))
            {
                return new PeSymbolicSlot(PeSymbolicKind.PeDerivedAddress, 0x3CL, IntegerWidth.Native);
            }

            // 2. Proven ModuleBase + PeHeaderField (specifically e_lfanew read from ModuleBase + 0x3C)
            if ((a.Kind == PeSymbolicKind.ModuleBase && b.Kind == PeSymbolicKind.PeHeaderField) ||
                (b.Kind == PeSymbolicKind.ModuleBase && a.Kind == PeSymbolicKind.PeHeaderField))
            {
                return new PeSymbolicSlot(PeSymbolicKind.NtDerivedAddress, 0L, IntegerWidth.Native);
            }

            // 3. ModuleBase + Numeric displacement
            if (a.Kind == PeSymbolicKind.ModuleBase && IsNumeric(b))
            {
                if (b.ConcreteValue.HasValue)
                {
                    long offset = b.ConcreteValue.Value;
                    if (offset >= 0 && offset <= MaxPeHeaderDisplacement)
                        return new PeSymbolicSlot(PeSymbolicKind.PeDerivedAddress, offset, IntegerWidth.Native);
                }
                return PeSymbolicSlot.None;
            }
            if (b.Kind == PeSymbolicKind.ModuleBase && IsNumeric(a))
            {
                if (a.ConcreteValue.HasValue)
                {
                    long offset = a.ConcreteValue.Value;
                    if (offset >= 0 && offset <= MaxPeHeaderDisplacement)
                        return new PeSymbolicSlot(PeSymbolicKind.PeDerivedAddress, offset, IntegerWidth.Native);
                }
                return PeSymbolicSlot.None;
            }

            // 4. Cumulative offset calculation from already derived PE DOS/stub address:
            if (a.Kind == PeSymbolicKind.PeDerivedAddress && IsNumeric(b))
            {
                if (a.ConcreteValue.HasValue && b.ConcreteValue.HasValue)
                {
                    try
                    {
                        checked
                        {
                            long cum = a.ConcreteValue.Value + b.ConcreteValue.Value;
                            if (cum >= 0 && cum <= MaxPeHeaderDisplacement)
                                return new PeSymbolicSlot(PeSymbolicKind.PeDerivedAddress, cum, a.Width);
                        }
                    }
                    catch (OverflowException)
                    {
                        return PeSymbolicSlot.None;
                    }
                }
                return PeSymbolicSlot.None;
            }
            if (b.Kind == PeSymbolicKind.PeDerivedAddress && IsNumeric(a))
            {
                if (b.ConcreteValue.HasValue && a.ConcreteValue.HasValue)
                {
                    try
                    {
                        checked
                        {
                            long cum = b.ConcreteValue.Value + a.ConcreteValue.Value;
                            if (cum >= 0 && cum <= MaxPeHeaderDisplacement)
                                return new PeSymbolicSlot(PeSymbolicKind.PeDerivedAddress, cum, b.Width);
                        }
                    }
                    catch (OverflowException)
                    {
                        return PeSymbolicSlot.None;
                    }
                }
                return PeSymbolicSlot.None;
            }

            // 5. Cumulative offset calculation from NT headers:
            if (a.Kind == PeSymbolicKind.NtDerivedAddress && IsNumeric(b))
            {
                if (a.ConcreteValue.HasValue && b.ConcreteValue.HasValue)
                {
                    try
                    {
                        checked
                        {
                            long cum = a.ConcreteValue.Value + b.ConcreteValue.Value;
                            if (cum >= -MaxPeHeaderDisplacement && cum <= MaxPeHeaderDisplacement)
                                return new PeSymbolicSlot(PeSymbolicKind.NtDerivedAddress, cum, a.Width);
                        }
                    }
                    catch (OverflowException)
                    {
                        return PeSymbolicSlot.None;
                    }
                }
                return PeSymbolicSlot.None;
            }
            if (b.Kind == PeSymbolicKind.NtDerivedAddress && IsNumeric(a))
            {
                if (b.ConcreteValue.HasValue && a.ConcreteValue.HasValue)
                {
                    try
                    {
                        checked
                        {
                            long cum = b.ConcreteValue.Value + a.ConcreteValue.Value;
                            if (cum >= -MaxPeHeaderDisplacement && cum <= MaxPeHeaderDisplacement)
                                return new PeSymbolicSlot(PeSymbolicKind.NtDerivedAddress, cum, b.Width);
                        }
                    }
                    catch (OverflowException)
                    {
                        return PeSymbolicSlot.None;
                    }
                }
                return PeSymbolicSlot.None;
            }

            // 6. Numeric + Numeric -> Numeric
            if (IsNumeric(a) && IsNumeric(b))
            {
                IntegerWidth width = (a.Width == IntegerWidth.Bit64 || b.Width == IntegerWidth.Bit64) ? IntegerWidth.Bit64 :
                                     (a.Width == IntegerWidth.Native || b.Width == IntegerWidth.Native) ? IntegerWidth.Native : IntegerWidth.Bit32;
                if (a.ConcreteValue.HasValue && b.ConcreteValue.HasValue)
                {
                    long res = width == IntegerWidth.Bit64 ? unchecked(a.ConcreteValue.Value + b.ConcreteValue.Value) :
                               (long)unchecked((int)a.ConcreteValue.Value + (int)b.ConcreteValue.Value);
                    return CreateNumericSlot(res, width);
                }
                return new PeSymbolicSlot(PeSymbolicKind.NumericOffset, null, width);
            }

            return PeSymbolicSlot.None;
        }

        public static PeSymbolicSlot CombineSub(PeSymbolicSlot a, PeSymbolicSlot b)
        {
            // Obvious arithmetic identity: X - 0 == X
            if (b.Kind == PeSymbolicKind.Zero || (b.Kind == PeSymbolicKind.NumericOffset && b.ConcreteValue.HasValue && b.ConcreteValue.Value == 0))
            {
                return a;
            }

            // 1. PeDerivedAddress - NumericOffset
            if (a.Kind == PeSymbolicKind.PeDerivedAddress && IsNumeric(b))
            {
                if (a.ConcreteValue.HasValue && b.ConcreteValue.HasValue)
                {
                    try
                    {
                        checked
                        {
                            long cum = a.ConcreteValue.Value - b.ConcreteValue.Value;
                            if (cum >= 0 && cum <= MaxPeHeaderDisplacement)
                                return new PeSymbolicSlot(PeSymbolicKind.PeDerivedAddress, cum, a.Width);
                        }
                    }
                    catch (OverflowException)
                    {
                        return PeSymbolicSlot.None;
                    }
                }
                return PeSymbolicSlot.None;
            }

            // 2. NtDerivedAddress - NumericOffset
            if (a.Kind == PeSymbolicKind.NtDerivedAddress && IsNumeric(b))
            {
                if (a.ConcreteValue.HasValue && b.ConcreteValue.HasValue)
                {
                    try
                    {
                        checked
                        {
                            long cum = a.ConcreteValue.Value - b.ConcreteValue.Value;
                            if (cum >= -MaxPeHeaderDisplacement && cum <= MaxPeHeaderDisplacement)
                                return new PeSymbolicSlot(PeSymbolicKind.NtDerivedAddress, cum, a.Width);
                        }
                    }
                    catch (OverflowException)
                    {
                        return PeSymbolicSlot.None;
                    }
                }
                return PeSymbolicSlot.None;
            }

            // 3. Numeric - Numeric -> Numeric
            if (IsNumeric(a) && IsNumeric(b))
            {
                IntegerWidth width = (a.Width == IntegerWidth.Bit64 || b.Width == IntegerWidth.Bit64) ? IntegerWidth.Bit64 :
                                     (a.Width == IntegerWidth.Native || b.Width == IntegerWidth.Native) ? IntegerWidth.Native : IntegerWidth.Bit32;
                if (a.ConcreteValue.HasValue && b.ConcreteValue.HasValue)
                {
                    long res = width == IntegerWidth.Bit64 ? unchecked(a.ConcreteValue.Value - b.ConcreteValue.Value) :
                               (long)unchecked((int)a.ConcreteValue.Value - (int)b.ConcreteValue.Value);
                    return CreateNumericSlot(res, width);
                }
                return new PeSymbolicSlot(PeSymbolicKind.NumericOffset, null, width);
            }

            return PeSymbolicSlot.None;
        }

        public static PeSymbolicSlot CombineAnd(PeSymbolicSlot a, PeSymbolicSlot b)
        {
            // Rule: X & 0 = 0. Provenance of an address MUST NEVER survive a bitwise AND whose exact result is 0!
            if (a.Kind == PeSymbolicKind.Zero || (a.Kind == PeSymbolicKind.NumericOffset && a.ConcreteValue.HasValue && a.ConcreteValue.Value == 0))
            {
                return a.Width == IntegerWidth.Bit64 ? PeSymbolicSlot.Zero64 : PeSymbolicSlot.Zero;
            }

            if (b.Kind == PeSymbolicKind.Zero || (b.Kind == PeSymbolicKind.NumericOffset && b.ConcreteValue.HasValue && b.ConcreteValue.Value == 0))
            {
                return b.Width == IntegerWidth.Bit64 ? PeSymbolicSlot.Zero64 : PeSymbolicSlot.Zero;
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
            if (a.Kind == PeSymbolicKind.PeDerivedAddress && b.ConcreteValue.HasValue && IsAlignmentMask(b.ConcreteValue.Value))
            {
                if (a.ConcreteValue.HasValue)
                {
                    long masked = a.ConcreteValue.Value & b.ConcreteValue.Value;
                    if (masked >= 0 && masked <= MaxPeHeaderDisplacement)
                        return new PeSymbolicSlot(PeSymbolicKind.PeDerivedAddress, masked, a.Width);
                }
                return PeSymbolicSlot.None;
            }
            if (b.Kind == PeSymbolicKind.PeDerivedAddress && a.ConcreteValue.HasValue && IsAlignmentMask(a.ConcreteValue.Value))
            {
                if (b.ConcreteValue.HasValue)
                {
                    long masked = b.ConcreteValue.Value & a.ConcreteValue.Value;
                    if (masked >= 0 && masked <= MaxPeHeaderDisplacement)
                        return new PeSymbolicSlot(PeSymbolicKind.PeDerivedAddress, masked, b.Width);
                }
                return PeSymbolicSlot.None;
            }

            // Pointer alignment: NtDerivedAddress & AlignmentMask
            if (a.Kind == PeSymbolicKind.NtDerivedAddress && b.ConcreteValue.HasValue && IsAlignmentMask(b.ConcreteValue.Value))
            {
                if (a.ConcreteValue.HasValue)
                {
                    long masked = a.ConcreteValue.Value & b.ConcreteValue.Value;
                    if (masked >= -MaxPeHeaderDisplacement && masked <= MaxPeHeaderDisplacement)
                        return new PeSymbolicSlot(PeSymbolicKind.NtDerivedAddress, masked, a.Width);
                }
                return PeSymbolicSlot.None;
            }
            if (b.Kind == PeSymbolicKind.NtDerivedAddress && a.ConcreteValue.HasValue && IsAlignmentMask(a.ConcreteValue.Value))
            {
                if (b.ConcreteValue.HasValue)
                {
                    long masked = b.ConcreteValue.Value & a.ConcreteValue.Value;
                    if (masked >= -MaxPeHeaderDisplacement && masked <= MaxPeHeaderDisplacement)
                        return new PeSymbolicSlot(PeSymbolicKind.NtDerivedAddress, masked, b.Width);
                }
                return PeSymbolicSlot.None;
            }

            // Numeric & Numeric
            if (IsNumeric(a) && IsNumeric(b))
            {
                IntegerWidth width = (a.Width == IntegerWidth.Bit64 || b.Width == IntegerWidth.Bit64) ? IntegerWidth.Bit64 :
                                     (a.Width == IntegerWidth.Native || b.Width == IntegerWidth.Native) ? IntegerWidth.Native : IntegerWidth.Bit32;
                if (a.ConcreteValue.HasValue && b.ConcreteValue.HasValue)
                {
                    long res = a.ConcreteValue.Value & b.ConcreteValue.Value;
                    return CreateNumericSlot(res, width);
                }
                return new PeSymbolicSlot(PeSymbolicKind.NumericOffset, null, width);
            }

            return PeSymbolicSlot.None;
        }

        public static bool IsGuaranteed64BitModule(ModuleDef module)
        {
            if (module == null)
                return false;

            if (module.IsAMD64 || module.IsARM64 || module.IsIA64)
                return true;

            if (module.Machine == Machine.AMD64 ||
                module.Machine == Machine.ARM64 ||
                module.Machine == Machine.IA64)
            {
                return true;
            }

            if (!string.IsNullOrEmpty(module.Location) && File.Exists(module.Location))
            {
                try
                {
                    var arch = ArchitectureDetector.Detect(module.Location);
                    if (arch.Architecture == TargetArchitecture.X64)
                        return true;
                }
                catch { }
            }

            return false;
        }

        public static bool IsGuaranteed32BitModule(ModuleDef module)
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

        public static PeSymbolicSlot EvaluateLdind(PeSymbolicSlot addr, Code code, ModuleDef module)
        {
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

        public static bool IsMarshalGetHINSTANCE(IMethod called)
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
    }
}
