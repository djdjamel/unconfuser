using System;
using System.Collections.Generic;
using ConfuserExKillerRunner.Analysis;
using ConfuserExKillerRunner.Core;
using ConfuserExKillerRunner.Killers;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.PE;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    [Trait("Category", "Unit")]
    public class PeSymbolicEvaluatorTests
    {
        [Fact]
        public void PeSymbolic_64BitMultiplication_Produces4294967296()
        {
            var module = new ModuleDefUser("TestMod");
            var stack = new List<PeSymbolicSlot>();
            var locals = Array.Empty<PeSymbolicSlot>();
            bool zeroing = false;

            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I8, 65536L), stack, locals, ref zeroing, module);
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I8, 65536L), stack, locals, ref zeroing, module);
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Mul), stack, locals, ref zeroing, module);

            Assert.Single(stack);
            var res = stack[0];
            Assert.Equal(PeSymbolicKind.NumericOffset, res.Kind);
            Assert.Equal(4294967296L, res.ConcreteValue);
            Assert.Equal(IntegerWidth.Bit64, res.Width);
        }

        [Fact]
        public void PeSymbolic_32BitMultiplication_WrapsAccordingToILWidth()
        {
            var module = new ModuleDefUser("TestMod");
            var stack = new List<PeSymbolicSlot>();
            var locals = Array.Empty<PeSymbolicSlot>();
            bool zeroing = false;

            // In 32-bit IL multiplication, 65536 * 65536 = 0x100000000 which wraps to 0
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, 65536), stack, locals, ref zeroing, module);
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, 65536), stack, locals, ref zeroing, module);
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Mul), stack, locals, ref zeroing, module);

            Assert.Single(stack);
            var res = stack[0];
            Assert.Equal(PeSymbolicKind.Zero, res.Kind);
            Assert.Equal(0L, res.ConcreteValue);
            Assert.Equal(IntegerWidth.Bit32, res.Width);
        }

        [Fact]
        public void PeSymbolic_MulOvf_OverflowFailsToNone()
        {
            var module = new ModuleDefUser("TestMod");
            var stack = new List<PeSymbolicSlot>();
            var locals = Array.Empty<PeSymbolicSlot>();
            bool zeroing = false;

            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, int.MaxValue), stack, locals, ref zeroing, module);
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, 2), stack, locals, ref zeroing, module);
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Mul_Ovf), stack, locals, ref zeroing, module);

            Assert.Single(stack);
            Assert.Equal(PeSymbolicSlot.None, stack[0]);
        }

        [Fact]
        public void PeSymbolic_64BitShiftLeft_DoesNotMaskWith0x1F()
        {
            var module = new ModuleDefUser("TestMod");
            var stack = new List<PeSymbolicSlot>();
            var locals = Array.Empty<PeSymbolicSlot>();
            bool zeroing = false;

            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I8, 1L), stack, locals, ref zeroing, module);
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, 32), stack, locals, ref zeroing, module);
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Shl), stack, locals, ref zeroing, module);

            Assert.Single(stack);
            var res = stack[0];
            Assert.Equal(PeSymbolicKind.NumericOffset, res.Kind);
            Assert.Equal(4294967296L, res.ConcreteValue);
            Assert.Equal(IntegerWidth.Bit64, res.Width);
        }

        [Fact]
        public void PeSymbolic_32BitShiftLeft_MasksWith0x1F()
        {
            var module = new ModuleDefUser("TestMod");
            var stack = new List<PeSymbolicSlot>();
            var locals = Array.Empty<PeSymbolicSlot>();
            bool zeroing = false;

            // 32-bit shift masks shift amount with 0x1F: 32 & 0x1F = 0, so 1 << 0 = 1
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, 1), stack, locals, ref zeroing, module);
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, 32), stack, locals, ref zeroing, module);
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Shl), stack, locals, ref zeroing, module);

            Assert.Single(stack);
            var res = stack[0];
            Assert.Equal(PeSymbolicKind.NumericOffset, res.Kind);
            Assert.Equal(1L, res.ConcreteValue);
            Assert.Equal(IntegerWidth.Bit32, res.Width);
        }

        [Fact]
        public void PeSymbolic_Shr_ArithmeticShiftOnNegativeValue()
        {
            var module = new ModuleDefUser("TestMod");
            var stack = new List<PeSymbolicSlot>();
            var locals = Array.Empty<PeSymbolicSlot>();
            bool zeroing = false;

            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I8, -16L), stack, locals, ref zeroing, module);
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, 2), stack, locals, ref zeroing, module);
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Shr), stack, locals, ref zeroing, module);

            Assert.Single(stack);
            var res = stack[0];
            Assert.Equal(-4L, res.ConcreteValue);
            Assert.Equal(IntegerWidth.Bit64, res.Width);
        }

        [Fact]
        public void PeSymbolic_ShrUn_LogicalShiftOnNegativeValue()
        {
            var module = new ModuleDefUser("TestMod");
            var stack = new List<PeSymbolicSlot>();
            var locals = Array.Empty<PeSymbolicSlot>();
            bool zeroing = false;

            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I8, -16L), stack, locals, ref zeroing, module);
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, 2), stack, locals, ref zeroing, module);
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Shr_Un), stack, locals, ref zeroing, module);

            Assert.Single(stack);
            var res = stack[0];
            long expected = (long)(unchecked((ulong)-16L) >> 2);
            Assert.Equal(expected, res.ConcreteValue);
            Assert.Equal(IntegerWidth.Bit64, res.Width);
        }

        [Fact]
        public void PeSymbolic_ShrUn_LogicalShiftOnNegative32BitValue()
        {
            var module = new ModuleDefUser("TestMod");
            var stack = new List<PeSymbolicSlot>();
            var locals = Array.Empty<PeSymbolicSlot>();
            bool zeroing = false;

            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, -16), stack, locals, ref zeroing, module);
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, 2), stack, locals, ref zeroing, module);
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Shr_Un), stack, locals, ref zeroing, module);

            Assert.Single(stack);
            var res = stack[0];
            long expected = (long)(unchecked((uint)-16) >> 2); // 1073741820L (0x3FFFFFFC), NOT arithmetic 4294967292L
            Assert.Equal(1073741820L, res.ConcreteValue);
            Assert.Equal(expected, res.ConcreteValue);
            Assert.Equal(IntegerWidth.Bit32, res.Width);
        }

        [Fact]
        public void PeSymbolic_ShrUn_32Bit_DistinguishesLogicalFromArithmetic()
        {
            var module = new ModuleDefUser("TestMod");
            var stack = new List<PeSymbolicSlot>();
            var locals = Array.Empty<PeSymbolicSlot>();
            bool zeroing = false;

            // Shr (arithmetic): -16 >> 2 == -4
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, -16), stack, locals, ref zeroing, module);
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, 2), stack, locals, ref zeroing, module);
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Shr), stack, locals, ref zeroing, module);
            var resShr = stack[0];
            Assert.Equal(-4L, resShr.ConcreteValue);

            stack.Clear();
            // Shr_Un (logical): unchecked((uint)-16) >> 2 == 1073741820
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, -16), stack, locals, ref zeroing, module);
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, 2), stack, locals, ref zeroing, module);
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Shr_Un), stack, locals, ref zeroing, module);
            var resShrUn = stack[0];
            Assert.Equal(1073741820L, resShrUn.ConcreteValue);
            Assert.NotEqual(resShr.ConcreteValue, resShrUn.ConcreteValue);
        }

        [Fact]
        public void PeSymbolic_ConvI8_SignExtendsNegative32BitInteger()
        {
            var module = new ModuleDefUser("TestMod");
            var stack = new List<PeSymbolicSlot>();
            var locals = Array.Empty<PeSymbolicSlot>();
            bool zeroing = false;

            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, -1), stack, locals, ref zeroing, module);
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Conv_I8), stack, locals, ref zeroing, module);

            Assert.Single(stack);
            var res = stack[0];
            Assert.Equal(-1L, res.ConcreteValue);
            Assert.Equal(IntegerWidth.Bit64, res.Width);
        }

        [Fact]
        public void PeSymbolic_ConvU8_ZeroExtends32BitInteger()
        {
            var module = new ModuleDefUser("TestMod");
            var stack = new List<PeSymbolicSlot>();
            var locals = Array.Empty<PeSymbolicSlot>();
            bool zeroing = false;

            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, -1), stack, locals, ref zeroing, module);
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Conv_U8), stack, locals, ref zeroing, module);

            Assert.Single(stack);
            var res = stack[0];
            Assert.Equal(4294967295L, res.ConcreteValue);
            Assert.Equal(IntegerWidth.Bit64, res.Width);
        }

        [Fact]
        public void PeSymbolic_ConvI_OnGuaranteed32BitModule_TruncatesTo32Bit()
        {
            var module = new ModuleDefUser("TestMod32") { Machine = Machine.I386, Is32BitRequired = true };
            var stack = new List<PeSymbolicSlot>();
            var locals = Array.Empty<PeSymbolicSlot>();
            bool zeroing = false;

            // 4294967296L is 0x100000000L. In 32-bit native int, it truncates to 0
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I8, 4294967296L), stack, locals, ref zeroing, module);
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Conv_I), stack, locals, ref zeroing, module);

            Assert.Single(stack);
            var res = stack[0];
            Assert.Equal(PeSymbolicKind.Zero, res.Kind);
            Assert.Equal(0L, res.ConcreteValue);
            Assert.Equal(IntegerWidth.Bit32, res.Width);
        }

        [Fact]
        public void PeSymbolic_ConvI_OnGuaranteed64BitModule_Preserves64Bit()
        {
            var module = new ModuleDefUser("TestMod64") { Machine = Machine.AMD64 };
            var stack = new List<PeSymbolicSlot>();
            var locals = Array.Empty<PeSymbolicSlot>();
            bool zeroing = false;

            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I8, 4294967296L), stack, locals, ref zeroing, module);
            PeSymbolicEvaluator.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Conv_I), stack, locals, ref zeroing, module);

            Assert.Single(stack);
            var res = stack[0];
            Assert.Equal(PeSymbolicKind.NumericOffset, res.Kind);
            Assert.Equal(4294967296L, res.ConcreteValue);
            Assert.Equal(IntegerWidth.Bit64, res.Width);
        }

        [Fact]
        public void PeSymbolic_DisplacementExceedingMaxPeHeader_LosesProvenance()
        {
            // Adding a displacement exceeding 0x1000 from ModuleBase revokes PE provenance
            var excessOffset = new PeSymbolicSlot(PeSymbolicKind.NumericOffset, 0x1001L, IntegerWidth.Bit32);
            var result = PeSymbolicEvaluator.CombineAdd(PeSymbolicSlot.ModuleBase, excessOffset);

            Assert.Equal(PeSymbolicSlot.None, result);
        }

        [Fact]
        public void PeSymbolic_CombineAnd_WithZero_RevokesProvenance()
        {
            // Strict X & 0 = 0: Address provenance MUST NOT survive bitwise AND with 0
            var derived = new PeSymbolicSlot(PeSymbolicKind.PeDerivedAddress, 0x3CL, IntegerWidth.Native);
            var res1 = PeSymbolicEvaluator.CombineAnd(derived, PeSymbolicSlot.Zero);
            var res2 = PeSymbolicEvaluator.CombineAnd(PeSymbolicSlot.ModuleBase, PeSymbolicSlot.Zero);
            var res3 = PeSymbolicEvaluator.CombineAnd(derived, PeSymbolicSlot.Zero64);

            Assert.Equal(PeSymbolicKind.Zero, res1.Kind);
            Assert.Equal(PeSymbolicKind.Zero, res2.Kind);
            Assert.Equal(PeSymbolicKind.Zero, res3.Kind);
            Assert.False(PeSymbolicEvaluator.IsPeTarget(res1));
            Assert.False(PeSymbolicEvaluator.IsPeTarget(res2));
            Assert.False(PeSymbolicEvaluator.IsPeTarget(res3));
        }

        [Fact]
        public void PeSymbolic_CombineAnd_WithArbitraryMask_LosesProvenance()
        {
            // Arbitrary mask 0x7F is NOT an alignment mask (e.g. -4, -16)
            var derived = new PeSymbolicSlot(PeSymbolicKind.PeDerivedAddress, 0x3CL, IntegerWidth.Native);
            var arbitraryMask = new PeSymbolicSlot(PeSymbolicKind.NumericOffset, 0x7FL, IntegerWidth.Bit32);

            var result = PeSymbolicEvaluator.CombineAnd(derived, arbitraryMask);

            Assert.Equal(PeSymbolicSlot.None, result);
        }

        [Fact]
        public void PeSymbolic_UnknownOperationFollowedByAddressCalculation_YieldsNone()
        {
            // Combining ModuleBase with None yields None (provenance lost)
            var result = PeSymbolicEvaluator.CombineAdd(PeSymbolicSlot.ModuleBase, PeSymbolicSlot.None);
            Assert.Equal(PeSymbolicSlot.None, result);
        }

        [Fact]
        public void PeSymbolic_IncompatibleBranchMerge_SafelyAbortsZeroingDetection()
        {
            var module = new ModuleDefUser("BranchMod");
            var method = new MethodDefUser("AmbiguousBranchMethod", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody { InitLocals = true }
            };
            method.Body.Variables.Add(new Local(module.CorLibTypes.IntPtr));

            var marshalType = new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef);
            var moduleType = new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef);
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, moduleType.ToTypeSig()),
                marshalType);

            // Path 1 branches over, pushing an extra value to stack, violating stack depth invariance across paths
            var labelTarget = Instruction.Create(OpCodes.Nop);
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Brtrue, labelTarget));

            // Path A: pushes ModuleBase
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));

            // Path B: labelTarget arrives with stack depth 0, but Path A would arrive with different state
            method.Body.Instructions.Add(labelTarget);
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            // Ambiguous / incompatible flow aborts symbolic zeroing analysis and safely returns false
            Assert.False(PeSymbolicEvaluator.HasLinkedPeHeaderZeroing(method));
        }

        [Fact]
        public void PeSymbolic_LargeDisplacementCipher_NotMisclassifiedAsAntiDump()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            var hook = new MethodDefUser("LargeDisplacementHook", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody { InitLocals = true }
            };
            var localBase = new Local(module.CorLibTypes.IntPtr);
            var localOldProtect = new Local(module.CorLibTypes.UInt32);
            hook.Body.Variables.Add(localBase);
            hook.Body.Variables.Add(localOldProtect);

            var vpRef = new MemberRefUser(module, "VirtualProtect",
                MethodSig.CreateStatic(module.CorLibTypes.Boolean,
                    module.CorLibTypes.IntPtr, module.CorLibTypes.UInt32, module.CorLibTypes.UInt32,
                    new ByRefSig(module.CorLibTypes.UInt32)),
                new TypeRefUser(module, string.Empty, "Kernel32", module.CorLibTypes.AssemblyRef));

            var marshalType = new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef);
            var moduleType = new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef);
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, moduleType.ToTypeSig()),
                marshalType);

            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));

            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x04));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localOldProtect));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // Large 64-bit displacement: base + 4294967296L
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I8, 4294967296L));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stind_I4));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(hook);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, hook));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            // Because the displacement is 4294967296L (beyond PE headers), zeroing is NOT linked to PE headers.
            Assert.False(PeSymbolicEvaluator.HasLinkedPeHeaderZeroing(hook));
        }

        [Fact]
        public void CombineSub_WithExtremeValuesAndLongMinValue_DoesNotThrowAndReturnsNone()
        {
            var ntSlot = new PeSymbolicSlot(PeSymbolicKind.NtDerivedAddress, 0L, IntegerWidth.Bit64);
            var minValSlot = new PeSymbolicSlot(PeSymbolicKind.NumericOffset, long.MinValue, IntegerWidth.Bit64);
            var maxValSlot = new PeSymbolicSlot(PeSymbolicKind.NumericOffset, long.MaxValue, IntegerWidth.Bit64);

            // 0 - long.MinValue causes OverflowException if checked, or long.MinValue if unchecked (Math.Abs throws)
            var resMin = PeSymbolicEvaluator.CombineSub(ntSlot, minValSlot);
            Assert.Equal(PeSymbolicKind.None, resMin.Kind);

            // 0 - long.MaxValue yields -long.MaxValue, which exceeds MaxPeHeaderDisplacement
            var resMax = PeSymbolicEvaluator.CombineSub(ntSlot, maxValSlot);
            Assert.Equal(PeSymbolicKind.None, resMax.Kind);

            // Subtraction underflow: long.MinValue - 1
            var underflowSlot = new PeSymbolicSlot(PeSymbolicKind.NtDerivedAddress, long.MinValue, IntegerWidth.Bit64);
            var oneSlot = new PeSymbolicSlot(PeSymbolicKind.NumericOffset, 1L, IntegerWidth.Bit64);
            var resUnderflow = PeSymbolicEvaluator.CombineSub(underflowSlot, oneSlot);
            Assert.Equal(PeSymbolicKind.None, resUnderflow.Kind);
        }

        [Fact]
        public void CombineAdd_WithExtremeValuesAndLongMinValue_DoesNotThrowAndReturnsNone()
        {
            var maxSlot = new PeSymbolicSlot(PeSymbolicKind.NtDerivedAddress, long.MaxValue, IntegerWidth.Bit64);
            var oneSlot = new PeSymbolicSlot(PeSymbolicKind.NumericOffset, 1L, IntegerWidth.Bit64);

            // long.MaxValue + 1 causes overflow
            var resOverflow = PeSymbolicEvaluator.CombineAdd(maxSlot, oneSlot);
            Assert.Equal(PeSymbolicKind.None, resOverflow.Kind);

            // NtDerivedAddress(0) + long.MinValue -> out of displacement range -> None
            var ntZero = new PeSymbolicSlot(PeSymbolicKind.NtDerivedAddress, 0L, IntegerWidth.Bit64);
            var minSlot = new PeSymbolicSlot(PeSymbolicKind.NumericOffset, long.MinValue, IntegerWidth.Bit64);
            var resMin = PeSymbolicEvaluator.CombineAdd(ntZero, minSlot);
            Assert.Equal(PeSymbolicKind.None, resMin.Kind);
        }

        [Fact]
        public void CombineAnd_WithLongMinValue_DoesNotThrowAndReturnsNone()
        {
            // Alignment mask on long.MinValue
            var minSlot = new PeSymbolicSlot(PeSymbolicKind.NtDerivedAddress, long.MinValue, IntegerWidth.Bit64);
            var maskSlot = new PeSymbolicSlot(PeSymbolicKind.NumericOffset, ~15L, IntegerWidth.Bit64);

            var res = PeSymbolicEvaluator.CombineAnd(minSlot, maskSlot);
            Assert.Equal(PeSymbolicKind.None, res.Kind);
        }

        [Fact]
        public void CleanerKiller_ForwardersToPeSymbolicEvaluator_WorkEquivalently()
        {
            // Test that CleanerKiller's backward-compatibility forwarders delegate cleanly to PeSymbolicEvaluator
            var slotA = CleanerKiller.CreateNumericSlot(0x3C, IntegerWidth.Bit32);
            var slotB = PeSymbolicSlot.ModuleBase;
            var combined = CleanerKiller.CombineAdd(slotB, slotA);

            Assert.Equal(PeSymbolicKind.PeDerivedAddress, combined.Kind);
            Assert.Equal(0x3CL, combined.ConcreteValue);
            Assert.True(CleanerKiller.IsPeTarget(combined));
        }
    }
}
