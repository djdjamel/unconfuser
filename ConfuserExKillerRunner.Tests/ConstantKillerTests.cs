using System;
using ConfuserExTools.ConstantKiller;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public class ConstantKillerTests
    {
        [Fact]
        public void TryGetConstantInstruction_U4_Zero_ReturnsExactLdcI4()
        {
            bool ok = ConstantKillerImpl.TryGetConstantInstruction(ElementType.U4, 0u, out var op, out var operand);
            Assert.True(ok);
            Assert.Equal(OpCodes.Ldc_I4, op);
            Assert.Equal(0, operand);
        }

        [Fact]
        public void TryGetConstantInstruction_U4_IntMaxValue_ReturnsExactLdcI4()
        {
            uint val = (uint)int.MaxValue;
            bool ok = ConstantKillerImpl.TryGetConstantInstruction(ElementType.U4, val, out var op, out var operand);
            Assert.True(ok);
            Assert.Equal(OpCodes.Ldc_I4, op);
            Assert.Equal(int.MaxValue, operand);
        }

        [Fact]
        public void TryGetConstantInstruction_U4_UIntMaxValue_PreservesBitsWithoutOverflow()
        {
            uint val = uint.MaxValue; // 0xFFFFFFFF
            bool ok = ConstantKillerImpl.TryGetConstantInstruction(ElementType.U4, val, out var op, out var operand);
            Assert.True(ok);
            Assert.Equal(OpCodes.Ldc_I4, op);
            Assert.Equal(-1, operand); // unchecked((int)uint.MaxValue) == -1
            Assert.Equal(val, unchecked((uint)(int)operand));
        }

        [Fact]
        public void TryGetConstantInstruction_U4_SignBitSet_PreservesExactBits()
        {
            uint val = 0x80000000u; // Sign bit set in 32-bit uint
            bool ok = ConstantKillerImpl.TryGetConstantInstruction(ElementType.U4, val, out var op, out var operand);
            Assert.True(ok);
            Assert.Equal(OpCodes.Ldc_I4, op);
            Assert.Equal(int.MinValue, operand); // 0x80000000 as signed int is int.MinValue
            Assert.Equal(val, unchecked((uint)(int)operand));
        }

        [Fact]
        public void TryGetConstantInstruction_U8_Zero_ReturnsExactLdcI8()
        {
            bool ok = ConstantKillerImpl.TryGetConstantInstruction(ElementType.U8, 0ul, out var op, out var operand);
            Assert.True(ok);
            Assert.Equal(OpCodes.Ldc_I8, op);
            Assert.Equal(0L, operand);
        }

        [Fact]
        public void TryGetConstantInstruction_U8_LongMaxValue_ReturnsExactLdcI8()
        {
            ulong val = (ulong)long.MaxValue;
            bool ok = ConstantKillerImpl.TryGetConstantInstruction(ElementType.U8, val, out var op, out var operand);
            Assert.True(ok);
            Assert.Equal(OpCodes.Ldc_I8, op);
            Assert.Equal(long.MaxValue, operand);
        }

        [Fact]
        public void TryGetConstantInstruction_U8_ULongMaxValue_PreservesBitsWithoutOverflow()
        {
            ulong val = ulong.MaxValue; // 0xFFFFFFFFFFFFFFFF
            bool ok = ConstantKillerImpl.TryGetConstantInstruction(ElementType.U8, val, out var op, out var operand);
            Assert.True(ok);
            Assert.Equal(OpCodes.Ldc_I8, op);
            Assert.Equal(-1L, operand); // unchecked((long)ulong.MaxValue) == -1L
            Assert.Equal(val, unchecked((ulong)(long)operand));
        }

        [Fact]
        public void TryGetConstantInstruction_U8_SignBitSet_PreservesExactBits()
        {
            ulong val = 0x8000000000000000ul; // Sign bit set in 64-bit ulong
            bool ok = ConstantKillerImpl.TryGetConstantInstruction(ElementType.U8, val, out var op, out var operand);
            Assert.True(ok);
            Assert.Equal(OpCodes.Ldc_I8, op);
            Assert.Equal(long.MinValue, operand);
            Assert.Equal(val, unchecked((ulong)(long)operand));
        }

        [Fact]
        public void TryGetConstantInstruction_UnsupportedObject_ReturnsFalseWithoutThrowing()
        {
            object unsupported = new System.Text.StringBuilder("not a primitive");
            bool ok = ConstantKillerImpl.TryGetConstantInstruction(ElementType.I4, unsupported, out var op, out var operand);
            Assert.False(ok);
            Assert.Null(operand);
        }

        [Fact]
        public void ConstantKiller_NullModule_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ConstantKillerImpl.Execute(null, null));
        }
    }
}
