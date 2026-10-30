using System.Collections.Generic;
using ConfuserExTools.ConstantKiller;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    [Trait("Category", "Unit")]
    public class KeyEvaluationTests
    {
        [Fact]
        public void TryEvaluateKey_ConstantLiteral_EvaluatesCorrectly()
        {
            var instructions = new List<Instruction>
            {
                Instruction.Create(OpCodes.Ldc_I4, 1337),
                new Instruction(OpCodes.Call, null) // call site at index 1
            };

            bool success = ConstantKillerImpl.TryEvaluateKey(instructions, 1, out int key, out int startIdx);

            Assert.True(success);
            Assert.Equal(1337, key);
            Assert.Equal(0, startIdx);
        }

        [Fact]
        public void TryEvaluateKey_BasicArithmetic_EvaluatesCorrectly()
        {
            // (100 + 50) * 2 - 10 = 290
            var instructions = new List<Instruction>
            {
                Instruction.Create(OpCodes.Ldc_I4, 100),
                Instruction.Create(OpCodes.Ldc_I4, 50),
                Instruction.Create(OpCodes.Add),
                Instruction.Create(OpCodes.Ldc_I4, 2),
                Instruction.Create(OpCodes.Mul),
                Instruction.Create(OpCodes.Ldc_I4, 10),
                Instruction.Create(OpCodes.Sub),
                new Instruction(OpCodes.Call, null)
            };

            bool success = ConstantKillerImpl.TryEvaluateKey(instructions, instructions.Count - 1, out int key, out int startIdx);

            Assert.True(success);
            Assert.Equal(290, key);
            Assert.Equal(0, startIdx);
        }

        [Fact]
        public void TryEvaluateKey_BitwiseOperations_EvaluatesCorrectly()
        {
            // (0x0F0F ^ 0x00FF) & 0x0FFF | 0x8000
            // 0x0F0F ^ 0x00FF = 0x0FF0
            // 0x0FF0 & 0x0FFF = 0x0FF0
            // 0x0FF0 | 0x8000 = 0x8FF0 (36848)
            var instructions = new List<Instruction>
            {
                Instruction.Create(OpCodes.Ldc_I4, 0x0F0F),
                Instruction.Create(OpCodes.Ldc_I4, 0x00FF),
                Instruction.Create(OpCodes.Xor),
                Instruction.Create(OpCodes.Ldc_I4, 0x0FFF),
                Instruction.Create(OpCodes.And),
                Instruction.Create(OpCodes.Ldc_I4, 0x8000),
                Instruction.Create(OpCodes.Or),
                new Instruction(OpCodes.Call, null)
            };

            bool success = ConstantKillerImpl.TryEvaluateKey(instructions, instructions.Count - 1, out int key, out _);

            Assert.True(success);
            Assert.Equal(0x8FF0, key);
        }

        [Fact]
        public void TryEvaluateKey_UnsignedShift_ShrUn_PerformsLogicalShift()
        {
            // Negative number -16 (0xFFFFFFF0)
            // Signed shift right (shr): -16 >> 2 = -4
            // Logical unsigned shift right (shr.un): (uint)-16 >> 2 = 0x3FFFFFFC = 1073741820
            var instructions = new List<Instruction>
            {
                Instruction.Create(OpCodes.Ldc_I4, -16),
                Instruction.Create(OpCodes.Ldc_I4, 2),
                Instruction.Create(OpCodes.Shr_Un),
                new Instruction(OpCodes.Call, null)
            };

            bool success = ConstantKillerImpl.TryEvaluateKey(instructions, instructions.Count - 1, out int key, out _);

            Assert.True(success);
            Assert.Equal(1073741820, key);
        }

        [Fact]
        public void TryEvaluateKey_SignedShift_Shr_PerformsArithmeticShift()
        {
            // -16 >> 2 = -4
            var instructions = new List<Instruction>
            {
                Instruction.Create(OpCodes.Ldc_I4, -16),
                Instruction.Create(OpCodes.Ldc_I4, 2),
                Instruction.Create(OpCodes.Shr),
                new Instruction(OpCodes.Call, null)
            };

            bool success = ConstantKillerImpl.TryEvaluateKey(instructions, instructions.Count - 1, out int key, out _);

            Assert.True(success);
            Assert.Equal(-4, key);
        }

        [Fact]
        public void TryEvaluateKey_NegAndNot_EvaluatesCorrectly()
        {
            // ~( -10 ) = 9
            var instructions = new List<Instruction>
            {
                Instruction.Create(OpCodes.Ldc_I4, 10),
                Instruction.Create(OpCodes.Neg),
                Instruction.Create(OpCodes.Not),
                new Instruction(OpCodes.Call, null)
            };

            bool success = ConstantKillerImpl.TryEvaluateKey(instructions, instructions.Count - 1, out int key, out _);

            Assert.True(success);
            Assert.Equal(9, key);
        }

        [Fact]
        public void TryEvaluateKey_InvalidStackUnderflow_ReturnsFalse()
        {
            // Add with only 1 operand
            var instructions = new List<Instruction>
            {
                Instruction.Create(OpCodes.Ldc_I4, 10),
                Instruction.Create(OpCodes.Add),
                new Instruction(OpCodes.Call, null)
            };

            bool success = ConstantKillerImpl.TryEvaluateKey(instructions, instructions.Count - 1, out _, out _);

            Assert.False(success);
        }
    }
}
