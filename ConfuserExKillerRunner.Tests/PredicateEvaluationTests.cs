using ConfuserExKillerRunner.Killers;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    [Trait("Category", "Unit")]
    public class PredicateEvaluationTests
    {
        [Theory]
        [InlineData(10, 5, 15)]
        public void TryEvaluateBinary_Add(int a, int b, int expected)
        {
            bool ok = PredicateKiller.TryEvaluateBinary(OpCodes.Add, a, b, out int res);
            Assert.True(ok);
            Assert.Equal(expected, res);
        }

        [Fact]
        public void TryEvaluateBinary_DivByZero_ReturnsFalse()
        {
            bool ok = PredicateKiller.TryEvaluateBinary(OpCodes.Div, 10, 0, out _);
            Assert.False(ok);
        }

        [Fact]
        public void TryEvaluateBinary_DivUn_PerformsUnsignedDivision()
        {
            // -1 as uint is 0xFFFFFFFF (4294967295)
            // 4294967295 / 2 = 2147483647 (0x7FFFFFFF)
            bool ok = PredicateKiller.TryEvaluateBinary(OpCodes.Div_Un, -1, 2, out int res);
            Assert.True(ok);
            Assert.Equal(int.MaxValue, res);
        }

        [Fact]
        public void TryEvaluateBinary_ShrUn_PerformsLogicalShift()
        {
            // -16 >> 2 unsigned = 1073741820
            bool ok = PredicateKiller.TryEvaluateBinary(OpCodes.Shr_Un, -16, 2, out int res);
            Assert.True(ok);
            Assert.Equal(1073741820, res);
        }

        [Fact]
        public void EvaluateTwoOperandCondition_SignedVsUnsigned()
        {
            // With signed comparison: -1 < 10
            Assert.True(PredicateKiller.EvaluateTwoOperandCondition(OpCodes.Blt, -1, 10));
            Assert.False(PredicateKiller.EvaluateTwoOperandCondition(OpCodes.Bgt, -1, 10));

            // With unsigned comparison: -1 (0xFFFFFFFF) > 10
            Assert.True(PredicateKiller.EvaluateTwoOperandCondition(OpCodes.Bgt_Un, -1, 10));
            Assert.False(PredicateKiller.EvaluateTwoOperandCondition(OpCodes.Blt_Un, -1, 10));
        }

        [Fact]
        public void EvaluateTwoOperandCondition_Equality()
        {
            Assert.True(PredicateKiller.EvaluateTwoOperandCondition(OpCodes.Beq, 42, 42));
            Assert.False(PredicateKiller.EvaluateTwoOperandCondition(OpCodes.Beq, 42, 43));
            Assert.True(PredicateKiller.EvaluateTwoOperandCondition(OpCodes.Bne_Un, 42, 43));
            Assert.False(PredicateKiller.EvaluateTwoOperandCondition(OpCodes.Bne_Un, 42, 42));
        }
    }
}
