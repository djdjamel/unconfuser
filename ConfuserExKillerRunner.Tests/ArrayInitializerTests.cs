using System.Linq;
using ConfuserExTools.ConstantKiller;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public class ArrayInitializerTests
    {
        [Fact]
        public void CreateArrayInitializer_EmitsCorrectILSequence()
        {
            var module = new ModuleDefUser("TestMod");
            byte[] rawBytes = new byte[] { 10, 20, 30, 40 };

            var instrs = ConstantKillerImpl.CreateArrayInitializer(module, module.CorLibTypes.Byte.TypeDefOrRef, rawBytes.Length, rawBytes);

            Assert.Equal(5, instrs.Count);
            Assert.Equal(OpCodes.Ldc_I4, instrs[0].OpCode);
            Assert.Equal(4, (int)instrs[0].Operand);

            Assert.Equal(OpCodes.Newarr, instrs[1].OpCode);
            Assert.Same(module.CorLibTypes.Byte.TypeDefOrRef, instrs[1].Operand);

            Assert.Equal(OpCodes.Dup, instrs[2].OpCode);

            Assert.Equal(OpCodes.Ldtoken, instrs[3].OpCode);
            var field = instrs[3].Operand as FieldDef;
            Assert.NotNull(field);
            Assert.NotNull(field.InitialValue);
            Assert.Equal(rawBytes, field.InitialValue);

            Assert.Equal(OpCodes.Call, instrs[4].OpCode);
        }

        [Fact]
        public void ArrayRewrite_NoppingPrecedingExpression_PreservesInsertedInstructions()
        {
            var module = new ModuleDefUser("TestMod");
            var instructions = new System.Collections.Generic.List<Instruction>
            {
                Instruction.Create(OpCodes.Ldc_I4, 100), // exprStart = 0
                Instruction.Create(OpCodes.Ldc_I4, 200), // arg 1
                Instruction.Create(OpCodes.Add),        // arg 2
                new Instruction(OpCodes.Call, null)     // call at index 3
            };

            int exprStart = 0;
            int callIndex = 3;

            byte[] arrayData = new byte[] { 1, 2, 3 };
            var arrayInitializer = ConstantKillerImpl.CreateArrayInitializer(module, module.CorLibTypes.Byte.TypeDefOrRef, arrayData.Length, arrayData);

            // Simulate the rewrite logic in ConstantKillerImpl:
            // 1. Nop out key expression arguments [exprStart, callIndex - 1]
            for (int k = exprStart; k < callIndex; k++)
            {
                instructions[k].OpCode = OpCodes.Nop;
                instructions[k].Operand = null;
            }

            // 2. Replace call with first initializer instruction
            instructions[callIndex].OpCode = arrayInitializer[0].OpCode;
            instructions[callIndex].Operand = arrayInitializer[0].Operand;

            // 3. Insert remaining instructions after callIndex
            if (arrayInitializer.Count > 1)
            {
                var remaining = arrayInitializer.Skip(1).ToList();
                instructions.InsertRange(callIndex + 1, remaining);
            }

            // Assert that instructions [0..2] are NOP
            Assert.Equal(OpCodes.Nop, instructions[0].OpCode);
            Assert.Equal(OpCodes.Nop, instructions[1].OpCode);
            Assert.Equal(OpCodes.Nop, instructions[2].OpCode);

            // Assert that none of the array initializer instructions were overwritten or nopped
            Assert.Equal(OpCodes.Ldc_I4, instructions[3].OpCode);
            Assert.Equal(3, (int)instructions[3].Operand);
            Assert.Equal(OpCodes.Newarr, instructions[4].OpCode);
            Assert.Equal(OpCodes.Dup, instructions[5].OpCode);
            Assert.Equal(OpCodes.Ldtoken, instructions[6].OpCode);
            Assert.Equal(OpCodes.Call, instructions[7].OpCode);
        }
    }
}
