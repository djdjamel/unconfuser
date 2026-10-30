using System.Linq;
using ConfuserExTools.ConstantKiller;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    [Trait("Category", "Unit")]
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

        [Fact]
        public void ConstantKiller_Execute_RewritesConstantArrayCallEndToEnd()
        {
            var module = new ModuleDefUser("TestArrayMod");
            var asm = new AssemblyDefUser("TestArrayAsm");
            asm.Modules.Add(module);

            // 1. Define ConfuserEx constant decrypter in GlobalType: static T Decrypter<T>(uint key)
            var decrypterDef = new MethodDefUser(
                "Decrypter",
                MethodSig.CreateStaticGeneric(1, new GenericMVar(0), module.CorLibTypes.UInt32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            decrypterDef.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));

            // IL implementation of Decrypter: returns new byte[] { 10, 20, 30, 40 }
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_4));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Newarr, module.CorLibTypes.Byte.TypeDefOrRef));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Dup));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 10));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Stelem_I1));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Dup));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 20));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Stelem_I1));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Dup));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_2));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 30));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Stelem_I1));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Dup));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_3));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 40));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Stelem_I1));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            module.GlobalType.Methods.Add(decrypterDef);

            // 2. Define calling method in a user type: calls Decrypter<byte[]>(12345)
            var userType = new TypeDefUser("CallerType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(userType);

            var runMethod = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            userType.Methods.Add(runMethod);

            var genMethodSig = new GenericInstMethodSig(new SZArraySig(module.CorLibTypes.Byte));
            var methodSpec = new MethodSpecUser(decrypterDef, genMethodSig);

            runMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 12345)); // key expression
            runMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, methodSpec));
            runMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            runMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            // 3. Emit assembly to memory and load into reflection context
            using (var ms = new System.IO.MemoryStream())
            {
                module.Write(ms);
                byte[] rawAsm = ms.ToArray();

                var reflAsm = System.Reflection.Assembly.Load(rawAsm);
                using (var modMD = ModuleDefMD.Load(rawAsm))
                {
                    // 4. Execute actual ConstantKillerImpl.Execute integration path
                    int count = ConstantKillerImpl.Execute(modMD, reflAsm.ManifestModule);

                    Assert.Equal(1, count);

                    // Verify in CallerType.Run that the call to Decrypter has been replaced by array initializer
                    var targetMethod = modMD.Find("CallerType", false).FindMethod("Run");
                    Assert.NotNull(targetMethod);

                    var instrs = targetMethod.Body.Instructions;
                    // Preceding key expression is nopped
                    Assert.Equal(OpCodes.Nop, instrs[0].OpCode);

                    // Array initializer instructions inserted
                    Assert.Equal(OpCodes.Ldc_I4, instrs[1].OpCode);
                    Assert.Equal(4, (int)instrs[1].Operand);
                    Assert.Equal(OpCodes.Newarr, instrs[2].OpCode);
                    Assert.Equal(OpCodes.Dup, instrs[3].OpCode);
                    Assert.Equal(OpCodes.Ldtoken, instrs[4].OpCode);
                    Assert.Equal(OpCodes.Call, instrs[5].OpCode);

                    // Verify static field RVA data was created with expected contents [10, 20, 30, 40]
                    var rvaField = instrs[4].Operand as FieldDef;
                    Assert.NotNull(rvaField);
                    Assert.Equal(new byte[] { 10, 20, 30, 40 }, rvaField.InitialValue);
                }
            }
        }
    }
}
