using ConfuserExKillerRunner;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public class SwitchKillerGuardsTests
    {
        [Fact]
        public void SwitchKiller_ZeroXorDivisor_DoesNotThrowAndRollsBackGracefully()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var method = new MethodDefUser("SwitchMethod", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            type.Methods.Add(method);

            var targetRet = Instruction.Create(OpCodes.Ret);
            var switchInst = Instruction.Create(OpCodes.Switch, new List<Instruction> { targetRet });

            // Pattern: ldc.i4, ldc.i4 (0), xor, switch (xor divisor = 0)
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 10));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0)); // Divisor = 0!
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Xor));
            method.Body.Instructions.Add(switchInst);
            method.Body.Instructions.Add(targetRet);

            // Execute switch killer - must not throw DivideByZeroException
            int count = SwitchKillerImpl.Execute(module);

            Assert.Equal(0, count);
            Assert.True(method.Body.Instructions.Count >= 1);
            Assert.Equal(OpCodes.Ret, method.Body.Instructions[method.Body.Instructions.Count - 1].OpCode);
        }

        [Fact]
        public void SwitchKiller_OutOfBoundsTargetIndex_DoesNotCrash()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var method = new MethodDefUser("SwitchMethod", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            type.Methods.Add(method);

            var targetRet = Instruction.Create(OpCodes.Ret);
            // Switch targets array is empty!
            var switchInst = Instruction.Create(OpCodes.Switch, new List<Instruction>());

            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 10));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 5));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Xor));
            method.Body.Instructions.Add(switchInst);
            method.Body.Instructions.Add(targetRet);

            int count = SwitchKillerImpl.Execute(module);

            Assert.Equal(0, count);
        }
    }
}
