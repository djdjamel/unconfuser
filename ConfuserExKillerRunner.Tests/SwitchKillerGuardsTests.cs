using System.Collections.Generic;
using ConfuserExKillerRunner;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public class SwitchKillerGuardsTests
    {
        [Fact]
        public void ResolveSimpleSwitch_ZeroXorDivisor_ReachesGuardAndLeavesMethodUnchanged()
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
            var ldc1 = Instruction.Create(OpCodes.Ldc_I4, 10);
            var ldc2 = Instruction.Create(OpCodes.Ldc_I4, 0); // Divisor = 0
            var xor = Instruction.Create(OpCodes.Xor);
            var switchInst = Instruction.Create(OpCodes.Switch, new Instruction[] { targetRet });

            var brVal = Instruction.Create(OpCodes.Ldc_I4, 42);
            var brInst = Instruction.Create(OpCodes.Br, ldc1);

            // Structure required for ResolveSimpleSwitch:
            // [0] brVal: ldc.i4 42
            // [1] brInst: br -> target (ldc1)
            // [2] ldc1 (target = instrs[si - 3]): ldc.i4 10
            // [3] ldc2: ldc.i4 0
            // [4] xor
            // [5] switchInst (si = 5, si-3 = 2 == target)
            // [6] targetRet: ret
            method.Body.Instructions.Add(brVal);
            method.Body.Instructions.Add(brInst);
            method.Body.Instructions.Add(ldc1);
            method.Body.Instructions.Add(ldc2);
            method.Body.Instructions.Add(xor);
            method.Body.Instructions.Add(switchInst);
            method.Body.Instructions.Add(targetRet);

            var origInstrsCount = method.Body.Instructions.Count;

            // Execute ResolveSimpleSwitch directly to verify zero-divisor guard
            SwitchKillerImpl.ResolveSimpleSwitch(new List<MethodDef> { method });

            // Method must remain unchanged except for branch optimization, candidate is rejected
            Assert.Equal(origInstrsCount, method.Body.Instructions.Count);
            Assert.Equal(OpCodes.Ldc_I4, method.Body.Instructions[0].OpCode);
            Assert.Equal(42, method.Body.Instructions[0].GetLdcI4Value());
            Assert.True(method.Body.Instructions[1].IsBr());
            Assert.Same(ldc1, method.Body.Instructions[1].Operand);
            Assert.Same(targetRet, method.Body.Instructions[6]);
        }

        [Fact]
        public void ResolveSimpleSwitch_OutOfBoundsTargetIndex_ReachesGuardAndLeavesMethodUnchanged()
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
            var ldc1 = Instruction.Create(OpCodes.Ldc_I4, 10);
            var ldc2 = Instruction.Create(OpCodes.Ldc_I4, 5); // Divisor = 5
            var xor = Instruction.Create(OpCodes.Xor);
            // Switch targets array has only 1 element (index 0)
            var switchInst = Instruction.Create(OpCodes.Switch, new Instruction[] { targetRet });

            // (42 ^ 10) % 5 = 32 % 5 = 2. Index 2 >= targets.Length (1), so it triggers the out-of-bounds guard!
            var brVal = Instruction.Create(OpCodes.Ldc_I4, 42);
            var brInst = Instruction.Create(OpCodes.Br, ldc1);

            method.Body.Instructions.Add(brVal);
            method.Body.Instructions.Add(brInst);
            method.Body.Instructions.Add(ldc1);
            method.Body.Instructions.Add(ldc2);
            method.Body.Instructions.Add(xor);
            method.Body.Instructions.Add(switchInst);
            method.Body.Instructions.Add(targetRet);

            var origInstrsCount = method.Body.Instructions.Count;

            // Execute ResolveSimpleSwitch directly to verify out-of-bounds index guard
            SwitchKillerImpl.ResolveSimpleSwitch(new List<MethodDef> { method });

            // Method must remain unchanged except for branch optimization, candidate is rejected
            Assert.Equal(origInstrsCount, method.Body.Instructions.Count);
            Assert.Equal(OpCodes.Ldc_I4, method.Body.Instructions[0].OpCode);
            Assert.Equal(42, method.Body.Instructions[0].GetLdcI4Value());
            Assert.True(method.Body.Instructions[1].IsBr());
            Assert.Same(ldc1, method.Body.Instructions[1].Operand);
            Assert.Same(targetRet, method.Body.Instructions[6]);
        }

        [Fact]
        public void RunCflow_FailsAfterMutation_RestoresCompleteOriginalMethodBody()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var method = new MethodDefUser("TargetMethod", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            type.Methods.Add(method);

            var local = new Local(module.CorLibTypes.Int32);
            method.Body.Variables.Add(local);

            var ret = Instruction.Create(OpCodes.Ret);
            var startTry = Instruction.Create(OpCodes.Ldc_I4_1);
            var endTry = Instruction.Create(OpCodes.Stloc, local);
            var leaveTry = Instruction.Create(OpCodes.Leave_S, ret);
            var startCatch = Instruction.Create(OpCodes.Pop);
            var leaveCatch = Instruction.Create(OpCodes.Leave_S, ret);

            method.Body.Instructions.Add(startTry);
            method.Body.Instructions.Add(endTry);
            method.Body.Instructions.Add(leaveTry);
            method.Body.Instructions.Add(startCatch);
            method.Body.Instructions.Add(leaveCatch);
            method.Body.Instructions.Add(ret);

            var handler = new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = startTry,
                TryEnd = startCatch,
                HandlerStart = startCatch,
                HandlerEnd = ret,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            };
            method.Body.ExceptionHandlers.Add(handler);

            var origInstCount = method.Body.Instructions.Count;
            var origVarCount = method.Body.Variables.Count;
            var origHandlerCount = method.Body.ExceptionHandlers.Count;

            var deobfuscator = new de4dot.blocks.cflow.BlocksCflowDeobfuscator();
            deobfuscator.Add(new MutatingAndFailingDeobfuscator());

            // RunCflow will encounter MutatingAndFailingDeobfuscator, mutate the blocks, throw, and catch
            SwitchKillerImpl.RunCflow(new List<MethodDef> { method }, deobfuscator);

            // Assert complete method body is restored
            Assert.NotNull(method.Body);
            Assert.Equal(origInstCount, method.Body.Instructions.Count);
            Assert.Equal(origVarCount, method.Body.Variables.Count);
            Assert.Equal(origHandlerCount, method.Body.ExceptionHandlers.Count);
            Assert.Equal(OpCodes.Ldc_I4_1, method.Body.Instructions[0].OpCode);
            Assert.Equal(OpCodes.Stloc, method.Body.Instructions[1].OpCode);
            Assert.Equal(OpCodes.Ret, method.Body.Instructions[5].OpCode);
            Assert.Same(method.Body.Instructions[0], method.Body.ExceptionHandlers[0].TryStart);
        }
    }

    public class MutatingAndFailingDeobfuscator : de4dot.blocks.cflow.IBlocksDeobfuscator
    {
        public bool ExecuteIfNotModified => true;

        public void DeobfuscateBegin(de4dot.blocks.Blocks blocks)
        {
        }

        public bool Deobfuscate(List<de4dot.blocks.Block> blocks)
        {
            if (blocks != null && blocks.Count > 0 && blocks[0].Instructions.Count > 0)
            {
                // Mutate the instructions in the block before throwing
                blocks[0].Instructions.Clear();
            }
            throw new InvalidOperationException("Forced failure after block mutation");
        }
    }
}
