using System;
using System.Collections.Generic;
using ConfuserExKillerRunner;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public class SwitchKillerTests
    {
        [Fact]
        public void RemoveNopPatterns_BranchTargetOnPop_NotNopped()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var method = new MethodDefUser("TestMethod", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            type.Methods.Add(method);

            var ldc = Instruction.CreateLdcI4(42);
            var pop = Instruction.Create(OpCodes.Pop);
            var br = Instruction.Create(OpCodes.Br, pop);
            var ret = Instruction.Create(OpCodes.Ret);

            method.Body.Instructions.Add(br);
            method.Body.Instructions.Add(ldc);
            method.Body.Instructions.Add(pop);
            method.Body.Instructions.Add(ret);

            SwitchKillerImpl.RemoveNopPatterns(new List<MethodDef> { method });

            // Pop was a branch target, so it MUST NOT be nopped
            Assert.True(ldc.IsLdcI4());
            Assert.Equal(OpCodes.Pop, pop.OpCode);
        }

        [Fact]
        public void RemoveNopPatterns_BranchTargetOnLdc_NotNopped()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var method = new MethodDefUser("TestMethod", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            type.Methods.Add(method);

            var ldc = Instruction.CreateLdcI4(42);
            var pop = Instruction.Create(OpCodes.Pop);
            var br = Instruction.Create(OpCodes.Br, ldc);
            var ret = Instruction.Create(OpCodes.Ret);

            method.Body.Instructions.Add(br);
            method.Body.Instructions.Add(ldc);
            method.Body.Instructions.Add(pop);
            method.Body.Instructions.Add(ret);

            SwitchKillerImpl.RemoveNopPatterns(new List<MethodDef> { method });

            // Ldc was a branch target, so it MUST NOT be nopped
            Assert.True(ldc.IsLdcI4());
            Assert.Equal(OpCodes.Pop, pop.OpCode);
        }

        [Fact]
        public void SwitchKiller_LargeMethodWithManyBlocks_DoesNotOverflowStack()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var method = new MethodDefUser("LargeMethod", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            type.Methods.Add(method);

            var ret = Instruction.Create(OpCodes.Ret);
            var instrs = method.Body.Instructions;

            // Generate a long chain of 2000 branch instructions to stress stack-depth
            var chain = new List<Instruction>();
            for (int i = 0; i < 2000; i++)
            {
                chain.Add(Instruction.Create(OpCodes.Nop));
            }
            for (int i = 0; i < 1999; i++)
            {
                instrs.Add(chain[i]);
                instrs.Add(Instruction.Create(OpCodes.Br, chain[i + 1]));
            }
            instrs.Add(chain[1999]);
            instrs.Add(ret);

            // Must not throw StackOverflowException
            int resolved = SwitchKillerImpl.Execute(module);
            Assert.True(resolved >= 0);
        }

        [Fact]
        public void ResolveSimpleSwitch_SimplePattern_ResolvesTarget()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var method = new MethodDefUser("SwitchMethod", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            type.Methods.Add(method);

            var target0 = Instruction.Create(OpCodes.Nop);
            var target1 = Instruction.Create(OpCodes.Nop);
            var ret = Instruction.Create(OpCodes.Ret);

            // Pattern: ldc 10, ldc 2, xor, switch [target0, target1]
            var ldcConst = Instruction.CreateLdcI4(10);
            var ldcMod = Instruction.CreateLdcI4(2);
            var xor = Instruction.Create(OpCodes.Xor);
            var sw = Instruction.Create(OpCodes.Switch, new Instruction[] { target0, target1 });

            // Call site: ldc 11; br -> ldcConst
            // 11 ^ 10 = 1, 1 % 2 = 1 => targets[1] == target1
            var callerLdc = Instruction.CreateLdcI4(11);
            var callerBr = Instruction.Create(OpCodes.Br, ldcConst);

            method.Body.Instructions.Add(callerLdc);
            method.Body.Instructions.Add(callerBr);
            method.Body.Instructions.Add(ldcConst);
            method.Body.Instructions.Add(ldcMod);
            method.Body.Instructions.Add(xor);
            method.Body.Instructions.Add(sw);
            method.Body.Instructions.Add(target0);
            method.Body.Instructions.Add(target1);
            method.Body.Instructions.Add(ret);

            SwitchKillerImpl.ResolveSimpleSwitch(new List<MethodDef> { method });

            // callerBr should now target target1 directly
            Assert.Equal(target1, callerBr.Operand);
        }

        [Fact]
        public void RemoveNopPatterns_WhenPopIsTargetedBySwitch_IsRetained()
        {
            var module = new ModuleDefUser("TestMod");
            var method = new MethodDefUser("TestMethod", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };

            var ldc = Instruction.CreateLdcI4(42);
            var pop = Instruction.Create(OpCodes.Pop);
            var otherTarget = Instruction.Create(OpCodes.Nop);
            var ret = Instruction.Create(OpCodes.Ret);
            var sw = Instruction.Create(OpCodes.Switch, new Instruction[] { otherTarget, pop });

            method.Body.Instructions.Add(sw);
            method.Body.Instructions.Add(otherTarget);
            method.Body.Instructions.Add(ldc);
            method.Body.Instructions.Add(pop);
            method.Body.Instructions.Add(ret);

            SwitchKillerImpl.RemoveNopPatterns(new List<MethodDef> { method });

            // Because pop is a switch target, it must NOT be converted to nop
            Assert.Equal(OpCodes.Pop, pop.OpCode);
            Assert.True(ldc.IsLdcI4());
        }

        [Fact]
        public void RemoveNopPatterns_WhenPopIsExceptionHandlerBoundary_IsRetained()
        {
            var module = new ModuleDefUser("TestMod");
            var method = new MethodDefUser("TestMethod", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };

            var ldc = Instruction.CreateLdcI4(100);
            var pop = Instruction.Create(OpCodes.Pop);
            var ret = Instruction.Create(OpCodes.Ret);

            method.Body.Instructions.Add(ldc);
            method.Body.Instructions.Add(pop);
            method.Body.Instructions.Add(ret);

            // Set pop as an ExceptionHandler HandlerStart
            var eh = new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = ldc,
                TryEnd = pop,
                HandlerStart = pop,
                HandlerEnd = ret
            };
            method.Body.ExceptionHandlers.Add(eh);

            SwitchKillerImpl.RemoveNopPatterns(new List<MethodDef> { method });

            // Because pop is an exception handler boundary, it must NOT be converted to nop
            Assert.Equal(OpCodes.Pop, pop.OpCode);
            Assert.True(ldc.IsLdcI4());
        }
    }
}
