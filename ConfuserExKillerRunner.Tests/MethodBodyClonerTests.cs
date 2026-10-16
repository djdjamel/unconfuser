using System.Collections.Generic;
using ConfuserExKillerRunner.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public class MethodBodyClonerTests
    {
        [Fact]
        public void Clone_NullSource_ReturnsNull()
        {
            var clone = MethodBodyCloner.Clone(null);
            Assert.Null(clone);
        }

        [Fact]
        public void Clone_Instructions_CreatesIndependentInstances()
        {
            var original = new CilBody();
            original.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 42));
            original.Instructions.Add(Instruction.Create(OpCodes.Ret));

            var clone = MethodBodyCloner.Clone(original);

            Assert.NotNull(clone);
            Assert.Equal(2, clone.Instructions.Count);
            Assert.NotSame(original.Instructions[0], clone.Instructions[0]);
            Assert.Equal(OpCodes.Ldc_I4, clone.Instructions[0].OpCode);
            Assert.Equal(42, (int)clone.Instructions[0].Operand);

            // Mutating clone does not mutate original
            clone.Instructions[0].Operand = 100;
            Assert.Equal(42, (int)original.Instructions[0].Operand);
        }

        [Fact]
        public void Clone_BranchTargets_AreRelinkedToClonedInstructions()
        {
            var original = new CilBody();
            var target = Instruction.Create(OpCodes.Ret);
            var branch = Instruction.Create(OpCodes.Br, target);
            original.Instructions.Add(branch);
            original.Instructions.Add(Instruction.Create(OpCodes.Nop));
            original.Instructions.Add(target);

            var clone = MethodBodyCloner.Clone(original);

            Assert.Equal(3, clone.Instructions.Count);
            var clonedBranch = clone.Instructions[0];
            var clonedTarget = clone.Instructions[2];

            Assert.NotSame(original.Instructions[0], clonedBranch);
            Assert.NotSame(target, clonedTarget);
            Assert.Same(clonedTarget, clonedBranch.Operand);
            Assert.NotSame(target, clonedBranch.Operand);
        }

        [Fact]
        public void Clone_SwitchTargets_AreRelinkedToClonedInstructions()
        {
            var original = new CilBody();
            var targetA = Instruction.Create(OpCodes.Ldc_I4_1);
            var targetB = Instruction.Create(OpCodes.Ldc_I4_2);
            var ret = Instruction.Create(OpCodes.Ret);

            var switchList = new List<Instruction> { targetA, targetB };
            var switchInst = Instruction.Create(OpCodes.Switch, switchList);

            original.Instructions.Add(switchInst);
            original.Instructions.Add(targetA);
            original.Instructions.Add(ret);
            original.Instructions.Add(targetB);
            original.Instructions.Add(ret);

            var clone = MethodBodyCloner.Clone(original);

            var clonedSwitch = clone.Instructions[0];
            var clonedTargets = clonedSwitch.Operand as IList<Instruction>;
            Assert.NotNull(clonedTargets);
            Assert.Equal(2, clonedTargets.Count);

            // Ensure targets are the cloned instances, not original
            Assert.Same(clone.Instructions[1], clonedTargets[0]);
            Assert.Same(clone.Instructions[3], clonedTargets[1]);
            Assert.NotSame(targetA, clonedTargets[0]);
            Assert.NotSame(targetB, clonedTargets[1]);
        }

        [Fact]
        public void Clone_ExceptionHandlers_AreRelinked()
        {
            var original = new CilBody();
            var tryStart = Instruction.Create(OpCodes.Nop);
            var tryEnd = Instruction.Create(OpCodes.Nop);
            var handlerStart = Instruction.Create(OpCodes.Pop);
            var handlerEnd = Instruction.Create(OpCodes.Ret);

            original.Instructions.Add(tryStart);
            original.Instructions.Add(tryEnd);
            original.Instructions.Add(handlerStart);
            original.Instructions.Add(handlerEnd);

            var eh = new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = tryStart,
                TryEnd = tryEnd,
                HandlerStart = handlerStart,
                HandlerEnd = handlerEnd
            };
            original.ExceptionHandlers.Add(eh);

            var clone = MethodBodyCloner.Clone(original);

            Assert.Single(clone.ExceptionHandlers);
            var clonedEh = clone.ExceptionHandlers[0];

            Assert.Same(clone.Instructions[0], clonedEh.TryStart);
            Assert.Same(clone.Instructions[1], clonedEh.TryEnd);
            Assert.Same(clone.Instructions[2], clonedEh.HandlerStart);
            Assert.Same(clone.Instructions[3], clonedEh.HandlerEnd);

            Assert.NotSame(tryStart, clonedEh.TryStart);
            Assert.NotSame(handlerStart, clonedEh.HandlerStart);
        }

        [Fact]
        public void Clone_Locals_AreDuplicatedAndMapped()
        {
            var module = new ModuleDefUser("TestModule");
            var original = new CilBody();
            var local = new Local(module.CorLibTypes.Int32, "testVar", 0);
            original.Variables.Add(local);

            var ldloc = Instruction.Create(OpCodes.Ldloc, local);
            original.Instructions.Add(ldloc);

            var clone = MethodBodyCloner.Clone(original);

            Assert.Single(clone.Variables);
            var clonedLocal = clone.Variables[0];
            Assert.NotSame(local, clonedLocal);
            Assert.Equal("testVar", clonedLocal.Name);

            var clonedLdloc = clone.Instructions[0];
            Assert.Same(clonedLocal, clonedLdloc.Operand);
            Assert.NotSame(local, clonedLdloc.Operand);
        }
    }
}
