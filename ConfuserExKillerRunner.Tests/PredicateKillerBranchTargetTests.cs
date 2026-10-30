using System.Collections.Generic;
using ConfuserExKillerRunner.Killers;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    [Trait("Category", "Unit")]
    public class PredicateKillerBranchTargetTests
    {
        [Fact]
        public void FoldConstants_LeftOperandIsBranchTarget_NotFolded()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var method = new MethodDefUser("TestMethod", MethodSig.CreateStatic(module.CorLibTypes.Int32))
            {
                Body = new CilBody()
            };
            type.Methods.Add(method);

            var left = Instruction.CreateLdcI4(10);
            var br = Instruction.Create(OpCodes.Br, left);
            var right = Instruction.CreateLdcI4(20);
            var add = Instruction.Create(OpCodes.Add);
            var ret = Instruction.Create(OpCodes.Ret);

            method.Body.Instructions.Add(br);
            method.Body.Instructions.Add(left);
            method.Body.Instructions.Add(right);
            method.Body.Instructions.Add(add);
            method.Body.Instructions.Add(ret);

            var result = PredicateKiller.Execute(module);

            // Left operand was a branch target, so the add MUST NOT be folded
            Assert.Equal(0, result.ConstantsFolded);
            Assert.True(left.IsLdcI4());
            Assert.Equal(10, left.GetLdcI4Value());
            Assert.True(right.IsLdcI4());
            Assert.Equal(OpCodes.Add, add.OpCode);
        }

        [Fact]
        public void FoldConstants_UnaryNegOperandIsBranchTarget_NotFolded()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var method = new MethodDefUser("TestMethod", MethodSig.CreateStatic(module.CorLibTypes.Int32))
            {
                Body = new CilBody()
            };
            type.Methods.Add(method);

            var ldc = Instruction.CreateLdcI4(42);
            var br = Instruction.Create(OpCodes.Br, ldc);
            var neg = Instruction.Create(OpCodes.Neg);
            var ret = Instruction.Create(OpCodes.Ret);

            method.Body.Instructions.Add(br);
            method.Body.Instructions.Add(ldc);
            method.Body.Instructions.Add(neg);
            method.Body.Instructions.Add(ret);

            var result = PredicateKiller.Execute(module);

            // The constant before neg was a branch target, so it MUST NOT be folded into -42
            Assert.Equal(0, result.ConstantsFolded);
            Assert.True(ldc.IsLdcI4());
            Assert.Equal(42, ldc.GetLdcI4Value());
            Assert.Equal(OpCodes.Neg, neg.OpCode);
        }

        [Fact]
        public void FoldAlgebraicIdentities_DupBeforeXorIsBranchTarget_NotSimplified()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var method = new MethodDefUser("TestMethod", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32))
            {
                Body = new CilBody()
            };
            type.Methods.Add(method);

            var ldarg = Instruction.Create(OpCodes.Ldarg_0);
            var dup = Instruction.Create(OpCodes.Dup);
            var br = Instruction.Create(OpCodes.Br, dup);
            var xor = Instruction.Create(OpCodes.Xor);
            var ret = Instruction.Create(OpCodes.Ret);

            method.Body.Instructions.Add(ldarg);
            method.Body.Instructions.Add(br);
            method.Body.Instructions.Add(dup);
            method.Body.Instructions.Add(xor);
            method.Body.Instructions.Add(ret);

            var result = PredicateKiller.Execute(module);

            // dup was a branch target, so dup; xor MUST NOT be rewritten to pop; ldc.i4.0
            Assert.Equal(0, result.IdentitiesSimplified);
            Assert.Equal(OpCodes.Dup, dup.OpCode);
            Assert.Equal(OpCodes.Xor, xor.OpCode);
        }

        [Fact]
        public void EvaluateConstantBranches_TwoOperandLeftIsBranchTarget_NotResolved()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var method = new MethodDefUser("TestMethod", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            type.Methods.Add(method);

            var ret = Instruction.Create(OpCodes.Ret);
            var left = Instruction.CreateLdcI4(42);
            var br = Instruction.Create(OpCodes.Br, left);
            var right = Instruction.CreateLdcI4(42);
            var beq = Instruction.Create(OpCodes.Beq, ret);

            method.Body.Instructions.Add(br);
            method.Body.Instructions.Add(left);
            method.Body.Instructions.Add(right);
            method.Body.Instructions.Add(beq);
            method.Body.Instructions.Add(ret);

            var result = PredicateKiller.Execute(module);

            // Left operand was a branch target, so beq MUST NOT be resolved to br
            Assert.Equal(0, result.BranchesResolved);
            Assert.True(left.IsLdcI4());
            Assert.Equal(42, left.GetLdcI4Value());
            Assert.Equal(OpCodes.Beq, beq.OpCode);
        }

        [Fact]
        public void EvaluateConstantBranches_SingleOperandIsBranchTarget_NotResolved()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var method = new MethodDefUser("TestMethod", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            type.Methods.Add(method);

            var ret = Instruction.Create(OpCodes.Ret);
            var ldc = Instruction.CreateLdcI4(1);
            var br = Instruction.Create(OpCodes.Br, ldc);
            var brtrue = Instruction.Create(OpCodes.Brtrue, ret);

            method.Body.Instructions.Add(br);
            method.Body.Instructions.Add(ldc);
            method.Body.Instructions.Add(brtrue);
            method.Body.Instructions.Add(ret);

            var result = PredicateKiller.Execute(module);

            // Constant was a branch target, so brtrue MUST NOT be resolved to br
            Assert.Equal(0, result.BranchesResolved);
            Assert.True(ldc.IsLdcI4());
            Assert.Equal(1, ldc.GetLdcI4Value());
            Assert.Equal(OpCodes.Brtrue, brtrue.OpCode);
        }

        [Fact]
        public void FoldAlgebraicIdentities_ModuloIntermediateAddIsBranchTarget_NotSimplified()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var method = new MethodDefUser("TestMethod", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32))
            {
                Body = new CilBody()
            };
            type.Methods.Add(method);

            var ldarg = Instruction.Create(OpCodes.Ldarg_0);
            var dup = Instruction.Create(OpCodes.Dup);
            var ldc1 = Instruction.CreateLdcI4(1);
            var add = Instruction.Create(OpCodes.Add);
            var mul = Instruction.Create(OpCodes.Mul);
            var ldc2 = Instruction.CreateLdcI4(2);
            var rem = Instruction.Create(OpCodes.Rem);
            var ret = Instruction.Create(OpCodes.Ret);
            var br = Instruction.Create(OpCodes.Br, add);

            method.Body.Instructions.Add(ldarg);
            method.Body.Instructions.Add(br);
            method.Body.Instructions.Add(dup);
            method.Body.Instructions.Add(ldc1);
            method.Body.Instructions.Add(add);
            method.Body.Instructions.Add(mul);
            method.Body.Instructions.Add(ldc2);
            method.Body.Instructions.Add(rem);
            method.Body.Instructions.Add(ret);

            var result = PredicateKiller.Execute(module);

            Assert.Equal(0, result.IdentitiesSimplified);
            Assert.Equal(OpCodes.Dup, dup.OpCode);
            Assert.Equal(OpCodes.Add, add.OpCode);
            Assert.Equal(OpCodes.Rem, rem.OpCode);
        }

        [Fact]
        public void FoldConstants_IntermediateNopIsBranchTarget_NotFolded()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var method = new MethodDefUser("TestMethod", MethodSig.CreateStatic(module.CorLibTypes.Int32))
            {
                Body = new CilBody()
            };
            type.Methods.Add(method);

            var left = Instruction.CreateLdcI4(10);
            var intermediateNop = Instruction.Create(OpCodes.Nop);
            var br = Instruction.Create(OpCodes.Br, intermediateNop);
            var right = Instruction.CreateLdcI4(20);
            var add = Instruction.Create(OpCodes.Add);
            var ret = Instruction.Create(OpCodes.Ret);

            method.Body.Instructions.Add(br);
            method.Body.Instructions.Add(left);
            method.Body.Instructions.Add(intermediateNop);
            method.Body.Instructions.Add(right);
            method.Body.Instructions.Add(add);
            method.Body.Instructions.Add(ret);

            var result = PredicateKiller.Execute(module);

            Assert.Equal(0, result.ConstantsFolded);
            Assert.True(left.IsLdcI4());
            Assert.Equal(10, left.GetLdcI4Value());
            Assert.Equal(OpCodes.Add, add.OpCode);
        }

        [Fact]
        public void FoldConstants_AcrossExceptionHandlerBoundary_NotFolded()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var method = new MethodDefUser("TestMethod", MethodSig.CreateStatic(module.CorLibTypes.Int32))
            {
                Body = new CilBody()
            };
            type.Methods.Add(method);

            var left = Instruction.CreateLdcI4(10);
            var right = Instruction.CreateLdcI4(20);
            var add = Instruction.Create(OpCodes.Add);
            var ret = Instruction.Create(OpCodes.Ret);
            var catchPop = Instruction.Create(OpCodes.Pop);
            var ldcZero = Instruction.CreateLdcI4(0);
            var catchRet = Instruction.Create(OpCodes.Ret);

            method.Body.Instructions.Add(left);
            method.Body.Instructions.Add(right);
            method.Body.Instructions.Add(add);
            method.Body.Instructions.Add(ret);
            method.Body.Instructions.Add(catchPop);
            method.Body.Instructions.Add(ldcZero);
            method.Body.Instructions.Add(catchRet);

            // Try block covers only 'left' (from left to right)
            var eh = new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = left,
                TryEnd = right,
                HandlerStart = catchPop,
                HandlerEnd = catchRet,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            };
            method.Body.ExceptionHandlers.Add(eh);

            var result = PredicateKiller.Execute(module);

            // Because left is inside Try and right is outside, folding across this boundary is forbidden
            Assert.Equal(0, result.ConstantsFolded);
            Assert.True(left.IsLdcI4());
            Assert.Equal(10, left.GetLdcI4Value());
            Assert.Equal(OpCodes.Add, add.OpCode);
        }
    }
}
