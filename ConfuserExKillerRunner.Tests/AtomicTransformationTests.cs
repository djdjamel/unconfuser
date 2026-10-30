using System;
using System.Collections.Generic;
using ConfuserExKillerRunner.Analysis;
using ConfuserExKillerRunner.Core;
using ConfuserExKillerRunner.Killers;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    [Trait("Category", "Unit")]
    public class AtomicTransformationTests
    {
        private MethodDef CreateValidMethod(string name = "TestMethod")
        {
            var module = new ModuleDefUser("TestModule.dll");
            var type = new TypeDefUser("TestNamespace", "TestClass", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var method = new MethodDefUser(
                name,
                MethodSig.CreateStatic(module.CorLibTypes.Int32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static);
            type.Methods.Add(method);

            var body = new CilBody();
            body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 42));
            body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            method.Body = body;

            return method;
        }

        [Fact]
        public void ExecuteAtomic_WhenTransformThrows_RollsBackBodyAndReturnsFalse()
        {
            var method = CreateValidMethod();
            int origCount = method.Body.Instructions.Count;
            int origVal = (int)method.Body.Instructions[0].Operand;

            bool success = MethodTransaction.ExecuteAtomic(method, () =>
            {
                method.Body.Instructions.Clear();
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Nop));
                throw new InvalidOperationException("Simulated unexpected failure during AST rewriting");
            }, "TestPass");

            Assert.False(success);
            Assert.Equal(origCount, method.Body.Instructions.Count);
            Assert.Equal(OpCodes.Ldc_I4, method.Body.Instructions[0].OpCode);
            Assert.Equal(origVal, (int)method.Body.Instructions[0].Operand);
            Assert.Equal(OpCodes.Ret, method.Body.Instructions[1].OpCode);
        }

        [Fact]
        public void ExecuteAtomic_WhenTransformIntroducesOrphanedBranchTarget_RollsBack()
        {
            var method = CreateValidMethod();
            int origCount = method.Body.Instructions.Count;

            bool success = MethodTransaction.ExecuteAtomic(method, () =>
            {
                // Create branch targeting an instruction that is never added to the body
                var orphanedTarget = Instruction.Create(OpCodes.Nop);
                method.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Br, orphanedTarget));
                return true;
            }, "TestPass");

            Assert.False(success);
            // Must have rolled back to 2 instructions (ldc_i4 + ret)
            Assert.Equal(origCount, method.Body.Instructions.Count);
            Assert.Equal(OpCodes.Ldc_I4, method.Body.Instructions[0].OpCode);
            Assert.Equal(OpCodes.Ret, method.Body.Instructions[1].OpCode);
        }

        [Fact]
        public void ExecuteAtomic_WhenTransformIntroducesStackUnderflow_RollsBack()
        {
            var method = CreateValidMethod();
            int origCount = method.Body.Instructions.Count;

            bool success = MethodTransaction.ExecuteAtomic(method, () =>
            {
                // Pop on empty stack violates evaluation stack balance
                method.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Pop));
                return true;
            }, "TestPass");

            Assert.False(success);
            Assert.Equal(origCount, method.Body.Instructions.Count);
            Assert.Equal(OpCodes.Ldc_I4, method.Body.Instructions[0].OpCode);
            Assert.Equal(OpCodes.Ret, method.Body.Instructions[1].OpCode);
        }

        [Fact]
        public void ExecuteAtomic_WhenTransformCorruptsExceptionHandler_RollsBack()
        {
            var method = CreateValidMethod();
            int origCount = method.Body.Instructions.Count;

            bool success = MethodTransaction.ExecuteAtomic(method, () =>
            {
                // Add exception handler pointing to instructions not in body
                var outsideTry = Instruction.Create(OpCodes.Nop);
                var outsideHandler = Instruction.Create(OpCodes.Nop);
                var eh = new ExceptionHandler(ExceptionHandlerType.Catch)
                {
                    TryStart = outsideTry,
                    TryEnd = method.Body.Instructions[0],
                    HandlerStart = outsideHandler,
                    HandlerEnd = method.Body.Instructions[1],
                    CatchType = method.Module.CorLibTypes.Object.TypeDefOrRef
                };
                method.Body.ExceptionHandlers.Add(eh);
                return true;
            }, "TestPass");

            Assert.False(success);
            Assert.Equal(origCount, method.Body.Instructions.Count);
            Assert.Empty(method.Body.ExceptionHandlers);
        }

        [Fact]
        public void ExecuteAtomic_WhenTransformIsValid_CommitsChangesAndReturnsTrue()
        {
            var method = CreateValidMethod();

            bool success = MethodTransaction.ExecuteAtomic(method, () =>
            {
                method.Body.Instructions.Clear();
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 100));
                method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                return true;
            }, "TestPass");

            Assert.True(success);
            Assert.Equal(2, method.Body.Instructions.Count);
            Assert.Equal(100, (int)method.Body.Instructions[0].Operand);
        }

        [Fact]
        public void MultiMethodAssembly_WhenOneMethodFails_OnlyFailedMethodIsRolledBack()
        {
            var method1 = CreateValidMethod("GoodMethod1");
            var method2 = CreateValidMethod("BadMethod2");
            var method3 = CreateValidMethod("GoodMethod3");

            // Method 1 succeeds
            bool s1 = MethodTransaction.ExecuteAtomic(method1, () =>
            {
                method1.Body.Instructions[0].Operand = 111;
                return true;
            }, "Pass1");

            // Method 2 introduces stack underflow (fails audit)
            bool s2 = MethodTransaction.ExecuteAtomic(method2, () =>
            {
                method2.Body.Instructions.Clear();
                method2.Body.Instructions.Add(Instruction.Create(OpCodes.Pop)); // Underflow!
                method2.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                return true;
            }, "Pass1");

            // Method 3 succeeds
            bool s3 = MethodTransaction.ExecuteAtomic(method3, () =>
            {
                method3.Body.Instructions[0].Operand = 333;
                return true;
            }, "Pass1");

            Assert.True(s1);
            Assert.False(s2);
            Assert.True(s3);

            // Method 1 was retained
            Assert.Equal(111, (int)method1.Body.Instructions[0].Operand);
            // Method 2 was rolled back to original
            Assert.Equal(42, (int)method2.Body.Instructions[0].Operand);
            Assert.Equal(OpCodes.Ldc_I4, method2.Body.Instructions[0].OpCode);
            // Method 3 was retained
            Assert.Equal(333, (int)method3.Body.Instructions[0].Operand);
        }

        [Fact]
        public void DeadCodeStripper_ExecutesSafelyAndMaintainsStructuralInvariants()
        {
            var module = new ModuleDefUser("TestModule.dll");
            var type = new TypeDefUser("TestNamespace", "TestClass", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            // Valid method with junk instruction pattern (ldc.i4 + pop)
            var methodValid = new MethodDefUser("ValidMethod", MethodSig.CreateStatic(module.CorLibTypes.Int32));
            type.Methods.Add(methodValid);
            var bodyValid = new CilBody();
            bodyValid.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 1234));
            bodyValid.Instructions.Add(Instruction.Create(OpCodes.Pop));
            bodyValid.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 42));
            bodyValid.Instructions.Add(Instruction.Create(OpCodes.Ret));
            methodValid.Body = bodyValid;

            var result = DeadCodeStripper.Execute(module);

            Assert.True(result.MethodsOptimized > 0);
            Assert.True(QualityAuditor.IsMethodStructurallyValid(methodValid, out var errors), string.Join("; ", errors));
        }
    }
}
