using System;
using System.Collections.Generic;
using ConfuserExKillerRunner;
using ConfuserExKillerRunner.Killers;
using de4dot.blocks.cflow;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public class ControlFlowAndPredicateHardeningTests
    {
        [Fact]
        public void FixConditionalBranches_ConditionalBranchAtEndOfMethod_DoesNotThrowIndexOutOfRange()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var method = new MethodDefUser("BoundaryMethod", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            type.Methods.Add(method);

            var target = Instruction.Create(OpCodes.Ret);
            var condBr = Instruction.Create(OpCodes.Brtrue, target);

            // Method ends exactly with condBr (no instrs[j + 1])
            method.Body.Instructions.Add(target);
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
            method.Body.Instructions.Add(condBr);

            // Must not throw ArgumentOutOfRangeException
            var exception = Record.Exception(() =>
            {
                // FixConditionalBranches is private static in SwitchKillerImpl, but can be invoked via SwitchKillerImpl.Execute
                SwitchKillerImpl.Execute(module);
            });

            Assert.Null(exception);
        }

        [Fact]
        public void PredicateKiller_DupXor_OnInt64_EmitsLdcI8Zero()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            // Method returning long, with local variable of type long
            var method = new MethodDefUser("TestMethod64", MethodSig.CreateStatic(module.CorLibTypes.Int64))
            {
                Body = new CilBody()
            };
            type.Methods.Add(method);

            var localLong = new Local(module.CorLibTypes.Int64);
            method.Body.Variables.Add(localLong);

            var ldloc = Instruction.Create(OpCodes.Ldloc, localLong);
            var dup = Instruction.Create(OpCodes.Dup);
            var xor = Instruction.Create(OpCodes.Xor);
            var ret = Instruction.Create(OpCodes.Ret);

            method.Body.Instructions.Add(ldloc);
            method.Body.Instructions.Add(dup);
            method.Body.Instructions.Add(xor);
            method.Body.Instructions.Add(ret);

            var result = PredicateKiller.Execute(module);

            Assert.True(result.IdentitiesSimplified > 0);
            Assert.Equal(OpCodes.Pop, method.Body.Instructions[1].OpCode);
            // Must emit Ldc_I8 0, NOT Ldc_I4_0!
            Assert.Equal(OpCodes.Ldc_I8, method.Body.Instructions[2].OpCode);
            Assert.Equal(0L, (long)method.Body.Instructions[2].Operand);
        }

        [Fact]
        public void PredicateKiller_DupXor_OnInt32_EmitsLdcI4Zero()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var method = new MethodDefUser("TestMethod32", MethodSig.CreateStatic(module.CorLibTypes.Int32))
            {
                Body = new CilBody()
            };
            type.Methods.Add(method);

            var localInt = new Local(module.CorLibTypes.Int32);
            method.Body.Variables.Add(localInt);

            var ldloc = Instruction.Create(OpCodes.Ldloc, localInt);
            var dup = Instruction.Create(OpCodes.Dup);
            var xor = Instruction.Create(OpCodes.Xor);
            var ret = Instruction.Create(OpCodes.Ret);

            method.Body.Instructions.Add(ldloc);
            method.Body.Instructions.Add(dup);
            method.Body.Instructions.Add(xor);
            method.Body.Instructions.Add(ret);

            var result = PredicateKiller.Execute(module);

            Assert.True(result.IdentitiesSimplified > 0);
            Assert.Equal(OpCodes.Pop, method.Body.Instructions[1].OpCode);
            // Must emit Ldc_I4_0 for 32-bit
            Assert.Equal(OpCodes.Ldc_I4_0, method.Body.Instructions[2].OpCode);
        }

        [Fact]
        public void PredicateKiller_QuadraticFormula_WithOverflowOpcode_IsNotSimplified()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var method = new MethodDefUser("TestMethodOvf", MethodSig.CreateStatic(module.CorLibTypes.Int32))
            {
                Body = new CilBody()
            };
            type.Methods.Add(method);

            var localInt = new Local(module.CorLibTypes.Int32);
            method.Body.Variables.Add(localInt);

            // dup, ldc.i4.1, add.ovf (overflow checked!), mul, ldc.i4.2, rem
            var ldloc = Instruction.Create(OpCodes.Ldloc, localInt);
            var dup = Instruction.Create(OpCodes.Dup);
            var ldc1 = Instruction.Create(OpCodes.Ldc_I4_1);
            var addOvf = Instruction.Create(OpCodes.Add_Ovf); // Ovf check!
            var mul = Instruction.Create(OpCodes.Mul);
            var ldc2 = Instruction.Create(OpCodes.Ldc_I4_2);
            var rem = Instruction.Create(OpCodes.Rem);
            var ret = Instruction.Create(OpCodes.Ret);

            method.Body.Instructions.Add(ldloc);
            method.Body.Instructions.Add(dup);
            method.Body.Instructions.Add(ldc1);
            method.Body.Instructions.Add(addOvf);
            method.Body.Instructions.Add(mul);
            method.Body.Instructions.Add(ldc2);
            method.Body.Instructions.Add(rem);
            method.Body.Instructions.Add(ret);

            var result = PredicateKiller.Execute(module);

            // Must NOT simplify because add.ovf could throw OverflowException at runtime
            Assert.Equal(0, result.IdentitiesSimplified);
            Assert.Equal(OpCodes.Add_Ovf, method.Body.Instructions[3].OpCode);
        }

        [Fact]
        public void ResolveComplexSwitch_DispatcherWithExceptionHandlerBoundary_PreservesDispatcherHeader()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var method = new MethodDefUser("EhBoundarySwitchMethod", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            type.Methods.Add(method);

            var target0 = Instruction.Create(OpCodes.Ret);
            var target1 = Instruction.Create(OpCodes.Ret);

            // Dispatcher 7-instruction pattern:
            var stateVar = new Local(module.CorLibTypes.Int32);
            method.Body.Variables.Add(stateVar);

            var dispKey = Instruction.Create(OpCodes.Ldc_I4, 0x10);
            var dispXor = Instruction.Create(OpCodes.Xor);
            var dispDup = Instruction.Create(OpCodes.Dup);
            var dispStloc = Instruction.Create(OpCodes.Stloc, stateVar);
            var dispRem = Instruction.Create(OpCodes.Ldc_I4, 2);
            var dispRemOp = Instruction.Create(OpCodes.Rem_Un);
            var dispSwitch = Instruction.Create(OpCodes.Switch, new Instruction[] { target0, target1 });

            // Transition branch:
            // ldc.i4 0x11, br -> dispKey
            var callerLdc = Instruction.Create(OpCodes.Ldc_I4, 0x11);
            var callerBr = Instruction.Create(OpCodes.Br, dispKey);

            method.Body.Instructions.Add(callerLdc);
            method.Body.Instructions.Add(callerBr);

            method.Body.Instructions.Add(dispKey);
            method.Body.Instructions.Add(dispXor);
            method.Body.Instructions.Add(dispDup);
            method.Body.Instructions.Add(dispStloc);
            method.Body.Instructions.Add(dispRem);
            method.Body.Instructions.Add(dispRemOp);
            method.Body.Instructions.Add(dispSwitch);

            method.Body.Instructions.Add(target0);
            method.Body.Instructions.Add(target1);

            // An exception handler's TryStart directly references dispKey
            var eh = new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = dispKey,
                TryEnd = target0,
                HandlerStart = target0,
                HandlerEnd = target1,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            };
            method.Body.ExceptionHandlers.Add(eh);

            var deobfuscator = new BlocksCflowDeobfuscator();
            SwitchKillerImpl.ResolveComplexSwitch(new List<MethodDef> { method }, deobfuscator);

            // Because TryStart targets dispKey, the dispatcher header MUST NOT be nopped!
            Assert.NotEqual(OpCodes.Nop, dispKey.OpCode);
            Assert.NotEqual(OpCodes.Nop, dispXor.OpCode);
        }

        [Fact]
        public void ResolveComplexSwitch_MultipleDispatchersWithDifferentLocals_AreResolvedIndependently()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var method = new MethodDefUser("MultiSwitchMethod", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            type.Methods.Add(method);

            var varA = new Local(module.CorLibTypes.Int32);
            var varB = new Local(module.CorLibTypes.Int32);
            method.Body.Variables.Add(varA);
            method.Body.Variables.Add(varB);

            var targetA0 = Instruction.Create(OpCodes.Nop);
            var targetA1 = Instruction.Create(OpCodes.Nop);
            var targetB0 = Instruction.Create(OpCodes.Nop);
            var targetB1 = Instruction.Create(OpCodes.Nop);
            var ret = Instruction.Create(OpCodes.Ret);

            // Dispatcher A (uses varA)
            var keyA = Instruction.Create(OpCodes.Ldc_I4, 0x20);
            var xorA = Instruction.Create(OpCodes.Xor);
            var dupA = Instruction.Create(OpCodes.Dup);
            var stlocA = Instruction.Create(OpCodes.Stloc, varA);
            var remA = Instruction.Create(OpCodes.Ldc_I4, 2);
            var remOpA = Instruction.Create(OpCodes.Rem_Un);
            var swA = Instruction.Create(OpCodes.Switch, new Instruction[] { targetA0, targetA1 });

            // Dispatcher B (uses varB)
            var keyB = Instruction.Create(OpCodes.Ldc_I4, 0x40);
            var xorB = Instruction.Create(OpCodes.Xor);
            var dupB = Instruction.Create(OpCodes.Dup);
            var stlocB = Instruction.Create(OpCodes.Stloc, varB);
            var remB = Instruction.Create(OpCodes.Ldc_I4, 2);
            var remOpB = Instruction.Create(OpCodes.Rem_Un);
            var swB = Instruction.Create(OpCodes.Switch, new Instruction[] { targetB0, targetB1 });

            // Caller A: state 0x21 => 0x21 ^ 0x20 = 1 => targetA1
            var callerLdcA = Instruction.Create(OpCodes.Ldc_I4, 0x21);
            var callerBrA = Instruction.Create(OpCodes.Br, keyA);

            // Caller B: state 0x40 => 0x40 ^ 0x40 = 0 => targetB0
            var callerLdcB = Instruction.Create(OpCodes.Ldc_I4, 0x40);
            var callerBrB = Instruction.Create(OpCodes.Br, keyB);

            method.Body.Instructions.Add(callerLdcA);
            method.Body.Instructions.Add(callerBrA);
            method.Body.Instructions.Add(callerLdcB);
            method.Body.Instructions.Add(callerBrB);

            method.Body.Instructions.Add(keyA);
            method.Body.Instructions.Add(xorA);
            method.Body.Instructions.Add(dupA);
            method.Body.Instructions.Add(stlocA);
            method.Body.Instructions.Add(remA);
            method.Body.Instructions.Add(remOpA);
            method.Body.Instructions.Add(swA);

            method.Body.Instructions.Add(keyB);
            method.Body.Instructions.Add(xorB);
            method.Body.Instructions.Add(dupB);
            method.Body.Instructions.Add(stlocB);
            method.Body.Instructions.Add(remB);
            method.Body.Instructions.Add(remOpB);
            method.Body.Instructions.Add(swB);

            method.Body.Instructions.Add(targetA0);
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Br, ret));
            method.Body.Instructions.Add(targetA1);
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Br, callerLdcB));
            method.Body.Instructions.Add(targetB0);
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Br, ret));
            method.Body.Instructions.Add(targetB1);
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Br, ret));
            method.Body.Instructions.Add(ret);

            var deobfuscator = new BlocksCflowDeobfuscator();
            int resolved = SwitchKillerImpl.ResolveComplexSwitch(new List<MethodDef> { method }, deobfuscator);

            // Both dispatchers resolved without conflict
            Assert.True(resolved >= 2);
        }

        [Fact]
        public void ResolveComplexSwitch_SwitchInExceptionHandler_TraversesCatchBlock()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var method = new MethodDefUser("EhSwitchMethod", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            type.Methods.Add(method);

            var tryStart = Instruction.Create(OpCodes.Nop);
            var tryEnd = Instruction.Create(OpCodes.Leave, tryStart); // dummy leave
            var handlerStart = Instruction.Create(OpCodes.Pop); // catch Exception
            var target0 = Instruction.Create(OpCodes.Nop);
            var target1 = Instruction.Create(OpCodes.Nop);
            var ret = Instruction.Create(OpCodes.Ret);

            // Switch dispatcher inside catch block:
            var key = Instruction.Create(OpCodes.Ldc_I4, 0x10);
            var xor = Instruction.Create(OpCodes.Xor);
            var rem = Instruction.Create(OpCodes.Ldc_I4, 2);
            var remOp = Instruction.Create(OpCodes.Rem_Un);
            var sw = Instruction.Create(OpCodes.Switch, new Instruction[] { target0, target1 });

            // Inside catch: state 0x11, br -> key
            var catchLdc = Instruction.Create(OpCodes.Ldc_I4, 0x11);
            var catchBr = Instruction.Create(OpCodes.Br, key);

            method.Body.Instructions.Add(tryStart);
            method.Body.Instructions.Add(tryEnd);

            method.Body.Instructions.Add(handlerStart);
            method.Body.Instructions.Add(catchLdc);
            method.Body.Instructions.Add(catchBr);

            method.Body.Instructions.Add(key);
            method.Body.Instructions.Add(xor);
            method.Body.Instructions.Add(rem);
            method.Body.Instructions.Add(remOp);
            method.Body.Instructions.Add(sw);

            method.Body.Instructions.Add(target0);
            method.Body.Instructions.Add(target1);
            method.Body.Instructions.Add(ret);

            tryEnd.Operand = ret;

            var eh = new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = tryStart,
                TryEnd = handlerStart,
                HandlerStart = handlerStart,
                HandlerEnd = ret,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            };
            method.Body.ExceptionHandlers.Add(eh);

            var deobfuscator = new BlocksCflowDeobfuscator();
            int resolved = SwitchKillerImpl.ResolveComplexSwitch(new List<MethodDef> { method }, deobfuscator);

            // Handler block was traversed and resolved
            Assert.True(resolved > 0);
        }
    }
}
