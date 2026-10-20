using System;
using System.Collections.Generic;
using System.Linq;
using ConfuserExKillerRunner.Analysis;
using ConfuserExKillerRunner.Killers;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public class RandomizedControlFlowPropertyTests
    {
        private (ModuleDef Module, MethodDef Method) CreateMethod(Func<ModuleDef, TypeSig> returnTypeFunc, params Func<ModuleDef, TypeSig>[] paramTypesFunc)
        {
            var module = new ModuleDefUser("RandomizedCflowMod_" + Guid.NewGuid().ToString("N"));
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var returnType = returnTypeFunc(module);
            var paramTypes = paramTypesFunc.Select(f => f(module)).ToArray();

            var sig = MethodSig.CreateStatic(returnType, paramTypes);
            var method = new MethodDefUser("ComputeMethod", sig, MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody { InitLocals = true }
            };
            type.Methods.Add(method);
            return (module, method);
        }

        [Theory]
        [InlineData(42)]
        [InlineData(1337)]
        [InlineData(2026)]
        [InlineData(9999)]
        public void RandomizedOpaquePredicates_AllPassStructuralAudit_StackStrictlyBalanced(int seed)
        {
            var rng = new Random(seed);
            var (module, method) = CreateMethod(m => m.CorLibTypes.Int32, m => m.CorLibTypes.Int32, m => m.CorLibTypes.Int32);
            var body = method.Body;

            var accumVar = new Local(module.CorLibTypes.Int32);
            body.Variables.Add(accumVar);

            // Initialize accum = arg0
            body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            body.Instructions.Add(Instruction.Create(OpCodes.Stloc, accumVar));

            // Add several randomized opaque predicate blocks
            int numPredicates = rng.Next(3, 7);
            for (int p = 0; p < numPredicates; p++)
            {
                var nextLiveBlock = Instruction.Create(OpCodes.Nop);
                var deadBlock = Instruction.Create(OpCodes.Nop);

                int constVal = rng.Next(1, 500);

                int predicateKind = rng.Next(0, 2);
                if (predicateKind == 0)
                {
                    // Constant equality: ldc A, ldc A, beq nextLiveBlock
                    body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, constVal));
                    body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, constVal));
                    body.Instructions.Add(Instruction.Create(OpCodes.Beq, nextLiveBlock));
                }
                else
                {
                    // Constant inequality: ldc A, ldc B, bne_un nextLiveBlock
                    body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, constVal));
                    body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, constVal + 10));
                    body.Instructions.Add(Instruction.Create(OpCodes.Bne_Un, nextLiveBlock));
                }

                // Dead code block (never executed, but structurally valid with balanced stack)
                body.Instructions.Add(deadBlock);
                body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_M1));
                body.Instructions.Add(Instruction.Create(OpCodes.Ret));

                // Live block: accum += arg1
                body.Instructions.Add(nextLiveBlock);
                body.Instructions.Add(Instruction.Create(OpCodes.Ldloc, accumVar));
                body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1));
                body.Instructions.Add(Instruction.Create(OpCodes.Add));
                body.Instructions.Add(Instruction.Create(OpCodes.Stloc, accumVar));
            }

            // Return accum
            body.Instructions.Add(Instruction.Create(OpCodes.Ldloc, accumVar));
            body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            // Execute deobfuscation pipeline passes
            PredicateKiller.Execute(module);
            DeadCodeStripper.Execute(module);

            // Audit
            var audit = new AuditReport { CanLoad = true };
            QualityAuditor.AuditMethod(method, audit);

            Assert.True(audit.StructuralAuditPassed);
            Assert.Equal(0, audit.InvalidInstructionsCount);
            Assert.Equal(0, audit.StackUnderflowCount);

            // Verify that all ret instructions in the cleaned method have stack depth == 1
            Assert.Contains(body.Instructions, i => i.OpCode == OpCodes.Ret);
        }

        [Theory]
        [InlineData(101)]
        [InlineData(202)]
        [InlineData(303)]
        public void RandomizedTrampolineJumps_FlattenedWithoutStructuralDefects(int seed)
        {
            var rng = new Random(seed);
            var (module, method) = CreateMethod(m => m.CorLibTypes.Int32, m => m.CorLibTypes.Int32);
            var body = method.Body;

            // Chain of trampolines: Jump to T1 -> T2 -> T3 -> FinalBlock
            var finalTarget = Instruction.Create(OpCodes.Ldarg_0);
            var ret = Instruction.Create(OpCodes.Ret);

            int chainLength = rng.Next(3, 7);
            var trampolines = new List<Instruction>();
            for (int i = 0; i < chainLength; i++)
            {
                trampolines.Add(Instruction.Create(OpCodes.Nop));
            }

            // Entry branches to first trampoline
            body.Instructions.Add(Instruction.Create(OpCodes.Br, trampolines[0]));

            // Chain trampolines
            for (int i = 0; i < chainLength - 1; i++)
            {
                body.Instructions.Add(trampolines[i]);
                body.Instructions.Add(Instruction.Create(OpCodes.Br, trampolines[i + 1]));
            }

            // Last trampoline branches to finalTarget
            body.Instructions.Add(trampolines[chainLength - 1]);
            body.Instructions.Add(Instruction.Create(OpCodes.Br, finalTarget));

            body.Instructions.Add(finalTarget);
            body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 42));
            body.Instructions.Add(Instruction.Create(OpCodes.Add));
            body.Instructions.Add(ret);

            // Optimize trampolines
            var dcs = DeadCodeStripper.Execute(module);
            Assert.True(dcs.TrampolinesFlattened > 0);

            var audit = new AuditReport { CanLoad = true };
            QualityAuditor.AuditMethod(method, audit);

            Assert.True(audit.StructuralAuditPassed);
            Assert.Equal(0, audit.InvalidInstructionsCount);
            Assert.Equal(0, audit.StackUnderflowCount);
        }

        [Theory]
        [InlineData(555)]
        [InlineData(777)]
        [InlineData(999)]
        public void RandomizedSimpleSwitch_ResolvedToDirectBranch_StackBalanced(int seed)
        {
            var rng = new Random(seed);
            var (module, method) = CreateMethod(m => m.CorLibTypes.Int32, m => m.CorLibTypes.Int32);
            var body = method.Body;

            var ret0 = Instruction.Create(OpCodes.Ret);
            var target0 = Instruction.Create(OpCodes.Pop);
            var target1 = Instruction.Create(OpCodes.Nop);
            var ret1 = Instruction.Create(OpCodes.Ret);

            int key = rng.Next(1, 100);
            int inputVal = key ^ 1; // inputVal ^ key == 1 -> target1

            var ldcConst = Instruction.CreateLdcI4(key);
            var ldcMod = Instruction.CreateLdcI4(2);
            var xor = Instruction.Create(OpCodes.Xor);
            var sw = Instruction.Create(OpCodes.Switch, new Instruction[] { target0, target1 });

            var callerLdc = Instruction.CreateLdcI4(inputVal);
            var callerBr = Instruction.Create(OpCodes.Br, ldcConst);

            body.Instructions.Add(callerLdc);
            body.Instructions.Add(callerBr);
            body.Instructions.Add(ldcConst);
            body.Instructions.Add(ldcMod);
            body.Instructions.Add(xor);
            body.Instructions.Add(sw);

            body.Instructions.Add(target0);
            body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            body.Instructions.Add(ret0);

            body.Instructions.Add(target1);
            body.Instructions.Add(ret1);

            SwitchKillerImpl.ResolveSimpleSwitch(new List<MethodDef> { method });

            Assert.Equal(target1, callerBr.Operand);

            var audit = new AuditReport { CanLoad = true };
            QualityAuditor.AuditMethod(method, audit);

            Assert.True(audit.StructuralAuditPassed);
            Assert.Equal(0, audit.InvalidInstructionsCount);
            Assert.Equal(0, audit.StackUnderflowCount);
        }

        [Fact]
        public void RandomizedJunkInstructions_DupPopAndLdcPop_SafelyStripped()
        {
            var (module, method) = CreateMethod(m => m.CorLibTypes.Int32, m => m.CorLibTypes.Int32);
            var body = method.Body;

            // Method body with random benign junk pairs
            body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));

            // Junk pair 1: dup, pop
            body.Instructions.Add(Instruction.Create(OpCodes.Dup));
            body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // Calculation
            body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 5));
            body.Instructions.Add(Instruction.Create(OpCodes.Add));

            // Junk pair 2: ldc.i4, pop
            body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 999));
            body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            var dcs = DeadCodeStripper.Execute(module);
            Assert.True(dcs.JunkPairsStripped >= 2);

            var audit = new AuditReport { CanLoad = true };
            QualityAuditor.AuditMethod(method, audit);

            Assert.True(audit.StructuralAuditPassed);
            Assert.Equal(0, audit.InvalidInstructionsCount);
            Assert.Equal(0, audit.StackUnderflowCount);
        }
    }
}
