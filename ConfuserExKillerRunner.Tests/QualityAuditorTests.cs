using System.Collections.Generic;
using ConfuserExKillerRunner.Analysis;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public class QualityAuditorTests
    {
        private static MethodDef CreateDummyMethod()
        {
            var module = new ModuleDefUser("TestModule");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);
            var method = new MethodDefUser("TestMethod", MethodSig.CreateStatic(module.CorLibTypes.Void));
            type.Methods.Add(method);
            return method;
        }

        [Fact]
        public void AuditMethod_StackUnderflow_StatusIsFailed()
        {
            var method = CreateDummyMethod();
            var body = new CilBody();
            // Pop without any prior push causes stack underflow
            body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            method.Body = body;

            var report = new AuditReport { CanLoad = true };
            QualityAuditor.AuditMethod(method, report);

            Assert.True(report.StackUnderflowCount > 0);
            Assert.True(report.InvalidInstructionsCount > 0);
            Assert.Equal("FAILED", report.Status);
            Assert.Contains(report.Errors, e => e.Contains("Stack underflow"));
        }

        [Fact]
        public void AuditMethod_ValidIL_StatusIsClean()
        {
            var method = CreateDummyMethod();
            var body = new CilBody();
            var ret = Instruction.Create(OpCodes.Ret);
            var branch = Instruction.Create(OpCodes.Br, ret);

            body.Instructions.Add(branch);
            body.Instructions.Add(ret);
            method.Body = body;

            var report = new AuditReport { CanLoad = true };
            QualityAuditor.AuditMethod(method, report);

            Assert.Equal(0, report.InvalidInstructionsCount);
            Assert.Equal("CLEAN", report.Status);
        }

        [Fact]
        public void AuditMethod_OrphanedBranchTarget_StatusIsFailed()
        {
            var method = CreateDummyMethod();
            var body = new CilBody();
            var foreignTarget = Instruction.Create(OpCodes.Ret); // Not added to body.Instructions
            var branch = Instruction.Create(OpCodes.Br, foreignTarget);

            body.Instructions.Add(branch);
            body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            method.Body = body;

            var report = new AuditReport { CanLoad = true };
            QualityAuditor.AuditMethod(method, report);

            Assert.True(report.InvalidInstructionsCount > 0);
            Assert.Equal("FAILED", report.Status);
            Assert.Contains(report.Warnings, w => w.Contains("orphaned/unlisted instruction"));
        }

        [Fact]
        public void AuditMethod_NullSwitchTarget_StatusIsFailed()
        {
            var method = CreateDummyMethod();
            var body = new CilBody();
            var ret = Instruction.Create(OpCodes.Ret);

            var switchList = new List<Instruction> { null };
            var switchInst = Instruction.Create(OpCodes.Switch, switchList);

            body.Instructions.Add(switchInst);
            body.Instructions.Add(ret);
            method.Body = body;

            var report = new AuditReport { CanLoad = true };
            QualityAuditor.AuditMethod(method, report);

            Assert.True(report.InvalidInstructionsCount > 0);
            Assert.Equal("FAILED", report.Status);
            Assert.Contains(report.Warnings, w => w.Contains("switch target #0 is null or unlisted"));
        }

        [Fact]
        public void AuditMethod_NullCallOperand_StatusIsFailed()
        {
            var method = CreateDummyMethod();
            var body = new CilBody();
            var callInst = new Instruction(OpCodes.Call, null);
            var ret = Instruction.Create(OpCodes.Ret);

            body.Instructions.Add(callInst);
            body.Instructions.Add(ret);
            method.Body = body;

            var report = new AuditReport { CanLoad = true };
            QualityAuditor.AuditMethod(method, report);

            Assert.True(report.InvalidInstructionsCount > 0);
            Assert.Equal("FAILED", report.Status);
            Assert.Contains(report.Warnings, w => w.Contains("null operand for call"));
        }

        [Fact]
        public void AuditMethod_InvalidExceptionHandlerBoundary_StatusIsFailed()
        {
            var method = CreateDummyMethod();
            var body = new CilBody();
            var tryStart = Instruction.Create(OpCodes.Nop);
            var handlerStart = Instruction.Create(OpCodes.Pop);

            body.Instructions.Add(tryStart);
            body.Instructions.Add(handlerStart);
            method.Body = body;

            var unlistedTryStart = Instruction.Create(OpCodes.Nop);
            var eh = new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = unlistedTryStart,
                HandlerStart = handlerStart
            };
            body.ExceptionHandlers.Add(eh);

            var report = new AuditReport { CanLoad = true };
            QualityAuditor.AuditMethod(method, report);

            Assert.True(report.InvalidInstructionsCount > 0);
            Assert.Equal("FAILED", report.Status);
            Assert.Contains(report.Warnings, w => w.Contains("invalid/unlisted TryStart"));
        }

        [Fact]
        public void AuditMethod_InvalidLocalAccess_StatusIsFailed()
        {
            var method = CreateDummyMethod();
            var body = new CilBody();
            // Method has 0 local variables, but tries to access local #1
            body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            method.Body = body;

            var report = new AuditReport { CanLoad = true };
            QualityAuditor.AuditMethod(method, report);

            Assert.True(report.InvalidInstructionsCount > 0);
            Assert.Equal("FAILED", report.Status);
            Assert.Contains(report.Errors, e => e.Contains("local variables"));
        }

        [Fact]
        public void AuditMethod_InvalidParamAccess_StatusIsFailed()
        {
            var method = CreateDummyMethod(); // static void TestMethod() -> 0 params
            var body = new CilBody();
            body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_2)); // Invalid param index
            body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            method.Body = body;

            var report = new AuditReport { CanLoad = true };
            QualityAuditor.AuditMethod(method, report);

            Assert.True(report.InvalidInstructionsCount > 0);
            Assert.Equal("FAILED", report.Status);
            Assert.Contains(report.Errors, e => e.Contains("parameters"));
        }

        [Fact]
        public void AuditMethod_InvertedExceptionHandler_StatusIsFailed()
        {
            var method = CreateDummyMethod();
            var body = new CilBody();
            var inst0 = Instruction.Create(OpCodes.Nop);
            var inst1 = Instruction.Create(OpCodes.Ret);
            body.Instructions.Add(inst0);
            body.Instructions.Add(inst1);
            method.Body = body;

            // Inverted: TryStart is at index 1, TryEnd is at index 0
            var eh = new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = inst1,
                TryEnd = inst0,
                HandlerStart = inst0,
                HandlerEnd = inst1
            };
            body.ExceptionHandlers.Add(eh);

            var report = new AuditReport { CanLoad = true };
            QualityAuditor.AuditMethod(method, report);

            Assert.True(report.InvalidInstructionsCount > 0);
            Assert.True(report.InvalidEHCount > 0);
            Assert.Equal("FAILED", report.Status);
            Assert.Contains(report.Errors, e => e.Contains("TryStart occurs after TryEnd"));
        }

        [Fact]
        public void AuditReport_ExplicitStatuses_DistinguishedCorrectly()
        {
            var report = new AuditReport
            {
                CanLoad = true,
                TotalTypes = 10,
                TotalMethods = 20,
                MethodsWithBody = 15,
                InvalidInstructionsCount = 0,
                InvalidBranchesCount = 0,
                InvalidEHCount = 0,
                StackUnderflowCount = 0,
                ILVerificationStatus = "UNVERIFIED"
            };

            // Can load and structural audit passes
            Assert.True(report.CanLoad);
            Assert.True(report.StructuralAuditPassed);

            // IL verification is explicitly distinguished as UNVERIFIED (not pretending to be verified)
            Assert.Equal("UNVERIFIED", report.ILVerificationStatus);
            Assert.False(report.ExecutionConfirmed);
            Assert.Equal("CLEAN", report.Status);

            // If an IL stack underflow occurs, structural audit fails and overall status is FAILED
            report.StackUnderflowCount = 1;
            Assert.False(report.StructuralAuditPassed);
            Assert.Equal("FAILED", report.Status);
        }
    }
}
