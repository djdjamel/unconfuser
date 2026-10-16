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
    }
}
