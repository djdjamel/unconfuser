using System.Collections.Generic;
using ConfuserExKillerRunner.Analysis;
using ConfuserExKillerRunner.Core;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    [Trait("Category", "Unit")]
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

        [Fact]
        public void AuditMethod_VoidMethodLeavesValueOnStackAfterBranch_StatusIsFailed()
        {
            var method = CreateDummyMethod(); // static void TestMethod()
            var body = new CilBody();
            var targetRet = Instruction.Create(OpCodes.Ret);
            var brInst = Instruction.Create(OpCodes.Br_S, targetRet);

            // Path branches with 1 element on stack to a void return
            body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
            body.Instructions.Add(brInst);
            body.Instructions.Add(targetRet);
            method.Body = body;

            var report = new AuditReport { CanLoad = true };
            QualityAuditor.AuditMethod(method, report);

            Assert.False(report.StructuralAuditPassed);
            Assert.True(report.StackUnderflowCount > 0);
            Assert.Contains(report.Errors, e => e.Contains("Non-empty stack") && e.Contains("void return"));
        }

        [Fact]
        public void AuditMethod_VoidMethodLeavesValueOnStackAfterSwitch_StatusIsFailed()
        {
            var method = CreateDummyMethod(); // static void TestMethod()
            var body = new CilBody();
            var targetBranch = Instruction.Create(OpCodes.Ldc_I4_2);
            var switchInst = Instruction.Create(OpCodes.Switch, new List<Instruction> { targetBranch });

            body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            body.Instructions.Add(switchInst);
            body.Instructions.Add(Instruction.Create(OpCodes.Ret)); // fallthrough return (stack 0)
            body.Instructions.Add(targetBranch); // switch target pushes 2
            body.Instructions.Add(Instruction.Create(OpCodes.Ret)); // void return with stack 1!
            method.Body = body;

            var report = new AuditReport { CanLoad = true };
            QualityAuditor.AuditMethod(method, report);

            Assert.False(report.StructuralAuditPassed);
            Assert.True(report.StackUnderflowCount > 0);
            Assert.Contains(report.Errors, e => e.Contains("Non-empty stack") && e.Contains("void return"));
        }

        [Fact]
        public void AuditMethod_VoidMethodLeavesValueOnStackInExceptionHandler_StatusIsFailed()
        {
            var method = CreateDummyMethod(); // static void TestMethod()
            var body = new CilBody();
            var exitRet = Instruction.Create(OpCodes.Ret);
            var tryLeave = Instruction.Create(OpCodes.Leave_S, exitRet);
            var handlerPop = Instruction.Create(OpCodes.Pop); // pop caught exception
            var handlerPush = Instruction.Create(OpCodes.Ldc_I4_3); // push integer
            var handlerRet = Instruction.Create(OpCodes.Ret); // void return with stack 1!

            body.Instructions.Add(tryLeave);
            body.Instructions.Add(handlerPop);
            body.Instructions.Add(handlerPush);
            body.Instructions.Add(handlerRet);
            body.Instructions.Add(exitRet);

            body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = tryLeave,
                TryEnd = handlerPop,
                HandlerStart = handlerPop,
                HandlerEnd = exitRet,
                CatchType = method.Module.CorLibTypes.Object.TypeDefOrRef
            });
            method.Body = body;

            var report = new AuditReport { CanLoad = true };
            QualityAuditor.AuditMethod(method, report);

            Assert.False(report.StructuralAuditPassed);
            Assert.True(report.StackUnderflowCount > 0);
            Assert.Contains(report.Errors, e => e.Contains("Non-empty stack") && e.Contains("void return"));
        }

        [Fact]
        public void AuditMethod_StackHeightMismatchAtCFGMergePoint_StatusIsFailed()
        {
            var method = CreateDummyMethod(); // static void TestMethod()
            var body = new CilBody();
            var mergeRet = Instruction.Create(OpCodes.Ret);
            var pathB = Instruction.Create(OpCodes.Ldc_I4_1);

            // brfalse: if condition false, branches to pathB; otherwise continues path A
            var condBr = Instruction.Create(OpCodes.Brfalse_S, pathB);

            // Entry: push condition for branch
            body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            body.Instructions.Add(condBr);

            // Path A: pushes 0 items then branches to mergeRet
            body.Instructions.Add(Instruction.Create(OpCodes.Br_S, mergeRet));

            // Path B: pushes 1 item then branches to mergeRet
            body.Instructions.Add(pathB);
            body.Instructions.Add(Instruction.Create(OpCodes.Br_S, mergeRet));

            // Merge point: incoming stack height from Path A is 0, from Path B is 1!
            body.Instructions.Add(mergeRet);
            method.Body = body;

            var report = new AuditReport { CanLoad = true };
            QualityAuditor.AuditMethod(method, report);

            Assert.False(report.StructuralAuditPassed);
            Assert.True(report.StackUnderflowCount > 0);
            Assert.Contains(report.Errors, e => e.Contains("Stack height mismatch at CFG merge point"));
        }

        [Fact]
        public void InterpretPEVerifyResult_Success_StatusIsPassedAndClean()
        {
            var report = new AuditReport { CanLoad = true };
            QualityAuditor.InterpretPEVerifyResult(0, "All Classes and Methods in test.dll Verified.", "", false, report);

            Assert.Equal("PASSED", report.ILVerificationStatus);
            Assert.Equal("CLEAN", report.Status);
            Assert.Empty(report.Errors);
        }

        [Fact]
        public void InterpretPEVerifyResult_RealILError_StatusIsFailed()
        {
            var report = new AuditReport { CanLoad = true };
            QualityAuditor.InterpretPEVerifyResult(1, "[IL]: Error: [test.dll : TestType::TestMethod][offset 0x00000001] Stack underflow.", "", false, report);

            Assert.Equal("FAILED", report.ILVerificationStatus);
            Assert.Equal("FAILED", report.Status);
            Assert.Contains(report.Errors, e => e.Contains("PEVerify reported errors"));
        }

        [Fact]
        public void InterpretPEVerifyResult_InternalError0x8013129d_StatusIsIndeterminate()
        {
            var report = new AuditReport { CanLoad = true };
            QualityAuditor.InterpretPEVerifyResult(-2146231907, ".NET Framework Internal error: 0x8013129d", "", false, report);

            Assert.Equal("INDETERMINATE", report.ILVerificationStatus);
            Assert.Equal("INDETERMINATE", report.Status);
            Assert.Empty(report.Errors);
            Assert.Contains(report.Warnings, w => w.Contains("PEVerify internal error") && w.Contains("0x8013129d"));
        }

        [Fact]
        public void InterpretPEVerifyResult_InternalErrorKeywords_StatusIsIndeterminate()
        {
            var report = new AuditReport { CanLoad = true };
            QualityAuditor.InterpretPEVerifyResult(-1, "Internal error in CLR engine", "", false, report);

            Assert.Equal("INDETERMINATE", report.ILVerificationStatus);
            Assert.Equal("INDETERMINATE", report.Status);
            Assert.Empty(report.Errors);
        }

        [Fact]
        public void InterpretPEVerifyResult_TimedOut_StatusIsIndeterminate()
        {
            var report = new AuditReport { CanLoad = true };
            QualityAuditor.InterpretPEVerifyResult(-1, "", "", true, report);

            Assert.Equal("INDETERMINATE", report.ILVerificationStatus);
            Assert.Equal("INDETERMINATE", report.Status);
            Assert.Empty(report.Errors);
            Assert.Contains(report.Warnings, w => w.Contains("timed out"));
        }

        [Fact]
        public void InterpretPEVerifyResult_EmptyOutputNonZeroExit_StatusIsIndeterminate()
        {
            var report = new AuditReport { CanLoad = true };
            QualityAuditor.InterpretPEVerifyResult(-1073741819, "", "", false, report);

            Assert.Equal("INDETERMINATE", report.ILVerificationStatus);
            Assert.Equal("INDETERMINATE", report.Status);
            Assert.Empty(report.Errors);
        }

        [Fact]
        public void InterpretILVerifyResult_Success_StatusIsPassed()
        {
            var report = new AuditReport { CanLoad = true };
            QualityAuditor.InterpretILVerifyResult(0, "All classes and methods verified.", "", false, report);

            Assert.Equal("PASSED", report.ILVerificationStatus);
            Assert.Equal("CLEAN", report.Status);
        }

        [Fact]
        public void InterpretILVerifyResult_InternalError_StatusIsIndeterminate()
        {
            var report = new AuditReport { CanLoad = true };
            QualityAuditor.InterpretILVerifyResult(1, "Fatal error: unexpected failure", "", false, report);

            Assert.Equal("INDETERMINATE", report.ILVerificationStatus);
            Assert.Equal("INDETERMINATE", report.Status);
            Assert.Empty(report.Errors);
        }

        [Fact]
        public void AuditReport_Status_Precedence_StructuralFailureOverridesIndeterminate()
        {
            var report = new AuditReport
            {
                CanLoad = true,
                InvalidInstructionsCount = 1,
                ILVerificationStatus = "INDETERMINATE"
            };

            Assert.Equal("FAILED", report.Status);
        }

        [Fact]
        public void AuditReport_Status_Precedence_IndeterminateOverridesWarnings()
        {
            var report = new AuditReport
            {
                CanLoad = true,
                ILVerificationStatus = "INDETERMINATE"
            };
            report.Warnings.Add("Some non-fatal warning");

            Assert.Equal("INDETERMINATE", report.Status);
        }

        [Fact]
        public void InterpretPEVerifyResult_FrenchInternalError_StatusIsIndeterminate()
        {
            var report = new AuditReport { CanLoad = true };
            QualityAuditor.InterpretPEVerifyResult(1, "Outil de vérification PE\nErreur interne dans le moteur CLR", "", false, report);

            Assert.Equal("INDETERMINATE", report.ILVerificationStatus);
            Assert.Equal("INDETERMINATE", report.Status);
            Assert.Empty(report.Errors);
            Assert.Contains(report.Warnings, w => w.Contains("PEVerify internal error"));
        }

        [Fact]
        public void InterpretPEVerifyResult_FrenchFatalError_StatusIsIndeterminate()
        {
            var report = new AuditReport { CanLoad = true };
            QualityAuditor.InterpretPEVerifyResult(1, "Outil de vérification PE\nErreur fatale lors de l'exécution", "", false, report);

            Assert.Equal("INDETERMINATE", report.ILVerificationStatus);
            Assert.Equal("INDETERMINATE", report.Status);
            Assert.Empty(report.Errors);
        }

        [Fact]
        public void InterpretPEVerifyILResult_FrenchUserMethodError_StatusIsFailed()
        {
            var report = new AuditReport { CanLoad = true };
            string stdout = "[IL]: Erreur : [test.dll : TestType::TestMethod][jeton :0x06000042][offset 0x0000000A] Échec de la vérification de type.";
            QualityAuditor.InterpretPEVerifyILResult(1, stdout, "", false, report);

            Assert.Equal("FAILED", report.ILVerificationStatus);
            Assert.Equal("FAILED", report.Status);
            Assert.False(report.StructuralAuditPassed);
            Assert.Single(report.Errors);
            Assert.Contains("method verification error(s)", report.ILVerificationNotes);
        }

        [Fact]
        public void InterpretPEVerifyILResult_EnglishUserMethodErrorWithMethodToken_StatusIsFailed()
        {
            var report = new AuditReport { CanLoad = true };
            // Crucial test: method token 'token :0x06000042' must NOT be classified as module stub warning!
            string stdout = "[IL]: Error: [test.dll : TestType::TestMethod][token :0x06000042][offset 0x00000010] Branch out of the method.";
            QualityAuditor.InterpretPEVerifyILResult(1, stdout, "", false, report);

            Assert.Equal("FAILED", report.ILVerificationStatus);
            Assert.Equal("FAILED", report.Status);
            Assert.False(report.StructuralAuditPassed);
            Assert.Single(report.Errors);
        }

        [Fact]
        public void InterpretPEVerifyMDResult_MetadataError_StatusIsFailed()
        {
            var report = new AuditReport { CanLoad = true };
            string stdout = "[MD]: Erreur : Le jeton TypeRef est dupliqué [jeton :0x01000002]";
            QualityAuditor.InterpretPEVerifyMDResult(1, stdout, "", false, report);

            Assert.False(report.StructuralAuditPassed);
            Assert.Equal("FAILED", report.Status);
            Assert.Single(report.Errors);
            Assert.Contains(report.Errors, e => e.Contains("metadata error(s)"));
        }

        [Fact]
        public void InterpretPEVerifyILResult_UnclassifiedOutputNonZeroExit_StatusIsIndeterminate()
        {
            var report = new AuditReport { CanLoad = true };
            string stdout = "Some unknown third-party verifier output that cannot be parsed";
            QualityAuditor.InterpretPEVerifyILResult(1, stdout, "", false, report);

            Assert.Equal("INDETERMINATE", report.ILVerificationStatus);
            Assert.Equal("INDETERMINATE", report.Status);
            Assert.Empty(report.Errors);
            Assert.Contains(report.Warnings, w => w.Contains("unclassified output"));
        }

        [Fact]
        public void DetectStructuredRegressions_WithBranchTargetError_ExtractsDefectTypeAndToken()
        {
            var baseline = new AuditReport { CanLoad = true };
            var candidate = new AuditReport
            {
                CanLoad = true,
                Errors = new List<string>
                {
                    "[IL]: Error: [offset 0x0000001B] Branch target out of range [token 0x06000015]"
                }
            };

            var diags = QualityAuditor.DetectStructuredRegressions(baseline, candidate);

            Assert.Single(diags);
            var diag = diags[0];
            Assert.Equal(DefectType.InvalidBranch, diag.DefectType);
            Assert.Equal(0x06000015u, diag.Token);
            Assert.Equal(0x1B, diag.InstructionIndex);
            Assert.Equal(DiagnosticSeverity.Error, diag.Severity);
            Assert.Contains("InvalidBranch", diag.ToString());
        }

        [Fact]
        public void DetectStructuredRegressions_WithStackUnderflow_ExtractsStackDefect()
        {
            var baseline = new AuditReport { CanLoad = true };
            var candidate = new AuditReport
            {
                CanLoad = true,
                Errors = new List<string>
                {
                    "Stack underflow in method TestMethod at IL_0005"
                }
            };

            var diags = QualityAuditor.DetectStructuredRegressions(baseline, candidate);

            Assert.Single(diags);
            var diag = diags[0];
            Assert.Equal(DefectType.StackUnderflow, diag.DefectType);
            Assert.Equal(5, diag.InstructionIndex);
        }

        [Fact]
        public void DetectStructuredRegressions_WithMetadataError_ExtractsMetadataDefect()
        {
            var baseline = new AuditReport { CanLoad = true };
            var candidate = new AuditReport
            {
                CanLoad = true,
                Errors = new List<string>
                {
                    "[MD]: Error: TypeRef duplicate [token 0x01000002]"
                }
            };

            var diags = QualityAuditor.DetectStructuredRegressions(baseline, candidate);

            Assert.Single(diags);
            var diag = diags[0];
            Assert.Equal(DefectType.MetadataError, diag.DefectType);
            Assert.Equal(0x01000002u, diag.Token);
        }

        [Fact]
        public void AuditManifestResourcesIntegrity_WhenMissingResource_ReportsError()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var formType = new TypeDefUser("TestApp", "MyForm", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(formType);

            var initMethod = new MethodDefUser("InitializeComponent", MethodSig.CreateInstance(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var crmTypeRef = new TypeRefUser(module, "System.ComponentModel", "ComponentResourceManager", module.CorLibTypes.AssemblyRef);
            var crmCtor = new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void,
                    new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                crmTypeRef);
            var getTypeFromHandle = new MemberRefUser(module, "GetTypeFromHandle",
                MethodSig.CreateStatic(new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef).ToTypeSig(),
                    new TypeRefUser(module, "System", "RuntimeTypeHandle", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef));

            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, formType));
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getTypeFromHandle));
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Newobj, crmCtor));
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            formType.Methods.Add(initMethod);

            var report = new AuditReport { CanLoad = true };
            QualityAuditor.AuditManifestResourcesIntegrity(module, report);

            Assert.NotEmpty(report.Errors);
            Assert.Contains(report.Errors, e => e.Contains("Missing Manifest Resource") && e.Contains("MyForm"));
        }

        [Fact]
        public void AuditManifestResourcesIntegrity_WhenResourcePresent_PassesClean()
        {
            var module = new ModuleDefUser("TestApp.dll");
            var formType = new TypeDefUser("TestApp", "MyForm", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(formType);

            var initMethod = new MethodDefUser("InitializeComponent", MethodSig.CreateInstance(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var crmTypeRef = new TypeRefUser(module, "System.ComponentModel", "ComponentResourceManager", module.CorLibTypes.AssemblyRef);
            var crmCtor = new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void,
                    new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                crmTypeRef);
            var getTypeFromHandle = new MemberRefUser(module, "GetTypeFromHandle",
                MethodSig.CreateStatic(new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef).ToTypeSig(),
                    new TypeRefUser(module, "System", "RuntimeTypeHandle", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                new TypeRefUser(module, "System", "Type", module.CorLibTypes.AssemblyRef));

            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, formType));
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getTypeFromHandle));
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Newobj, crmCtor));
            initMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            formType.Methods.Add(initMethod);

            module.Resources.Add(new EmbeddedResource("TestApp.MyForm.resources", new byte[] { 1, 2, 3 }));

            var report = new AuditReport { CanLoad = true };
            QualityAuditor.AuditManifestResourcesIntegrity(module, report);

            Assert.Empty(report.Errors);
        }
    }
}
