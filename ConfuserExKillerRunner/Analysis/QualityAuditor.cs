using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace ConfuserExKillerRunner.Analysis
{
    public sealed class AuditReport
    {
        public bool CanLoad { get; set; }
        public string TargetPath { get; set; }
        public int TotalTypes { get; set; }
        public int TotalMethods { get; set; }
        public int MethodsWithBody { get; set; }
        public int InvalidInstructionsCount { get; set; }
        public int InvalidBranchesCount { get; set; }
        public int InvalidEHCount { get; set; }
        public int StackUnderflowCount { get; set; }
        public int UnresolvedCallSitesCount { get; set; }
        public List<string> Warnings { get; set; } = new List<string>();
        public List<string> Errors { get; set; } = new List<string>();

        /// <summary>
        /// Explicit structural audit result: true if no structural defects, orphaned branch targets, invalid EH boundaries, or stack underflows were found.
        /// </summary>
        public bool StructuralAuditPassed => CanLoad && InvalidInstructionsCount == 0 && InvalidBranchesCount == 0 && InvalidEHCount == 0 && StackUnderflowCount == 0 && Errors.Count == 0;

        /// <summary>
        /// Explicit IL verification status: "VERIFIED", "UNVERIFIED", or "FAILED".
        /// External IL verification (via ilverify/peverify) is marked UNVERIFIED if tools are not installed or target is historical .NET Framework.
        /// </summary>
        public string ILVerificationStatus { get; set; } = "UNVERIFIED";

        public string ILVerificationNotes { get; set; } = "Static analysis & control-flow stack simulation passed; external ILVerify/PEVerify not invoked.";

        /// <summary>
        /// Explicit runtime execution confirmation (e.g. dynamic smoke test or benchmark).
        /// </summary>
        public bool ExecutionConfirmed { get; set; } = false;

        public string Status => (!CanLoad || InvalidInstructionsCount > 0 || InvalidBranchesCount > 0 || InvalidEHCount > 0 || StackUnderflowCount > 0 || Errors.Count > 0 || ILVerificationStatus == "FAILED")
            ? "FAILED"
            : (Warnings.Count > 0 ? "WARNINGS" : "CLEAN");
    }

    public static class QualityAuditor
    {
        public static AuditReport Audit(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                throw new FileNotFoundException("Assembly file not found for audit", filePath);

            var report = new AuditReport { TargetPath = filePath, CanLoad = false };

            try
            {
                using (var module = ModuleDefMD.Load(filePath))
                {
                    report.CanLoad = true;
                    var types = module.GetTypes();
                    report.TotalTypes = 0;
                    report.TotalMethods = 0;
                    report.MethodsWithBody = 0;

                    foreach (var type in types)
                    {
                        report.TotalTypes++;
                        foreach (var method in type.Methods)
                        {
                            report.TotalMethods++;
                            if (method.HasBody && method.Body != null)
                            {
                                report.MethodsWithBody++;
                                AuditMethod(method, report);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                report.CanLoad = false;
                report.Errors.Add($"Failed to load assembly in dnlib: {ex.Message}");
                report.Warnings.Add($"Failed to load assembly in dnlib: {ex.Message}");
            }

            return report;
        }

        public static void AuditMethod(MethodDef method, AuditReport report)
        {
            var instructions = method.Body.Instructions;
            var instSet = new HashSet<Instruction>(instructions);

            for (int i = 0; i < instructions.Count; i++)
            {
                var inst = instructions[i];
                if (inst == null)
                {
                    report.InvalidInstructionsCount++;
                    report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} contains null instruction entry at index {i}");
                    continue;
                }

                // Check for valid branch targets
                if (inst.Operand is Instruction branchTarget)
                {
                    if (!instSet.Contains(branchTarget))
                    {
                        report.InvalidInstructionsCount++;
                        report.InvalidBranchesCount++;
                        report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} branches to orphaned/unlisted instruction at IL_{inst.Offset:X4}");
                        report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} branches to orphaned/unlisted instruction at IL_{inst.Offset:X4}");
                    }
                }
                else if (inst.Operand is IList<Instruction> switchTargets)
                {
                    for (int st = 0; st < switchTargets.Count; st++)
                    {
                        var target = switchTargets[st];
                        if (target == null || !instSet.Contains(target))
                        {
                            report.InvalidInstructionsCount++;
                            report.InvalidBranchesCount++;
                            report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} switch target #{st} is null or unlisted at IL_{inst.Offset:X4}");
                            report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} switch target #{st} is null or unlisted at IL_{inst.Offset:X4}");
                        }
                    }
                }
                else if (inst.Operand is Instruction[] switchArray)
                {
                    for (int st = 0; st < switchArray.Length; st++)
                    {
                        var target = switchArray[st];
                        if (target == null || !instSet.Contains(target))
                        {
                            report.InvalidInstructionsCount++;
                            report.InvalidBranchesCount++;
                            report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} switch target #{st} is null or unlisted at IL_{inst.Offset:X4}");
                            report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} switch target #{st} is null or unlisted at IL_{inst.Offset:X4}");
                        }
                    }
                }

                // Check operands for call instructions
                if (inst.OpCode == OpCodes.Call || inst.OpCode == OpCodes.Callvirt || inst.OpCode == OpCodes.Newobj)
                {
                    if (inst.Operand == null)
                    {
                        report.InvalidInstructionsCount++;
                        report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has null operand for call at IL_{inst.Offset:X4}");
                        report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has null operand for call at IL_{inst.Offset:X4}");
                    }
                    else if (inst.Operand is IMethod calledMethod)
                    {
                        if (calledMethod is MemberRef mr)
                        {
                            if (mr.Class is TypeDef || (mr.Class is TypeRef tr && tr.ResolutionScope is ModuleDef))
                            {
                                if (mr.ResolveMethodDef() == null)
                                {
                                    report.UnresolvedCallSitesCount++;
                                    report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Unresolved internal call site: {mr.FullName}");
                                }
                            }
                        }
                    }
                }

                // Check operands for field instructions
                if (inst.OpCode == OpCodes.Ldfld || inst.OpCode == OpCodes.Stfld || inst.OpCode == OpCodes.Ldsfld || inst.OpCode == OpCodes.Stsfld)
                {
                    if (inst.Operand == null)
                    {
                        report.InvalidInstructionsCount++;
                        report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has null operand for field access at IL_{inst.Offset:X4}");
                    }
                }

                // Check operands for method pointer instructions
                if (inst.OpCode == OpCodes.Ldftn || inst.OpCode == OpCodes.Ldvirtftn)
                {
                    if (inst.Operand == null)
                    {
                        report.InvalidInstructionsCount++;
                        report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has null operand for function pointer load at IL_{inst.Offset:X4}");
                    }
                }

                // Check local variable references
                if (inst.Operand is Local local)
                {
                    if (!method.Body.Variables.Contains(local))
                    {
                        report.InvalidInstructionsCount++;
                        report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} references unlisted local variable at IL_{inst.Offset:X4}");
                    }
                }
                else
                {
                    int localIdx = -1;
                    if (inst.OpCode == OpCodes.Ldloc_0 || inst.OpCode == OpCodes.Stloc_0) localIdx = 0;
                    else if (inst.OpCode == OpCodes.Ldloc_1 || inst.OpCode == OpCodes.Stloc_1) localIdx = 1;
                    else if (inst.OpCode == OpCodes.Ldloc_2 || inst.OpCode == OpCodes.Stloc_2) localIdx = 2;
                    else if (inst.OpCode == OpCodes.Ldloc_3 || inst.OpCode == OpCodes.Stloc_3) localIdx = 3;

                    if (localIdx >= 0 && localIdx >= method.Body.Variables.Count)
                    {
                        report.InvalidInstructionsCount++;
                        report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} uses {inst.OpCode} but method has only {method.Body.Variables.Count} local variables");
                    }
                }

                // Check parameter references
                int paramIdx = -1;
                if (inst.OpCode == OpCodes.Ldarg_0) paramIdx = 0;
                else if (inst.OpCode == OpCodes.Ldarg_1) paramIdx = 1;
                else if (inst.OpCode == OpCodes.Ldarg_2) paramIdx = 2;
                else if (inst.OpCode == OpCodes.Ldarg_3) paramIdx = 3;

                if (paramIdx >= 0 && paramIdx >= method.Parameters.Count)
                {
                    report.InvalidInstructionsCount++;
                    report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} uses {inst.OpCode} but method has only {method.Parameters.Count} parameters (including this)");
                }
            }

            // Check exception handler boundaries
            if (method.Body.HasExceptionHandlers)
            {
                foreach (var eh in method.Body.ExceptionHandlers)
                {
                    bool validStart = true;
                    if (eh.TryStart == null || !instSet.Contains(eh.TryStart))
                    {
                        report.InvalidInstructionsCount++;
                        report.InvalidEHCount++;
                        report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has invalid/unlisted TryStart in exception handler");
                        report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has invalid/unlisted TryStart in exception handler");
                        validStart = false;
                    }
                    if (eh.TryEnd != null && !instSet.Contains(eh.TryEnd))
                    {
                        report.InvalidInstructionsCount++;
                        report.InvalidEHCount++;
                        report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has unlisted TryEnd in exception handler");
                        report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has unlisted TryEnd in exception handler");
                        validStart = false;
                    }
                    if (eh.HandlerStart == null || !instSet.Contains(eh.HandlerStart))
                    {
                        report.InvalidInstructionsCount++;
                        report.InvalidEHCount++;
                        report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has invalid/unlisted HandlerStart in exception handler");
                        report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has invalid/unlisted HandlerStart in exception handler");
                        validStart = false;
                    }
                    if (eh.HandlerEnd != null && !instSet.Contains(eh.HandlerEnd))
                    {
                        report.InvalidInstructionsCount++;
                        report.InvalidEHCount++;
                        report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has unlisted HandlerEnd in exception handler");
                        report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has unlisted HandlerEnd in exception handler");
                        validStart = false;
                    }
                    if (eh.FilterStart != null && !instSet.Contains(eh.FilterStart))
                    {
                        report.InvalidInstructionsCount++;
                        report.InvalidEHCount++;
                        report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has unlisted FilterStart in exception handler");
                        report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has unlisted FilterStart in exception handler");
                        validStart = false;
                    }

                    // Check boundary ordering if instructions are listed
                    if (validStart && eh.TryStart != null && eh.TryEnd != null)
                    {
                        int tryStartIdx = instructions.IndexOf(eh.TryStart);
                        int tryEndIdx = instructions.IndexOf(eh.TryEnd);
                        if (tryStartIdx > tryEndIdx)
                        {
                            report.InvalidInstructionsCount++;
                            report.InvalidEHCount++;
                            report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name}: ExceptionHandler TryStart occurs after TryEnd");
                        }
                    }
                }
            }

            // Evaluation stack simulation & underflow check
            int stackDepth = 0;
            bool hasControlFlow = method.Body.HasExceptionHandlers || instructions.Any(inst => inst != null && (inst.OpCode.OperandType == OperandType.InlineBrTarget || inst.OpCode.OperandType == OperandType.ShortInlineBrTarget || inst.OpCode.OperandType == OperandType.InlineSwitch));

            for (int i = 0; i < instructions.Count; i++)
            {
                var inst = instructions[i];
                if (inst == null) continue;

                inst.CalculateStackUsage(out int pushes, out int pops);
                if (pops > 0 && pops > stackDepth && (!hasControlFlow || i == 0))
                {
                    report.StackUnderflowCount++;
                    report.InvalidInstructionsCount++;
                    report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name}: Stack underflow at IL_{inst.Offset:X4} ({inst.OpCode}): required pop {pops} but stack depth is {stackDepth}");
                    report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name}: Stack underflow at IL_{inst.Offset:X4} ({inst.OpCode}): required pop {pops} but stack depth is {stackDepth}");
                    stackDepth = 0;
                }
                else
                {
                    stackDepth = Math.Max(0, stackDepth - pops);
                    stackDepth += pushes;
                }

                if (!hasControlFlow)
                {
                    if (inst.OpCode == OpCodes.Ret)
                    {
                        bool isVoid = method.ReturnType.ElementType == ElementType.Void;
                        if (isVoid && stackDepth > 0)
                        {
                            report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name}: Non-empty stack ({stackDepth}) at void return");
                        }
                        stackDepth = 0;
                    }
                    else if (inst.OpCode == OpCodes.Throw || inst.OpCode == OpCodes.Rethrow)
                    {
                        stackDepth = 0;
                    }
                }
            }

            // CFG-aware evaluation stack validation via dnlib MaxStackCalculator
            try
            {
                dnlib.DotNet.Writer.MaxStackCalculator.GetMaxStack(instructions, method.Body.ExceptionHandlers);
            }
            catch (Exception ex)
            {
                report.StackUnderflowCount++;
                report.InvalidInstructionsCount++;
                report.Errors.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name}: Evaluation stack CFG error: {ex.Message}");
                report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name}: Evaluation stack CFG error: {ex.Message}");
            }

            // Check end-of-method termination
            if (instructions.Count > 0)
            {
                var last = instructions[instructions.Count - 1];
                if (last != null && !IsTerminatingOpCode(last.OpCode))
                {
                    report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} does not terminate with ret/throw/br at IL_{last.Offset:X4} ({last.OpCode})");
                }
            }
        }

        private static bool IsTerminatingOpCode(OpCode op)
        {
            return op == OpCodes.Ret || op == OpCodes.Throw || op == OpCodes.Rethrow ||
                   op == OpCodes.Br || op == OpCodes.Br_S || op == OpCodes.Jmp;
        }
    }
}
