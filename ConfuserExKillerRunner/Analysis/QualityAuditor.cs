using System;
using System.Collections.Generic;
using System.IO;
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
        public int UnresolvedCallSitesCount { get; set; }
        public List<string> Warnings { get; set; } = new List<string>();
        public string Status => (!CanLoad || InvalidInstructionsCount > 0) ? "FAILED" : (Warnings.Count > 0 ? "WARNINGS" : "CLEAN");
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
                    continue;
                }

                // Check for valid branch targets
                if (inst.Operand is Instruction branchTarget)
                {
                    if (!instSet.Contains(branchTarget))
                    {
                        report.InvalidInstructionsCount++;
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
                            report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} switch target #{st} is null or unlisted at IL_{inst.Offset:X4}");
                        }
                    }
                }

                // Check for null operands in call instructions
                if (inst.OpCode == OpCodes.Call || inst.OpCode == OpCodes.Callvirt)
                {
                    if (inst.Operand == null)
                    {
                        report.InvalidInstructionsCount++;
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
            }

            // Check exception handler boundaries
            if (method.Body.HasExceptionHandlers)
            {
                foreach (var eh in method.Body.ExceptionHandlers)
                {
                    if (eh.TryStart == null || !instSet.Contains(eh.TryStart))
                    {
                        report.InvalidInstructionsCount++;
                        report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has invalid/unlisted TryStart in exception handler");
                    }
                    if (eh.TryEnd != null && !instSet.Contains(eh.TryEnd))
                    {
                        report.InvalidInstructionsCount++;
                        report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has unlisted TryEnd in exception handler");
                    }
                    if (eh.HandlerStart == null || !instSet.Contains(eh.HandlerStart))
                    {
                        report.InvalidInstructionsCount++;
                        report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has invalid/unlisted HandlerStart in exception handler");
                    }
                    if (eh.HandlerEnd != null && !instSet.Contains(eh.HandlerEnd))
                    {
                        report.InvalidInstructionsCount++;
                        report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has unlisted HandlerEnd in exception handler");
                    }
                    if (eh.FilterStart != null && !instSet.Contains(eh.FilterStart))
                    {
                        report.InvalidInstructionsCount++;
                        report.Warnings.Add($"[0x{method.MDToken.Raw:X8}] Method {method.Name} has unlisted FilterStart in exception handler");
                    }
                }
            }
        }
    }
}
