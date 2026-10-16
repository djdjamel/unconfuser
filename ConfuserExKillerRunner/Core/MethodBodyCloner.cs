using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet.Emit;

namespace ConfuserExKillerRunner.Core
{
    /// <summary>
    /// Provides deep cloning of dnlib CilBody instances for reliable, atomic rollbacks.
    /// Clones instructions, re-links branch and switch targets, re-links exception handlers,
    /// and duplicates local variables.
    /// </summary>
    public static class MethodBodyCloner
    {
        public static CilBody Clone(CilBody source)
        {
            if (source == null) return null;

            var newBody = new CilBody
            {
                InitLocals = source.InitLocals,
                MaxStack = source.MaxStack
            };

            // Clone local variables
            var varMap = new Dictionary<Local, Local>();
            foreach (var variable in source.Variables)
            {
                var newVar = new Local(variable.Type, variable.Name, variable.Index);
                varMap[variable] = newVar;
                newBody.Variables.Add(newVar);
            }

            // Clone instructions
            var instMap = new Dictionary<Instruction, Instruction>();
            foreach (var inst in source.Instructions)
            {
                var newInst = new Instruction(inst.OpCode, inst.Operand);
                instMap[inst] = newInst;
                newBody.Instructions.Add(newInst);
            }

            // Fix instruction operands (branches, switches, locals)
            foreach (var inst in newBody.Instructions)
            {
                if (inst.Operand is Instruction targetInst && instMap.TryGetValue(targetInst, out var newTarget))
                {
                    inst.Operand = newTarget;
                }
                else if (inst.Operand is IList<Instruction> targetList)
                {
                    inst.Operand = targetList.Select(t => instMap.TryGetValue(t, out var nt) ? nt : t).ToArray();
                }
                else if (inst.Operand is Local targetLocal && varMap.TryGetValue(targetLocal, out var newLocal))
                {
                    inst.Operand = newLocal;
                }
            }

            // Clone exception handlers
            foreach (var eh in source.ExceptionHandlers)
            {
                var newEh = new ExceptionHandler(eh.HandlerType)
                {
                    CatchType = eh.CatchType,
                    TryStart = eh.TryStart != null && instMap.TryGetValue(eh.TryStart, out var ts) ? ts : null,
                    TryEnd = eh.TryEnd != null && instMap.TryGetValue(eh.TryEnd, out var te) ? te : null,
                    HandlerStart = eh.HandlerStart != null && instMap.TryGetValue(eh.HandlerStart, out var hs) ? hs : null,
                    HandlerEnd = eh.HandlerEnd != null && instMap.TryGetValue(eh.HandlerEnd, out var he) ? he : null,
                    FilterStart = eh.FilterStart != null && instMap.TryGetValue(eh.FilterStart, out var fs) ? fs : null
                };
                newBody.ExceptionHandlers.Add(newEh);
            }

            return newBody;
        }
    }
}
