using System;
using System.Collections.Generic;
using ConfuserExKillerRunner.Analysis;
using dnlib.DotNet;
using Tool;

namespace ConfuserExKillerRunner.Core
{
    /// <summary>
    /// Provides atomic, transactional execution for method-level AST transformations.
    /// Snapshots the method body before transformation, validates structural invariants
    /// (branch targets, exception handler containment, evaluation stack balance) immediately after,
    /// and performs automatic in-place rollback if an exception or structural defect is detected.
    /// </summary>
    public static class MethodTransaction
    {
        public static bool ExecuteAtomic(MethodDef method, Func<bool> transform, string passName)
        {
            if (method == null || !method.HasBody || method.Body == null)
                return false;

            var originalBody = MethodBodyCloner.Clone(method.Body);
            try
            {
                bool modified = transform();
                if (!modified)
                    return false;

                if (!QualityAuditor.IsMethodStructurallyValid(method, out var errors))
                {
                    Logger.LogWarning($"[{passName}] Structural invariant violation in {method.FullName}: {string.Join("; ", errors)}. Rolling back method body.");
                    method.Body = MethodBodyCloner.Clone(originalBody);
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"[{passName}] Exception during transformation in {method.FullName}: {ex.Message}. Rolling back method body.");
                method.Body = MethodBodyCloner.Clone(originalBody);
                return false;
            }
        }

        public static bool ExecuteAtomic(MethodDef method, Action transform, string passName)
        {
            return ExecuteAtomic(method, () =>
            {
                transform();
                return true;
            }, passName);
        }
    }
}
