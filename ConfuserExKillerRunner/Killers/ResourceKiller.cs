using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using Tool;
using MethodAttributes = dnlib.DotNet.MethodAttributes;

namespace ConfuserExKillerRunner.Killers
{
    public sealed class ResourceKillerResult
    {
        public int ExtractedResourcesCount { get; set; }
        public int DecryptedResourcesCount { get; set; }
        public int TotalManifestResourcesCount { get; set; }
        public bool HandlerStripped { get; set; }
        public bool ResourcesDecrypted { get; set; }
        public List<string> ResourceNames { get; set; } = new List<string>();
        public string Message { get; set; }
    }

    public static class ResourceKiller
    {
        public static ResourceKillerResult Execute(ModuleDefMD module, Module reflModule = null, bool resourcesAlreadyDecrypted = false)
        {
            if (module == null) throw new ArgumentNullException(nameof(module));

            var result = new ResourceKillerResult();
            if (resourcesAlreadyDecrypted)
            {
                result.ResourcesDecrypted = true;
            }

            // Stage 1: Try in-memory method-rewrite resource decryption (NoFuserEx technique)
            if (reflModule != null && !result.ResourcesDecrypted)
            {
                try
                {
                    TryDecryptAndReEmbedResources(module, result);
                }
                catch (Exception ex)
                {
                    Logger.LogWarning($"[ResourceKiller] Dynamic resource decryption warning: {ex.Message}");
                }
            }
            else if (!result.ResourcesDecrypted)
            {
                Logger.LogInfo("[ResourceKiller] Dynamic execution disabled; skipping resource decryption & re-embedding.");
            }

            // Stage 2: Strip resource / assembly resolution hooks in <Module>.cctor ONLY if resources were decrypted
            if (result.ResourcesDecrypted)
            {
                StripResourceHooksFromCctor(module, result);
            }

            // Stage 3: Audit current resources
            result.ResourceNames.Clear();
            foreach (var res in module.Resources)
            {
                result.ResourceNames.Add(res.Name.String);
            }

            result.TotalManifestResourcesCount = result.ResourceNames.Count;
            result.Message = $"Audited {result.TotalManifestResourcesCount} manifest resources ({result.DecryptedResourcesCount} decrypted and re-embedded). Hook stripped: {result.HandlerStripped}";
            return result;
        }

        internal static void TryDecryptAndReEmbedResources(ModuleDefMD module, ResourceKillerResult result)
        {
            var decrypterMethod = FindResourceDecrypterMethod(module);
            if (decrypterMethod == null || !decrypterMethod.HasBody)
                return;

            Logger.LogInfo($"[ResourceKiller] Found ConfuserEx resource decrypter: {decrypterMethod.FullName}");

            var originalBody = ConfuserExKillerRunner.Core.MethodBodyCloner.Clone(decrypterMethod.Body);
            var originalMethodSig = decrypterMethod.MethodSig;
            var originalAsmName = module.Assembly.Name;
            var cctor = module.GlobalType?.FindStaticConstructor();
            var originalCctorBody = cctor?.HasBody == true ? ConfuserExKillerRunner.Core.MethodBodyCloner.Clone(cctor.Body) : null;
            var originalResources = module.Resources.ToList();

            void Rollback()
            {
                module.Assembly.Name = originalAsmName;
                decrypterMethod.MethodSig = originalMethodSig;
                decrypterMethod.Body = ConfuserExKillerRunner.Core.MethodBodyCloner.Clone(originalBody);
                if (cctor != null && originalCctorBody != null)
                    cctor.Body = ConfuserExKillerRunner.Core.MethodBodyCloner.Clone(originalCctorBody);

                module.Resources.Clear();
                foreach (var r in originalResources)
                    module.Resources.Add(r);

                result.DecryptedResourcesCount = 0;
                result.ExtractedResourcesCount = 0;
                result.ResourcesDecrypted = false;
                result.HandlerStripped = false;
            }

            try
            {
                // Set static method signature returning byte[]
                decrypterMethod.MethodSig = MethodSig.CreateStatic(new SZArraySig(module.CorLibTypes.Byte));

                bool patchedLoad = false;
                for (int i = 0; i < decrypterMethod.Body.Instructions.Count; i++)
                {
                    var inst = decrypterMethod.Body.Instructions[i];
                    if (inst.OpCode == OpCodes.Call && inst.Operand != null)
                    {
                        string opStr = inst.Operand.ToString();
                        if (opStr.Contains("System.Reflection.Assembly::Load(System.Byte[])") ||
                            opStr.Contains("Assembly::Load"))
                        {
                            inst.OpCode = OpCodes.Ret;
                            inst.Operand = null;
                            patchedLoad = true;
                        }
                    }
                    else if (inst.OpCode == OpCodes.Ret)
                    {
                        inst.OpCode = OpCodes.Ldnull;
                        decrypterMethod.Body.Instructions.Insert(i + 1, Instruction.Create(OpCodes.Ret));
                        i++;
                    }
                }

                if (!patchedLoad)
                {
                    Logger.LogWarning("[ResourceKiller] Could not locate Assembly.Load call in decrypter method. Rolling back.");
                    Rollback();
                    return;
                }

                byte[] moduleBytes = null;
                try
                {
                    // Temporarily neutralize <Module>.cctor to prevent TypeInitializationException when tempAsm is loaded
                    if (cctor != null && cctor.HasBody)
                    {
                        cctor.Body.Instructions.Clear();
                        cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                    }

                    // Rename assembly to a unique name so the CLR does not return the already-loaded assembly
                    string tempName = "TempRes_" + Guid.NewGuid().ToString("N");
                    module.Assembly.Name = (UTF8String)tempName;

                    using (var stream = new MemoryStream())
                    {
                        var writerOpts = new ModuleWriterOptions(module) { Logger = DummyLogger.NoThrowInstance };
                        module.Write(stream, writerOpts);
                        moduleBytes = stream.ToArray();
                    }
                }
                finally
                {
                    // Guarantee that assembly name and cctor are immediately restored in moduleDef
                    module.Assembly.Name = originalAsmName;
                    if (cctor != null && originalCctorBody != null)
                        cctor.Body = ConfuserExKillerRunner.Core.MethodBodyCloner.Clone(originalCctorBody);
                }

                if (moduleBytes == null || moduleBytes.Length == 0)
                {
                    Rollback();
                    return;
                }

                var tempAsm = Assembly.Load(moduleBytes);
                var reflMethod = tempAsm.ManifestModule.ResolveMethod(decrypterMethod.MDToken.ToInt32());

                if (reflMethod == null)
                {
                    Logger.LogWarning($"[ResourceKiller] Could not locate rewritten static decrypter method {decrypterMethod.Name} in memory assembly. Rolling back.");
                    Rollback();
                    return;
                }

                string retTypeName = reflMethod is MethodInfo mi ? mi.ReturnType.FullName : reflMethod.ToString();
                Logger.LogInfo($"[ResourceKiller] Resolved in tempAsm: token=0x{decrypterMethod.MDToken.Raw:X8}, name={reflMethod.Name}, returnType={retTypeName}");

                object invokeResult = reflMethod.Invoke(null, null);
                Logger.LogInfo($"[ResourceKiller] Method invoke returned: {invokeResult?.GetType()?.FullName ?? "null"}");

                byte[] decryptedBytes = invokeResult as byte[];

                if (decryptedBytes != null && decryptedBytes.Length > 0)
                {
                    using (var resModule = ModuleDefMD.Load(decryptedBytes))
                    {
                        int count = 0;
                        var stagedAdditions = new List<Resource>();
                        var stagedRemovalNames = new HashSet<UTF8String>();

                        foreach (var res in resModule.Resources)
                        {
                            stagedRemovalNames.Add(res.Name);

                            var er = res as EmbeddedResource;
                            if (er != null)
                            {
                                // Deep copy resource data into managed byte array so disposed resModule does not invalidate the stream
                                byte[] data = er.GetResourceData();
                                var copy = new EmbeddedResource(er.Name, data, er.Attributes);
                                stagedAdditions.Add(copy);
                            }
                            else
                            {
                                stagedAdditions.Add(res);
                            }
                            count++;
                        }

                        // Atomic commit: stage resource changes before committing
                        foreach (var name in stagedRemovalNames)
                        {
                            var existing = module.Resources.Find(name);
                            if (existing != null)
                                module.Resources.Remove(existing);
                        }
                        foreach (var res in stagedAdditions)
                        {
                            module.Resources.Add(res);
                        }

                        result.DecryptedResourcesCount = count;
                        result.ExtractedResourcesCount = count;
                        result.ResourcesDecrypted = true;
                        Logger.LogInfo($"[ResourceKiller] Successfully extracted and re-embedded {count} decrypted resources from {resModule.Name}.");
                    }
                }
                else
                {
                    Logger.LogWarning("[ResourceKiller] Decrypter method returned null or empty bytes. Rolling back.");
                    Rollback();
                    return;
                }

                // Restore decrypter method signature (returns void) and stub out body to clean ret
                decrypterMethod.MethodSig = originalMethodSig;
                decrypterMethod.Body = new CilBody
                {
                    Instructions = { Instruction.Create(OpCodes.Ret) }
                };

                // Nop out calls to decrypterMethod in <Module>.cctor with atomic audit
                if (cctor != null && cctor.HasBody)
                {
                    var cctorOriginal = ConfuserExKillerRunner.Core.MethodBodyCloner.Clone(cctor.Body);
                    bool modifiedCctor = false;
                    foreach (var inst in cctor.Body.Instructions)
                    {
                        if (inst.OpCode == OpCodes.Call || inst.OpCode == OpCodes.Callvirt)
                        {
                            if (inst.Operand is IMethod called && (called == decrypterMethod || called.ResolveMethodDef() == decrypterMethod))
                            {
                                inst.OpCode = OpCodes.Nop;
                                inst.Operand = null;
                                modifiedCctor = true;
                            }
                        }
                    }
                    if (modifiedCctor && !ConfuserExKillerRunner.Analysis.QualityAuditor.IsMethodStructurallyValid(cctor, out var cctorErrors))
                    {
                        cctor.Body = cctorOriginal;
                        Logger.LogWarning($"[ResourceKiller] Neutralizing call to {decrypterMethod.Name} in <Module>.cctor failed structural audit: {string.Join("; ", cctorErrors)}. Restored cctor.");
                    }
                }
            }
            catch (Exception ex)
            {
                string innerDetail = ex.InnerException != null ? $"{ex.Message} -> {ex.InnerException.GetType().Name}: {ex.InnerException.Message}" : ex.Message;
                Logger.LogWarning($"[ResourceKiller] Method rewrite decryption failed: {innerDetail}. Rolling back decrypter method.");
                Rollback();
            }
        }

        private static void StripResourceHooksFromCctor(ModuleDefMD module, ResourceKillerResult result)
        {
            var cctor = module.GlobalType?.FindStaticConstructor();
            if (cctor == null || !cctor.HasBody || cctor.Body.Instructions == null)
                return;

            var instructions = cctor.Body.Instructions;

            // Collect branch targets within <Module>..cctor
            var branchTargets = new HashSet<Instruction>();
            foreach (var ins in instructions)
            {
                if (ins == null) continue;
                if (ins.Operand is Instruction singleTarget)
                {
                    if (singleTarget != null) branchTargets.Add(singleTarget);
                }
                else if (ins.Operand is IList<Instruction> switchTargets)
                {
                    foreach (var st in switchTargets)
                        if (st != null) branchTargets.Add(st);
                }
                else if (ins.Operand is Instruction[] switchArray)
                {
                    foreach (var st in switchArray)
                        if (st != null) branchTargets.Add(st);
                }
            }

            // Collect exception handler boundaries
            var ehBoundaries = new HashSet<Instruction>();
            if (cctor.Body.HasExceptionHandlers)
            {
                foreach (var eh in cctor.Body.ExceptionHandlers)
                {
                    if (eh.TryStart != null) ehBoundaries.Add(eh.TryStart);
                    if (eh.TryEnd != null) ehBoundaries.Add(eh.TryEnd);
                    if (eh.HandlerStart != null) ehBoundaries.Add(eh.HandlerStart);
                    if (eh.HandlerEnd != null) ehBoundaries.Add(eh.HandlerEnd);
                    if (eh.FilterStart != null) ehBoundaries.Add(eh.FilterStart);
                }
            }

            for (int i = 0; i < instructions.Count; i++)
            {
                var inst = instructions[i];
                if (inst.OpCode != OpCodes.Call && inst.OpCode != OpCodes.Callvirt)
                    continue;

                if (!(inst.Operand is IMethod called))
                    continue;

                string fullName = called.FullName;
                bool isResourceResolve = fullName.IndexOf("add_ResourceResolve", StringComparison.OrdinalIgnoreCase) >= 0;
                bool isAssemblyResolve = fullName.IndexOf("add_AssemblyResolve", StringComparison.OrdinalIgnoreCase) >= 0;

                if (!isResourceResolve && !isAssemblyResolve)
                    continue;

                if (!TryIdentifyResourceHookInstructions(instructions, i, branchTargets, ehBoundaries, out var toNeutralize, out var handlerMethod))
                {
                    Logger.LogWarning($"[ResourceKiller] Retaining {called.Name} hook in <Module>.cctor: argument sequence is ambiguous, non-standard, or intersects branches/EH boundaries.");
                    continue;
                }

                if (handlerMethod != null && handlerMethod.DeclaringType != null && !handlerMethod.DeclaringType.IsGlobalModuleType)
                {
                    Logger.LogWarning($"[ResourceKiller] Retaining {called.Name} hook in <Module>.cctor: handler {handlerMethod.FullName} belongs to a user class, not protector module.");
                    continue;
                }

                // In-place snapshot for atomic rollback
                var originalStates = toNeutralize.Select(n => (Instruction: n, OpCode: n.OpCode, Operand: n.Operand)).ToList();

                foreach (var n in toNeutralize)
                {
                    n.OpCode = OpCodes.Nop;
                    n.Operand = null;
                }

                if (!ConfuserExKillerRunner.Analysis.QualityAuditor.IsMethodStructurallyValid(cctor, out var errors))
                {
                    foreach (var s in originalStates)
                    {
                        s.Instruction.OpCode = s.OpCode;
                        s.Instruction.Operand = s.Operand;
                    }
                    Logger.LogWarning($"[ResourceKiller] Rollback in <Module>.cctor: stripping {called.Name} failed structural audit: {string.Join("; ", errors)}.");
                    continue;
                }

                result.HandlerStripped = true;
                Logger.LogInfo($"[ResourceKiller] Safely stripped resource resolver hook ({called.Name}) and {toNeutralize.Count - 1} setup instruction(s) from <Module>.cctor");
            }
        }

        private static bool TryIdentifyResourceHookInstructions(
            IList<Instruction> instructions,
            int callIndex,
            HashSet<Instruction> branchTargets,
            HashSet<Instruction> ehBoundaries,
            out List<Instruction> instructionsToNeutralize,
            out MethodDef handlerMethod)
        {
            instructionsToNeutralize = new List<Instruction>();
            handlerMethod = null;

            var callInst = instructions[callIndex];
            if (branchTargets.Contains(callInst) || ehBoundaries.Contains(callInst))
                return false;

            instructionsToNeutralize.Add(callInst);

            int curr = callIndex - 1;
            while (curr >= 0 && instructions[curr].OpCode == OpCodes.Nop)
                curr--;

            if (curr < 0) return false;
            var newobjInst = instructions[curr];
            if (newobjInst.OpCode != OpCodes.Newobj || branchTargets.Contains(newobjInst) || ehBoundaries.Contains(newobjInst))
                return false;
            instructionsToNeutralize.Add(newobjInst);

            curr--;
            while (curr >= 0 && instructions[curr].OpCode == OpCodes.Nop)
                curr--;

            if (curr < 0) return false;
            var ldftnInst = instructions[curr];
            if (ldftnInst.OpCode != OpCodes.Ldftn || branchTargets.Contains(ldftnInst) || ehBoundaries.Contains(ldftnInst))
                return false;

            if (ldftnInst.Operand is MethodDef md)
                handlerMethod = md;
            else if (ldftnInst.Operand is MemberRef mr)
                handlerMethod = mr.ResolveMethodDef();
            instructionsToNeutralize.Add(ldftnInst);

            curr--;
            while (curr >= 0 && instructions[curr].OpCode == OpCodes.Nop)
                curr--;

            if (curr < 0) return false;
            var targetObjInst = instructions[curr];
            if (branchTargets.Contains(targetObjInst) || ehBoundaries.Contains(targetObjInst))
                return false;
            if (targetObjInst.OpCode != OpCodes.Ldnull && targetObjInst.OpCode != OpCodes.Ldsfld)
                return false;
            instructionsToNeutralize.Add(targetObjInst);

            curr--;
            while (curr >= 0 && instructions[curr].OpCode == OpCodes.Nop)
                curr--;

            if (curr < 0) return false;
            var domainInst = instructions[curr];
            if (branchTargets.Contains(domainInst) || ehBoundaries.Contains(domainInst))
                return false;

            if (domainInst.OpCode == OpCodes.Call || domainInst.OpCode == OpCodes.Callvirt)
            {
                if (domainInst.Operand is IMethod m && m.Name.Contains("get_CurrentDomain"))
                {
                    instructionsToNeutralize.Add(domainInst);
                    return true;
                }
            }
            else if (domainInst.OpCode == OpCodes.Ldnull)
            {
                instructionsToNeutralize.Add(domainInst);
                return true;
            }

            return false;
        }

        private static MethodDef FindResourceDecrypterMethod(ModuleDefMD module)
        {
            var cctor = module.GlobalType?.FindStaticConstructor();
            if (cctor == null || !cctor.HasBody)
                return null;

            foreach (var inst in cctor.Body.Instructions)
            {
                if (inst.OpCode != OpCodes.Call && inst.OpCode != OpCodes.Callvirt)
                    continue;

                MethodDef md = null;
                if (inst.Operand is MethodDef def)
                    md = def;
                else if (inst.Operand is MemberRef mr)
                    md = mr.ResolveMethodDef();
                else if (inst.Operand is MethodSpec ms)
                    md = ms.Method.ResolveMethodDef() ?? (ms.Method as MethodDef);

                if (md == null || md.DeclaringType == null || !md.DeclaringType.IsGlobalModuleType || !md.IsStatic || !md.HasBody)
                    continue;

                if (md.Parameters.Count > 0)
                    continue;

                bool hasInitArray = false;
                bool hasAssemblyLoad = false;
                foreach (var mInst in md.Body.Instructions)
                {
                    if (mInst.OpCode == OpCodes.Call || mInst.OpCode == OpCodes.Callvirt)
                    {
                        if (mInst.Operand is IMethod called)
                        {
                            string fullName = called.FullName;
                            if (fullName.IndexOf("InitializeArray", StringComparison.OrdinalIgnoreCase) >= 0)
                                hasInitArray = true;
                            if (fullName.IndexOf("Assembly::Load", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                (called.DeclaringType?.FullName == "System.Reflection.Assembly" && called.Name == "Load"))
                                hasAssemblyLoad = true;
                        }
                    }
                }

                if (hasInitArray && hasAssemblyLoad)
                    return md;
            }

            return null;
        }
    }
}
