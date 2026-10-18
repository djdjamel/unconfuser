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
        public static ResourceKillerResult Execute(ModuleDefMD module, Module reflModule = null)
        {
            if (module == null) throw new ArgumentNullException(nameof(module));

            var result = new ResourceKillerResult();

            // Stage 1: Try in-memory method-rewrite resource decryption (NoFuserEx technique)
            if (reflModule != null)
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
            else
            {
                Logger.LogInfo("[ResourceKiller] Dynamic execution disabled; skipping resource decryption & re-embedding.");
            }

            // Stage 2: Strip resource / assembly resolution hooks in <Module>.cctor ONLY if resources were decrypted
            if (result.ResourcesDecrypted)
            {
                var cctor = module.GlobalType?.FindStaticConstructor();
                if (cctor != null && cctor.HasBody)
                {
                    var instrs = cctor.Body.Instructions;
                    for (int i = 0; i < instrs.Count; i++)
                    {
                        var inst = instrs[i];
                        if (inst.OpCode == OpCodes.Call || inst.OpCode == OpCodes.Callvirt)
                        {
                            if (inst.Operand is IMethod called)
                            {
                                string fullName = called.FullName;
                                if (fullName.IndexOf("add_ResourceResolve", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                    fullName.IndexOf("add_AssemblyResolve", StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    inst.OpCode = OpCodes.Nop;
                                    inst.Operand = null;
                                    for (int j = i - 1; j >= 0 && j >= i - 5; j--)
                                    {
                                        if (instrs[j].OpCode == OpCodes.Newobj ||
                                            instrs[j].OpCode == OpCodes.Ldftn ||
                                            instrs[j].OpCode == OpCodes.Ldnull ||
                                            instrs[j].OpCode == OpCodes.Call)
                                        {
                                            instrs[j].OpCode = OpCodes.Nop;
                                            instrs[j].Operand = null;
                                        }
                                    }
                                    result.HandlerStripped = true;
                                    Logger.LogInfo($"[ResourceKiller] Stripped resource resolver hook ({called.Name}) from <Module>.cctor");
                                }
                            }
                        }
                    }
                }
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

                // Nop out calls to decrypterMethod in <Module>.cctor
                if (cctor != null && cctor.HasBody)
                {
                    foreach (var inst in cctor.Body.Instructions)
                    {
                        if (inst.OpCode == OpCodes.Call || inst.OpCode == OpCodes.Callvirt)
                        {
                            if (inst.Operand is IMethod called && (called == decrypterMethod || called.ResolveMethodDef() == decrypterMethod))
                            {
                                inst.OpCode = OpCodes.Nop;
                                inst.Operand = null;
                            }
                        }
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

        private static MethodDef FindResourceDecrypterMethod(ModuleDefMD module)
        {
            var cctor = module.GlobalType?.FindStaticConstructor();
            if (cctor == null || !cctor.HasBody)
                return null;

            foreach (var inst in cctor.Body.Instructions)
            {
                if (inst.OpCode != OpCodes.Call || !(inst.Operand is MethodDef md))
                    continue;

                if (!md.DeclaringType.IsGlobalModuleType || !md.IsStatic || !md.HasBody)
                    continue;

                if (md.Parameters.Count > 0)
                    continue;

                bool hasInitArray = false;
                bool hasAssemblyLoad = false;
                foreach (var mInst in md.Body.Instructions)
                {
                    if (mInst.OpCode == OpCodes.Call && mInst.Operand != null)
                    {
                        string opStr = mInst.Operand.ToString();
                        if (opStr.Contains("InitializeArray")) hasInitArray = true;
                        if (opStr.Contains("Assembly::Load")) hasAssemblyLoad = true;
                    }
                }

                if (hasInitArray && hasAssemblyLoad)
                    return md;
            }

            return null;
        }
    }
}
