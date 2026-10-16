using System.IO;
using System.Linq;
using ConfuserExKillerRunner.Killers;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public class ResourceKillerTests
    {
        [Fact]
        public void TryDecryptAndReEmbedResources_SatisfiesDecrypterMethod_RollsBackAtomicOnFailure()
        {
            // Build in-memory module with cctor calling a decrypter method that satisfies FindResourceDecrypterMethod
            var module = new ModuleDefUser("TestResourceMod");
            var asm = new AssemblyDefUser("TestAssembly");
            asm.Modules.Add(module);

            var globalType = module.GlobalType;

            // Existing resource that must survive rollback
            var initialResData = new byte[] { 1, 2, 3, 4, 5 };
            module.Resources.Add(new EmbeddedResource("InitialResource", initialResData));

            // Member references to satisfy FindResourceDecrypterMethod: InitializeArray and Assembly::Load
            var initArrayRef = new MemberRefUser(module, "InitializeArray",
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr),
                new TypeRefUser(module, "System.Runtime.CompilerServices", "RuntimeHelpers", module.CorLibTypes.AssemblyRef));

            var asmLoadRef = new MemberRefUser(module, "Load",
                MethodSig.CreateStatic(module.CorLibTypes.Object, new SZArraySig(module.CorLibTypes.Byte)),
                new TypeRefUser(module, "System.Reflection", "Assembly", module.CorLibTypes.AssemblyRef));

            var decrypterMethod = new MethodDefUser("ConfuserResourceDecrypter", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            decrypterMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            decrypterMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            decrypterMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, initArrayRef)); // satisfies InitializeArray
            decrypterMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            decrypterMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, asmLoadRef));    // satisfies Assembly::Load
            decrypterMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            decrypterMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(decrypterMethod);

            // cctor calling decrypterMethod
            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, decrypterMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            // Save to memory and reload as ModuleDefMD so it matches parameter type
            using (var ms = new MemoryStream())
            {
                module.Write(ms);
                using (var modMD = ModuleDefMD.Load(ms.ToArray()))
                {
                    var originalAsmName = modMD.Assembly.Name.String;
                    var origTarget = modMD.GlobalType.FindMethod("ConfuserResourceDecrypter");
                    var origSig = origTarget.MethodSig.ToString();
                    int origInstCount = origTarget.Body.Instructions.Count;
                    int origResourceCount = modMD.Resources.Count;

                    var result = new ResourceKillerResult();
                    ResourceKiller.TryDecryptAndReEmbedResources(modMD, result);

                    // Must report not decrypted
                    Assert.False(result.ResourcesDecrypted);
                    Assert.Equal(0, result.DecryptedResourcesCount);
                    Assert.Equal(0, result.ExtractedResourcesCount);

                    // Signature, instruction count, opcodes, resources, and assembly name must be preserved via rollback
                    Assert.Equal(origSig, origTarget.MethodSig.ToString());
                    Assert.Equal(origInstCount, origTarget.Body.Instructions.Count);
                    Assert.Equal(originalAsmName, modMD.Assembly.Name.String);
                    Assert.Equal(origResourceCount, modMD.Resources.Count);
                    Assert.Equal("InitialResource", modMD.Resources[0].Name.String);
                    Assert.Equal(OpCodes.Call, origTarget.Body.Instructions[4].OpCode);
                }
            }
        }

        [Fact]
        public void TryDecryptAndReEmbedResources_FailsAfterResourceChangesBegin_RollsBackAtomic()
        {
            // 1. Create a decrypted payload module that contains a decrypted resource
            var payloadMod = new ModuleDefUser("DecryptedPayloadModule");
            var payloadAsm = new AssemblyDefUser("DecryptedPayloadAssembly");
            payloadAsm.Modules.Add(payloadMod);
            payloadMod.Resources.Add(new EmbeddedResource("DecryptedExtractedResource", new byte[] { 42, 43, 44, 45 }));
            byte[] payloadBytes;
            using (var pms = new MemoryStream())
            {
                payloadMod.Write(pms);
                payloadBytes = pms.ToArray();
            }

            // 2. Build target module with initial resource
            var module = new ModuleDefUser("TestResourceMod2");
            var asm = new AssemblyDefUser("TestAssembly2");
            asm.Modules.Add(module);

            var initialResData = new byte[] { 1, 2, 3 };
            module.Resources.Add(new EmbeddedResource("InitialResource", initialResData));

            var initArrayRef = new MemberRefUser(module, "InitializeArray",
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr),
                new TypeRefUser(module, "System.Runtime.CompilerServices", "RuntimeHelpers", module.CorLibTypes.AssemblyRef));

            var asmLoadRef = new MemberRefUser(module, "Load",
                MethodSig.CreateStatic(module.CorLibTypes.Object, new SZArraySig(module.CorLibTypes.Byte)),
                new TypeRefUser(module, "System.Reflection", "Assembly", module.CorLibTypes.AssemblyRef));

            var decrypterMethod = new MethodDefUser("ConfuserResourceDecrypter", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };

            // Satisfy InitializeArray
            decrypterMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            decrypterMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            decrypterMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, initArrayRef));

            // Push payloadBytes onto stack using array initializer
            var arrayInitInstrs = ConfuserExTools.ConstantKiller.ConstantKillerImpl.CreateArrayInitializer(
                module, module.CorLibTypes.Byte.TypeDefOrRef, payloadBytes.Length, payloadBytes);
            foreach (var inst in arrayInitInstrs)
                decrypterMethod.Body.Instructions.Add(inst);

            // Call Assembly.Load(payloadBytes) -> patched to Ret returning payloadBytes!
            decrypterMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, asmLoadRef));
            decrypterMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            decrypterMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            module.GlobalType.Methods.Add(decrypterMethod);

            // cctor calling decrypterMethod
            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, decrypterMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            module.GlobalType.Methods.Add(cctor);

            using (var ms = new MemoryStream())
            {
                module.Write(ms);
                using (var modMD = ModuleDefMD.Load(ms.ToArray()))
                {
                    var originalAsmName = modMD.Assembly.Name.String;
                    var origTarget = modMD.GlobalType.FindMethod("ConfuserResourceDecrypter");
                    var origSig = origTarget.MethodSig.ToString();
                    int origInstCount = origTarget.Body.Instructions.Count;
                    int origResourceCount = modMD.Resources.Count;

                    // Inject ThrowingMemberRef into cctor so that after resources are extracted and embedded,
                    // post-processing of cctor instructions throws and forces rollback
                    var targetCctor = modMD.GlobalType.FindStaticConstructor();
                    int origCctorInstCount = targetCctor.Body.Instructions.Count;
                    var throwingRef = new ThrowingMemberRef(modMD, "ThrowingCall", MethodSig.CreateStatic(modMD.CorLibTypes.Void), modMD.CorLibTypes.Object.TypeDefOrRef);
                    targetCctor.Body.Instructions.Insert(1, Instruction.Create(OpCodes.Call, throwingRef));

                    var result = new ResourceKillerResult();
                    ResourceKiller.TryDecryptAndReEmbedResources(modMD, result);

                    // 1. Verify that rollback cleared result counters
                    Assert.False(result.ResourcesDecrypted);
                    Assert.Equal(0, result.DecryptedResourcesCount);
                    Assert.Equal(0, result.ExtractedResourcesCount);

                    // 2. Verify that injected resource was discarded and original resource was restored
                    Assert.Equal(origResourceCount, modMD.Resources.Count);
                    Assert.Equal("InitialResource", modMD.Resources[0].Name.String);
                    Assert.DoesNotContain(modMD.Resources, r => r.Name.String == "DecryptedExtractedResource");

                    // 3. Verify that decrypter method signature and body are restored
                    Assert.Equal(origSig, origTarget.MethodSig.ToString());
                    Assert.Equal(origInstCount, origTarget.Body.Instructions.Count);

                    // 4. Verify assembly name is restored
                    Assert.Equal(originalAsmName, modMD.Assembly.Name.String);

                    // 5. Verify cctor is restored from original snapshot
                    Assert.NotNull(modMD.GlobalType.FindStaticConstructor());
                    Assert.Equal(origCctorInstCount + 1, modMD.GlobalType.FindStaticConstructor().Body.Instructions.Count);
                }
            }
        }
    }

    internal class ThrowingMemberRef : MemberRefUser, dnlib.DotNet.IFullName
    {
        public ThrowingMemberRef(ModuleDef module, UTF8String name, MethodSig sig, IMemberRefParent parent)
            : base(module, name, sig, parent)
        {
        }

        UTF8String dnlib.DotNet.IFullName.Name
        {
            get => throw new System.InvalidOperationException("Forced failure after resource extraction in cctor cleanup");
            set => base.Name = value;
        }
    }
}
