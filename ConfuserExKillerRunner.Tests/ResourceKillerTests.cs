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
    }
}
