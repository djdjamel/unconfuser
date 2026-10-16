using System.IO;
using ConfuserExKillerRunner.Killers;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public class ResourceKillerTests
    {
        [Fact]
        public void TryDecryptAndReEmbedResources_NoAssemblyLoad_RollsBackAtomic()
        {
            // Build in-memory module with cctor calling a dummy decrypter method
            var module = new ModuleDefUser("TestResourceMod");
            var asm = new AssemblyDefUser("TestAssembly");
            asm.Modules.Add(module);

            var globalType = module.GlobalType;

            // Decrypter method with byte array init but NO Assembly.Load
            var decrypterMethod = new MethodDefUser("DecrypterNoLoad", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            decrypterMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 100));
            decrypterMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Newarr, module.CorLibTypes.Byte.TypeDefOrRef));
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
                    var origTarget = modMD.GlobalType.FindMethod("DecrypterNoLoad");
                    var origSig = origTarget.MethodSig.ToString();
                    int origInstCount = origTarget.Body.Instructions.Count;

                    var result = new ResourceKillerResult();
                    ResourceKiller.TryDecryptAndReEmbedResources(modMD, result);

                    // Must report not decrypted
                    Assert.False(result.ResourcesDecrypted);
                    Assert.Equal(0, result.DecryptedResourcesCount);

                    // Signature, instruction count, and assembly name must be preserved
                    Assert.Equal(origSig, origTarget.MethodSig.ToString());
                    Assert.Equal(origInstCount, origTarget.Body.Instructions.Count);
                    Assert.Equal(originalAsmName, modMD.Assembly.Name.String);
                    Assert.Equal(OpCodes.Ret, origTarget.Body.Instructions[3].OpCode);
                }
            }
        }
    }
}
