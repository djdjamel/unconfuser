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
        public void Execute_DynamicExecutionDisabled_HooksRemainIntact()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            var addResolveRef = new MemberRefUser(module, "add_ResourceResolve",
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object),
                new TypeRefUser(module, "System", "AppDomain", module.CorLibTypes.AssemblyRef));

            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, addResolveRef));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            // Save to memory to get a ModuleDefMD
            byte[] moduleBytes;
            using (var ms = new MemoryStream())
            {
                module.Write(ms);
                moduleBytes = ms.ToArray();
            }

            using (var moduleMD = ModuleDefMD.Load(moduleBytes))
            {
                var result = ResourceKiller.Execute(moduleMD, reflModule: null);

                Assert.False(result.ResourcesDecrypted);
                Assert.False(result.HandlerStripped);

                var loadedCctor = moduleMD.GlobalType.FindStaticConstructor();
                Assert.NotNull(loadedCctor);
                Assert.Equal(OpCodes.Call, loadedCctor.Body.Instructions[1].OpCode);
            }
        }

        [Fact]
        public void Execute_DecryptionFailed_RollsBackAndPreservesHooks()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            // Create a fake decrypter method that has InitializeArray and Assembly.Load but cannot run / fails
            var decrypter = new MethodDefUser("ResDecrypter", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var initArrayRef = new MemberRefUser(module, "InitializeArray",
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr),
                new TypeRefUser(module, "System.Runtime.CompilerServices", "RuntimeHelpers", module.CorLibTypes.AssemblyRef));
            var asmLoadRef = new MemberRefUser(module, "Load",
                MethodSig.CreateStatic(module.CorLibTypes.Object, new SZArraySig(module.CorLibTypes.Byte)),
                new TypeRefUser(module, "System.Reflection", "Assembly", module.CorLibTypes.AssemblyRef));

            decrypter.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            decrypter.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            decrypter.Body.Instructions.Add(Instruction.Create(OpCodes.Call, initArrayRef));
            decrypter.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            decrypter.Body.Instructions.Add(Instruction.Create(OpCodes.Call, asmLoadRef));
            decrypter.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            decrypter.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(decrypter);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            var addResolveRef = new MemberRefUser(module, "add_ResourceResolve",
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object),
                new TypeRefUser(module, "System", "AppDomain", module.CorLibTypes.AssemblyRef));

            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, decrypter));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, addResolveRef));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            // Add dummy resource
            var dummyRes = new EmbeddedResource("TestResource", new byte[] { 1, 2, 3 });
            module.Resources.Add(dummyRes);

            byte[] moduleBytes;
            using (var ms = new MemoryStream())
            {
                module.Write(ms);
                moduleBytes = ms.ToArray();
            }

            using (var moduleMD = ModuleDefMD.Load(moduleBytes))
            {
                var result = new ResourceKillerResult();
                // Calling TryDecryptAndReEmbedResources directly; since tempAsm invoke will fail or return null, it will rollback
                ResourceKiller.TryDecryptAndReEmbedResources(moduleMD, result);

                Assert.False(result.ResourcesDecrypted);
                Assert.False(result.HandlerStripped);

                // Check rollback preserved resources
                Assert.Single(moduleMD.Resources);
                Assert.Equal("TestResource", moduleMD.Resources[0].Name);

                // Check rollback preserved cctor call to decrypter
                var loadedCctor = moduleMD.GlobalType.FindStaticConstructor();
                Assert.NotNull(loadedCctor);
                Assert.Equal(OpCodes.Call, loadedCctor.Body.Instructions[0].OpCode);
                Assert.Equal(OpCodes.Call, loadedCctor.Body.Instructions[2].OpCode);
            }
        }

        [Fact]
        public void Execute_ResourcesAlreadyDecrypted_StripsHookSafely()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            var handlerMethod = new MethodDefUser("ResHandler", MethodSig.CreateStatic(module.CorLibTypes.Object, module.CorLibTypes.Object, module.CorLibTypes.Object))
            {
                Body = new CilBody { Instructions = { Instruction.Create(OpCodes.Ldnull), Instruction.Create(OpCodes.Ret) } }
            };
            globalType.Methods.Add(handlerMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };

            var getDomainRef = new MemberRefUser(module, "get_CurrentDomain",
                MethodSig.CreateStatic(new TypeRefUser(module, "System", "AppDomain", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                new TypeRefUser(module, "System", "AppDomain", module.CorLibTypes.AssemblyRef));

            var resolveHandlerRef = new TypeRefUser(module, "System", "ResolveEventHandler", module.CorLibTypes.AssemblyRef);
            var handlerCtorRef = new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr),
                resolveHandlerRef);

            var addResolveRef = new MemberRefUser(module, "add_ResourceResolve",
                MethodSig.CreateInstance(module.CorLibTypes.Void, resolveHandlerRef.ToTypeSig()),
                new TypeRefUser(module, "System", "AppDomain", module.CorLibTypes.AssemblyRef));

            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getDomainRef));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldftn, handlerMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Newobj, handlerCtorRef));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, addResolveRef));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            byte[] moduleBytes;
            using (var ms = new MemoryStream())
            {
                module.Write(ms);
                moduleBytes = ms.ToArray();
            }

            using (var moduleMD = ModuleDefMD.Load(moduleBytes))
            {
                var result = ResourceKiller.Execute(moduleMD, reflModule: null, resourcesAlreadyDecrypted: true);

                Assert.True(result.ResourcesDecrypted);
                Assert.True(result.HandlerStripped);

                var loadedCctor = moduleMD.GlobalType.FindStaticConstructor();
                Assert.NotNull(loadedCctor);
                Assert.Equal(OpCodes.Nop, loadedCctor.Body.Instructions[0].OpCode);
                Assert.Equal(OpCodes.Nop, loadedCctor.Body.Instructions[1].OpCode);
                Assert.Equal(OpCodes.Nop, loadedCctor.Body.Instructions[2].OpCode);
                Assert.Equal(OpCodes.Nop, loadedCctor.Body.Instructions[3].OpCode);
                Assert.Equal(OpCodes.Nop, loadedCctor.Body.Instructions[4].OpCode);
                Assert.Equal(OpCodes.Ret, loadedCctor.Body.Instructions[5].OpCode);
            }
        }

        [Fact]
        public void Execute_UserClassHandler_RetainsHookUntouched()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            var userType = new TypeDefUser("UserType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(userType);

            var userHandlerMethod = new MethodDefUser("UserHandler", MethodSig.CreateStatic(module.CorLibTypes.Object, module.CorLibTypes.Object, module.CorLibTypes.Object))
            {
                Body = new CilBody { Instructions = { Instruction.Create(OpCodes.Ldnull), Instruction.Create(OpCodes.Ret) } }
            };
            userType.Methods.Add(userHandlerMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };

            var getDomainRef = new MemberRefUser(module, "get_CurrentDomain",
                MethodSig.CreateStatic(new TypeRefUser(module, "System", "AppDomain", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                new TypeRefUser(module, "System", "AppDomain", module.CorLibTypes.AssemblyRef));

            var resolveHandlerRef = new TypeRefUser(module, "System", "ResolveEventHandler", module.CorLibTypes.AssemblyRef);
            var handlerCtorRef = new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr),
                resolveHandlerRef);

            var addResolveRef = new MemberRefUser(module, "add_AssemblyResolve",
                MethodSig.CreateInstance(module.CorLibTypes.Void, resolveHandlerRef.ToTypeSig()),
                new TypeRefUser(module, "System", "AppDomain", module.CorLibTypes.AssemblyRef));

            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getDomainRef));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldftn, userHandlerMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Newobj, handlerCtorRef));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, addResolveRef));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            byte[] moduleBytes;
            using (var ms = new MemoryStream())
            {
                module.Write(ms);
                moduleBytes = ms.ToArray();
            }

            using (var moduleMD = ModuleDefMD.Load(moduleBytes))
            {
                // Even though resourcesAlreadyDecrypted is true, user class handler MUST NOT be stripped!
                var result = ResourceKiller.Execute(moduleMD, reflModule: null, resourcesAlreadyDecrypted: true);

                Assert.True(result.ResourcesDecrypted);
                Assert.False(result.HandlerStripped);

                var loadedCctor = moduleMD.GlobalType.FindStaticConstructor();
                Assert.NotNull(loadedCctor);
                Assert.Equal(OpCodes.Call, loadedCctor.Body.Instructions[0].OpCode);
                Assert.Equal(OpCodes.Ldftn, loadedCctor.Body.Instructions[2].OpCode);
                Assert.Equal(OpCodes.Callvirt, loadedCctor.Body.Instructions[4].OpCode);
            }
        }

        [Fact]
        public void Execute_BranchTargetInHookSetup_RetainsHookUntouched()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            var handlerMethod = new MethodDefUser("ResHandler", MethodSig.CreateStatic(module.CorLibTypes.Object, module.CorLibTypes.Object, module.CorLibTypes.Object))
            {
                Body = new CilBody { Instructions = { Instruction.Create(OpCodes.Ldnull), Instruction.Create(OpCodes.Ret) } }
            };
            globalType.Methods.Add(handlerMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };

            var getDomainRef = new MemberRefUser(module, "get_CurrentDomain",
                MethodSig.CreateStatic(new TypeRefUser(module, "System", "AppDomain", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                new TypeRefUser(module, "System", "AppDomain", module.CorLibTypes.AssemblyRef));

            var resolveHandlerRef = new TypeRefUser(module, "System", "ResolveEventHandler", module.CorLibTypes.AssemblyRef);
            var handlerCtorRef = new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr),
                resolveHandlerRef);

            var addResolveRef = new MemberRefUser(module, "add_ResourceResolve",
                MethodSig.CreateInstance(module.CorLibTypes.Void, resolveHandlerRef.ToTypeSig()),
                new TypeRefUser(module, "System", "AppDomain", module.CorLibTypes.AssemblyRef));

            var branchTargetInst = Instruction.Create(OpCodes.Call, getDomainRef);

            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Brtrue_S, branchTargetInst));
            cctor.Body.Instructions.Add(branchTargetInst);
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldftn, handlerMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Newobj, handlerCtorRef));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, addResolveRef));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            byte[] moduleBytes;
            using (var ms = new MemoryStream())
            {
                module.Write(ms);
                moduleBytes = ms.ToArray();
            }

            using (var moduleMD = ModuleDefMD.Load(moduleBytes))
            {
                var result = ResourceKiller.Execute(moduleMD, reflModule: null, resourcesAlreadyDecrypted: true);

                // Because branchTargetInst is targeted by brtrue_s, hook setup cannot be safely neutralized
                Assert.False(result.HandlerStripped);

                var loadedCctor = moduleMD.GlobalType.FindStaticConstructor();
                Assert.NotNull(loadedCctor);
                Assert.Equal(OpCodes.Callvirt, loadedCctor.Body.Instructions[6].OpCode);
            }
        }
    }
}
