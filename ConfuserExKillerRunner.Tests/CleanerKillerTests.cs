using ConfuserExKillerRunner.Killers;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public class CleanerKillerTests
    {
        [Fact]
        public void IsReferencedInModule_TargetNotCalled_ReturnsFalse()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var targetMethod = new MethodDefUser("Target", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody { Instructions = { Instruction.Create(OpCodes.Ret) } }
            };
            type.Methods.Add(targetMethod);

            var otherMethod = new MethodDefUser("Other", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody { Instructions = { Instruction.Create(OpCodes.Nop), Instruction.Create(OpCodes.Ret) } }
            };
            type.Methods.Add(otherMethod);

            bool isRef = CleanerKiller.IsReferencedInModule(module, targetMethod);
            Assert.False(isRef);
        }

        [Fact]
        public void IsReferencedInModule_TargetCalled_ReturnsTrue()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var targetMethod = new MethodDefUser("Target", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody { Instructions = { Instruction.Create(OpCodes.Ret) } }
            };
            type.Methods.Add(targetMethod);

            var callerMethod = new MethodDefUser("Caller", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody
                {
                    Instructions =
                    {
                        Instruction.Create(OpCodes.Call, targetMethod),
                        Instruction.Create(OpCodes.Ret)
                    }
                }
            };
            type.Methods.Add(callerMethod);

            bool isRef = CleanerKiller.IsReferencedInModule(module, targetMethod);
            Assert.True(isRef);
        }

        [Fact]
        public void StripProtectorHooks_ProtectorMethodWithLiveCallers_IsRetained()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            // Create cctor
            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            globalType.Methods.Add(cctor);

            // Create synthetic protector method (matches anti-tamper via GetHINSTANCE)
            var protectorMethod = new MethodDefUser("ConfuserAntiTamper", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            // Call GetHINSTANCE to trigger classification
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr),
                new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef));
            protectorMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            protectorMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(protectorMethod);

            // Add call to protectorMethod in <Module>..cctor
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, protectorMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            // Also add another method that still references protectorMethod!
            var userType = new TypeDefUser("UserType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(userType);
            var otherCaller = new MethodDefUser("LiveMethod", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody
                {
                    Instructions =
                    {
                        Instruction.Create(OpCodes.Call, protectorMethod),
                        Instruction.Create(OpCodes.Ret)
                    }
                }
            };
            userType.Methods.Add(otherCaller);

            // Execute StripProtectorHooks
            var result = CleanerKiller.StripProtectorHooks(module);

            // cctor call was stripped (nulled)
            Assert.Equal(1, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Nop, cctor.Body.Instructions[0].OpCode);

            // Because LiveMethod still references protectorMethod, it MUST NOT be removed from globalType
            Assert.Contains(protectorMethod, globalType.Methods);
            Assert.Equal(0, result.RemovedMethodsCount);
        }

        [Fact]
        public void StripProtectorHooks_LegitimateUserClassConstructorWithInitializeArray_IsUntouched()
        {
            var module = new ModuleDefUser("TestMod");
            var userType = new TypeDefUser("UserClass", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(userType);

            // UserClass static constructor calling RuntimeHelpers.InitializeArray and AppDomain.add_AssemblyResolve
            var userCctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            var initArrayRef = new MemberRefUser(module, "InitializeArray",
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr),
                new TypeRefUser(module, "System.Runtime.CompilerServices", "RuntimeHelpers", module.CorLibTypes.AssemblyRef));
            var addResolveRef = new MemberRefUser(module, "add_AssemblyResolve",
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object),
                new TypeRefUser(module, "System", "AppDomain", module.CorLibTypes.AssemblyRef));

            userCctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, initArrayRef));
            userCctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, addResolveRef));
            userCctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            userType.Methods.Add(userCctor);

            var result = CleanerKiller.StripProtectorHooks(module);

            // CleanerKiller MUST NOT strip or touch user class constructors
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(0, result.RemovedMethodsCount);
            Assert.Equal(OpCodes.Call, userCctor.Body.Instructions[0].OpCode);
            Assert.Equal(OpCodes.Call, userCctor.Body.Instructions[1].OpCode);
            Assert.Contains(userCctor, userType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_LegitimateModuleInitializerInUserClass_IsUntouched()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            var userType = new TypeDefUser("AppInitializer", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(userType);

            // Legitimate C# 9+ [ModuleInitializer] method inside a user class
            var userInitMethod = new MethodDefUser("Init", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var initArrayRef = new MemberRefUser(module, "InitializeArray",
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr),
                new TypeRefUser(module, "System.Runtime.CompilerServices", "RuntimeHelpers", module.CorLibTypes.AssemblyRef));
            userInitMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, initArrayRef));
            userInitMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            userType.Methods.Add(userInitMethod);

            // <Module>.cctor calls AppInitializer.Init()
            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, userInitMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var result = CleanerKiller.StripProtectorHooks(module);

            // The call in <Module>.cctor is to a method declared in AppInitializer (not <Module>), so it MUST NOT be stripped
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(0, result.RemovedMethodsCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Contains(userInitMethod, userType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_ResourceResolverHook_WhenResourcesNotDecrypted_IsUntouched()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            var resolverMethod = new MethodDefUser("ResResolver", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var addResolveRef = new MemberRefUser(module, "add_ResourceResolve",
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object),
                new TypeRefUser(module, "System", "AppDomain", module.CorLibTypes.AssemblyRef));
            resolverMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, addResolveRef));
            resolverMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(resolverMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, resolverMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            // StripProtectorHooks with resourcesDecrypted = false MUST NOT touch or strip the hook
            var result = CleanerKiller.StripProtectorHooks(module, resourcesDecrypted: false);

            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(0, result.RemovedMethodsCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Contains(resolverMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_ResourceResolverHook_WhenResourcesDecrypted_IsStripped()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            var resolverMethod = new MethodDefUser("ResResolver", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var addResolveRef = new MemberRefUser(module, "add_ResourceResolve",
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object),
                new TypeRefUser(module, "System", "AppDomain", module.CorLibTypes.AssemblyRef));
            resolverMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, addResolveRef));
            resolverMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(resolverMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, resolverMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            // StripProtectorHooks with resourcesDecrypted = true MUST strip the hook
            var result = CleanerKiller.StripProtectorHooks(module, resourcesDecrypted: true);

            Assert.Equal(1, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Nop, cctor.Body.Instructions[0].OpCode);
            Assert.DoesNotContain(resolverMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_ConstantBuffer_WhenConstantsNotDecrypted_IsUntouched()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            // Create private RVA field in <Module>
            var rvaField = new FieldDefUser("FieldRva", new FieldSig(module.CorLibTypes.Byte),
                FieldAttributes.Private | FieldAttributes.Static | FieldAttributes.HasFieldRVA)
            {
                InitialValue = new byte[] { 1, 2, 3, 4 }
            };
            globalType.Fields.Add(rvaField);

            var constMethod = new MethodDefUser("ConstInit", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var initArrayRef = new MemberRefUser(module, "InitializeArray",
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr),
                new TypeRefUser(module, "System.Runtime.CompilerServices", "RuntimeHelpers", module.CorLibTypes.AssemblyRef));
            constMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, rvaField));
            constMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, initArrayRef));
            constMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(constMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, constMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            // When constantsDecrypted = false, hook is kept
            var result = CleanerKiller.StripProtectorHooks(module, constantsDecrypted: false);

            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Contains(constMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_ConstantBuffer_WhenConstantsDecrypted_IsStripped()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            var rvaField = new FieldDefUser("FieldRva", new FieldSig(module.CorLibTypes.Byte),
                FieldAttributes.Private | FieldAttributes.Static | FieldAttributes.HasFieldRVA)
            {
                InitialValue = new byte[] { 1, 2, 3, 4 }
            };
            globalType.Fields.Add(rvaField);

            var constMethod = new MethodDefUser("ConstInit", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var initArrayRef = new MemberRefUser(module, "InitializeArray",
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr),
                new TypeRefUser(module, "System.Runtime.CompilerServices", "RuntimeHelpers", module.CorLibTypes.AssemblyRef));
            constMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, rvaField));
            constMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, initArrayRef));
            constMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(constMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, constMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            // When constantsDecrypted = true, hook is stripped
            var result = CleanerKiller.StripProtectorHooks(module, constantsDecrypted: true);

            Assert.Equal(1, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Nop, cctor.Body.Instructions[0].OpCode);
            Assert.DoesNotContain(constMethod, globalType.Methods);
        }
    }
}
