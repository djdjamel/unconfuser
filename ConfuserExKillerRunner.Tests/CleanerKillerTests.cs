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

            // Create synthetic protector method (matches exact protector stub via GetHINSTANCE)
            var protectorMethod = new MethodDefUser("ConfuserAntiTamper", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            // Call Marshal.GetHINSTANCE(Module) to trigger canonical stub classification
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef));
            protectorMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            protectorMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            protectorMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
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

            // Execute StripProtectorHooks with antiTamperDecrypted: true
            var result = CleanerKiller.StripProtectorHooks(module, antiTamperDecrypted: true);

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

        [Fact]
        public void StripProtectorHooks_AntiTamper_WhenAntiTamperNotDecrypted_IsRetained()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            var atMethod = new MethodDefUser("RealAntiTamperInit", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var vpRef = new MemberRefUser(module, "VirtualProtect",
                MethodSig.CreateStatic(module.CorLibTypes.Boolean),
                new TypeRefUser(module, string.Empty, "Kernel32", module.CorLibTypes.AssemblyRef));
            var secField = new FieldDefUser("VirtualAddress", new FieldSig(module.CorLibTypes.Int32));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldfld, secField));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(atMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, atMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            // When antiTamperDecrypted = false (e.g. pure static analysis mode or section changes unconfirmed), Anti-Tamper hook MUST be retained
            var result = CleanerKiller.StripProtectorHooks(module, antiTamperDecrypted: false);

            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Equal(atMethod, cctor.Body.Instructions[0].Operand);
            Assert.Contains(atMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_AntiTamper_WhenAntiTamperDecrypted_IsStripped()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            var atMethod = new MethodDefUser("RealAntiTamperInit", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var vpRef = new MemberRefUser(module, "VirtualProtect",
                MethodSig.CreateStatic(module.CorLibTypes.Boolean),
                new TypeRefUser(module, string.Empty, "Kernel32", module.CorLibTypes.AssemblyRef));
            var secField = new FieldDefUser("VirtualAddress", new FieldSig(module.CorLibTypes.Int32));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldfld, secField));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(atMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, atMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            // When antiTamperDecrypted = true (dynamic execution or unpacker confirmed section decryption), hook is safely stripped
            var result = CleanerKiller.StripProtectorHooks(module, antiTamperDecrypted: true);

            Assert.Equal(1, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Nop, cctor.Body.Instructions[0].OpCode);
            Assert.DoesNotContain(atMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_HelperWithApplicationLogicAndGetHINSTANCE_IsPreserved()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            // A helper that calls GetHINSTANCE, but also has local variables and arithmetic
            var helperMethod = new MethodDefUser("AntiTamperHelper", MethodSig.CreateStatic(module.CorLibTypes.Int32))
            {
                Body = new CilBody()
            };
            helperMethod.Body.Variables.Add(new Local(module.CorLibTypes.Int32));
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr),
                new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            helperMethod.Body.Instructions.Add(Instruction.CreateLdcI4(123));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(helperMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, helperMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            // Because helperMethod is NOT a pure 2-4 instruction stub, it MUST be preserved
            var result = CleanerKiller.StripProtectorHooks(module);

            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Contains(helperMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_ExactStubWithGetHINSTANCE_IsStripped()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            var moduleTypeRef = new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef);
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, moduleTypeRef.ToTypeSig()),
                new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef));

            // Representative ConfuserEx hook fixture:
            // ConfuserEx emits a parameterless static protector method in <Module> (e.g. Anti-Tamper/Cleaner stub).
            // Inside the stub: ldnull; call Marshal.GetHINSTANCE; pop; ret;
            // The caller in <Module>..cctor does NOT pass any arguments: simply calls the parameterless stub.
            //
            // Justification for stripping this hook:
            // 1. Anti-Tamper/Cleaner stubs in ConfuserEx execute during module initialization to decrypt code
            //    or install runtime integrity hooks prior to user code execution.
            // 2. Once Unconfuser has successfully decrypted and restored the protected methods in the PE image,
            //    the hook has completed its role.
            // 3. Leaving this hook in <Module>..cctor would cause it to re-execute at runtime when the restored assembly
            //    is executed, which would attempt to re-decrypt already-plaintext code or fail on restored PE headers.
            // 4. Safely stripping this hook call from <Module>..cctor returns the module constructor to a clean, runnable state.
            var stubMethod = new MethodDefUser("ConfuserProtectorInit_ExactStub",
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(stubMethod);

            // <Module>..cctor calls the parameterless protector hook
            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, stubMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            // Structurally verified stub is stripped
            var result = CleanerKiller.StripProtectorHooks(module);

            Assert.Equal(1, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Nop, cctor.Body.Instructions[0].OpCode);
            Assert.DoesNotContain(stubMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_ArgumentProducedByFieldAccess_IsPreserved()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;
            var field = new FieldDefUser("HookArgField", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Public | FieldAttributes.Static);
            globalType.Fields.Add(field);

            var stubMethod = new MethodDefUser("HookWithParam", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32))
            {
                Body = new CilBody()
            };
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(stubMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldsfld, field)); // Field access producer!
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, stubMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Field access producer is unsupported -> hook must be preserved to prevent stack debris
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[1].OpCode);
            Assert.Contains(stubMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_ArgumentProducedByMethodCall_IsPreserved()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;
            var helper = new MethodDefUser("GetArg", MethodSig.CreateStatic(module.CorLibTypes.Int32))
            {
                Body = new CilBody { Instructions = { Instruction.Create(OpCodes.Ldc_I4_0), Instruction.Create(OpCodes.Ret) } }
            };
            globalType.Methods.Add(helper);

            var stubMethod = new MethodDefUser("HookWithParam", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32))
            {
                Body = new CilBody()
            };
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(stubMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, helper)); // Call producer!
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, stubMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Call producer is unsupported -> hook must be preserved
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[1].OpCode);
            Assert.Contains(stubMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_ArgumentProducedByMultipleInstructions_IsPreserved()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            var stubMethod = new MethodDefUser("HookWithParam", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32))
            {
                Body = new CilBody()
            };
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(stubMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            // Multi-instruction expression: 1 + 2 = 3
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_2));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Add)); // Pops 2, pushes 1!
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, stubMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Multi-instruction producer is unsupported -> hook must be preserved
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[3].OpCode);
            Assert.Contains(stubMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_ArgumentProducerIsBranchTarget_IsPreserved()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            var stubMethod = new MethodDefUser("HookWithParam", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32))
            {
                Body = new CilBody()
            };
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(stubMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            var argInst = Instruction.Create(OpCodes.Ldc_I4_0);
            var brInst = Instruction.Create(OpCodes.Br_S, argInst); // Branch targets the argument producer!
            cctor.Body.Instructions.Add(brInst);
            cctor.Body.Instructions.Add(argInst);
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, stubMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Branch target producer must not be neutralized -> hook preserved
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[2].OpCode);
            Assert.Contains(stubMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_ArgumentProducerCrossesEHBoundary_IsPreserved()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            var stubMethod = new MethodDefUser("HookWithParam", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32))
            {
                Body = new CilBody()
            };
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(stubMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            var iTryStart = Instruction.Create(OpCodes.Ldc_I4_0); // Inside try block
            var iCall = Instruction.Create(OpCodes.Call, stubMethod); // Outside try block (handler)
            var iRet = Instruction.Create(OpCodes.Ret);

            cctor.Body.Instructions.Add(iTryStart);
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Leave_S, iRet));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            cctor.Body.Instructions.Add(iCall);
            cctor.Body.Instructions.Add(iRet);

            cctor.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = iTryStart,
                TryEnd = cctor.Body.Instructions[2],
                HandlerStart = cctor.Body.Instructions[2],
                HandlerEnd = iRet,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            });
            globalType.Methods.Add(cctor);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Crosses EH boundary -> hook preserved
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, iCall.OpCode);
            Assert.Contains(stubMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_AtomicRollbackOnCorruptedBody_RestoresOriginalBody()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            var stubMethod = new MethodDefUser("ConfuserStub", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(stubMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            // cctor: call stubMethod; pop; ret;
            // When call is nopped, the following pop instruction underflows the evaluation stack (pops 1 from stack 0).
            // The atomic post-strip audit will detect the stack underflow and trigger rollback to restore the original body.
            var callInst = Instruction.Create(OpCodes.Call, stubMethod);
            var popInst = Instruction.Create(OpCodes.Pop);
            var retInst = Instruction.Create(OpCodes.Ret);
            cctor.Body.Instructions.Add(callInst);
            cctor.Body.Instructions.Add(popInst);
            cctor.Body.Instructions.Add(retInst);
            globalType.Methods.Add(cctor);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Because stripping causes a stack underflow at pop, rollback must restore the original IL
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Equal(stubMethod, cctor.Body.Instructions[0].Operand);
            Assert.Contains(stubMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_CallvirtOnGetHINSTANCE_IsPreserved()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            var moduleTypeRef = new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef);
            var helperMethod = new MethodDefUser("CallvirtStub",
                MethodSig.CreateStatic(module.CorLibTypes.Void, moduleTypeRef.ToTypeSig()),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, moduleTypeRef.ToTypeSig()),
                new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef));

            // Uses Callvirt instead of Call for static method -> rejected!
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, getHinstanceRef));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(helperMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, helperMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Method using Callvirt on GetHINSTANCE must NOT be classified as stub and must be preserved
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[1].OpCode);
            Assert.Contains(helperMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_HomonymousMarshalInAppAssembly_IsPreserved()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            var moduleTypeRef = new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef);
            var helperMethod = new MethodDefUser("AppMarshalStub",
                MethodSig.CreateStatic(module.CorLibTypes.Void, moduleTypeRef.ToTypeSig()),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };

            // Declaring type named Marshal in System.Runtime.InteropServices, BUT resolving to non-framework app assembly!
            var customAsmRef = new AssemblyRefUser(new AssemblyNameInfo("CustomAppLibrary"));
            var customMarshalRef = new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", customAsmRef);
            var customGetHinstance = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, moduleTypeRef.ToTypeSig()),
                customMarshalRef);

            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, customGetHinstance));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(helperMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, helperMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Must NOT strip method referencing a homonymous Marshal class defined in an application/third-party assembly
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[1].OpCode);
            Assert.Contains(helperMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_StubWithObservableSideEffects_IsPreserved()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            // Define a static field to record state
            var stateField = new FieldDefUser("StateField", new FieldSig(module.CorLibTypes.IntPtr),
                FieldAttributes.Public | FieldAttributes.Static);
            globalType.Fields.Add(stateField);

            var moduleTypeRef = new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef);
            var helperMethod = new MethodDefUser("SideEffectStub",
                MethodSig.CreateStatic(module.CorLibTypes.Void, moduleTypeRef.ToTypeSig()),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, moduleTypeRef.ToTypeSig()),
                new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef));

            // Instead of pop, stores result in a static field (observable side-effect!)
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Stsfld, stateField));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(helperMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, helperMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Method with observable side effects must NOT be stripped
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[1].OpCode);
            Assert.Contains(helperMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_HomonymousGetHINSTANCEOnDifferentType_IsPreserved()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            // Method calls CustomAppHelper.GetHINSTANCE(Module), NOT Marshal.GetHINSTANCE
            var helperMethod = new MethodDefUser("AppHelperStub", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            var customGetHinstance = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                new TypeRefUser(module, "CustomAppNamespace", "AppHelper", module.CorLibTypes.AssemblyRef));

            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, customGetHinstance));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(helperMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, helperMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Must NOT strip helper method with homonymous method on different declaring type
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Contains(helperMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_GetHINSTANCEWithIncorrectSignature_IsPreserved()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            // Method calls Marshal.GetHINSTANCE(string) instead of Marshal.GetHINSTANCE(Module)
            var helperMethod = new MethodDefUser("WrongSigStub", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            var wrongSigRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, module.CorLibTypes.String),
                new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef));

            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, wrongSigRef));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(helperMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, helperMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Must NOT strip method calling GetHINSTANCE with non-Module parameter signature
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Contains(helperMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_StubWithScrambledStackOrder_IsPreserved()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            // Method with scrambled instruction sequence (e.g., pop; ldnull; call; ret)
            var helperMethod = new MethodDefUser("ScrambledStub", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef));

            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(helperMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, helperMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Non-canonical stack sequence must be preserved
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Contains(helperMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_StubReturningVoidWithoutPop_IsPreserved()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            // Void return method without pop: ldnull; call; ret (leaves IntPtr unconsumed on stack)
            var helperMethod = new MethodDefUser("ImbalancedStub", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef));

            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            helperMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(helperMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, helperMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Stack imbalanced method must be preserved
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Contains(helperMethod, globalType.Methods);
        }
    }
}
