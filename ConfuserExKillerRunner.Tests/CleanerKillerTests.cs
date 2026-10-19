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

        [Fact]
        public void StripProtectorHooks_ConfuserExNormalAntiTamper_PointerArithmeticWithoutVirtualAddress_RetainedWhenNotDecrypted()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            // Define ConfuserEx normal Anti-Tamper hook based purely on pointer arithmetic:
            // 1. Calls VirtualProtect
            // 2. Reads PE header at offset 0x3c (e_lfanew)
            // 3. Loops through section bytes: address arithmetic, xor cipher, stind.i4, backward branch loop
            // 4. Contains NO field named "VirtualAddress"
            // Note: This synthetic fixture validates CleanerKiller's static hook classification
            // (safeguarding Anti-Tamper hooks from being misclassified as Anti-Dump or stripped when unconfirmed).
            // It does not simulate native PE section decryption.
            var atMethod = new MethodDefUser("ConfuserNormalAntiTamper", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody { InitLocals = true }
            };
            var localBase = new Local(module.CorLibTypes.IntPtr);
            var localIndex = new Local(module.CorLibTypes.Int32);
            var localOldProtect = new Local(module.CorLibTypes.UInt32);
            atMethod.Body.Variables.Add(localBase);
            atMethod.Body.Variables.Add(localIndex);
            atMethod.Body.Variables.Add(localOldProtect);

            var vpRef = new MemberRefUser(module, "VirtualProtect",
                MethodSig.CreateStatic(module.CorLibTypes.Boolean,
                    module.CorLibTypes.IntPtr, module.CorLibTypes.UInt32, module.CorLibTypes.UInt32,
                    new ByRefSig(module.CorLibTypes.UInt32)),
                new TypeRefUser(module, string.Empty, "Kernel32", module.CorLibTypes.AssemblyRef));

            var loopStart = Instruction.Create(OpCodes.Ldloc_0);

            // 1. Call VirtualProtect(base, 0x1000, 0x40, out oldProtect)
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x40));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localOldProtect));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // 2. PE header access at offset 0x3c
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x3C));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldind_U4));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // 3. Initialize loop counter
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_1));

            // 4. Decryption loop: * (base + index) ^= 0x5A5A5A5A
            atMethod.Body.Instructions.Add(loopStart);
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Dup));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldind_U4));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x5A5A5A5A));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Xor));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Stind_I4));

            // 5. Increment index and branch back
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_4));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_1));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x100));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Blt_S, loopStart));
            atMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(atMethod);

            // Verify structural IL validity of the synthetic fixture
            var auditReport = new ConfuserExKillerRunner.Analysis.AuditReport { CanLoad = true };
            ConfuserExKillerRunner.Analysis.QualityAuditor.AuditMethod(atMethod, auditReport);
            Assert.Equal("CLEAN", auditReport.Status);
            Assert.Equal(0, auditReport.StackUnderflowCount);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, atMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            // Case A: When antiTamperDecrypted = false, hook MUST NOT be removed by fallback as Anti-Dump!
            var resultNotDecrypted = CleanerKiller.StripProtectorHooks(module, antiTamperDecrypted: false);

            Assert.Equal(0, resultNotDecrypted.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Equal(atMethod, cctor.Body.Instructions[0].Operand);
            Assert.Contains(atMethod, globalType.Methods);

            // Case B: When antiTamperDecrypted = true, hook is confirmed decrypted and safely stripped
            var resultDecrypted = CleanerKiller.StripProtectorHooks(module, antiTamperDecrypted: true);

            Assert.Equal(1, resultDecrypted.StrippedHooksCount);
            Assert.Equal(OpCodes.Nop, cctor.Body.Instructions[0].OpCode);
            Assert.DoesNotContain(atMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_AntiDump_WithPeHeaderOffsetAndHeaderZeroing_IsStripped()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            // Legitimate Anti-Dump hook: calls VirtualProtect, navigates PE header offset 0x3c,
            // and explicitly zeros headers (ldc.i4.0 + stind.i4) without cipher arithmetic or debugger checks.
            var antiDumpMethod = new MethodDefUser("AntiDumpHook", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody { InitLocals = true }
            };
            var localBase = new Local(module.CorLibTypes.IntPtr);
            var localOldProtect = new Local(module.CorLibTypes.UInt32);
            antiDumpMethod.Body.Variables.Add(localBase);
            antiDumpMethod.Body.Variables.Add(localOldProtect);

            var vpRef = new MemberRefUser(module, "VirtualProtect",
                MethodSig.CreateStatic(module.CorLibTypes.Boolean,
                    module.CorLibTypes.IntPtr, module.CorLibTypes.UInt32, module.CorLibTypes.UInt32,
                    new ByRefSig(module.CorLibTypes.UInt32)),
                new TypeRefUser(module, string.Empty, "Kernel32", module.CorLibTypes.AssemblyRef));

            var marshalType = new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef);
            var moduleType = new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef);
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, moduleType.ToTypeSig()),
                marshalType);

            // Initialize module base: Marshal.GetHINSTANCE(null) -> stloc.0
            antiDumpMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            antiDumpMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            antiDumpMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));

            // VirtualProtect call
            antiDumpMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            antiDumpMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            antiDumpMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x04));
            antiDumpMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localOldProtect));
            antiDumpMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            antiDumpMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // Locate PE offset 0x3c and zero it: *(uint*)(base + 0x3c) = 0
            antiDumpMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            antiDumpMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x3C));
            antiDumpMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            antiDumpMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0)); // Zero value
            antiDumpMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Stind_I4)); // Header zeroing!
            antiDumpMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(antiDumpMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, antiDumpMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            // Audit structural validity
            var auditReport = new ConfuserExKillerRunner.Analysis.AuditReport { CanLoad = true };
            ConfuserExKillerRunner.Analysis.QualityAuditor.AuditMethod(antiDumpMethod, auditReport);
            Assert.Equal("CLEAN", auditReport.Status);

            // Anti-Dump with verified header zeroing is cleanly stripped
            var result = CleanerKiller.StripProtectorHooks(module);

            Assert.Equal(1, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Nop, cctor.Body.Instructions[0].OpCode);
            Assert.DoesNotContain(antiDumpMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_HookWithPeHeaderOffsetAndVirtualProtect_WithoutZeroing_IsPreservedAsAmbiguous()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            // Hook that calls VirtualProtect and reads offset 0x3c, but DOES NOT wipe or zero headers.
            // E.g., it writes a non-zero configuration value or reads headers for runtime inspection.
            // Under tightened classification, lack of explicit zeroing makes its Anti-Dump role unestablished.
            // CleanerKiller must treat it as ambiguous and retain it!
            var ambiguousHook = new MethodDefUser("AmbiguousPeHook", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody { InitLocals = true }
            };
            var localBase = new Local(module.CorLibTypes.IntPtr);
            var localOldProtect = new Local(module.CorLibTypes.UInt32);
            ambiguousHook.Body.Variables.Add(localBase);
            ambiguousHook.Body.Variables.Add(localOldProtect);

            var vpRef = new MemberRefUser(module, "VirtualProtect",
                MethodSig.CreateStatic(module.CorLibTypes.Boolean,
                    module.CorLibTypes.IntPtr, module.CorLibTypes.UInt32, module.CorLibTypes.UInt32,
                    new ByRefSig(module.CorLibTypes.UInt32)),
                new TypeRefUser(module, string.Empty, "Kernel32", module.CorLibTypes.AssemblyRef));

            // VirtualProtect call
            ambiguousHook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            ambiguousHook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            ambiguousHook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x04));
            ambiguousHook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localOldProtect));
            ambiguousHook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            ambiguousHook.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // Reads offset 0x3c and writes a non-zero marker (0x12345678) instead of zeroing!
            ambiguousHook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            ambiguousHook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x3C));
            ambiguousHook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            ambiguousHook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x12345678)); // Non-zero!
            ambiguousHook.Body.Instructions.Add(Instruction.Create(OpCodes.Stind_I4));
            ambiguousHook.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(ambiguousHook);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, ambiguousHook));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            // Audit structural validity
            var auditAmbiguous = new ConfuserExKillerRunner.Analysis.AuditReport { CanLoad = true };
            ConfuserExKillerRunner.Analysis.QualityAuditor.AuditMethod(ambiguousHook, auditAmbiguous);
            Assert.Equal("CLEAN", auditAmbiguous.Status);

            // Ambiguous hook MUST be preserved in <Module>.cctor
            var result = CleanerKiller.StripProtectorHooks(module, antiTamperDecrypted: false);

            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Equal(ambiguousHook, cctor.Body.Instructions[0].Operand);
            Assert.Contains(ambiguousHook, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_HookWithVirtualProtectAndUnlinkedZeroing_IsPreservedAsAmbiguous()
        {
            var module = new ModuleDefUser("TestModUnlinked");
            var globalType = module.GlobalType;

            // Method calls VirtualProtect, loads 0x3c for an unrelated local calculation,
            // and zeros an unrelated local variable/buffer.
            // There is NO structural link between the zeroing and the PE header or module base!
            // CleanerKiller must treat it as ambiguous and retain it.
            var hook = new MethodDefUser("UnlinkedZeroHook", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody { InitLocals = true }
            };
            var localBase = new Local(module.CorLibTypes.IntPtr);
            var localOldProtect = new Local(module.CorLibTypes.UInt32);
            var localUnrelated = new Local(module.CorLibTypes.Int32);
            hook.Body.Variables.Add(localBase);
            hook.Body.Variables.Add(localOldProtect);
            hook.Body.Variables.Add(localUnrelated);

            var vpRef = new MemberRefUser(module, "VirtualProtect",
                MethodSig.CreateStatic(module.CorLibTypes.Boolean,
                    module.CorLibTypes.IntPtr, module.CorLibTypes.UInt32, module.CorLibTypes.UInt32,
                    new ByRefSig(module.CorLibTypes.UInt32)),
                new TypeRefUser(module, string.Empty, "Kernel32", module.CorLibTypes.AssemblyRef));

            // VirtualProtect call
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x04));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localOldProtect));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // Unrelated use of 0x3C: e.g. int val = 0x3c;
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x3C));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_2));

            // Zero an unrelated pointer/variable: localUnrelated = 0
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localUnrelated));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stind_I4));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(hook);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, hook));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var auditReport = new ConfuserExKillerRunner.Analysis.AuditReport { CanLoad = true };
            ConfuserExKillerRunner.Analysis.QualityAuditor.AuditMethod(hook, auditReport);
            Assert.Equal("CLEAN", auditReport.Status);

            var result = CleanerKiller.StripProtectorHooks(module);

            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Equal(hook, cctor.Body.Instructions[0].Operand);
            Assert.Contains(hook, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_HookWithIndependentPointerOffset3CAndZeroing_IsPreservedAsAmbiguous()
        {
            var module = new ModuleDefUser("TestModIndependentPtr");
            var globalType = module.GlobalType;

            // Scenario: A hook calls VirtualProtect, receives or creates an independent pointer 'p'
            // (e.g. from an internal buffer or struct, NOT from Marshal.GetHINSTANCE),
            // calculates 'p + 0x3C', and writes zero to that address.
            // Because 'p' has no proven provenance from the module base, CleanerKiller
            // must NOT classify this method as Anti-Dump, and must strictly retain it!
            var hook = new MethodDefUser("IndependentPtrHook", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody { InitLocals = true }
            };
            var localP = new Local(module.CorLibTypes.IntPtr);
            var localOldProtect = new Local(module.CorLibTypes.UInt32);
            hook.Body.Variables.Add(localP);
            hook.Body.Variables.Add(localOldProtect);

            var vpRef = new MemberRefUser(module, "VirtualProtect",
                MethodSig.CreateStatic(module.CorLibTypes.Boolean,
                    module.CorLibTypes.IntPtr, module.CorLibTypes.UInt32, module.CorLibTypes.UInt32,
                    new ByRefSig(module.CorLibTypes.UInt32)),
                new TypeRefUser(module, string.Empty, "Kernel32", module.CorLibTypes.AssemblyRef));

            // VirtualProtect call on localP
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x04));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localOldProtect));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // Independent pointer calculation: p + 0x3C (NOT from Marshal.GetHINSTANCE!)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x3C));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0)); // Write zero to (p + 0x3C)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stind_I4));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(hook);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, hook));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var auditReport = new ConfuserExKillerRunner.Analysis.AuditReport { CanLoad = true };
            ConfuserExKillerRunner.Analysis.QualityAuditor.AuditMethod(hook, auditReport);
            Assert.Equal("CLEAN", auditReport.Status);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Hook MUST be preserved because 'p' has no proven provenance from Marshal.GetHINSTANCE!
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Equal(hook, cctor.Body.Instructions[0].Operand);
            Assert.Contains(hook, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_HookWithMarshalGetHinstanceAndIndependentPointerOffset3CZeroing_IsPreservedAsAmbiguous()
        {
            var module = new ModuleDefUser("TestModGetHinstanceIndependentPtr");
            var globalType = module.GlobalType;

            // Scenario requested by code review:
            // The method actually calls Marshal.GetHINSTANCE and stores the module base into a variable (loc.0).
            // However, it then uses another independent pointer 'p' (loc.1) to compute 'p + 0x3C' and write zero.
            // Under symbolic stack tracking, the address passed to stind does NOT derive from the module base.
            // CleanerKiller must establish that the written address lacks proven provenance from the module base
            // and strictly preserve the hook!
            var hook = new MethodDefUser("IndependentPtrWithGetHinstanceHook", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody { InitLocals = true }
            };
            var localBase = new Local(module.CorLibTypes.IntPtr);
            var localIndependentP = new Local(module.CorLibTypes.IntPtr);
            var localOldProtect = new Local(module.CorLibTypes.UInt32);
            hook.Body.Variables.Add(localBase);
            hook.Body.Variables.Add(localIndependentP);
            hook.Body.Variables.Add(localOldProtect);

            var marshalType = new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef);
            var moduleType = new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef);
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, moduleType.ToTypeSig()),
                marshalType);

            var vpRef = new MemberRefUser(module, "VirtualProtect",
                MethodSig.CreateStatic(module.CorLibTypes.Boolean,
                    module.CorLibTypes.IntPtr, module.CorLibTypes.UInt32, module.CorLibTypes.UInt32,
                    new ByRefSig(module.CorLibTypes.UInt32)),
                new TypeRefUser(module, string.Empty, "Kernel32", module.CorLibTypes.AssemblyRef));

            // 1. Call Marshal.GetHINSTANCE(null) -> stored into localBase (loc.0)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));

            // 2. VirtualProtect call on localIndependentP (loc.1)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x04));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localOldProtect));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // 3. Compute p + 0x3C using localIndependentP (loc.1), NOT localBase (loc.0)!
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x3C));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0)); // Write zero to (p + 0x3C)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stind_I4));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(hook);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, hook));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var auditReport = new ConfuserExKillerRunner.Analysis.AuditReport { CanLoad = true };
            ConfuserExKillerRunner.Analysis.QualityAuditor.AuditMethod(hook, auditReport);
            Assert.Equal("CLEAN", auditReport.Status);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Hook MUST be preserved because the zeroed address was derived from 'p', NOT from Marshal.GetHINSTANCE!
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Equal(hook, cctor.Body.Instructions[0].Operand);
            Assert.Contains(hook, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_AntiDump_WithMarshalGetHinstanceAndZeroing_IsStripped()
        {
            var module = new ModuleDefUser("TestModGetHinstance");
            var globalType = module.GlobalType;

            // Pattern mirroring Confuser.Runtime.AntiDump:
            // Calls Marshal.GetHINSTANCE, offsets to e_lfanew (0x3c), calls VirtualProtect,
            // and zeroes PE header memory at that linked pointer.
            var hook = new MethodDefUser("AntiDumpRealPattern", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody { InitLocals = true }
            };
            var localBase = new Local(module.CorLibTypes.IntPtr);
            var localPe = new Local(module.CorLibTypes.IntPtr);
            var localOldProtect = new Local(module.CorLibTypes.UInt32);
            hook.Body.Variables.Add(localBase);
            hook.Body.Variables.Add(localPe);
            hook.Body.Variables.Add(localOldProtect);

            var marshalType = new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef);
            var moduleType = new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef);
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, moduleType.ToTypeSig()),
                marshalType);

            var vpRef = new MemberRefUser(module, "VirtualProtect",
                MethodSig.CreateStatic(module.CorLibTypes.Boolean,
                    module.CorLibTypes.IntPtr, module.CorLibTypes.UInt32, module.CorLibTypes.UInt32,
                    new ByRefSig(module.CorLibTypes.UInt32)),
                new TypeRefUser(module, string.Empty, "Kernel32", module.CorLibTypes.AssemblyRef));

            // Call Marshal.GetHINSTANCE(null) -> stloc.0 (base)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));

            // Calculate PE header address: pe = base + 0x3c -> stloc.1
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x3C));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_1));

            // Call VirtualProtect on pe
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x04));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localOldProtect));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // Zero PE header: *(int*)pe = 0
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stind_I4));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(hook);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, hook));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var auditReport = new ConfuserExKillerRunner.Analysis.AuditReport { CanLoad = true };
            ConfuserExKillerRunner.Analysis.QualityAuditor.AuditMethod(hook, auditReport);
            Assert.Equal("CLEAN", auditReport.Status);

            var result = CleanerKiller.StripProtectorHooks(module);

            Assert.Equal(1, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Nop, cctor.Body.Instructions[0].OpCode);
            Assert.DoesNotContain(hook, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_AmbiguousVirtualProtectHook_IsPreserved()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            // Ambiguous method calling VirtualProtect: no section headers, no cipher decryption loop,
            // no Anti-Dump zeroing, mixed with application logic.
            var ambiguousMethod = new MethodDefUser("AmbiguousHook", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var vpRef = new MemberRefUser(module, "VirtualProtect",
                MethodSig.CreateStatic(module.CorLibTypes.Boolean,
                    module.CorLibTypes.IntPtr, module.CorLibTypes.UInt32, module.CorLibTypes.UInt32,
                    new ByRefSig(module.CorLibTypes.UInt32)),
                new TypeRefUser(module, string.Empty, "Kernel32", module.CorLibTypes.AssemblyRef));

            ambiguousMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            ambiguousMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 256));
            ambiguousMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 4));
            ambiguousMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            ambiguousMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            ambiguousMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            ambiguousMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(ambiguousMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, ambiguousMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var result = CleanerKiller.StripProtectorHooks(module, antiTamperDecrypted: false);

            // Ambiguous classification MUST retain the hook!
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Contains(ambiguousMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_RollbackWithBranchesAndEH_PreservesOriginalInstructionInstancesAndBoundaries()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            // Define a protector hook (Anti-Debug)
            var dbgMethod = new MethodDefUser("AntiDebugInit", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var isAttachedRef = new MemberRefUser(module, "get_IsAttached",
                MethodSig.CreateStatic(module.CorLibTypes.Boolean),
                new TypeRefUser(module, "System.Diagnostics", "Debugger", module.CorLibTypes.AssemblyRef));
            dbgMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, isAttachedRef));
            dbgMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            dbgMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(dbgMethod);

            // Build <Module>..cctor with branches and ExceptionHandler boundaries:
            // try {
            //     call AntiDebugInit; // stripped tentatively
            //     pop;                // underflows stack if call is nopped!
            //     br.s targetInst;
            //     nop;
            // targetInst:
            //     leave.s tryEnd;
            // }
            // catch (Exception) {
            //     pop;
            //     leave.s handlerEnd;
            // }
            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };

            var callInst = Instruction.Create(OpCodes.Call, dbgMethod);
            var badPop = Instruction.Create(OpCodes.Pop);
            var targetInst = Instruction.Create(OpCodes.Nop);
            var brInst = Instruction.Create(OpCodes.Br_S, targetInst);
            var unreachedNop = Instruction.Create(OpCodes.Nop);

            var tryEnd = Instruction.Create(OpCodes.Leave_S, targetInst);
            var handlerStart = Instruction.Create(OpCodes.Pop);
            var finalRet = Instruction.Create(OpCodes.Ret);
            var handlerEnd = Instruction.Create(OpCodes.Leave_S, finalRet);

            tryEnd.Operand = finalRet;
            handlerEnd.Operand = finalRet;

            cctor.Body.Instructions.Add(callInst);       // index 0 (TryStart)
            cctor.Body.Instructions.Add(badPop);         // index 1
            cctor.Body.Instructions.Add(brInst);         // index 2
            cctor.Body.Instructions.Add(unreachedNop);   // index 3
            cctor.Body.Instructions.Add(targetInst);     // index 4
            cctor.Body.Instructions.Add(tryEnd);         // index 5
            cctor.Body.Instructions.Add(handlerStart);   // index 6 (HandlerStart)
            cctor.Body.Instructions.Add(handlerEnd);     // index 7
            cctor.Body.Instructions.Add(finalRet);       // index 8

            var eh = new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = callInst,
                TryEnd = handlerStart,
                HandlerStart = handlerStart,
                HandlerEnd = finalRet,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            };
            cctor.Body.ExceptionHandlers.Add(eh);
            globalType.Methods.Add(cctor);

            // Execute StripProtectorHooks.
            // Stripping callInst causes badPop to underflow evaluation stack.
            // QualityAuditor detects structural failure and triggers atomic in-place rollback.
            var result = CleanerKiller.StripProtectorHooks(module);

            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Equal(dbgMethod, cctor.Body.Instructions[0].Operand);
            Assert.Contains(dbgMethod, globalType.Methods);

            // Verify branch operand refers to the exact instruction object in Body.Instructions
            Assert.Same(targetInst, brInst.Operand);
            Assert.Contains((Instruction)brInst.Operand, cctor.Body.Instructions);

            // Verify all ExceptionHandler boundaries refer to exact instruction objects in Body.Instructions
            Assert.Same(callInst, eh.TryStart);
            Assert.Contains(eh.TryStart, cctor.Body.Instructions);

            Assert.Same(handlerStart, eh.TryEnd);
            Assert.Contains(eh.TryEnd, cctor.Body.Instructions);

            Assert.Same(handlerStart, eh.HandlerStart);
            Assert.Contains(eh.HandlerStart, cctor.Body.Instructions);

            Assert.Same(finalRet, eh.HandlerEnd);
            Assert.Contains(eh.HandlerEnd, cctor.Body.Instructions);
        }

        [Fact]
        public void StripProtectorHooks_IntPtrStubFollowedByPop_Unambiguous_BothNeutralizedAndStripped()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            // Canonical 3-instruction IntPtr stub: ldnull -> call Marshal.GetHINSTANCE -> ret
            var stubMethod = new MethodDefUser("IntPtrStub", MethodSig.CreateStatic(module.CorLibTypes.IntPtr),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef));

            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(stubMethod);

            // <Module>..cctor calls IntPtrStub and consumes returned IntPtr with pop
            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, stubMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Both call and pop must be neutralized to Nop and hook stripped cleanly
            Assert.Equal(1, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Nop, cctor.Body.Instructions[0].OpCode);
            Assert.Equal(OpCodes.Nop, cctor.Body.Instructions[1].OpCode);
            Assert.Equal(OpCodes.Ret, cctor.Body.Instructions[2].OpCode);
            Assert.DoesNotContain(stubMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_IntPtrStubFollowedByPop_AmbiguousBranchTarget_HookRetained()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            var stubMethod = new MethodDefUser("IntPtrStub", MethodSig.CreateStatic(module.CorLibTypes.IntPtr),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef));

            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(stubMethod);

            // <Module>..cctor: br.s popInst; call stubMethod; popInst: pop; ret;
            // The pop instruction is a branch target! Therefore, producer and consumer cannot be safely or unambiguously removed together.
            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            var callInst = Instruction.Create(OpCodes.Call, stubMethod);
            var popInst = Instruction.Create(OpCodes.Pop);
            var brInst = Instruction.Create(OpCodes.Br_S, popInst);

            cctor.Body.Instructions.Add(brInst);
            cctor.Body.Instructions.Add(callInst);
            cctor.Body.Instructions.Add(popInst);
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Hook must be preserved because pop is a branch target
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[1].OpCode);
            Assert.Equal(stubMethod, cctor.Body.Instructions[1].Operand);
            Assert.Equal(OpCodes.Pop, cctor.Body.Instructions[2].OpCode);
            Assert.Contains(stubMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_IntPtrStubWithoutPop_HookRetained()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            var stubMethod = new MethodDefUser("IntPtrStub", MethodSig.CreateStatic(module.CorLibTypes.IntPtr),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef));

            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            stubMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(stubMethod);

            var stateField = new FieldDefUser("StatePtr", new FieldSig(module.CorLibTypes.IntPtr),
                FieldAttributes.Public | FieldAttributes.Static);
            globalType.Fields.Add(stateField);

            // <Module>..cctor calls stub and stores in field (consumer is stsfld, not pop!)
            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, stubMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Stsfld, stateField));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Hook must be preserved because return value consumer is not an unambiguous pop
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Contains(stubMethod, globalType.Methods);
        }
    }
}
