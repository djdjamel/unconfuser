using System;
using ConfuserExKillerRunner.Analysis;
using ConfuserExKillerRunner.Killers;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.PE;
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

            Assert.True(CleanerKiller.HasLinkedPeHeaderZeroing(antiDumpMethod));

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
        public void StripProtectorHooks_HookWithBranchDivergentBaseAndOffset_IsPreservedDueToNonCorrelatedProvenance()
        {
            var module = new ModuleDefUser("TestModDivergentBranch");
            var globalType = module.GlobalType;

            // Scenario requested by code review:
            // A method contains a conditional branch.
            // On Path 1: local variables 'a' (loc.0) and 'b' (loc.1) both receive ModuleBase.
            // On Path 2: local variables 'a' (loc.0) and 'b' (loc.1) both receive the constant 0x3C.
            // The paths merge into a join point, which then computes 'a + b' and zeroes memory at *(a + b).
            // Under naive bitwise-OR union, 'a' and 'b' would each hold (ModuleBase | 0x3C), falsely suggesting
            // that 'a + b' could compute (ModuleBase + 0x3C).
            // Under our sound conservative join, MergeValue(ModuleBase, 0x3C) yields None.
            // CleanerKiller must establish that neither concrete path computed a PE header address,
            // and strictly preserve the hook!
            var hook = new MethodDefUser("DivergentBranchHook", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32))
            {
                Body = new CilBody { InitLocals = true }
            };
            var localA = new Local(module.CorLibTypes.IntPtr);
            var localB = new Local(module.CorLibTypes.IntPtr);
            var localSum = new Local(module.CorLibTypes.IntPtr);
            var localOldProtect = new Local(module.CorLibTypes.UInt32);
            var localBase = new Local(module.CorLibTypes.IntPtr);
            hook.Body.Variables.Add(localA);
            hook.Body.Variables.Add(localB);
            hook.Body.Variables.Add(localSum);
            hook.Body.Variables.Add(localOldProtect);
            hook.Body.Variables.Add(localBase);

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

            // localBase = Marshal.GetHINSTANCE(null) -> stloc.s localBase (loc.4)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_S, localBase));

            // VirtualProtect call on localBase
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_S, localBase));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x04));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localOldProtect));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // Branch: if (arg0 != 0) goto PATH2
            var path2Label = Instruction.Create(OpCodes.Ldc_I4, 0x3C);
            var mergeLabel = Instruction.Create(OpCodes.Ldloc_0);

            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Brtrue_S, path2Label));

            // PATH 1: Both a and b receive ModuleBase
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_S, localBase));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0)); // a = ModuleBase
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_S, localBase));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_1)); // b = ModuleBase
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Br_S, mergeLabel));

            // PATH 2: Both a and b receive 0x3C
            hook.Body.Instructions.Add(path2Label);
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Conv_I));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0)); // a = 0x3C
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x3C));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Conv_I));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_1)); // b = 0x3C

            // MERGE: compute a + b, zero memory
            hook.Body.Instructions.Add(mergeLabel);
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_2));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_2));
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
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, hook));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var auditReport = new ConfuserExKillerRunner.Analysis.AuditReport { CanLoad = true };
            ConfuserExKillerRunner.Analysis.QualityAuditor.AuditMethod(hook, auditReport);
            Assert.Equal("CLEAN", auditReport.Status);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Hook MUST be preserved because neither path computed (ModuleBase + 0x3C)!
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[1].OpCode);
            Assert.Equal(hook, cctor.Body.Instructions[1].Operand);
            Assert.Contains(hook, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_HookWithIncompatibleStackHeightsAtMerge_IsPreservedDueToInconclusiveAnalysis()
        {
            var module = new ModuleDefUser("TestModIncompatibleStack");
            var globalType = module.GlobalType;

            // Scenario requested by code review:
            // A real conditional branch leads to two reachable paths arriving at the same merge point
            // with incompatible evaluation stack heights (height 1 on Path 1 vs height 0 on Path 2).
            //
            // If the analyzer ignored stack incompatibility or blindly continued, it would process
            // the subsequent PE zeroing sequence and strip the hook.
            // Under our guard, MergeFrom flags incompatible=true upon stack height mismatch,
            // HasLinkedPeHeaderZeroing aborts symbolic analysis as inconclusive, and the hook is preserved.
            var hook = new MethodDefUser("IncompatibleStackHook", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32))
            {
                Body = new CilBody { InitLocals = true }
            };
            var localBase = new Local(module.CorLibTypes.IntPtr);
            var localOldProtect = new Local(module.CorLibTypes.UInt32);
            hook.Body.Variables.Add(localBase);
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

            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));

            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x04));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localOldProtect));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // Real conditional branch:
            // if (arg0 != 0) goto path1Target
            var path1Target = Instruction.Create(OpCodes.Ldc_I4_1);
            var mergeLabel = Instruction.Create(OpCodes.Nop);

            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Brtrue_S, path1Target));

            // Path 2 (fallthrough): arrives at mergeLabel with stack height 0
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Br_S, mergeLabel));

            // Path 1 (branch target): pushes 1 item onto stack -> arrives at mergeLabel with stack height 1
            hook.Body.Instructions.Add(path1Target);
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Br_S, mergeLabel));

            // Merge point: both paths reach here with incompatible stack heights (0 vs 1)
            hook.Body.Instructions.Add(mergeLabel);

            // Subsequent PE header zeroing sequence:
            // If the guard did not abort at mergeLabel, this zeroing would cause the hook to be classified as Anti-Dump!
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x3C));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
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
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, hook));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Inconclusive analysis due to incompatible stack heights at merge -> hook must be safely preserved!
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Contains(hook, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_HookWithIndependentPointerAddedToPeAddress_IsPreserved()
        {
            var module = new ModuleDefUser("TestModIndependentPtr");
            var globalType = module.GlobalType;

            // Scenario requested by code review:
            // 1. Obtain base via Marshal.GetHINSTANCE -> localBase (ModuleBase)
            // 2. pe = base + 0x3C -> localPe (PeDerivedAddress)
            // 3. Load an independent pointer or unproven value (from parameter / unknown source -> None)
            // 4. Calculate q = pe + independentValue
            // 5. Write zero to address q: *(int*)q = 0
            //
            // Under naive propagation, pe + None would propagate PeDerivedAddress, falsely classifying this as Anti-Dump.
            // Under our revised model:
            // - PeDerivedAddress + NumericOffset (demonstrated integer displacement) is preserved.
            // - PeDerivedAddress + None (unproven operand or independent pointer) strictly evaluates to None.
            // Consequently, zeroing memory at q is NOT recognized as PE header zeroing, and the hook is strictly preserved!
            var hook = new MethodDefUser("IndependentPointerHook",
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.IntPtr))
            {
                Body = new CilBody { InitLocals = true }
            };
            var localBase = new Local(module.CorLibTypes.IntPtr);
            var localPe = new Local(module.CorLibTypes.IntPtr);
            var localQ = new Local(module.CorLibTypes.IntPtr);
            var localOldProtect = new Local(module.CorLibTypes.UInt32);
            hook.Body.Variables.Add(localBase);
            hook.Body.Variables.Add(localPe);
            hook.Body.Variables.Add(localQ);
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

            // 1. localBase = Marshal.GetHINSTANCE(null) -> ModuleBase
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));

            // 2. VirtualProtect(localBase, 0x1000, 0x04, out localOldProtect)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x04));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localOldProtect));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // 3. pe = localBase + 0x3C -> PeDerivedAddress (loc.1)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x3C));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_1));

            // 4. q = pe + independentPtr (arg0) -> ldloc.1; ldarg.0; add; stloc.2
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0)); // Independent unproven operand (None)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_2)); // localQ is None!

            // 5. Zero write: *(int*)localQ = 0
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_2));
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
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Conv_I));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, hook));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var auditReport = new ConfuserExKillerRunner.Analysis.AuditReport { CanLoad = true };
            ConfuserExKillerRunner.Analysis.QualityAuditor.AuditMethod(hook, auditReport);
            Assert.Equal("CLEAN", auditReport.Status);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Hook MUST be preserved because q was derived using an independent unproven operand!
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Contains(hook, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_HookWithIndependentPointerSubtractedOrAnded_IsPreserved()
        {
            var module = new ModuleDefUser("TestModIndependentSubAnd");
            var globalType = module.GlobalType;

            // Test that CombineSub and CombineAnd also reject unproven operands:
            // pe - independentValue -> None
            // pe & independentValue -> None
            var hook = new MethodDefUser("IndependentSubAndHook",
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.IntPtr))
            {
                Body = new CilBody { InitLocals = true }
            };
            var localBase = new Local(module.CorLibTypes.IntPtr);
            var localPe = new Local(module.CorLibTypes.IntPtr);
            var localQ1 = new Local(module.CorLibTypes.IntPtr);
            var localQ2 = new Local(module.CorLibTypes.IntPtr);
            var localOldProtect = new Local(module.CorLibTypes.UInt32);
            hook.Body.Variables.Add(localBase);
            hook.Body.Variables.Add(localPe);
            hook.Body.Variables.Add(localQ1);
            hook.Body.Variables.Add(localQ2);
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

            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));

            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x04));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localOldProtect));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // pe = base + 0x3C
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x3C));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_1));

            // q1 = pe - independentPtr -> None
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Sub));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_2));

            // *(int*)q1 = 0
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_2));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stind_I4));

            // q2 = pe & independentPtr -> None
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.And));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_3));

            // *(int*)q2 = 0
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_3));
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
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Conv_I));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, hook));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Hook must be preserved because q1 and q2 were derived using an unproven operand
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Contains(hook, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_AntiDump_WithPeHeaderDereferenceAndZeroing_IsStripped()
        {
            var module = new ModuleDefUser("TestModDereferenceAntiDump");
            var globalType = module.GlobalType;

            // Scenario requested by code review:
            // Multi-step PE header resolution mirroring ConfuserEx AntiDump runtime:
            // 1. Marshal.GetHINSTANCE -> localBase (loc.0)
            // 2. peOffset = localBase + 0x3C -> localPeOffset (loc.1)
            // 3. ntHeaderOffset = *(uint*)localPeOffset -> localNtOffset (loc.2)
            // 4. ntHeader = localBase + ntHeaderOffset -> localNtHeader (loc.3)
            // 5. VirtualProtect(ntHeader, 0x1000, 0x04, out localOldProtect)
            // 6. *(int*)ntHeader = 0 -> header wiped!
            var hook = new MethodDefUser("AntiDumpDereferencePattern", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody { InitLocals = true }
            };
            var localBase = new Local(module.CorLibTypes.IntPtr);
            var localPeOffset = new Local(module.CorLibTypes.IntPtr);
            var localNtOffset = new Local(module.CorLibTypes.UInt32);
            var localNtHeader = new Local(module.CorLibTypes.IntPtr);
            var localOldProtect = new Local(module.CorLibTypes.UInt32);
            hook.Body.Variables.Add(localBase);
            hook.Body.Variables.Add(localPeOffset);
            hook.Body.Variables.Add(localNtOffset);
            hook.Body.Variables.Add(localNtHeader);
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

            // 1. Marshal.GetHINSTANCE(null) -> stloc.0 (localBase)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));

            // 2. peOffset = localBase + 0x3C -> stloc.1
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x3C));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_1));

            // 3. ntHeaderOffset = *(uint*)peOffset -> ldloc.1; ldind.u4; stloc.2
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldind_U4));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_2));

            // 4. ntHeader = localBase + ntHeaderOffset -> ldloc.0; ldloc.2; add; stloc.3
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_2));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_3));

            // 5. VirtualProtect(ntHeader, 0x1000, 0x04, out oldProtect)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_3));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x04));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localOldProtect));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // 6. Zero NT header memory: *(int*)ntHeader = 0
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_3));
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

            // Hook is properly recognized as Anti-Dump and stripped!
            Assert.Equal(1, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Nop, cctor.Body.Instructions[0].OpCode);
            Assert.DoesNotContain(hook, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_HookWithPeAddressAndZeroMask_IsPreserved()
        {
            var module = new ModuleDefUser("TestModPeAddressAndZeroMask");
            var globalType = module.GlobalType;

            // Scenario requested by code review (Null Mask in CombineAnd):
            // 1. Obtain module base via Marshal.GetHINSTANCE -> localBase (ModuleBase)
            // 2. pe = localBase + 0x3C -> localPe (PeDerivedAddress)
            // 3. q = pe & 0 -> ldloc.1; ldc.i4.0; and; stloc.2
            // 4. VirtualProtect(q, 0x1000, 0x04, out localOldProtect)
            // 5. Zero write: *(int*)q = 0
            //
            // Under naive propagation, PeDerivedAddress & Zero preserved PeDerivedAddress.
            // In mathematical reality, pointer & 0 == 0.
            // Under our corrected evaluation order, X & 0 strictly evaluates to Zero.
            // Because q is Zero (not PeDerivedAddress or ModuleBase), the zero write is not classified
            // as PE header zeroing, and the hook is strictly preserved!
            var hook = new MethodDefUser("PeAddressAndZeroMaskHook", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody { InitLocals = true }
            };
            var localBase = new Local(module.CorLibTypes.IntPtr);
            var localPe = new Local(module.CorLibTypes.IntPtr);
            var localQ = new Local(module.CorLibTypes.IntPtr);
            var localOldProtect = new Local(module.CorLibTypes.UInt32);
            hook.Body.Variables.Add(localBase);
            hook.Body.Variables.Add(localPe);
            hook.Body.Variables.Add(localQ);
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

            // 1. localBase = Marshal.GetHINSTANCE(null) -> ModuleBase
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));

            // 2. pe = localBase + 0x3C -> PeDerivedAddress (loc.1)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x3C));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_1));

            // 3. q = pe & 0 -> ldloc.1; ldc.i4.0; and; stloc.2
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.And));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_2));

            // 4. VirtualProtect(q, 0x1000, 0x04, out oldProtect)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_2));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x04));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localOldProtect));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // 5. Zero write: *(int*)q = 0
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_2));
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

            // Hook MUST be preserved because q is 0, not a valid PE header address!
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Contains(hook, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_HookWithArbitraryLargeOffsetAddedToPeAddress_IsPreserved()
        {
            var module = new ModuleDefUser("TestModLargeOffset");
            var globalType = module.GlobalType;

            // Scenario requested by code review:
            // 1. Obtain module base via Marshal.GetHINSTANCE -> localBase (ModuleBase)
            // 2. pe = localBase + 0x3C -> localPe (PeDerivedAddress)
            // 3. q = pe + 0x100000 (arbitrary large displacement outside PE header space: 1MB offset)
            // 4. VirtualProtect(q, 0x1000, 0x04, out localOldProtect)
            // 5. Zero write: *(int*)q = 0
            //
            // Under unconstrained displacement tracking, any constant displacement preserved PeDerivedAddress.
            // Under our bounded model (|offset| <= 0x1000), arbitrary displacements outside the PE header
            // page produce None. The zero write is not classified as PE header zeroing, and the hook is strictly preserved!
            var hook = new MethodDefUser("LargeOffsetHook", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody { InitLocals = true }
            };
            var localBase = new Local(module.CorLibTypes.IntPtr);
            var localPe = new Local(module.CorLibTypes.IntPtr);
            var localQ = new Local(module.CorLibTypes.IntPtr);
            var localOldProtect = new Local(module.CorLibTypes.UInt32);
            hook.Body.Variables.Add(localBase);
            hook.Body.Variables.Add(localPe);
            hook.Body.Variables.Add(localQ);
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

            // 1. localBase = Marshal.GetHINSTANCE(null) -> ModuleBase
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));

            // 2. pe = localBase + 0x3C -> PeDerivedAddress (loc.1)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x3C));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_1));

            // 3. q = pe + 0x100000 (large offset: 1 MB)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x100000));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_2));

            // 4. VirtualProtect(q, 0x1000, 0x04, out oldProtect)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_2));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x04));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localOldProtect));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // 5. Zero write: *(int*)q = 0
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_2));
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

            // Hook MUST be preserved because displacement 0x100000 exceeds PE header bounds!
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Contains(hook, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_HookWithNonAlignmentMaskAppliedToPeAddress_IsPreserved()
        {
            var module = new ModuleDefUser("TestModNonAlignmentMask");
            var globalType = module.GlobalType;

            // Scenario requested by code review:
            // 1. Obtain module base via Marshal.GetHINSTANCE -> localBase (ModuleBase)
            // 2. pe = localBase + 0x3C -> localPe (PeDerivedAddress)
            // 3. q = pe & 0x7F (non-alignment mask)
            // 4. VirtualProtect(q, 0x1000, 0x04, out localOldProtect)
            // 5. Zero write: *(int*)q = 0
            //
            // Only genuine alignment masks (-2, -4, -8, -16, -32, -64) preserve PeDerivedAddress.
            // Arbitrary numeric bitwise AND masks produce None. The zero write is not classified
            // as PE header zeroing, and the hook is strictly preserved!
            var hook = new MethodDefUser("NonAlignmentMaskHook", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody { InitLocals = true }
            };
            var localBase = new Local(module.CorLibTypes.IntPtr);
            var localPe = new Local(module.CorLibTypes.IntPtr);
            var localQ = new Local(module.CorLibTypes.IntPtr);
            var localOldProtect = new Local(module.CorLibTypes.UInt32);
            hook.Body.Variables.Add(localBase);
            hook.Body.Variables.Add(localPe);
            hook.Body.Variables.Add(localQ);
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

            // 1. localBase = Marshal.GetHINSTANCE(null) -> ModuleBase
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));

            // 2. pe = localBase + 0x3C -> PeDerivedAddress (loc.1)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x3C));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_1));

            // 3. q = pe & 0x7F (non-alignment mask)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x7F));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.And));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_2));

            // 4. VirtualProtect(q, 0x1000, 0x04, out oldProtect)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_2));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x04));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localOldProtect));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // 5. Zero write: *(int*)q = 0
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_2));
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

            // Hook MUST be preserved because 0x7F is an arbitrary mask, not an alignment mask!
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Contains(hook, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_AntiDump_WithValidAlignmentMaskAndZeroing_IsStripped()
        {
            var module = new ModuleDefUser("TestModValidAlignmentMask");
            var globalType = module.GlobalType;

            // Real Anti-Dump pointer alignment pattern: pe & -4 (or ~3)
            var hook = new MethodDefUser("AntiDumpAlignmentHook", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody { InitLocals = true }
            };
            var localBase = new Local(module.CorLibTypes.IntPtr);
            var localPe = new Local(module.CorLibTypes.IntPtr);
            var localQ = new Local(module.CorLibTypes.IntPtr);
            var localOldProtect = new Local(module.CorLibTypes.UInt32);
            hook.Body.Variables.Add(localBase);
            hook.Body.Variables.Add(localPe);
            hook.Body.Variables.Add(localQ);
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

            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));

            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x3C));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_1));

            // pe & -4 (valid pointer alignment mask)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, -4));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.And));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_2));

            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_2));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x04));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localOldProtect));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_2));
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

            var result = CleanerKiller.StripProtectorHooks(module);

            Assert.Equal(1, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Nop, cctor.Body.Instructions[0].OpCode);
            Assert.DoesNotContain(hook, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_HookWithPeCumulativeDisplacementExceedingHeader_IsPreserved()
        {
            var module = new ModuleDefUser("TestModCumulativeDisplacement");
            var globalType = module.GlobalType;

            // Scenario specifically requested by code review:
            // 1. base = Marshal.GetHINSTANCE(...) -> ModuleBase
            // 2. pe = base + 0x3C -> PeDerivedAddress with cumulative offset 0x3C
            // 3. p = pe + 0x1000 -> address at base + 0x103C (exceeds MaxPeHeaderDisplacement 0x1000)
            // 4. read integer at address p: val = *(int*)p
            // 5. q = base + val
            // 6. *(int*)q = 0
            //
            // Without cumulative displacement tracking, pe + 0x1000 individually satisfied <= 0x1000,
            // retained PeDerivedAddress, and reading from it produced PeHeaderField, falsely classifying
            // this hook as an Anti-Dump zeroing sequence.
            // With cumulative tracking:
            // - 0x3C + 0x1000 = 0x103C > 0x1000, which exceeds PE header space and produces None.
            // - Furthermore, EvaluateLdind requires specifically offset 0x3C (e_lfanew); reading from
            //   any other address produces None.
            // Therefore, q is None, the write is not recognized as PE zeroing, and the hook is strictly preserved!
            var hook = new MethodDefUser("CumulativeDisplacementHook", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody { InitLocals = true }
            };
            var localBase = new Local(module.CorLibTypes.IntPtr);
            var localPe = new Local(module.CorLibTypes.IntPtr);
            var localP = new Local(module.CorLibTypes.IntPtr);
            var localVal = new Local(module.CorLibTypes.UInt32);
            var localQ = new Local(module.CorLibTypes.IntPtr);
            var localOldProtect = new Local(module.CorLibTypes.UInt32);
            hook.Body.Variables.Add(localBase);
            hook.Body.Variables.Add(localPe);
            hook.Body.Variables.Add(localP);
            hook.Body.Variables.Add(localVal);
            hook.Body.Variables.Add(localQ);
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

            // 1. base = Marshal.GetHINSTANCE(null) -> ModuleBase (loc.0)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));

            // 2. pe = base + 0x3C -> PeDerivedAddress(0x3C) (loc.1)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x3C));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_1));

            // 3. p = pe + 0x1000 -> base + 0x103C (exceeds header bound -> None) (loc.2)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_2));

            // 4. val = *(int*)p -> ldloc.2; ldind.u4; stloc.3
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_2));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldind_U4));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_3));

            // 5. q = base + val -> ldloc.0; ldloc.3; add; stloc.s loc.4
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_3));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_S, localQ));

            // VirtualProtect(q, 0x1000, 0x04, out oldProtect)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_S, localQ));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x04));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localOldProtect));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // 6. *(int*)q = 0
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_S, localQ));
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

            // Hook MUST be preserved because p escaped the PE header boundary (0x103C > 0x1000)!
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Contains(hook, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_HookWithNonELfanewDereference_IsPreserved()
        {
            var module = new ModuleDefUser("TestModNonELfanewDereference");
            var globalType = module.GlobalType;

            // Scenario specifically requested by code review:
            // Even when an address is within PE header space (e.g. base + 0x40 <= 0x1000),
            // dereferencing it must NOT automatically produce PeHeaderField (e_lfanew).
            // Only dereferencing specifically offset 0x3C (IMAGE_DOS_HEADER.e_lfanew) provides
            // valid PE header displacement provenance.
            // 1. base = Marshal.GetHINSTANCE(...) -> ModuleBase
            // 2. p = base + 0x40 (valid displacement within header space, but NOT e_lfanew)
            // 3. val = *(int*)p -> EvaluateLdind(p) strictly returns None
            // 4. q = base + val -> base + None strictly returns None
            // 5. *(int*)q = 0 -> write zero to None
            // Hook must be preserved!
            var hook = new MethodDefUser("NonELfanewDereferenceHook", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody { InitLocals = true }
            };
            var localBase = new Local(module.CorLibTypes.IntPtr);
            var localP = new Local(module.CorLibTypes.IntPtr);
            var localVal = new Local(module.CorLibTypes.UInt32);
            var localQ = new Local(module.CorLibTypes.IntPtr);
            var localOldProtect = new Local(module.CorLibTypes.UInt32);
            hook.Body.Variables.Add(localBase);
            hook.Body.Variables.Add(localP);
            hook.Body.Variables.Add(localVal);
            hook.Body.Variables.Add(localQ);
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

            // 1. base = Marshal.GetHINSTANCE(null) -> ModuleBase
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));

            // 2. p = base + 0x40 -> PeDerivedAddress(0x40) (loc.1)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x40));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_1));

            // 3. val = *(uint*)p -> ldloc.1; ldind.u4; stloc.2 (returns None because offset 0x40 != 0x3C)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldind_U4));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_2));

            // 4. q = base + val -> ldloc.0; ldloc.2; add; stloc.3 (returns None)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_2));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_3));

            // VirtualProtect(q, 0x1000, 0x04, out oldProtect)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_3));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x04));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localOldProtect));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // 5. *(int*)q = 0
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_3));
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

            // Hook MUST be preserved because dereference was at offset 0x40, not e_lfanew (0x3C)!
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Contains(hook, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_HookWithChainedSmallOffsetsExceedingHeader_IsPreserved()
        {
            var module = new ModuleDefUser("TestModChainedSmallOffsets");
            var globalType = module.GlobalType;

            // Tests cumulative tracking across chained small additions:
            // pe = base + 0x3C (0x3C)
            // pe = pe + 0x600 (0x63C <= 0x1000)
            // pe = pe + 0x600 (0xC3C <= 0x1000)
            // pe = pe + 0x600 (0x123C > 0x1000 -> None!)
            // *(int*)pe = 0 -> hook preserved!
            var hook = new MethodDefUser("ChainedSmallOffsetsHook", MethodSig.CreateStatic(module.CorLibTypes.Void))
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

            // 1. base = Marshal.GetHINSTANCE(null) -> ModuleBase
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));

            // 2. pe = base + 0x3C -> PeDerivedAddress(0x3C)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x3C));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_1));

            // 3. pe = pe + 0x600 -> cumulative 0x63C
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x600));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_1));

            // 4. pe = pe + 0x600 -> cumulative 0xC3C
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x600));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_1));

            // 5. pe = pe + 0x600 -> cumulative 0x123C > 0x1000 -> None!
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x600));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_1));

            // VirtualProtect(pe, 0x1000, 0x04, out oldProtect)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x04));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localOldProtect));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // 6. *(int*)pe = 0
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

            // Hook MUST be preserved because chained small additions accumulated past 0x1000!
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Contains(hook, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_HookWithPeAddressAndXorOfIndependentUnknownValues_IsPreserved()
        {
            var module = new ModuleDefUser("TestModXorUnknownValues");
            var globalType = module.GlobalType;

            // Scenario specifically requested by code review:
            // 1. base = Marshal.GetHINSTANCE(...) -> ModuleBase
            // 2. pe = base + 0x3C -> PeDerivedAddress(0x3C)
            // 3. val = arg0 ^ arg1 (XOR between two independent unknown/abstract arguments: None ^ None)
            // 4. *(int*)pe = val (stind.i4)
            //
            // Two abstract None values are NOT proven equal at runtime.
            // Under our corrected model, None ^ None evaluates to None (never assumed to be Zero).
            // Therefore, writing this value to pe does not constitute PE zeroing, and the hook is strictly preserved!
            var hook = new MethodDefUser("XorUnknownValuesHook",
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32, module.CorLibTypes.Int32))
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

            // 1. base = Marshal.GetHINSTANCE(null) -> ModuleBase
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));

            // 2. pe = base + 0x3C -> PeDerivedAddress(0x3C)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x3C));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_1));

            // VirtualProtect(pe, 0x1000, 0x04, out oldProtect)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x04));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localOldProtect));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // 3. *(int*)pe = arg0 ^ arg1 (ldloc.1; ldarg.0; ldarg.1; xor; stind.i4)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Xor));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stind_I4));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(hook);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_2));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, hook));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var auditReport = new ConfuserExKillerRunner.Analysis.AuditReport { CanLoad = true };
            ConfuserExKillerRunner.Analysis.QualityAuditor.AuditMethod(hook, auditReport);
            Assert.Equal("CLEAN", auditReport.Status);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Hook MUST be preserved because arg0 ^ arg1 was not proven to be zero!
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Contains(hook, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_HookWithNarrowByteReadOfELfanew_IsPreserved()
        {
            var module = new ModuleDefUser("TestModNarrowByteRead");
            var globalType = module.GlobalType;

            // Scenario specifically requested by code review:
            // 1. base = Marshal.GetHINSTANCE(...) -> ModuleBase
            // 2. pe = base + 0x3C -> PeDerivedAddress(0x3C)
            // 3. val = *(byte*)pe using ldind.u1 (1-byte read, NOT the full 32-bit e_lfanew field!)
            // 4. q = base + val (EvaluateLdind rejects 1-byte read -> val is None -> q is None)
            // 5. *(int*)q = 0 (stind.i4)
            //
            // A 1-byte read does not read the full 32-bit e_lfanew displacement to IMAGE_NT_HEADERS.
            // Under our corrected analyzer, EvaluateLdind requires a full 32-bit/native read (ldind.i4, ldind.u4, ldind.i).
            // Partial reads produce None, q evaluates to None, and the hook is strictly preserved!
            var hook = new MethodDefUser("NarrowByteReadHook", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody { InitLocals = true }
            };
            var localBase = new Local(module.CorLibTypes.IntPtr);
            var localPe = new Local(module.CorLibTypes.IntPtr);
            var localVal = new Local(module.CorLibTypes.Byte);
            var localQ = new Local(module.CorLibTypes.IntPtr);
            var localOldProtect = new Local(module.CorLibTypes.UInt32);
            hook.Body.Variables.Add(localBase);
            hook.Body.Variables.Add(localPe);
            hook.Body.Variables.Add(localVal);
            hook.Body.Variables.Add(localQ);
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

            // 1. base = Marshal.GetHINSTANCE(null) -> ModuleBase
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));

            // 2. pe = base + 0x3C -> PeDerivedAddress(0x3C)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x3C));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_1));

            // 3. val = *(byte*)pe -> ldloc.1; ldind.u1; stloc.2 (narrow byte read!)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldind_U1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_2));

            // 4. q = base + val -> ldloc.0; ldloc.2; conv.i; add; stloc.3 (q is None!)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_2));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Conv_I));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_3));

            // VirtualProtect(q, 0x1000, 0x04, out oldProtect)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_3));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x04));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localOldProtect));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // 5. *(int*)q = 0
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_3));
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

            // Hook MUST be preserved because ldind.u1 is a partial 1-byte read, not full 32-bit e_lfanew!
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Contains(hook, globalType.Methods);
        }

        private static (MethodDef hook, MethodDef cctor) CreateLdindIHook(ModuleDefUser module)
        {
            var hook = new MethodDefUser("LdindIHook_" + Guid.NewGuid().ToString("N").Substring(0, 8),
                MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody { InitLocals = true }
            };
            var localBase = new Local(module.CorLibTypes.IntPtr);
            var localPe = new Local(module.CorLibTypes.IntPtr);
            var localVal = new Local(module.CorLibTypes.IntPtr);
            var localQ = new Local(module.CorLibTypes.IntPtr);
            var localOldProtect = new Local(module.CorLibTypes.UInt32);
            hook.Body.Variables.Add(localBase);
            hook.Body.Variables.Add(localPe);
            hook.Body.Variables.Add(localVal);
            hook.Body.Variables.Add(localQ);
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

            // 1. base = Marshal.GetHINSTANCE(null) -> ModuleBase
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));

            // 2. pe = base + 0x3C -> PeDerivedAddress(0x3C)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x3C));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_1));

            // 3. val = *(IntPtr*)pe -> ldloc.1; ldind.i; stloc.2 (native int read!)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_1));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldind_I));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_2));

            // 4. q = base + val -> ldloc.0; ldloc.2; add; stloc.3
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_2));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_3));

            // VirtualProtect(q, 0x1000, 0x04, out oldProtect)
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_3));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x04));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localOldProtect));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // 5. *(int*)q = 0
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_3));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stind_I4));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            module.GlobalType.Methods.Add(hook);

            var cctor = module.GlobalType.FindStaticConstructor();
            if (cctor == null)
            {
                cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                    MethodImplAttributes.IL | MethodImplAttributes.Managed,
                    MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
                {
                    Body = new CilBody()
                };
                cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                module.GlobalType.Methods.Add(cctor);
            }
            cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, hook));

            var auditReport = new ConfuserExKillerRunner.Analysis.AuditReport { CanLoad = true };
            ConfuserExKillerRunner.Analysis.QualityAuditor.AuditMethod(hook, auditReport);
            Assert.Equal("CLEAN", auditReport.Status);

            return (hook, cctor);
        }

        [Fact]
        public void StripProtectorHooks_HookWithNativeIntReadOfELfanew_64BitModule_IsPreserved()
        {
            var module = new ModuleDefUser("TestMod64Bit");
            module.Machine = Machine.AMD64;

            var (hook, _) = CreateLdindIHook(module);
            var result = CleanerKiller.StripProtectorHooks(module);

            // On 64-bit target, ldind.i reads 8 bytes, which overflows 4-byte e_lfanew.
            // Hook MUST be preserved!
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Contains(hook, module.GlobalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_HookWithNativeIntReadOfELfanew_AmbiguousAnyCPUModule_IsPreserved()
        {
            var module = new ModuleDefUser("TestModAnyCPU");
            module.Machine = Machine.I386;
            module.Is32BitRequired = false;
            module.IsILOnly = true;

            var (hook, _) = CreateLdindIHook(module);
            var result = CleanerKiller.StripProtectorHooks(module);

            // AnyCPU module without 32BitRequired has ambiguous runtime bitness (runs as 64-bit on 64-bit OS/hosts).
            // Conservative analyzer must reject ldind.i as proof of 4-byte read, preserving the hook!
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Contains(hook, module.GlobalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_HookWithNativeIntReadOfELfanew_UnknownArchitecture_IsPreserved()
        {
            var module = new ModuleDefUser("TestModUnknownArch");
            module.Machine = Machine.Unknown;

            var (hook, _) = CreateLdindIHook(module);
            var result = CleanerKiller.StripProtectorHooks(module);

            // Unknown architecture cannot guarantee 32-bit execution. Hook must be preserved!
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Contains(hook, module.GlobalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_HookWithNativeIntReadOfELfanew_Guaranteed32BitModule_IsStripped()
        {
            var module = new ModuleDefUser("TestMod32BitReq");
            module.Machine = Machine.I386;
            module.Is32BitRequired = true;

            var (hook, _) = CreateLdindIHook(module);
            var result = CleanerKiller.StripProtectorHooks(module);

            // Target module is guaranteed to execute as 32-bit, so ldind.i is strictly 4 bytes and reads e_lfanew.
            // Hook is properly recognized as Anti-Dump and stripped!
            Assert.Equal(1, result.StrippedHooksCount);
            Assert.DoesNotContain(hook, module.GlobalType.Methods);
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

        #region SanitizeModuleStaticConstructor Tests (Phase 2)

        [Fact]
        public void SanitizeModuleStaticConstructor_UserStaticMethodCall_IsPreserved()
        {
            // Case 1: Call to known static application method must be preserved
            var module = new ModuleDefUser("TestMod");
            var userType = new TypeDefUser("AppNamespace", "AppConfig", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(userType);

            var userMethod = new MethodDefUser("InitializeLogging", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed, MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody { Instructions = { Instruction.Create(OpCodes.Ret) } }
            };
            userType.Methods.Add(userMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            module.GlobalType.Methods.Add(cctor);

            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, userMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Pop)); // Induces structural defect
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            var result = new CleanerResult();
            CleanerKiller.SanitizeModuleStaticConstructor(cctor, result);

            // User call must remain intact
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Equal(userMethod, cctor.Body.Instructions[0].Operand);
            Assert.Equal(0, result.StrippedHooksCount);
        }

        [Fact]
        public void SanitizeModuleStaticConstructor_UserInstanceMethodCall_IsPreserved()
        {
            // Case 2: Call to known instance application method must be preserved
            var module = new ModuleDefUser("TestMod");
            var userType = new TypeDefUser("AppNamespace", "ServiceHost", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(userType);

            var userInstanceMethod = new MethodDefUser("Start", MethodSig.CreateInstance(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed, MethodAttributes.Public)
            {
                Body = new CilBody { Instructions = { Instruction.Create(OpCodes.Ret) } }
            };
            userType.Methods.Add(userInstanceMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            module.GlobalType.Methods.Add(cctor);

            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, userInstanceMethod)); // Unbalanced instance call
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            var result = new CleanerResult();
            CleanerKiller.SanitizeModuleStaticConstructor(cctor, result);

            // Instance user call must NEVER be neutralized
            Assert.Equal(OpCodes.Callvirt, cctor.Body.Instructions[0].OpCode);
            Assert.Equal(userInstanceMethod, cctor.Body.Instructions[0].Operand);
            Assert.Equal(0, result.StrippedHooksCount);
        }

        [Fact]
        public void SanitizeModuleStaticConstructor_UnresolvableExternalRef_IsPreserved()
        {
            // Case 3: Missing external assembly reference must be preserved
            var module = new ModuleDefUser("TestMod");
            var missingAsmRef = new AssemblyRefUser("ExternalDependency", new Version(2, 0, 0, 0));
            var missingTypeRef = new TypeRefUser(module, "ExternalLib", "Initializer", missingAsmRef);
            var missingMethodRef = new MemberRefUser(module, "InitModule", MethodSig.CreateStatic(module.CorLibTypes.Void), missingTypeRef);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            module.GlobalType.Methods.Add(cctor);

            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, missingMethodRef));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Pop)); // Structural defect
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            var result = new CleanerResult();
            CleanerKiller.SanitizeModuleStaticConstructor(cctor, result);

            // External call must be preserved
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Equal(missingMethodRef, cctor.Body.Instructions[0].Operand);
            Assert.Equal(0, result.StrippedHooksCount);
        }

        [Fact]
        public void SanitizeModuleStaticConstructor_UnresolvableMemberRef_IsPreserved()
        {
            // Case 4: Unresolvable MemberRef on local type must be preserved
            var module = new ModuleDefUser("TestMod");
            var userType = new TypeDefUser("AppNamespace", "AppBootstrap", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(userType);
            var unresolvableRef = new MemberRefUser(module, "GhostMethod", MethodSig.CreateStatic(module.CorLibTypes.Void), userType);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            module.GlobalType.Methods.Add(cctor);

            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, unresolvableRef));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Pop)); // Structural defect
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            var result = new CleanerResult();
            CleanerKiller.SanitizeModuleStaticConstructor(cctor, result);

            // Unresolvable MemberRef must be preserved
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Equal(unresolvableRef, cctor.Body.Instructions[0].Operand);
            Assert.Equal(0, result.StrippedHooksCount);
        }

        [Fact]
        public void SanitizeModuleStaticConstructor_UnknownSignatureOnModule_IsPreserved()
        {
            // Case 5: Target on <Module> with application behavior (not a protector) must be preserved
            var module = new ModuleDefUser("TestMod");
            var appHelperOnModule = new MethodDefUser("ComputeChecksum", MethodSig.CreateStatic(module.CorLibTypes.Int32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed, MethodAttributes.Private | MethodAttributes.Static)
            {
                Body = new CilBody
                {
                    Instructions =
                    {
                        Instruction.Create(OpCodes.Ldc_I4, 12345),
                        Instruction.Create(OpCodes.Ret)
                    }
                }
            };
            module.GlobalType.Methods.Add(appHelperOnModule);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            module.GlobalType.Methods.Add(cctor);

            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, appHelperOnModule)); // Pushes int, causes non-zero stack at ret
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            var result = new CleanerResult();
            CleanerKiller.SanitizeModuleStaticConstructor(cctor, result);

            // Helper must NOT be classified as protector or stripped
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Equal(appHelperOnModule, cctor.Body.Instructions[0].Operand);
            Assert.Equal(0, result.StrippedHooksCount);
        }

        [Fact]
        public void SanitizeModuleStaticConstructor_UnambiguousProtectorHook_IsSanitized()
        {
            // Case 6: Unambiguously recognized protector hook causing structural invalidity is sanitized
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            // Canonical protector stub
            var protectorStub = new MethodDefUser("ConfuserStub", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed, MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef));
            protectorStub.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            protectorStub.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            protectorStub.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            protectorStub.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(protectorStub);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            globalType.Methods.Add(cctor);

            // Call to protector stub is present with null operand defect elsewhere or missing argument
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, protectorStub));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            // Force an orphaned stack underflow by prepending pop
            cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Pop));

            var result = new CleanerResult();
            CleanerKiller.SanitizeModuleStaticConstructor(cctor, result);

            // Since pop underflows, neutralizing protectorStub alone doesn't fix pop underflow, so it rolls back
            Assert.Equal(OpCodes.Pop, cctor.Body.Instructions[0].OpCode);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[1].OpCode);
        }

        [Fact]
        public void SanitizeModuleStaticConstructor_ProtectorStubUnderflow_FixedAndSanitized()
        {
            // Case 6b: Protector stub call with non-void return whose consumer was stripped leaves stack at ret = 1
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            var stubMethod = new MethodDefUser("IntPtrStub", MethodSig.CreateStatic(module.CorLibTypes.IntPtr),
                MethodImplAttributes.IL | MethodImplAttributes.Managed, MethodAttributes.Public | MethodAttributes.Static)
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

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            globalType.Methods.Add(cctor);

            // cctor calls IntPtrStub and does NOT pop -> stack depth at ret is 1 for void method (structural defect!)
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, stubMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            Assert.False(QualityAuditor.IsMethodStructurallyValid(cctor, out _));

            var result = new CleanerResult();
            CleanerKiller.SanitizeModuleStaticConstructor(cctor, result);

            // Sanitizing recognized stub fixes stack depth at ret from 1 to 0!
            Assert.True(QualityAuditor.IsMethodStructurallyValid(cctor, out _));
            Assert.Equal(OpCodes.Nop, cctor.Body.Instructions[0].OpCode);
            Assert.Null(cctor.Body.Instructions[0].Operand);
            Assert.Equal(1, result.StrippedHooksCount);
        }

        [Fact]
        public void SanitizeModuleStaticConstructor_MethodNamedLikeHook_ButApplicationBehavior_IsPreserved()
        {
            // Case 7: Method named "AntiTamper_Init" with application code must be preserved
            var module = new ModuleDefUser("TestMod");
            var fakeHook = new MethodDefUser("AntiTamper_Init", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed, MethodAttributes.Private | MethodAttributes.Static)
            {
                Body = new CilBody
                {
                    Instructions =
                    {
                        Instruction.Create(OpCodes.Ldstr, "App Started"),
                        Instruction.Create(OpCodes.Pop),
                        Instruction.Create(OpCodes.Ret)
                    }
                }
            };
            module.GlobalType.Methods.Add(fakeHook);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            module.GlobalType.Methods.Add(cctor);

            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, fakeHook));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Pop)); // Induce structural defect
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            var result = new CleanerResult();
            CleanerKiller.SanitizeModuleStaticConstructor(cctor, result);

            // Must NOT be neutralized based on name alone!
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Equal(fakeHook, cctor.Body.Instructions[0].Operand);
            Assert.Equal(0, result.StrippedHooksCount);
        }

        [Fact]
        public void SanitizeModuleStaticConstructor_ConstructorWithBranches_PreservesControlFlowIntegrity()
        {
            // Case 8: cctor containing branches preserves CFG integrity
            var module = new ModuleDefUser("TestMod");
            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            module.GlobalType.Methods.Add(cctor);

            var retTarget = Instruction.Create(OpCodes.Ret);
            var branchInst = Instruction.Create(OpCodes.Brtrue, retTarget);

            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
            cctor.Body.Instructions.Add(branchInst);
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Nop));
            cctor.Body.Instructions.Add(retTarget);

            // Valid CFG initially
            Assert.True(QualityAuditor.IsMethodStructurallyValid(cctor, out _));

            CleanerKiller.SanitizeModuleStaticConstructor(cctor);

            // Must remain structurally valid with branch target unchanged
            Assert.True(QualityAuditor.IsMethodStructurallyValid(cctor, out _));
            Assert.Equal(retTarget, branchInst.Operand);
        }

        [Fact]
        public void SanitizeModuleStaticConstructor_ConstructorWithExceptionHandlers_PreservesEHIntegrity()
        {
            // Case 9: cctor containing exception handler clauses preserves EH integrity
            var module = new ModuleDefUser("TestMod");
            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            module.GlobalType.Methods.Add(cctor);

            var tryStart = Instruction.Create(OpCodes.Nop);
            var tryEnd = Instruction.Create(OpCodes.Leave_S, (Instruction)null);
            var handlerStart = Instruction.Create(OpCodes.Pop);
            var handlerEnd = Instruction.Create(OpCodes.Leave_S, (Instruction)null);
            var retInst = Instruction.Create(OpCodes.Ret);

            tryEnd.Operand = retInst;
            handlerEnd.Operand = retInst;

            cctor.Body.Instructions.Add(tryStart);
            cctor.Body.Instructions.Add(tryEnd);
            cctor.Body.Instructions.Add(handlerStart);
            cctor.Body.Instructions.Add(handlerEnd);
            cctor.Body.Instructions.Add(retInst);

            cctor.Body.ExceptionHandlers.Add(new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = tryStart,
                TryEnd = handlerStart,
                HandlerStart = handlerStart,
                HandlerEnd = retInst,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
            });

            Assert.True(QualityAuditor.IsMethodStructurallyValid(cctor, out _));

            CleanerKiller.SanitizeModuleStaticConstructor(cctor);

            // EH clause bounds and method validity must be 100% preserved
            Assert.True(QualityAuditor.IsMethodStructurallyValid(cctor, out _));
            Assert.Single(cctor.Body.ExceptionHandlers);
            Assert.Equal(tryStart, cctor.Body.ExceptionHandlers[0].TryStart);
        }

        [Fact]
        public void SanitizeModuleStaticConstructor_ValidationFailureAfterCorrection_RollsBackToOriginal()
        {
            // Case 10: Validation failure after correction triggers atomic rollback
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            // Stub that returns IntPtr
            var stubMethod = new MethodDefUser("IntPtrStub", MethodSig.CreateStatic(module.CorLibTypes.IntPtr),
                MethodImplAttributes.IL | MethodImplAttributes.Managed, MethodAttributes.Public | MethodAttributes.Static)
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

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            globalType.Methods.Add(cctor);

            // cctor has stub call, PLUS an unfixable stack underflow before it
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Pop)); // Underflow at IL_0000
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, stubMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            var result = new CleanerResult();
            CleanerKiller.SanitizeModuleStaticConstructor(cctor, result);

            // Because neutralizing stubMethod still leaves the underflow pop at IL_0000,
            // QualityAuditor fails and the method MUST be completely restored to its original instructions!
            Assert.Equal(OpCodes.Pop, cctor.Body.Instructions[0].OpCode);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[1].OpCode);
            Assert.Equal(stubMethod, cctor.Body.Instructions[1].Operand);
            Assert.Equal(0, result.StrippedHooksCount);
        }

        #endregion

        #region Phase 3 — PE Symbolic Evaluation & Integer Width Regression Tests

        [Fact]
        public void PeSymbolic_64BitMultiplication_Produces4294967296()
        {
            var module = new ModuleDefUser("TestMod");
            var stack = new List<CleanerKiller.PeSymbolicSlot>();
            var locals = Array.Empty<CleanerKiller.PeSymbolicSlot>();
            bool zeroing = false;

            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I8, 65536L), stack, locals, ref zeroing, module);
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I8, 65536L), stack, locals, ref zeroing, module);
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Mul), stack, locals, ref zeroing, module);

            Assert.Single(stack);
            var res = stack[0];
            Assert.Equal(CleanerKiller.PeSymbolicKind.NumericOffset, res.Kind);
            Assert.Equal(4294967296L, res.ConcreteValue);
            Assert.Equal(CleanerKiller.IntegerWidth.Bit64, res.Width);
        }

        [Fact]
        public void PeSymbolic_32BitMultiplication_WrapsAccordingToILWidth()
        {
            var module = new ModuleDefUser("TestMod");
            var stack = new List<CleanerKiller.PeSymbolicSlot>();
            var locals = Array.Empty<CleanerKiller.PeSymbolicSlot>();
            bool zeroing = false;

            // In 32-bit IL multiplication, 65536 * 65536 = 0x100000000 which wraps to 0
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, 65536), stack, locals, ref zeroing, module);
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, 65536), stack, locals, ref zeroing, module);
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Mul), stack, locals, ref zeroing, module);

            Assert.Single(stack);
            var res = stack[0];
            Assert.Equal(CleanerKiller.PeSymbolicKind.Zero, res.Kind);
            Assert.Equal(0L, res.ConcreteValue);
            Assert.Equal(CleanerKiller.IntegerWidth.Bit32, res.Width);
        }

        [Fact]
        public void PeSymbolic_MulOvf_OverflowFailsToNone()
        {
            var module = new ModuleDefUser("TestMod");
            var stack = new List<CleanerKiller.PeSymbolicSlot>();
            var locals = Array.Empty<CleanerKiller.PeSymbolicSlot>();
            bool zeroing = false;

            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, int.MaxValue), stack, locals, ref zeroing, module);
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, 2), stack, locals, ref zeroing, module);
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Mul_Ovf), stack, locals, ref zeroing, module);

            Assert.Single(stack);
            Assert.Equal(CleanerKiller.PeSymbolicSlot.None, stack[0]);
        }

        [Fact]
        public void PeSymbolic_64BitShiftLeft_DoesNotMaskWith0x1F()
        {
            var module = new ModuleDefUser("TestMod");
            var stack = new List<CleanerKiller.PeSymbolicSlot>();
            var locals = Array.Empty<CleanerKiller.PeSymbolicSlot>();
            bool zeroing = false;

            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I8, 1L), stack, locals, ref zeroing, module);
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, 32), stack, locals, ref zeroing, module);
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Shl), stack, locals, ref zeroing, module);

            Assert.Single(stack);
            var res = stack[0];
            Assert.Equal(CleanerKiller.PeSymbolicKind.NumericOffset, res.Kind);
            Assert.Equal(4294967296L, res.ConcreteValue);
            Assert.Equal(CleanerKiller.IntegerWidth.Bit64, res.Width);
        }

        [Fact]
        public void PeSymbolic_32BitShiftLeft_MasksWith0x1F()
        {
            var module = new ModuleDefUser("TestMod");
            var stack = new List<CleanerKiller.PeSymbolicSlot>();
            var locals = Array.Empty<CleanerKiller.PeSymbolicSlot>();
            bool zeroing = false;

            // 32-bit shift masks shift amount with 0x1F: 32 & 0x1F = 0, so 1 << 0 = 1
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, 1), stack, locals, ref zeroing, module);
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, 32), stack, locals, ref zeroing, module);
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Shl), stack, locals, ref zeroing, module);

            Assert.Single(stack);
            var res = stack[0];
            Assert.Equal(CleanerKiller.PeSymbolicKind.NumericOffset, res.Kind);
            Assert.Equal(1L, res.ConcreteValue);
            Assert.Equal(CleanerKiller.IntegerWidth.Bit32, res.Width);
        }

        [Fact]
        public void PeSymbolic_Shr_ArithmeticShiftOnNegativeValue()
        {
            var module = new ModuleDefUser("TestMod");
            var stack = new List<CleanerKiller.PeSymbolicSlot>();
            var locals = Array.Empty<CleanerKiller.PeSymbolicSlot>();
            bool zeroing = false;

            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I8, -16L), stack, locals, ref zeroing, module);
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, 2), stack, locals, ref zeroing, module);
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Shr), stack, locals, ref zeroing, module);

            Assert.Single(stack);
            var res = stack[0];
            Assert.Equal(-4L, res.ConcreteValue);
            Assert.Equal(CleanerKiller.IntegerWidth.Bit64, res.Width);
        }

        [Fact]
        public void PeSymbolic_ShrUn_LogicalShiftOnNegativeValue()
        {
            var module = new ModuleDefUser("TestMod");
            var stack = new List<CleanerKiller.PeSymbolicSlot>();
            var locals = Array.Empty<CleanerKiller.PeSymbolicSlot>();
            bool zeroing = false;

            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I8, -16L), stack, locals, ref zeroing, module);
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, 2), stack, locals, ref zeroing, module);
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Shr_Un), stack, locals, ref zeroing, module);

            Assert.Single(stack);
            var res = stack[0];
            long expected = (long)(unchecked((ulong)-16L) >> 2);
            Assert.Equal(expected, res.ConcreteValue);
            Assert.Equal(CleanerKiller.IntegerWidth.Bit64, res.Width);
        }

        [Fact]
        public void PeSymbolic_ShrUn_LogicalShiftOnNegative32BitValue()
        {
            var module = new ModuleDefUser("TestMod");
            var stack = new List<CleanerKiller.PeSymbolicSlot>();
            var locals = Array.Empty<CleanerKiller.PeSymbolicSlot>();
            bool zeroing = false;

            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, -16), stack, locals, ref zeroing, module);
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, 2), stack, locals, ref zeroing, module);
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Shr_Un), stack, locals, ref zeroing, module);

            Assert.Single(stack);
            var res = stack[0];
            long expected = (long)(unchecked((uint)-16) >> 2); // 1073741820L (0x3FFFFFFC), NOT arithmetic 4294967292L
            Assert.Equal(1073741820L, res.ConcreteValue);
            Assert.Equal(expected, res.ConcreteValue);
            Assert.Equal(CleanerKiller.IntegerWidth.Bit32, res.Width);
        }

        [Fact]
        public void PeSymbolic_ShrUn_32Bit_DistinguishesLogicalFromArithmetic()
        {
            var module = new ModuleDefUser("TestMod");
            var stack = new List<CleanerKiller.PeSymbolicSlot>();
            var locals = Array.Empty<CleanerKiller.PeSymbolicSlot>();
            bool zeroing = false;

            // Shr (arithmetic): -16 >> 2 == -4
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, -16), stack, locals, ref zeroing, module);
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, 2), stack, locals, ref zeroing, module);
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Shr), stack, locals, ref zeroing, module);
            var resShr = stack[0];
            Assert.Equal(-4L, resShr.ConcreteValue);

            stack.Clear();
            // Shr_Un (logical): unchecked((uint)-16) >> 2 == 1073741820
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, -16), stack, locals, ref zeroing, module);
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, 2), stack, locals, ref zeroing, module);
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Shr_Un), stack, locals, ref zeroing, module);
            var resShrUn = stack[0];
            Assert.Equal(1073741820L, resShrUn.ConcreteValue);
            Assert.NotEqual(resShr.ConcreteValue, resShrUn.ConcreteValue);
        }

        [Fact]
        public void PeSymbolic_ConvI8_SignExtendsNegative32BitInteger()
        {
            var module = new ModuleDefUser("TestMod");
            var stack = new List<CleanerKiller.PeSymbolicSlot>();
            var locals = Array.Empty<CleanerKiller.PeSymbolicSlot>();
            bool zeroing = false;

            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, -1), stack, locals, ref zeroing, module);
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Conv_I8), stack, locals, ref zeroing, module);

            Assert.Single(stack);
            var res = stack[0];
            Assert.Equal(-1L, res.ConcreteValue);
            Assert.Equal(CleanerKiller.IntegerWidth.Bit64, res.Width);
        }

        [Fact]
        public void PeSymbolic_ConvU8_ZeroExtends32BitInteger()
        {
            var module = new ModuleDefUser("TestMod");
            var stack = new List<CleanerKiller.PeSymbolicSlot>();
            var locals = Array.Empty<CleanerKiller.PeSymbolicSlot>();
            bool zeroing = false;

            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I4, -1), stack, locals, ref zeroing, module);
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Conv_U8), stack, locals, ref zeroing, module);

            Assert.Single(stack);
            var res = stack[0];
            Assert.Equal(4294967295L, res.ConcreteValue);
            Assert.Equal(CleanerKiller.IntegerWidth.Bit64, res.Width);
        }

        [Fact]
        public void PeSymbolic_ConvI_OnGuaranteed32BitModule_TruncatesTo32Bit()
        {
            var module = new ModuleDefUser("TestMod32") { Machine = Machine.I386, Is32BitRequired = true };
            var stack = new List<CleanerKiller.PeSymbolicSlot>();
            var locals = Array.Empty<CleanerKiller.PeSymbolicSlot>();
            bool zeroing = false;

            // 4294967296L is 0x100000000L. In 32-bit native int, it truncates to 0
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I8, 4294967296L), stack, locals, ref zeroing, module);
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Conv_I), stack, locals, ref zeroing, module);

            Assert.Single(stack);
            var res = stack[0];
            Assert.Equal(CleanerKiller.PeSymbolicKind.Zero, res.Kind);
            Assert.Equal(0L, res.ConcreteValue);
            Assert.Equal(CleanerKiller.IntegerWidth.Bit32, res.Width);
        }

        [Fact]
        public void PeSymbolic_ConvI_OnGuaranteed64BitModule_Preserves64Bit()
        {
            var module = new ModuleDefUser("TestMod64") { Machine = Machine.AMD64 };
            var stack = new List<CleanerKiller.PeSymbolicSlot>();
            var locals = Array.Empty<CleanerKiller.PeSymbolicSlot>();
            bool zeroing = false;

            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Ldc_I8, 4294967296L), stack, locals, ref zeroing, module);
            CleanerKiller.ExecuteSymbolicInstruction(Instruction.Create(OpCodes.Conv_I), stack, locals, ref zeroing, module);

            Assert.Single(stack);
            var res = stack[0];
            Assert.Equal(CleanerKiller.PeSymbolicKind.NumericOffset, res.Kind);
            Assert.Equal(4294967296L, res.ConcreteValue);
            Assert.Equal(CleanerKiller.IntegerWidth.Bit64, res.Width);
        }

        [Fact]
        public void PeSymbolic_DisplacementExceedingMaxPeHeader_LosesProvenance()
        {
            // Adding a displacement exceeding 0x1000 from ModuleBase revokes PE provenance
            var excessOffset = new CleanerKiller.PeSymbolicSlot(CleanerKiller.PeSymbolicKind.NumericOffset, 0x1001L, CleanerKiller.IntegerWidth.Bit32);
            var result = CleanerKiller.CombineAdd(CleanerKiller.PeSymbolicSlot.ModuleBase, excessOffset);

            Assert.Equal(CleanerKiller.PeSymbolicSlot.None, result);
        }

        [Fact]
        public void PeSymbolic_CombineAnd_WithZero_RevokesProvenance()
        {
            // Strict X & 0 = 0: Address provenance MUST NOT survive bitwise AND with 0
            var derived = new CleanerKiller.PeSymbolicSlot(CleanerKiller.PeSymbolicKind.PeDerivedAddress, 0x3CL, CleanerKiller.IntegerWidth.Native);
            var res1 = CleanerKiller.CombineAnd(derived, CleanerKiller.PeSymbolicSlot.Zero);
            var res2 = CleanerKiller.CombineAnd(CleanerKiller.PeSymbolicSlot.ModuleBase, CleanerKiller.PeSymbolicSlot.Zero);
            var res3 = CleanerKiller.CombineAnd(derived, CleanerKiller.PeSymbolicSlot.Zero64);

            Assert.Equal(CleanerKiller.PeSymbolicKind.Zero, res1.Kind);
            Assert.Equal(CleanerKiller.PeSymbolicKind.Zero, res2.Kind);
            Assert.Equal(CleanerKiller.PeSymbolicKind.Zero, res3.Kind);
            Assert.False(CleanerKiller.IsPeTarget(res1));
            Assert.False(CleanerKiller.IsPeTarget(res2));
            Assert.False(CleanerKiller.IsPeTarget(res3));
        }

        [Fact]
        public void PeSymbolic_CombineAnd_WithArbitraryMask_LosesProvenance()
        {
            // Arbitrary mask 0x7F is NOT an alignment mask (e.g. -4, -16)
            var derived = new CleanerKiller.PeSymbolicSlot(CleanerKiller.PeSymbolicKind.PeDerivedAddress, 0x3CL, CleanerKiller.IntegerWidth.Native);
            var arbitraryMask = new CleanerKiller.PeSymbolicSlot(CleanerKiller.PeSymbolicKind.NumericOffset, 0x7FL, CleanerKiller.IntegerWidth.Bit32);

            var result = CleanerKiller.CombineAnd(derived, arbitraryMask);

            Assert.Equal(CleanerKiller.PeSymbolicSlot.None, result);
        }

        [Fact]
        public void PeSymbolic_UnknownOperationFollowedByAddressCalculation_YieldsNone()
        {
            // Combining ModuleBase with None yields None (provenance lost)
            var result = CleanerKiller.CombineAdd(CleanerKiller.PeSymbolicSlot.ModuleBase, CleanerKiller.PeSymbolicSlot.None);
            Assert.Equal(CleanerKiller.PeSymbolicSlot.None, result);
        }

        [Fact]
        public void PeSymbolic_IncompatibleBranchMerge_SafelyAbortsZeroingDetection()
        {
            var module = new ModuleDefUser("BranchMod");
            var method = new MethodDefUser("AmbiguousBranchMethod", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody { InitLocals = true }
            };
            method.Body.Variables.Add(new Local(module.CorLibTypes.IntPtr));

            var marshalType = new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef);
            var moduleType = new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef);
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, moduleType.ToTypeSig()),
                marshalType);

            // Path 1 branches over, pushing an extra value to stack, violating stack depth invariance across paths
            var labelTarget = Instruction.Create(OpCodes.Nop);
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Brtrue, labelTarget));

            // Path A: pushes ModuleBase
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));

            // Path B: labelTarget arrives with stack depth 0, but Path A would arrive with different state
            method.Body.Instructions.Add(labelTarget);
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            // Ambiguous / incompatible flow aborts symbolic zeroing analysis and safely returns false
            Assert.False(CleanerKiller.HasLinkedPeHeaderZeroing(method));
        }

        [Fact]
        public void PeSymbolic_LargeDisplacementCipher_NotMisclassifiedAsAntiDump()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            // Hook that calls VirtualProtect, but adds a 64-bit large displacement (4294967296L)
            // If the analyzer had 32-bit truncation, 4294967296 would truncate to 0 and mimic ModuleBase write!
            // With 64-bit integer width, the large displacement exceeds MaxPeHeaderDisplacement and is rejected!
            var hook = new MethodDefUser("LargeDisplacementHook", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody { InitLocals = true }
            };
            var localBase = new Local(module.CorLibTypes.IntPtr);
            var localOldProtect = new Local(module.CorLibTypes.UInt32);
            hook.Body.Variables.Add(localBase);
            hook.Body.Variables.Add(localOldProtect);

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

            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Stloc_0));

            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x1000));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 0x04));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloca_S, localOldProtect));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Call, vpRef));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // Large 64-bit displacement: base + 4294967296L
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldloc_0));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I8, 4294967296L));
            hook.Body.Instructions.Add(Instruction.Create(OpCodes.Add));
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

            // Because the displacement is 4294967296L (beyond PE headers), zeroing is NOT linked to PE headers.
            Assert.False(CleanerKiller.HasLinkedPeHeaderZeroing(hook));

            var result = CleanerKiller.StripProtectorHooks(module);

            // The ambiguous hook MUST BE RETAINED and NOT stripped!
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Contains(hook, globalType.Methods);
        }

        #endregion

        #region Phase 6 False Positive Anti-Debug & Anti-Dump Tests

        [Fact]
        public void StripProtectorHooks_ApplicationDiagnosticReturningBool_IsRetained()
        {
            var module = new ModuleDefUser("AppMod");
            var globalType = module.GlobalType;

            // Application method CheckDebugger returns bool and only calls Debugger.IsAttached (diagnostic)
            var diagMethod = new MethodDefUser("CheckDebugger", MethodSig.CreateStatic(module.CorLibTypes.Boolean))
            {
                Body = new CilBody()
            };
            var isAttachedRef = new MemberRefUser(module, "get_IsAttached",
                MethodSig.CreateStatic(module.CorLibTypes.Boolean),
                new TypeRefUser(module, "System.Diagnostics", "Debugger", module.CorLibTypes.AssemblyRef));
            diagMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, isAttachedRef));
            diagMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(diagMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, diagMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Diagnostic method returning bool must be RETAINED and NOT stripped
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Contains(diagMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_ApplicationDiagnosticVoidWithoutTermination_IsRetained()
        {
            var module = new ModuleDefUser("AppMod");
            var globalType = module.GlobalType;

            // Void method checking Debugger.IsLogging but without FailFast or Kill
            var diagMethod = new MethodDefUser("LogDebuggerState", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var isLoggingRef = new MemberRefUser(module, "IsLogging",
                MethodSig.CreateStatic(module.CorLibTypes.Boolean),
                new TypeRefUser(module, "System.Diagnostics", "Debugger", module.CorLibTypes.AssemblyRef));
            diagMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, isLoggingRef));
            diagMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            diagMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(diagMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, diagMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Without termination or watchdog thread, it is an application diagnostic: RETAINED
            Assert.Equal(0, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Call, cctor.Body.Instructions[0].OpCode);
            Assert.Contains(diagMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_ConfirmedConfuserAntiDebugWithFailFast_IsStripped()
        {
            var module = new ModuleDefUser("AppMod");
            var globalType = module.GlobalType;

            // ConfuserEx Anti-Debug pattern: checks Debugger.IsAttached AND calls FailFast
            var antiDebugMethod = new MethodDefUser("ConfuserAntiDebug", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var isAttachedRef = new MemberRefUser(module, "get_IsAttached",
                MethodSig.CreateStatic(module.CorLibTypes.Boolean),
                new TypeRefUser(module, "System.Diagnostics", "Debugger", module.CorLibTypes.AssemblyRef));
            var failFastRef = new MemberRefUser(module, "FailFast",
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.String),
                new TypeRefUser(module, "System", "Environment", module.CorLibTypes.AssemblyRef));

            var retIns = Instruction.Create(OpCodes.Ret);
            antiDebugMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, isAttachedRef));
            antiDebugMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Brfalse_S, retIns));
            antiDebugMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            antiDebugMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, failFastRef));
            antiDebugMethod.Body.Instructions.Add(retIns);
            globalType.Methods.Add(antiDebugMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, antiDebugMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Confirmed ConfuserEx Anti-Debug: stripped!
            Assert.Equal(1, result.StrippedHooksCount);
            Assert.True(result.AntiDebugStripped);
            Assert.Equal(OpCodes.Nop, cctor.Body.Instructions[0].OpCode);
            Assert.DoesNotContain(antiDebugMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_ConfirmedConfuserAntiDebugWithWatchdogThread_IsStripped()
        {
            var module = new ModuleDefUser("AppMod");
            var globalType = module.GlobalType;

            // Worker thread method that checks ENABLE_PROFILING
            var workerMethod = new MethodDefUser("WatchdogWorker", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            workerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "ENABLE_PROFILING"));
            workerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            workerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(workerMethod);

            // Main hook method that starts the thread
            var antiDebugMethod = new MethodDefUser("ConfuserAntiDebugThread", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var threadStartCtor = new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr),
                new TypeRefUser(module, "System.Threading", "ThreadStart", module.CorLibTypes.AssemblyRef));
            var threadType = new TypeRefUser(module, "System.Threading", "Thread", module.CorLibTypes.AssemblyRef);
            var threadCtor = new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void, new TypeRefUser(module, "System.Threading", "ThreadStart", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                threadType);
            var threadStartMethod = new MemberRefUser(module, "Start",
                MethodSig.CreateInstance(module.CorLibTypes.Void),
                threadType);

            antiDebugMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            antiDebugMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldftn, workerMethod));
            antiDebugMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Newobj, threadStartCtor));
            antiDebugMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Newobj, threadCtor));
            antiDebugMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, threadStartMethod));
            antiDebugMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(antiDebugMethod);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, antiDebugMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var result = CleanerKiller.StripProtectorHooks(module);

            Assert.Equal(1, result.StrippedHooksCount);
            Assert.True(result.AntiDebugStripped);
            Assert.Equal(OpCodes.Nop, cctor.Body.Instructions[0].OpCode);
            Assert.DoesNotContain(antiDebugMethod, globalType.Methods);
            Assert.DoesNotContain(workerMethod, globalType.Methods);
        }

        [Fact]
        public void StripProtectorHooks_MethodReferencedByDelegate_IsNotDeletedFromModule()
        {
            var module = new ModuleDefUser("AppMod");
            var globalType = module.GlobalType;

            // Protector hook that matches exact stub
            var stub = new MethodDefUser("ExactStub", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef));
            stub.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            stub.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            stub.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            stub.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(stub);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, stub));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            // An application method holds a delegate reference (ldftn stub)
            var appType = new TypeDefUser("AppNamespace", "AppClass", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(appType);
            var appMethod = new MethodDefUser("UseDelegate", MethodSig.CreateStatic(module.CorLibTypes.Void)) { Body = new CilBody() };
            appMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldftn, stub));
            appMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            appMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            appType.Methods.Add(appMethod);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Hook call in cctor was stripped to nop
            Assert.Equal(1, result.StrippedHooksCount);
            Assert.Equal(OpCodes.Nop, cctor.Body.Instructions[0].OpCode);
            // But because appMethod references it via ldftn, the method itself MUST NOT be deleted from globalType
            Assert.Contains(stub, globalType.Methods);
            Assert.Equal(0, result.RemovedMethodsCount);
        }

        [Fact]
        public void StripProtectorHooks_MethodReferencedByReflectionString_IsNotDeletedFromModule()
        {
            var module = new ModuleDefUser("AppMod");
            var globalType = module.GlobalType;

            var stub = new MethodDefUser("ExactStubWithReflect", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            var getHinstanceRef = new MemberRefUser(module, "GetHINSTANCE",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, new TypeRefUser(module, "System.Reflection", "Module", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", module.CorLibTypes.AssemblyRef));
            stub.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            stub.Body.Instructions.Add(Instruction.Create(OpCodes.Call, getHinstanceRef));
            stub.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            stub.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(stub);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, stub));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            // An application method references the method name via ldstr (reflection)
            var appType = new TypeDefUser("AppNamespace", "AppClass", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(appType);
            var appMethod = new MethodDefUser("ReflectCall", MethodSig.CreateStatic(module.CorLibTypes.Void)) { Body = new CilBody() };
            appMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "ExactStubWithReflect"));
            appMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            appMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            appType.Methods.Add(appMethod);

            var result = CleanerKiller.StripProtectorHooks(module);

            // Call in cctor stripped, but method preserved due to reflection string reference
            Assert.Equal(1, result.StrippedHooksCount);
            Assert.Contains(stub, globalType.Methods);
            Assert.Equal(0, result.RemovedMethodsCount);
        }

        #endregion
    }
}
