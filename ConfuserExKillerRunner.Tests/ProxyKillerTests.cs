using System.Collections.Generic;
using ConfuserExTools.ProxyKiller;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public class ProxyKillerTests
    {
        [Fact]
        public void TryAnalyzeClassicProxy_ValidStaticProxy_RecognizedSuccessfully()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var target = new MethodDefUser("Add", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32, module.CorLibTypes.Int32));
            type.Methods.Add(target);

            var proxy = new MethodDefUser("Proxy_Add",
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.PrivateScope | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1));
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Call, target));
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            type.Methods.Add(proxy);

            bool ok = ProxyKillerImpl.TryAnalyzeClassicProxy(proxy, ignoreAccess: false, out var callInst, out var reason);
            Assert.True(ok, reason);
            Assert.NotNull(callInst);
            Assert.Equal(target, callInst.Operand);
        }

        [Fact]
        public void TryAnalyzeClassicProxy_ArgumentPermutation_Rejected()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var target = new MethodDefUser("Sub", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32, module.CorLibTypes.Int32));
            type.Methods.Add(target);

            // Permuted arguments: loads arg 1 then arg 0!
            var proxy = new MethodDefUser("Proxy_Sub_Permuted",
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.PrivateScope | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1)); // Wrong order!
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Call, target));
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            type.Methods.Add(proxy);

            bool ok = ProxyKillerImpl.TryAnalyzeClassicProxy(proxy, ignoreAccess: false, out var callInst, out var reason);
            Assert.False(ok);
            Assert.Contains("order or opcode mismatch", reason);
        }

        [Fact]
        public void TryAnalyzeClassicProxy_WrongArgumentCount_Rejected()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            // Target expects 1 param
            var target = new MethodDefUser("Print", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32));
            type.Methods.Add(target);

            // Proxy declares 2 params but only passes 1!
            var proxy = new MethodDefUser("Proxy_Print_ExtraArg",
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32, module.CorLibTypes.String),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.PrivateScope | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Call, target));
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            type.Methods.Add(proxy);

            bool ok = ProxyKillerImpl.TryAnalyzeClassicProxy(proxy, ignoreAccess: false, out var callInst, out var reason);
            Assert.False(ok);
            Assert.Contains("count mismatch", reason);
        }

        [Fact]
        public void TryAnalyzeClassicProxy_InstanceMethod_Rejected()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var target = new MethodDefUser("DoWork", MethodSig.CreateStatic(module.CorLibTypes.Void));
            type.Methods.Add(target);

            // Instance method (not static)
            var proxy = new MethodDefUser("InstanceMethodWrapper",
                MethodSig.CreateInstance(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.PrivateScope)
            {
                Body = new CilBody()
            };
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Call, target));
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            type.Methods.Add(proxy);

            bool ok = ProxyKillerImpl.TryAnalyzeClassicProxy(proxy, ignoreAccess: false, out var callInst, out var reason);
            Assert.False(ok);
            Assert.Contains("Instance method cannot be classic proxy", reason);
        }

        [Fact]
        public void TryAnalyzeClassicProxy_TypeMismatch_Rejected()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var target = new MethodDefUser("Compute", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32));
            type.Methods.Add(target);

            // Proxy takes String instead of Int32
            var proxy = new MethodDefUser("Proxy_Mismatch",
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.String),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.PrivateScope | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Call, target));
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            type.Methods.Add(proxy);

            bool ok = ProxyKillerImpl.TryAnalyzeClassicProxy(proxy, ignoreAccess: false, out var callInst, out var reason);
            Assert.False(ok);
            Assert.Contains("type mismatch", reason);
        }

        [Fact]
        public void InlineStrongDelegateProxies_NestedCalls_CorrectlyAssociated()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            // Target 1: int AddTen(int x)
            var targetAddTen = new MethodDefUser("AddTen", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32));
            globalType.Methods.Add(targetAddTen);

            // Target 2: int MultiplyTwo(int x)
            var targetMulTwo = new MethodDefUser("MultiplyTwo", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32));
            globalType.Methods.Add(targetMulTwo);

            // Delegate Type 1
            var delType1 = new TypeDefUser("DelegateType1", module.CorLibTypes.GetTypeRef("System", "MulticastDelegate"));
            module.Types.Add(delType1);
            var invoke1 = new MethodDefUser("Invoke", MethodSig.CreateInstance(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed, MethodAttributes.Public | MethodAttributes.Virtual);
            delType1.Methods.Add(invoke1);

            // Delegate Type 2
            var delType2 = new TypeDefUser("DelegateType2", module.CorLibTypes.GetTypeRef("System", "MulticastDelegate"));
            module.Types.Add(delType2);
            var invoke2 = new MethodDefUser("Invoke", MethodSig.CreateInstance(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed, MethodAttributes.Public | MethodAttributes.Virtual);
            delType2.Methods.Add(invoke2);

            // Fields in GlobalType
            var field1 = new FieldDefUser("FieldDel1", new FieldSig(delType1.ToTypeSig()), FieldAttributes.Static | FieldAttributes.Public);
            globalType.Fields.Add(field1);

            var field2 = new FieldDefUser("FieldDel2", new FieldSig(delType2.ToTypeSig()), FieldAttributes.Static | FieldAttributes.Public);
            globalType.Fields.Add(field2);

            // cctor initializing fields with ldtoken targetMethod
            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed, MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, targetAddTen));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Stsfld, field1));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, targetMulTwo));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Stsfld, field2));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            // User method with nested call: AddTen(MultiplyTwo(x))
            // In IL:
            // ldsfld field1 (AddTen)
            // ldsfld field2 (MultiplyTwo)
            // ldarg.0 (x)
            // callvirt DelegateType2::Invoke
            // callvirt DelegateType1::Invoke
            // ret
            var userType = new TypeDefUser("UserType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(userType);
            var caller = new MethodDefUser("RunNested", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32))
            {
                Body = new CilBody()
            };
            var ldsfld1 = Instruction.Create(OpCodes.Ldsfld, field1);
            var ldsfld2 = Instruction.Create(OpCodes.Ldsfld, field2);
            var ldarg = Instruction.Create(OpCodes.Ldarg_0);
            var callInvoke2 = Instruction.Create(OpCodes.Callvirt, invoke2);
            var callInvoke1 = Instruction.Create(OpCodes.Callvirt, invoke1);
            var ret = Instruction.Create(OpCodes.Ret);

            caller.Body.Instructions.Add(ldsfld1);
            caller.Body.Instructions.Add(ldsfld2);
            caller.Body.Instructions.Add(ldarg);
            caller.Body.Instructions.Add(callInvoke2);
            caller.Body.Instructions.Add(callInvoke1);
            caller.Body.Instructions.Add(ret);
            userType.Methods.Add(caller);

            int inlined = ProxyKillerImpl.Execute(module, ignoreAccess: true, removeProxyMethods: false);

            Assert.Equal(2, inlined);

            // ldsfld instructions are turned to Nop
            Assert.Equal(OpCodes.Nop, ldsfld1.OpCode);
            Assert.Equal(OpCodes.Nop, ldsfld2.OpCode);

            // Inner call was to MultiplyTwo
            Assert.Equal(OpCodes.Call, callInvoke2.OpCode);
            Assert.Equal(targetMulTwo, callInvoke2.Operand);

            // Outer call was to AddTen
            Assert.Equal(OpCodes.Call, callInvoke1.OpCode);
            Assert.Equal(targetAddTen, callInvoke1.Operand);
        }

        [Fact]
        public void Execute_ClosedInstanceDelegateProxy_IsRetained()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            var userType = new TypeDefUser("UserType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(userType);

            // Target is an INSTANCE method (requires this)
            var targetInstanceMethod = new MethodDefUser("InstanceMethod", MethodSig.CreateInstance(module.CorLibTypes.Int32))
            {
                Body = new CilBody()
            };
            userType.Methods.Add(targetInstanceMethod);

            // Delegate type
            var delType = new TypeDefUser("MyAction", module.CorLibTypes.GetTypeRef("System", "MulticastDelegate"));
            module.Types.Add(delType);
            var invoke = new MethodDefUser("Invoke", MethodSig.CreateInstance(module.CorLibTypes.Int32));
            delType.Methods.Add(invoke);

            // Field in <Module>
            var field = new FieldDefUser("FieldInstance", new FieldSig(delType.ToTypeSig()), FieldAttributes.Public | FieldAttributes.Static);
            globalType.Fields.Add(field);

            // <Module>..cctor loads token of targetInstanceMethod
            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed, MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, targetInstanceMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Stsfld, field));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            // Caller tries to invoke the delegate
            var caller = new MethodDefUser("CallDelegate", MethodSig.CreateStatic(module.CorLibTypes.Int32))
            {
                Body = new CilBody()
            };
            var ldsfld = Instruction.Create(OpCodes.Ldsfld, field);
            var callInvoke = Instruction.Create(OpCodes.Callvirt, invoke);
            var ret = Instruction.Create(OpCodes.Ret);
            caller.Body.Instructions.Add(ldsfld);
            caller.Body.Instructions.Add(callInvoke);
            caller.Body.Instructions.Add(ret);
            userType.Methods.Add(caller);

            int inlined = ProxyKillerImpl.Execute(module, ignoreAccess: true, removeProxyMethods: false);

            // Must NOT inline because instance delegate cannot be called directly without captured instance on stack
            Assert.Equal(0, inlined);
            Assert.Equal(OpCodes.Ldsfld, ldsfld.OpCode);
            Assert.Equal(OpCodes.Callvirt, callInvoke.OpCode);
            Assert.Equal(invoke, callInvoke.Operand);
        }

        [Fact]
        public void Execute_DelegateProxyWithInterveningBranchInInit_IsRetained()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            var targetStatic = new MethodDefUser("TargetStatic", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            globalType.Methods.Add(targetStatic);

            var delType = new TypeDefUser("MyVoidAction", module.CorLibTypes.GetTypeRef("System", "MulticastDelegate"));
            module.Types.Add(delType);
            var invoke = new MethodDefUser("Invoke", MethodSig.CreateInstance(module.CorLibTypes.Void));
            delType.Methods.Add(invoke);

            var field = new FieldDefUser("FieldBranch", new FieldSig(delType.ToTypeSig()), FieldAttributes.Public | FieldAttributes.Static);
            globalType.Fields.Add(field);

            // <Module>..cctor with a branch between ldtoken and stsfld
            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed, MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            var brTarget = Instruction.Create(OpCodes.Nop);
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, targetStatic));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Br_S, brTarget));
            cctor.Body.Instructions.Add(brTarget);
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Stsfld, field));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var userType = new TypeDefUser("UserType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(userType);
            var caller = new MethodDefUser("CallBranchDel", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var ldsfld = Instruction.Create(OpCodes.Ldsfld, field);
            var callInvoke = Instruction.Create(OpCodes.Callvirt, invoke);
            var ret = Instruction.Create(OpCodes.Ret);
            caller.Body.Instructions.Add(ldsfld);
            caller.Body.Instructions.Add(callInvoke);
            caller.Body.Instructions.Add(ret);
            userType.Methods.Add(caller);

            int inlined = ProxyKillerImpl.Execute(module, ignoreAccess: true, removeProxyMethods: false);

            // Intervening branch prevents ambiguous delegate mapping
            Assert.Equal(0, inlined);
            Assert.Equal(OpCodes.Ldsfld, ldsfld.OpCode);
        }
    }
}
