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
            var targetAddTen = new MethodDefUser("AddTen", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed, MethodAttributes.Public | MethodAttributes.Static);
            globalType.Methods.Add(targetAddTen);

            // Target 2: int MultiplyTwo(int x)
            var targetMulTwo = new MethodDefUser("MultiplyTwo", MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed, MethodAttributes.Public | MethodAttributes.Static);
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

        [Fact]
        public void Execute_RecursiveProxyChain_InlinedAndPrunedSuccessfully()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            // Target: int RealTarget(int a, int b)
            var realTarget = new MethodDefUser("RealTarget",
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static);
            type.Methods.Add(realTarget);

            // Proxy 2: calls RealTarget
            var proxy2 = new MethodDefUser("Proxy_Two",
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.PrivateScope | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            proxy2.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            proxy2.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1));
            proxy2.Body.Instructions.Add(Instruction.Create(OpCodes.Call, realTarget));
            proxy2.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            type.Methods.Add(proxy2);

            // Proxy 1: calls Proxy 2
            var proxy1 = new MethodDefUser("Proxy_One",
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.PrivateScope | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            proxy1.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            proxy1.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1));
            proxy1.Body.Instructions.Add(Instruction.Create(OpCodes.Call, proxy2));
            proxy1.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            type.Methods.Add(proxy1);

            // Caller: calls Proxy 1
            var caller = new MethodDefUser("CallerMethod", MethodSig.CreateStatic(module.CorLibTypes.Int32))
            {
                Body = new CilBody()
            };
            var ldc1 = Instruction.Create(OpCodes.Ldc_I4, 10);
            var ldc2 = Instruction.Create(OpCodes.Ldc_I4, 20);
            var callProxy1 = Instruction.Create(OpCodes.Call, proxy1);
            var ret = Instruction.Create(OpCodes.Ret);
            caller.Body.Instructions.Add(ldc1);
            caller.Body.Instructions.Add(ldc2);
            caller.Body.Instructions.Add(callProxy1);
            caller.Body.Instructions.Add(ret);
            type.Methods.Add(caller);

            // Caller 2: calls Proxy 2 directly
            var caller2 = new MethodDefUser("CallerMethod2", MethodSig.CreateStatic(module.CorLibTypes.Int32))
            {
                Body = new CilBody()
            };
            var callProxy2 = Instruction.Create(OpCodes.Call, proxy2);
            caller2.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 1));
            caller2.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 2));
            caller2.Body.Instructions.Add(callProxy2);
            caller2.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            type.Methods.Add(caller2);

            int inlined = ProxyKillerImpl.Execute(module, ignoreAccess: true, removeProxyMethods: true);

            Assert.Equal(2, inlined);
            // CallProxy1 was rewritten directly to realTarget (flattened across proxy1 -> proxy2)
            Assert.Equal(OpCodes.Call, callProxy1.OpCode);
            Assert.Equal(realTarget, callProxy1.Operand);

            // CallProxy2 was also rewritten directly to realTarget
            Assert.Equal(OpCodes.Call, callProxy2.OpCode);
            Assert.Equal(realTarget, callProxy2.Operand);

            // Both proxy methods were cleanly pruned
            Assert.DoesNotContain(proxy1, type.Methods);
            Assert.DoesNotContain(proxy2, type.Methods);
        }

        [Fact]
        public void Execute_RecursiveProxyCycle_SafelyIgnoredWithoutLooping()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            // Proxy A declares calling Proxy B
            var proxyA = new MethodDefUser("Proxy_A",
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.PrivateScope | MethodAttributes.Static)
            {
                Body = new CilBody()
            };

            // Proxy B declares calling Proxy A (cycle!)
            var proxyB = new MethodDefUser("Proxy_B",
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.Int32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.PrivateScope | MethodAttributes.Static)
            {
                Body = new CilBody()
            };

            proxyA.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            proxyA.Body.Instructions.Add(Instruction.Create(OpCodes.Call, proxyB));
            proxyA.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            proxyB.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            proxyB.Body.Instructions.Add(Instruction.Create(OpCodes.Call, proxyA));
            proxyB.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            type.Methods.Add(proxyA);
            type.Methods.Add(proxyB);

            var caller = new MethodDefUser("CallerMethod", MethodSig.CreateStatic(module.CorLibTypes.Int32))
            {
                Body = new CilBody()
            };
            var ldc = Instruction.Create(OpCodes.Ldc_I4, 42);
            var callProxyA = Instruction.Create(OpCodes.Call, proxyA);
            var ret = Instruction.Create(OpCodes.Ret);
            caller.Body.Instructions.Add(ldc);
            caller.Body.Instructions.Add(callProxyA);
            caller.Body.Instructions.Add(ret);
            type.Methods.Add(caller);

            // Must terminate safely and not infinite-loop
            int inlined = ProxyKillerImpl.Execute(module, ignoreAccess: true, removeProxyMethods: true);

            Assert.Equal(0, inlined);
            Assert.Equal(proxyA, callProxyA.Operand);
        }

        [Fact]
        public void Execute_StrongDelegateProxy_ExternalTarget_InlinedSuccessfully()
        {
            var module = new ModuleDefUser("TestMod");
            var globalType = module.GlobalType;

            // Target is an external static method (e.g. System.Console.WriteLine(string))
            var consoleRef = module.CorLibTypes.GetTypeRef("System", "Console");
            var writeLineSig = MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.String);
            var writeLineRef = new MemberRefUser(module, "WriteLine", writeLineSig, consoleRef);

            var delType = new TypeDefUser("WriteDelegate", module.CorLibTypes.GetTypeRef("System", "MulticastDelegate"));
            module.Types.Add(delType);
            var invoke = new MethodDefUser("Invoke", MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String));
            delType.Methods.Add(invoke);

            var field = new FieldDefUser("FieldDelExt", new FieldSig(delType.ToTypeSig()), FieldAttributes.Public | FieldAttributes.Static);
            globalType.Fields.Add(field);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed, MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, writeLineRef));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Stsfld, field));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var userType = new TypeDefUser("UserType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(userType);
            var caller = new MethodDefUser("CallerMethod", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var ldsfld = Instruction.Create(OpCodes.Ldsfld, field);
            var ldstr = Instruction.Create(OpCodes.Ldstr, "Hello World");
            var callInvoke = Instruction.Create(OpCodes.Callvirt, invoke);
            var ret = Instruction.Create(OpCodes.Ret);
            caller.Body.Instructions.Add(ldsfld);
            caller.Body.Instructions.Add(ldstr);
            caller.Body.Instructions.Add(callInvoke);
            caller.Body.Instructions.Add(ret);
            userType.Methods.Add(caller);

            int inlined = ProxyKillerImpl.Execute(module, ignoreAccess: true, removeProxyMethods: true);

            Assert.Equal(1, inlined);
            Assert.Equal(OpCodes.Nop, ldsfld.OpCode);
            Assert.Equal(OpCodes.Call, callInvoke.OpCode);
            Assert.Equal(writeLineRef, callInvoke.Operand);

            // Delegate field and type pruned cleanly
            Assert.DoesNotContain(field, globalType.Fields);
            Assert.DoesNotContain(delType, module.Types);
        }

        [Fact]
        public void Execute_StrongDelegateProxy_InterveningBranchInCaller_IsRetained()
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

            var field = new FieldDefUser("FieldDel", new FieldSig(delType.ToTypeSig()), FieldAttributes.Public | FieldAttributes.Static);
            globalType.Fields.Add(field);

            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed, MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, targetStatic));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Stsfld, field));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            globalType.Methods.Add(cctor);

            var userType = new TypeDefUser("UserType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(userType);
            var caller = new MethodDefUser("CallerWithBranch", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var ldsfld = Instruction.Create(OpCodes.Ldsfld, field);
            var dummyTarget = Instruction.Create(OpCodes.Nop);
            var br = Instruction.Create(OpCodes.Br_S, dummyTarget);
            var callInvoke = Instruction.Create(OpCodes.Callvirt, invoke);
            var ret = Instruction.Create(OpCodes.Ret);

            // Intervening branch between ldsfld and callvirt
            caller.Body.Instructions.Add(ldsfld);
            caller.Body.Instructions.Add(br);
            caller.Body.Instructions.Add(dummyTarget);
            caller.Body.Instructions.Add(callInvoke);
            caller.Body.Instructions.Add(ret);
            userType.Methods.Add(caller);

            int inlined = ProxyKillerImpl.Execute(module, ignoreAccess: true, removeProxyMethods: false);

            Assert.Equal(0, inlined);
            Assert.Equal(OpCodes.Ldsfld, ldsfld.OpCode);
            Assert.Equal(OpCodes.Callvirt, callInvoke.OpCode);
        }

        [Fact]
        public void TryAnalyzeInstanceProxy_ValidInstanceProxy_RecognizedSuccessfully()
        {
            var module = new ModuleDefUser("TestMod");
            var hostType = new TypeDefUser("HostType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(hostType);

            var targetType = new TypeDefUser("TargetType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(targetType);

            // Target method: virtual instance method string TargetType.Compute(int)
            var target = new MethodDefUser("Compute",
                MethodSig.CreateInstance(module.CorLibTypes.String, module.CorLibTypes.Int32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.HideBySig);
            targetType.Methods.Add(target);

            // ConfuserEx instance proxy: declared on HostType, takes (HostType this, int param), forwards to TargetType.Compute
            var proxy = new MethodDefUser("Proxy_Compute",
                MethodSig.CreateInstance(module.CorLibTypes.String, module.CorLibTypes.Int32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.PrivateScope)
            {
                Body = new CilBody()
            };
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1));
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Call, target));
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            hostType.Methods.Add(proxy);

            bool ok = ProxyKillerImpl.TryAnalyzeInstanceProxy(proxy, ignoreAccess: false, out var callInst, out var reason);
            Assert.True(ok, reason);
            Assert.NotNull(callInst);
            Assert.Equal(OpCodes.Callvirt, callInst.OpCode);
            Assert.Equal(target, callInst.Operand);
        }

        [Fact]
        public void TryAnalyzeInstanceProxy_StaticMethod_Rejected()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var target = new MethodDefUser("Target", MethodSig.CreateStatic(module.CorLibTypes.Void));
            type.Methods.Add(target);

            var proxy = new MethodDefUser("StaticProxy",
                MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.PrivateScope | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Call, target));
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            type.Methods.Add(proxy);

            bool ok = ProxyKillerImpl.TryAnalyzeInstanceProxy(proxy, ignoreAccess: false, out var callInst, out var reason);
            Assert.False(ok);
            Assert.Contains("Static method cannot be instance proxy", reason);
        }

        [Fact]
        public void TryAnalyzeInstanceProxy_Constructor_Rejected()
        {
            var module = new ModuleDefUser("TestMod");
            var type = new TypeDefUser("TestType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(type);

            var target = new MethodDefUser("Target", MethodSig.CreateInstance(module.CorLibTypes.Void));
            type.Methods.Add(target);

            var ctor = new MethodDefUser(".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.PrivateScope | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            ctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            ctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, target));
            ctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            type.Methods.Add(ctor);

            bool ok = ProxyKillerImpl.TryAnalyzeInstanceProxy(ctor, ignoreAccess: false, out var callInst, out var reason);
            Assert.False(ok);
            Assert.Contains("Constructor cannot be instance proxy", reason);
        }

        [Fact]
        public void TryAnalyzeInstanceProxy_ArgumentPermutation_Rejected()
        {
            var module = new ModuleDefUser("TestMod");
            var hostType = new TypeDefUser("HostType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(hostType);

            var targetType = new TypeDefUser("TargetType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(targetType);

            var target = new MethodDefUser("Target",
                MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Int32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.HideBySig);
            targetType.Methods.Add(target);

            // Loads arg 1 before arg 0
            var proxy = new MethodDefUser("Proxy_Permuted",
                MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Int32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.PrivateScope)
            {
                Body = new CilBody()
            };
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1));
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Call, target));
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            hostType.Methods.Add(proxy);

            bool ok = ProxyKillerImpl.TryAnalyzeInstanceProxy(proxy, ignoreAccess: false, out var callInst, out var reason);
            Assert.False(ok);
            Assert.Contains("order or opcode mismatch", reason);
        }

        [Fact]
        public void Execute_InlinesInstanceProxiesAndRemovesFromType()
        {
            var module = new ModuleDefUser("TestMod");
            var hostType = new TypeDefUser("HostType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(hostType);

            var targetType = new TypeDefUser("TargetType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(targetType);

            var target = new MethodDefUser("EqualsMethod",
                MethodSig.CreateInstance(module.CorLibTypes.Boolean, module.CorLibTypes.String),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.HideBySig);
            targetType.Methods.Add(target);

            var proxy = new MethodDefUser("ConfuserInstanceProxy",
                MethodSig.CreateInstance(module.CorLibTypes.Boolean, module.CorLibTypes.String),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.PrivateScope)
            {
                Body = new CilBody()
            };
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1));
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Call, target));
            proxy.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            hostType.Methods.Add(proxy);

            var userType = new TypeDefUser("UserType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(userType);

            var caller = new MethodDefUser("UserMethod",
                MethodSig.CreateStatic(module.CorLibTypes.Boolean),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            // Caller pushes string, string, calls proxy
            caller.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "a"));
            caller.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "b"));
            var callProxyInst = Instruction.Create(OpCodes.Call, proxy);
            caller.Body.Instructions.Add(callProxyInst);
            caller.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            userType.Methods.Add(caller);

            int restored = ProxyKillerImpl.Execute(module, ignoreAccess: false, removeProxyMethods: true);

            Assert.Equal(1, restored);
            Assert.Equal(OpCodes.Callvirt, callProxyInst.OpCode);
            Assert.Equal(target, callProxyInst.Operand);
            Assert.DoesNotContain(proxy, hostType.Methods);
        }
    }
}
