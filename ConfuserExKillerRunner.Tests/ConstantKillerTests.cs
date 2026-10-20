using System;
using ConfuserExTools.ConstantKiller;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public class ConstantKillerTests
    {
        [Fact]
        public void TryGetConstantInstruction_U4_Zero_ReturnsExactLdcI4()
        {
            bool ok = ConstantKillerImpl.TryGetConstantInstruction(ElementType.U4, 0u, out var op, out var operand);
            Assert.True(ok);
            Assert.Equal(OpCodes.Ldc_I4, op);
            Assert.Equal(0, operand);
        }

        [Fact]
        public void TryGetConstantInstruction_U4_IntMaxValue_ReturnsExactLdcI4()
        {
            uint val = (uint)int.MaxValue;
            bool ok = ConstantKillerImpl.TryGetConstantInstruction(ElementType.U4, val, out var op, out var operand);
            Assert.True(ok);
            Assert.Equal(OpCodes.Ldc_I4, op);
            Assert.Equal(int.MaxValue, operand);
        }

        [Fact]
        public void TryGetConstantInstruction_U4_UIntMaxValue_PreservesBitsWithoutOverflow()
        {
            uint val = uint.MaxValue; // 0xFFFFFFFF
            bool ok = ConstantKillerImpl.TryGetConstantInstruction(ElementType.U4, val, out var op, out var operand);
            Assert.True(ok);
            Assert.Equal(OpCodes.Ldc_I4, op);
            Assert.Equal(-1, operand); // unchecked((int)uint.MaxValue) == -1
            Assert.Equal(val, unchecked((uint)(int)operand));
        }

        [Fact]
        public void TryGetConstantInstruction_U4_SignBitSet_PreservesExactBits()
        {
            uint val = 0x80000000u; // Sign bit set in 32-bit uint
            bool ok = ConstantKillerImpl.TryGetConstantInstruction(ElementType.U4, val, out var op, out var operand);
            Assert.True(ok);
            Assert.Equal(OpCodes.Ldc_I4, op);
            Assert.Equal(int.MinValue, operand); // 0x80000000 as signed int is int.MinValue
            Assert.Equal(val, unchecked((uint)(int)operand));
        }

        [Fact]
        public void TryGetConstantInstruction_U8_Zero_ReturnsExactLdcI8()
        {
            bool ok = ConstantKillerImpl.TryGetConstantInstruction(ElementType.U8, 0ul, out var op, out var operand);
            Assert.True(ok);
            Assert.Equal(OpCodes.Ldc_I8, op);
            Assert.Equal(0L, operand);
        }

        [Fact]
        public void TryGetConstantInstruction_U8_LongMaxValue_ReturnsExactLdcI8()
        {
            ulong val = (ulong)long.MaxValue;
            bool ok = ConstantKillerImpl.TryGetConstantInstruction(ElementType.U8, val, out var op, out var operand);
            Assert.True(ok);
            Assert.Equal(OpCodes.Ldc_I8, op);
            Assert.Equal(long.MaxValue, operand);
        }

        [Fact]
        public void TryGetConstantInstruction_U8_ULongMaxValue_PreservesBitsWithoutOverflow()
        {
            ulong val = ulong.MaxValue; // 0xFFFFFFFFFFFFFFFF
            bool ok = ConstantKillerImpl.TryGetConstantInstruction(ElementType.U8, val, out var op, out var operand);
            Assert.True(ok);
            Assert.Equal(OpCodes.Ldc_I8, op);
            Assert.Equal(-1L, operand); // unchecked((long)ulong.MaxValue) == -1L
            Assert.Equal(val, unchecked((ulong)(long)operand));
        }

        [Fact]
        public void TryGetConstantInstruction_U8_SignBitSet_PreservesExactBits()
        {
            ulong val = 0x8000000000000000ul; // Sign bit set in 64-bit ulong
            bool ok = ConstantKillerImpl.TryGetConstantInstruction(ElementType.U8, val, out var op, out var operand);
            Assert.True(ok);
            Assert.Equal(OpCodes.Ldc_I8, op);
            Assert.Equal(long.MinValue, operand);
            Assert.Equal(val, unchecked((ulong)(long)operand));
        }

        [Fact]
        public void TryGetConstantInstruction_UnsupportedObject_ReturnsFalseWithoutThrowing()
        {
            object unsupported = new System.Text.StringBuilder("not a primitive");
            bool ok = ConstantKillerImpl.TryGetConstantInstruction(ElementType.I4, unsupported, out var op, out var operand);
            Assert.False(ok);
            Assert.Null(operand);
        }

        [Fact]
        public void ConstantKiller_NullModule_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ConstantKillerImpl.Execute(null, null));
        }

        [Fact]
        public void ConstantKiller_Execute_PartialSuccess_PreservesDecrypterAndConstantBufferInitializer()
        {
            var module = new ModuleDefUser("TestPartialConstMod");
            var asm = new AssemblyDefUser("TestPartialConstAsm");
            asm.Modules.Add(module);

            // 1. Define ConfuserEx constant decrypter in GlobalType: static T Decrypter<T>(uint key)
            // returns new byte[] { 10, 20, 30, 40 }
            var decrypterDef = new MethodDefUser(
                "Decrypter",
                MethodSig.CreateStaticGeneric(1, new GenericMVar(0), module.CorLibTypes.UInt32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            decrypterDef.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));

            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_4));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Newarr, module.CorLibTypes.Byte.TypeDefOrRef));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Dup));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 10));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Stelem_I1));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Dup));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_1));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 20));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Stelem_I1));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Dup));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_2));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 30));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Stelem_I1));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Dup));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_3));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 40));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Stelem_I1));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            module.GlobalType.Methods.Add(decrypterDef);

            // 2. Define a Constant-Buffer initializer method in GlobalType:
            // It calls InitializeArray on an RVA field in GlobalType.
            var rvaField = new FieldDefUser("ConstDataField", new FieldSig(module.CorLibTypes.Int32),
                FieldAttributes.Public | FieldAttributes.Static | FieldAttributes.HasFieldRVA)
            {
                InitialValue = new byte[] { 1, 2, 3, 4 }
            };
            module.GlobalType.Fields.Add(rvaField);

            var initArrayRef = new MemberRefUser(module, "InitializeArray",
                MethodSig.CreateStatic(module.CorLibTypes.Void,
                    new TypeRefUser(module, "System", "Array", module.CorLibTypes.AssemblyRef).ToTypeSig(),
                    new TypeRefUser(module, "System", "RuntimeFieldHandle", module.CorLibTypes.AssemblyRef).ToTypeSig()),
                new TypeRefUser(module, "System.Runtime.CompilerServices", "RuntimeHelpers", module.CorLibTypes.AssemblyRef));

            var bufferInitMethod = new MethodDefUser("InitConstantBuffer", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            var runLabel = Instruction.Create(OpCodes.Ldc_I4_4);
            bufferInitMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            bufferInitMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Brtrue_S, runLabel));
            bufferInitMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            bufferInitMethod.Body.Instructions.Add(runLabel);
            bufferInitMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Newarr, module.CorLibTypes.Byte.TypeDefOrRef));
            bufferInitMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, rvaField));
            bufferInitMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, initArrayRef));
            bufferInitMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            module.GlobalType.Methods.Add(bufferInitMethod);

            // 3. Define <Module>..cctor calling bufferInitMethod
            var cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Call, bufferInitMethod));
            cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            module.GlobalType.Methods.Add(cctor);

            // 4. Define calling method in a user type:
            // Call 1: Decrypter<byte[]>(12345) -> succeeds
            // Call 2: Decrypter<byte[]>(ldarg.0) -> fails (unresolvable key expression)
            var userType = new TypeDefUser("UserType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(userType);

            var callerMethod = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32))
            {
                Body = new CilBody()
            };
            userType.Methods.Add(callerMethod);

            var genMethodSig = new GenericInstMethodSig(new SZArraySig(module.CorLibTypes.Byte));
            var methodSpec = new MethodSpecUser(decrypterDef, genMethodSig);

            // Call 1 (succeeds)
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 12345));
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, methodSpec));
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // Call 2 (fails to evaluate key expression because ldarg.0 is not a compile-time constant)
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, methodSpec));
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            // 5. Emit to memory and load in reflection context
            using (var ms = new System.IO.MemoryStream())
            {
                module.Write(ms);
                byte[] rawAsm = ms.ToArray();

                var reflAsm = System.Reflection.Assembly.Load(rawAsm);
                using (var modMD = ModuleDefMD.Load(rawAsm))
                {
                    // Execute ConstantKillerImpl.Execute
                    var result = ConstantKillerImpl.Execute(modMD, reflAsm.ManifestModule);

                    Assert.NotNull(result);
                    Assert.Equal(2, result.TotalReferencesCount);
                    Assert.Equal(1, result.ResolvedReferencesCount);
                    Assert.Equal(1, result.DecryptedConstantsCount);
                    Assert.False(result.AllReferencesResolved);

                    // Decrypter must be retained because 1 reference was unrewritten
                    var loadedDecrypter = modMD.GlobalType.FindMethod("Decrypter");
                    Assert.NotNull(loadedDecrypter);
                    Assert.Contains(loadedDecrypter, modMD.GlobalType.Methods);

                    // Execute CleanerKiller.StripProtectorHooks with constantsDecrypted = result.AllReferencesResolved (false)
                    var cleanResult = ConfuserExKillerRunner.Killers.CleanerKiller.StripProtectorHooks(
                        modMD,
                        constantsDecrypted: result.AllReferencesResolved);

                    // The constant buffer initializer must NOT be stripped!
                    var loadedBufferInit = modMD.GlobalType.FindMethod("InitConstantBuffer");
                    Assert.NotNull(loadedBufferInit);
                    Assert.Contains(loadedBufferInit, modMD.GlobalType.Methods);

                    var loadedCctor = modMD.GlobalType.FindStaticConstructor();
                    Assert.NotNull(loadedCctor);
                    Assert.Equal(OpCodes.Call, loadedCctor.Body.Instructions[0].OpCode);
                    Assert.Equal(loadedBufferInit, loadedCctor.Body.Instructions[0].Operand);
                    Assert.Equal(0, cleanResult.StrippedHooksCount);
                }
            }
        }

        [Fact]
        public void ConstantKiller_Execute_InterDecrypterCall_WhenCallerDecrypterHasUnrewrittenReferences_RetainsBothDecrypters()
        {
            var module = new ModuleDefUser("TestInterDecrypterRetainMod");
            var asm = new AssemblyDefUser("TestInterDecrypterRetainAsm");
            asm.Modules.Add(module);

            // DecrypterA<T>(uint key): returns int 42
            var decrypterA = new MethodDefUser(
                "DecrypterA",
                MethodSig.CreateStaticGeneric(1, new GenericMVar(0), module.CorLibTypes.UInt32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            decrypterA.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            decrypterA.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 42));
            decrypterA.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            module.GlobalType.Methods.Add(decrypterA);

            // DecrypterB<T>(uint key): calls DecrypterA<T>(key) and returns it!
            var decrypterB = new MethodDefUser(
                "DecrypterB",
                MethodSig.CreateStaticGeneric(1, new GenericMVar(0), module.CorLibTypes.UInt32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            decrypterB.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            var aSpec = new MethodSpecUser(decrypterA, new GenericInstMethodSig(new GenericMVar(0)));
            decrypterB.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            decrypterB.Body.Instructions.Add(Instruction.Create(OpCodes.Call, aSpec));
            decrypterB.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            module.GlobalType.Methods.Add(decrypterB);

            // UserType:
            // Method 1 calls DecrypterA<int>(10) -> can be rewritten!
            // Method 2 calls DecrypterB<int>(ldarg.0) -> key unresolvable, fails!
            var userType = new TypeDefUser("UserType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(userType);

            var userMethod1 = new MethodDefUser("Method1", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var aIntSpec = new MethodSpecUser(decrypterA, new GenericInstMethodSig(module.CorLibTypes.Int32));
            userMethod1.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 10));
            userMethod1.Body.Instructions.Add(Instruction.Create(OpCodes.Call, aIntSpec));
            userMethod1.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            userMethod1.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            userType.Methods.Add(userMethod1);

            var userMethod2 = new MethodDefUser("Method2", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32))
            {
                Body = new CilBody()
            };
            var bIntSpec = new MethodSpecUser(decrypterB, new GenericInstMethodSig(module.CorLibTypes.Int32));
            userMethod2.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            userMethod2.Body.Instructions.Add(Instruction.Create(OpCodes.Call, bIntSpec));
            userMethod2.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            userMethod2.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            userType.Methods.Add(userMethod2);

            using (var ms = new System.IO.MemoryStream())
            {
                module.Write(ms);
                byte[] rawAsm = ms.ToArray();

                var reflAsm = System.Reflection.Assembly.Load(rawAsm);
                using (var modMD = ModuleDefMD.Load(rawAsm))
                {
                    var result = ConstantKillerImpl.Execute(modMD, reflAsm.ManifestModule);

                    Assert.NotNull(result);
                    Assert.Equal(2, result.TotalReferencesCount);
                    Assert.Equal(1, result.ResolvedReferencesCount);
                    Assert.Equal(1, result.DecryptedConstantsCount);
                    Assert.False(result.AllReferencesResolved);

                    // DecrypterB is retained because user call failed to rewrite
                    var loadedB = modMD.GlobalType.FindMethod("DecrypterB");
                    Assert.NotNull(loadedB);
                    Assert.Contains(loadedB, modMD.GlobalType.Methods);

                    // DecrypterA MUST ALSO BE RETAINED because live DecrypterB calls it,
                    // even though all direct user calls to DecrypterA were rewritten!
                    var loadedA = modMD.GlobalType.FindMethod("DecrypterA");
                    Assert.NotNull(loadedA);
                    Assert.Contains(loadedA, modMD.GlobalType.Methods);
                }
            }
        }

        [Fact]
        public void ConstantKiller_Execute_InterDecrypterCall_WhenAllUserReferencesResolved_RemovesBothDecrypters()
        {
            var module = new ModuleDefUser("TestInterDecrypterAllResolvedMod");
            var asm = new AssemblyDefUser("TestInterDecrypterAllResolvedAsm");
            asm.Modules.Add(module);

            var decrypterA = new MethodDefUser(
                "DecrypterA",
                MethodSig.CreateStaticGeneric(1, new GenericMVar(0), module.CorLibTypes.UInt32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            decrypterA.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            decrypterA.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 42));
            decrypterA.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            module.GlobalType.Methods.Add(decrypterA);

            var decrypterB = new MethodDefUser(
                "DecrypterB",
                MethodSig.CreateStaticGeneric(1, new GenericMVar(0), module.CorLibTypes.UInt32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            decrypterB.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            var aSpec = new MethodSpecUser(decrypterA, new GenericInstMethodSig(new GenericMVar(0)));
            decrypterB.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            decrypterB.Body.Instructions.Add(Instruction.Create(OpCodes.Call, aSpec));
            decrypterB.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            module.GlobalType.Methods.Add(decrypterB);

            var userType = new TypeDefUser("UserType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(userType);

            // Method 1 calls DecrypterA<int>(10)
            var userMethod1 = new MethodDefUser("Method1", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var aIntSpec = new MethodSpecUser(decrypterA, new GenericInstMethodSig(module.CorLibTypes.Int32));
            userMethod1.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 10));
            userMethod1.Body.Instructions.Add(Instruction.Create(OpCodes.Call, aIntSpec));
            userMethod1.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            userMethod1.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            userType.Methods.Add(userMethod1);

            // Method 2 calls DecrypterB<int>(20) - constant key, succeeds!
            var userMethod2 = new MethodDefUser("Method2", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var bIntSpec = new MethodSpecUser(decrypterB, new GenericInstMethodSig(module.CorLibTypes.Int32));
            userMethod2.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 20));
            userMethod2.Body.Instructions.Add(Instruction.Create(OpCodes.Call, bIntSpec));
            userMethod2.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            userMethod2.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            userType.Methods.Add(userMethod2);

            using (var ms = new System.IO.MemoryStream())
            {
                module.Write(ms);
                byte[] rawAsm = ms.ToArray();

                var reflAsm = System.Reflection.Assembly.Load(rawAsm);
                using (var modMD = ModuleDefMD.Load(rawAsm))
                {
                    var result = ConstantKillerImpl.Execute(modMD, reflAsm.ManifestModule);

                    Assert.NotNull(result);
                    Assert.Equal(2, result.TotalReferencesCount);
                    Assert.Equal(2, result.ResolvedReferencesCount);
                    Assert.Equal(2, result.DecryptedConstantsCount);
                    Assert.True(result.AllReferencesResolved);

                    // When 100% of user references are rewritten and neither is needed by a live decrypter,
                    // both are safely pruned from the module!
                    var loadedB = modMD.GlobalType.FindMethod("DecrypterB");
                    Assert.Null(loadedB);

                    var loadedA = modMD.GlobalType.FindMethod("DecrypterA");
                    Assert.Null(loadedA);
                }
            }
        }

        [Fact]
        public void ConstantKiller_Execute_IndirectDecrypterChain_WhenCallerRetained_RetainsEntireChain()
        {
            var module = new ModuleDefUser("TestIndirectChainMod");
            var asm = new AssemblyDefUser("TestIndirectChainAsm");
            asm.Modules.Add(module);

            // DecrypterC: leaf decrypter
            var decrypterC = new MethodDefUser(
                "DecrypterC",
                MethodSig.CreateStaticGeneric(1, new GenericMVar(0), module.CorLibTypes.UInt32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            decrypterC.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            decrypterC.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 100));
            decrypterC.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            module.GlobalType.Methods.Add(decrypterC);

            // DecrypterB: intermediate decrypter calling DecrypterC
            var decrypterB = new MethodDefUser(
                "DecrypterB",
                MethodSig.CreateStaticGeneric(1, new GenericMVar(0), module.CorLibTypes.UInt32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            decrypterB.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            var cSpec = new MethodSpecUser(decrypterC, new GenericInstMethodSig(new GenericMVar(0)));
            decrypterB.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            decrypterB.Body.Instructions.Add(Instruction.Create(OpCodes.Call, cSpec));
            decrypterB.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            module.GlobalType.Methods.Add(decrypterB);

            // DecrypterA: top decrypter calling DecrypterB
            var decrypterA = new MethodDefUser(
                "DecrypterA",
                MethodSig.CreateStaticGeneric(1, new GenericMVar(0), module.CorLibTypes.UInt32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            decrypterA.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            var bSpec = new MethodSpecUser(decrypterB, new GenericInstMethodSig(new GenericMVar(0)));
            decrypterA.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            decrypterA.Body.Instructions.Add(Instruction.Create(OpCodes.Call, bSpec));
            decrypterA.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            module.GlobalType.Methods.Add(decrypterA);

            var userType = new TypeDefUser("UserType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(userType);

            // User method calls DecrypterA with non-constant argument -> cannot be decrypted statically
            var userMethod = new MethodDefUser("UserMethod", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.UInt32))
            {
                Body = new CilBody()
            };
            var aSpec = new MethodSpecUser(decrypterA, new GenericInstMethodSig(module.CorLibTypes.Int32));
            userMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            userMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, aSpec));
            userMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            userMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            userType.Methods.Add(userMethod);

            using (var ms = new System.IO.MemoryStream())
            {
                module.Write(ms);
                byte[] rawAsm = ms.ToArray();

                var reflAsm = System.Reflection.Assembly.Load(rawAsm);
                using (var modMD = ModuleDefMD.Load(rawAsm))
                {
                    var result = ConstantKillerImpl.Execute(modMD, reflAsm.ManifestModule);

                    Assert.NotNull(result);
                    Assert.False(result.AllReferencesResolved);

                    // All 3 decrypters in the transitive dependency chain must be retained!
                    Assert.NotNull(modMD.GlobalType.FindMethod("DecrypterA"));
                    Assert.NotNull(modMD.GlobalType.FindMethod("DecrypterB"));
                    Assert.NotNull(modMD.GlobalType.FindMethod("DecrypterC"));
                }
            }
        }

        [Fact]
        public void ConstantKiller_Execute_CyclicDecrypters_WhenCallerHasUnrewrittenReference_RetainsBothDecrypters()
        {
            var module = new ModuleDefUser("TestCyclicRetainedMod");
            var asm = new AssemblyDefUser("TestCyclicRetainedAsm");
            asm.Modules.Add(module);

            // Mutually recursive decrypters: DecrypterA calls DecrypterB, DecrypterB calls DecrypterA
            var decrypterA = new MethodDefUser(
                "DecrypterA",
                MethodSig.CreateStaticGeneric(1, new GenericMVar(0), module.CorLibTypes.UInt32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            decrypterA.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));

            var decrypterB = new MethodDefUser(
                "DecrypterB",
                MethodSig.CreateStaticGeneric(1, new GenericMVar(0), module.CorLibTypes.UInt32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            decrypterB.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));

            var bSpec = new MethodSpecUser(decrypterB, new GenericInstMethodSig(new GenericMVar(0)));
            decrypterA.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            decrypterA.Body.Instructions.Add(Instruction.Create(OpCodes.Call, bSpec));
            decrypterA.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            var aSpec = new MethodSpecUser(decrypterA, new GenericInstMethodSig(new GenericMVar(0)));
            decrypterB.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            decrypterB.Body.Instructions.Add(Instruction.Create(OpCodes.Call, aSpec));
            decrypterB.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            module.GlobalType.Methods.Add(decrypterA);
            module.GlobalType.Methods.Add(decrypterB);

            var userType = new TypeDefUser("UserType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(userType);

            // User method has unrewritten call to DecrypterA
            var userMethod = new MethodDefUser("UserMethod", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.UInt32))
            {
                Body = new CilBody()
            };
            var aCallSpec = new MethodSpecUser(decrypterA, new GenericInstMethodSig(module.CorLibTypes.Int32));
            userMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            userMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, aCallSpec));
            userMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            userMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            userType.Methods.Add(userMethod);

            using (var ms = new System.IO.MemoryStream())
            {
                module.Write(ms);
                byte[] rawAsm = ms.ToArray();

                var reflAsm = System.Reflection.Assembly.Load(rawAsm);
                using (var modMD = ModuleDefMD.Load(rawAsm))
                {
                    // Must not enter an infinite loop during transitive closure resolution
                    var result = ConstantKillerImpl.Execute(modMD, reflAsm.ManifestModule);

                    Assert.NotNull(result);
                    Assert.False(result.AllReferencesResolved);

                    // Both A and B must be retained due to the cycle
                    Assert.NotNull(modMD.GlobalType.FindMethod("DecrypterA"));
                    Assert.NotNull(modMD.GlobalType.FindMethod("DecrypterB"));
                }
            }
        }

        [Fact]
        public void ConstantKiller_Execute_CyclicDecrypters_WhenAllUserReferencesResolved_PrunesBothDecrypters()
        {
            var module = new ModuleDefUser("TestCyclicPrunedMod");
            var asm = new AssemblyDefUser("TestCyclicPrunedAsm");
            asm.Modules.Add(module);

            var decrypterA = new MethodDefUser(
                "DecrypterA",
                MethodSig.CreateStaticGeneric(1, new GenericMVar(0), module.CorLibTypes.UInt32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            decrypterA.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));

            var decrypterB = new MethodDefUser(
                "DecrypterB",
                MethodSig.CreateStaticGeneric(1, new GenericMVar(0), module.CorLibTypes.UInt32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            decrypterB.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));

            var bSpec = new MethodSpecUser(decrypterB, new GenericInstMethodSig(new GenericMVar(0)));
            decrypterA.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 42));
            decrypterA.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            var aSpec = new MethodSpecUser(decrypterA, new GenericInstMethodSig(new GenericMVar(0)));
            decrypterB.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            decrypterB.Body.Instructions.Add(Instruction.Create(OpCodes.Call, aSpec));
            decrypterB.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            module.GlobalType.Methods.Add(decrypterA);
            module.GlobalType.Methods.Add(decrypterB);

            var userType = new TypeDefUser("UserType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(userType);

            // User calls DecrypterA(10) with constant key -> rewritten!
            var userMethod = new MethodDefUser("UserMethod", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            var aCallSpec = new MethodSpecUser(decrypterA, new GenericInstMethodSig(module.CorLibTypes.Int32));
            userMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 10));
            userMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, aCallSpec));
            userMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            userMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            userType.Methods.Add(userMethod);

            using (var ms = new System.IO.MemoryStream())
            {
                module.Write(ms);
                byte[] rawAsm = ms.ToArray();

                var reflAsm = System.Reflection.Assembly.Load(rawAsm);
                using (var modMD = ModuleDefMD.Load(rawAsm))
                {
                    var result = ConstantKillerImpl.Execute(modMD, reflAsm.ManifestModule);

                    Assert.NotNull(result);
                    Assert.True(result.AllReferencesResolved);

                    // When all user calls are resolved, dead cycle A <-> B is safely pruned
                    Assert.Null(modMD.GlobalType.FindMethod("DecrypterA"));
                    Assert.Null(modMD.GlobalType.FindMethod("DecrypterB"));
                }
            }
        }

        [Fact]
        public void ConstantKiller_Execute_DecrypterReferencedViaLdftn_IsRetained()
        {
            var module = new ModuleDefUser("TestLdftnMod");
            var asm = new AssemblyDefUser("TestLdftnAsm");
            asm.Modules.Add(module);

            var decrypterA = new MethodDefUser(
                "DecrypterA",
                MethodSig.CreateStaticGeneric(1, new GenericMVar(0), module.CorLibTypes.UInt32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            decrypterA.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            decrypterA.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 42));
            decrypterA.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            module.GlobalType.Methods.Add(decrypterA);

            var userType = new TypeDefUser("UserType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(userType);

            // User takes pointer to decrypter using ldftn
            var userMethod = new MethodDefUser("UserMethod", MethodSig.CreateStatic(module.CorLibTypes.Void))
            {
                Body = new CilBody()
            };
            userMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldftn, decrypterA));
            userMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            userMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            userType.Methods.Add(userMethod);

            using (var ms = new System.IO.MemoryStream())
            {
                module.Write(ms);
                byte[] rawAsm = ms.ToArray();

                var reflAsm = System.Reflection.Assembly.Load(rawAsm);
                using (var modMD = ModuleDefMD.Load(rawAsm))
                {
                    var result = ConstantKillerImpl.Execute(modMD, reflAsm.ManifestModule);

                    Assert.NotNull(result);
                    Assert.False(result.AllReferencesResolved);

                    // DecrypterA is referenced via ldftn so it must NOT be removed!
                    Assert.NotNull(modMD.GlobalType.FindMethod("DecrypterA"));
                }
            }
        }

        /// <summary>
        /// Defensive test for malformed / obfuscated IL:
        /// Under ECMA-335 (Partition III, §4.18), the 'ldvirtftn' instruction is strictly defined
        /// for virtual instance methods of an object and is invalid on static methods.
        /// However, in ConfuserEx, all constant decrypters are static generic methods on &lt;Module&gt;.
        /// This test defensively verifies that ConstantKillerImpl's inter-decrypter dependency tracking
        /// protects against malformed or obfuscated bytecode constructs using 'ldvirtftn' targeting
        /// a static decrypter token, ensuring that the target decrypter is preserved when its caller is live.
        /// </summary>
        [Fact]
        public void ConstantKiller_Execute_InterDecrypterLdvirtftn_DefensiveMalformedIL_RetainsTargetDecrypter()
        {
            var module = new ModuleDefUser("TestLdvirtftnMod");
            var asm = new AssemblyDefUser("TestLdvirtftnAsm");
            asm.Modules.Add(module);

            // Target decrypter B
            var decrypterB = new MethodDefUser(
                "DecrypterB",
                MethodSig.CreateStaticGeneric(1, new GenericMVar(0), module.CorLibTypes.UInt32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            decrypterB.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            decrypterB.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 88));
            decrypterB.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            module.GlobalType.Methods.Add(decrypterB);

            // Caller decrypter A: retained because user call is unrewritten, and loads DecrypterB using ldvirtftn
            var decrypterA = new MethodDefUser(
                "DecrypterA",
                MethodSig.CreateStaticGeneric(1, new GenericMVar(0), module.CorLibTypes.UInt32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            decrypterA.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            var bSpec = new MethodSpecUser(decrypterB, new GenericInstMethodSig(new GenericMVar(0)));
            // ldvirtftn consumes an object reference on stack: ldnull; ldvirtftn DecrypterB; pop
            decrypterA.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            decrypterA.Body.Instructions.Add(Instruction.Create(OpCodes.Ldvirtftn, bSpec));
            decrypterA.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            decrypterA.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 42));
            decrypterA.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            module.GlobalType.Methods.Add(decrypterA);

            var userType = new TypeDefUser("UserType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(userType);

            // User method calls DecrypterA with non-constant parameter -> unrewritten, DecrypterA is retained
            var userMethod = new MethodDefUser("UserMethod", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.UInt32))
            {
                Body = new CilBody()
            };
            var aSpec = new MethodSpecUser(decrypterA, new GenericInstMethodSig(module.CorLibTypes.Int32));
            userMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            userMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, aSpec));
            userMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            userMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            userType.Methods.Add(userMethod);

            using (var ms = new System.IO.MemoryStream())
            {
                module.Write(ms);
                byte[] rawAsm = ms.ToArray();

                var reflAsm = System.Reflection.Assembly.Load(rawAsm);
                using (var modMD = ModuleDefMD.Load(rawAsm))
                {
                    var result = ConstantKillerImpl.Execute(modMD, reflAsm.ManifestModule);

                    Assert.NotNull(result);
                    Assert.False(result.AllReferencesResolved);

                    // DecrypterA is retained because user call was not rewritten
                    Assert.NotNull(modMD.GlobalType.FindMethod("DecrypterA"));

                    // DecrypterB MUST ALSO BE RETAINED because live DecrypterA references it via ldvirtftn!
                    Assert.NotNull(modMD.GlobalType.FindMethod("DecrypterB"));
                }
            }
        }

        [Fact]
        public void TryGetConstantInstruction_U4_EnumUIntMaxValue_PreservesBitsWithoutOverflow()
        {
            object val = TestUIntEnum.MaxValue;
            bool ok = ConstantKillerImpl.TryGetConstantInstruction(ElementType.U4, val, out var op, out var operand);
            Assert.True(ok);
            Assert.Equal(OpCodes.Ldc_I4, op);
            Assert.Equal(-1, operand);
            Assert.Equal(0xFFFFFFFFu, unchecked((uint)(int)operand));
        }

        [Fact]
        public void TryGetConstantInstruction_U4_EnumSignBitSet_PreservesBitsWithoutOverflow()
        {
            object val = TestUIntEnum.MidValue;
            bool ok = ConstantKillerImpl.TryGetConstantInstruction(ElementType.U4, val, out var op, out var operand);
            Assert.True(ok);
            Assert.Equal(OpCodes.Ldc_I4, op);
            Assert.Equal(int.MinValue, operand);
            Assert.Equal(0x80000000u, unchecked((uint)(int)operand));
        }

        [Fact]
        public void TryGetConstantInstruction_U8_EnumULongMaxValue_PreservesBitsWithoutOverflow()
        {
            object val = TestULongEnum.MaxValue;
            bool ok = ConstantKillerImpl.TryGetConstantInstruction(ElementType.U8, val, out var op, out var operand);
            Assert.True(ok);
            Assert.Equal(OpCodes.Ldc_I8, op);
            Assert.Equal(-1L, operand);
            Assert.Equal(0xFFFFFFFFFFFFFFFFul, unchecked((ulong)(long)operand));
        }

        [Fact]
        public void TryGetConstantInstruction_U8_EnumSignBitSet_PreservesBitsWithoutOverflow()
        {
            object val = TestULongEnum.MidValue;
            bool ok = ConstantKillerImpl.TryGetConstantInstruction(ElementType.U8, val, out var op, out var operand);
            Assert.True(ok);
            Assert.Equal(OpCodes.Ldc_I8, op);
            Assert.Equal(long.MinValue, operand);
            Assert.Equal(0x8000000000000000ul, unchecked((ulong)(long)operand));
        }

        [Fact]
        public void TryGetConstantInstruction_I4_EnumNegative_PreservesBits()
        {
            object val = TestIntEnum.Negative;
            bool ok = ConstantKillerImpl.TryGetConstantInstruction(ElementType.I4, val, out var op, out var operand);
            Assert.True(ok);
            Assert.Equal(OpCodes.Ldc_I4, op);
            Assert.Equal(-42, operand);
        }

        [Fact]
        public void ConstantKiller_Execute_NeighboringConstants_OneFails_OtherSucceedsWithoutRollback()
        {
            var module = new ModuleDefUser("TestNeighboringMod");
            var asm = new AssemblyDefUser("TestNeighboringAsm");
            asm.Modules.Add(module);

            // Decrypter<T>(uint key): returns int 999
            var decrypterDef = new MethodDefUser(
                "Decrypter",
                MethodSig.CreateStaticGeneric(1, new GenericMVar(0), module.CorLibTypes.UInt32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            decrypterDef.GenericParameters.Add(new GenericParamUser(0, GenericParamAttributes.NonVariant, "T"));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 999));
            decrypterDef.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            module.GlobalType.Methods.Add(decrypterDef);

            var userType = new TypeDefUser("UserType", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(userType);

            var callerMethod = new MethodDefUser("Run", MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32))
            {
                Body = new CilBody()
            };
            userType.Methods.Add(callerMethod);

            var intSpec = new MethodSpecUser(decrypterDef, new GenericInstMethodSig(module.CorLibTypes.Int32));

            // Call 1: valid constant key -> succeeds and inlined!
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, 123));
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, intSpec));
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            // Call 2: non-constant key (ldarg.0) -> evaluation fails, preserved!
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, intSpec));
            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));

            callerMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

            using (var ms = new System.IO.MemoryStream())
            {
                module.Write(ms);
                byte[] rawAsm = ms.ToArray();

                var reflAsm = System.Reflection.Assembly.Load(rawAsm);
                using (var modMD = ModuleDefMD.Load(rawAsm))
                {
                    var result = ConstantKillerImpl.Execute(modMD, reflAsm.ManifestModule);

                    Assert.NotNull(result);
                    Assert.Equal(2, result.TotalReferencesCount);
                    Assert.Equal(1, result.ResolvedReferencesCount);
                    Assert.Equal(1, result.DecryptedConstantsCount);
                    Assert.False(result.AllReferencesResolved);

                    // Call 1 in Run was replaced with ldc.i4 999
                    var loadedCaller = modMD.Find("UserType", false).FindMethod("Run");
                    Assert.NotNull(loadedCaller);
                    Assert.Equal(OpCodes.Ldc_I4, loadedCaller.Body.Instructions[1].OpCode);
                    Assert.Equal(999, loadedCaller.Body.Instructions[1].Operand);

                    // Call 2 in Run remains Call to Decrypter
                    Assert.Equal(OpCodes.Call, loadedCaller.Body.Instructions[4].OpCode);

                    // Decrypter must be retained in module
                    var loadedDecrypter = modMD.GlobalType.FindMethod("Decrypter");
                    Assert.NotNull(loadedDecrypter);
                }
            }
        }
    }

    public enum TestUIntEnum : uint
    {
        MinValue = 0u,
        MidValue = 0x80000000u,
        MaxValue = 0xFFFFFFFFu
    }

    public enum TestULongEnum : ulong
    {
        MinValue = 0ul,
        MidValue = 0x8000000000000000ul,
        MaxValue = 0xFFFFFFFFFFFFFFFFul
    }

    public enum TestIntEnum : int
    {
        Negative = -42
    }
}
