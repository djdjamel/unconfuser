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
    }
}
