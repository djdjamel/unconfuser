using System;
using System.IO;
using System.Linq;
using ConfuserExKillerRunner.Killers;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public static class CompressorTestSentinel
    {
        public static bool EntryPointExecuted { get; set; }
        public static void SignalExecution() => EntryPointExecuted = true;
    }

    public class CompressorUnpackerTests
    {
        [Fact]
        public void TryDynamicMethodRewriteUnpack_ForcedFailure_RestoresSignatureInstructionsBranchesLocalsAndHandlers()
        {
            var module = new ModuleDefUser("TestCompressorMod");
            var asm = new AssemblyDefUser("TestCompressorAsm");
            asm.Modules.Add(module);

            var globalType = module.GlobalType;

            // Member reference for Assembly::Load(byte[]) which TryDynamicMethodRewriteUnpack looks for
            var asmLoadRef = new MemberRefUser(module, "Load",
                MethodSig.CreateStatic(module.CorLibTypes.Object, new SZArraySig(module.CorLibTypes.Byte)),
                new TypeRefUser(module, "System.Reflection", "Assembly", module.CorLibTypes.AssemblyRef));

            var exceptionCtorRef = new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.String),
                new TypeRefUser(module, "System", "InvalidOperationException", module.CorLibTypes.AssemblyRef));

            var signalRef = module.Import(typeof(CompressorTestSentinel).GetMethod(nameof(CompressorTestSentinel.SignalExecution)));

            // Entry point method with:
            // - Signature: static int Main(string arg)
            // - Locals: int, bool
            // - Instructions: branch target, sentinel invocation, exception throw, Assembly.Load call
            // - Exception handler
            var epMethod = new MethodDefUser("Main",
                MethodSig.CreateStatic(module.CorLibTypes.Int32, module.CorLibTypes.String),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            globalType.Methods.Add(epMethod);
            module.EntryPoint = epMethod;

            var local0 = new Local(module.CorLibTypes.Int32);
            var local1 = new Local(module.CorLibTypes.Boolean);
            epMethod.Body.Variables.Add(local0);
            epMethod.Body.Variables.Add(local1);

            epMethod.Body.KeepOldMaxStack = true;
            epMethod.Body.MaxStack = 8;

            // Instructions layout:
            // [0] inst0: ldc.i4.0
            // [1] inst1: stloc.0
            // [2] instBr: br.s instTarget
            // [3] instDummy: nop
            // [4] instTarget: ldc.i4.1
            // [5] inst2: stloc.1
            // Try block starts:
            // [6] instSignal: call CompressorTestSentinel.SignalExecution()
            // [7] instLdstr: ldstr "Forced failure inside loaded entry point"
            // [8] instNewobj: newobj InvalidOperationException(string)
            // [9] instThrow: throw (forces TargetInvocationException during reflMethod.Invoke)
            // Catch handler starts:
            // [10] instHandlerStart: pop (catches ArgumentException)
            // [11] instLeave: leave.s instRetVal
            // Catch handler ends:
            // [12] instLdnull: ldnull
            // [13] callLoad: call Assembly.Load(byte[]) -> patched to Ret/null operand by TryDynamicMethodRewriteUnpack
            // [14] instRetVal: ldc.i4.0
            // [15] instRet: ret
            var inst0 = Instruction.Create(OpCodes.Ldc_I4_0);
            var inst1 = Instruction.Create(OpCodes.Stloc, local0);
            var instTarget = Instruction.Create(OpCodes.Ldc_I4_1);
            var instBr = Instruction.Create(OpCodes.Br_S, instTarget);
            var instDummy = Instruction.Create(OpCodes.Nop);
            var inst2 = Instruction.Create(OpCodes.Stloc, local1);
            var instSignal = Instruction.Create(OpCodes.Call, signalRef);
            var instLdstr = Instruction.Create(OpCodes.Ldstr, "Forced failure inside loaded entry point");
            var instNewobj = Instruction.Create(OpCodes.Newobj, exceptionCtorRef);
            var instThrow = Instruction.Create(OpCodes.Throw);
            var instHandlerStart = Instruction.Create(OpCodes.Pop);
            var instRetVal = Instruction.Create(OpCodes.Ldc_I4_0);
            var instLeave = Instruction.Create(OpCodes.Leave_S, instRetVal);
            var instLdnull = Instruction.Create(OpCodes.Ldnull);
            var callLoad = Instruction.Create(OpCodes.Call, asmLoadRef);
            var instRet = Instruction.Create(OpCodes.Ret);

            epMethod.Body.Instructions.Add(inst0);
            epMethod.Body.Instructions.Add(inst1);
            epMethod.Body.Instructions.Add(instBr);
            epMethod.Body.Instructions.Add(instDummy);
            epMethod.Body.Instructions.Add(instTarget);
            epMethod.Body.Instructions.Add(inst2);
            epMethod.Body.Instructions.Add(instSignal);
            epMethod.Body.Instructions.Add(instLdstr);
            epMethod.Body.Instructions.Add(instNewobj);
            epMethod.Body.Instructions.Add(instThrow);
            epMethod.Body.Instructions.Add(instHandlerStart);
            epMethod.Body.Instructions.Add(instLeave);
            epMethod.Body.Instructions.Add(instLdnull);
            epMethod.Body.Instructions.Add(callLoad);
            epMethod.Body.Instructions.Add(instRetVal);
            epMethod.Body.Instructions.Add(instRet);

            var argExRef = new TypeRefUser(module, "System", "ArgumentException", module.CorLibTypes.AssemblyRef);
            var handler = new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = instSignal,
                TryEnd = instHandlerStart,
                HandlerStart = instHandlerStart,
                HandlerEnd = instLdnull,
                CatchType = argExRef
            };
            epMethod.Body.ExceptionHandlers.Add(handler);

            using (var ms = new MemoryStream())
            {
                var writerOpts = new dnlib.DotNet.Writer.ModuleWriterOptions(module);
                writerOpts.MetaDataOptions.Flags |= dnlib.DotNet.Writer.MetaDataFlags.KeepOldMaxStack;
                module.Write(ms, writerOpts);

                using (var modMD = ModuleDefMD.Load(ms.ToArray()))
                {
                    var targetEp = modMD.EntryPoint;
                    var origReturnType = targetEp.ReturnType;
                    var origMethodSig = targetEp.MethodSig.ToString();
                    int origInstCount = targetEp.Body.Instructions.Count;
                    int origVarCount = targetEp.Body.Variables.Count;
                    int origHandlerCount = targetEp.Body.ExceptionHandlers.Count;
                    var origCallInst = targetEp.Body.Instructions[13];
                    var origCallOpCode = origCallInst.OpCode;

                    CompressorTestSentinel.EntryPointExecuted = false;

                    // When invoked, targetEp executes and throws inside tempAsm, forcing a TargetInvocationException inside TryDynamicMethodRewriteUnpack
                    // The test strictly asserts TargetInvocationException wrapping the specific sentinel exception and confirms entry point execution
                    var ex = Assert.Throws<System.Reflection.TargetInvocationException>(() => CompressorUnpacker.TryDynamicMethodRewriteUnpack(modMD));

                    // Verify that forced failure occurs specifically after assembly load and during entry point invocation
                    Assert.True(CompressorTestSentinel.EntryPointExecuted);
                    Assert.NotNull(ex.InnerException);
                    var innerEx = Assert.IsType<InvalidOperationException>(ex.InnerException);
                    Assert.Equal("Forced failure inside loaded entry point", innerEx.Message);

                    // 1. Verify return type and signature are restored (not SZArray byte[])
                    Assert.Equal(origReturnType.FullName, targetEp.ReturnType.FullName);
                    Assert.Equal(origMethodSig, targetEp.MethodSig.ToString());
                    Assert.Equal(ElementType.I4, targetEp.ReturnType.ElementType);

                    // 2. Verify instruction count and that the patched Call instruction was unpatched (not left as Ret with null operand)
                    Assert.Equal(origInstCount, targetEp.Body.Instructions.Count);
                    var restoredCall = targetEp.Body.Instructions[13];
                    Assert.Equal(origCallOpCode, restoredCall.OpCode);
                    Assert.Equal(OpCodes.Call, restoredCall.OpCode);
                    Assert.NotNull(restoredCall.Operand);
                    Assert.Contains("Assembly::Load", restoredCall.Operand.ToString());

                    // 3. Verify branch targets are remapped to instructions in the restored body
                    var branch = targetEp.Body.Instructions[2];
                    Assert.True(branch.IsBr());
                    Assert.Same(targetEp.Body.Instructions[4], branch.Operand);

                    // 4. Verify local variables are fully restored
                    Assert.Equal(origVarCount, targetEp.Body.Variables.Count);
                    Assert.Equal(ElementType.I4, targetEp.Body.Variables[0].Type.ElementType);
                    Assert.Equal(ElementType.Boolean, targetEp.Body.Variables[1].Type.ElementType);

                    // 5. Verify exception handler boundaries are remapped to instructions in the restored body
                    Assert.Equal(origHandlerCount, targetEp.Body.ExceptionHandlers.Count);
                    Assert.Same(targetEp.Body.Instructions[6], targetEp.Body.ExceptionHandlers[0].TryStart);
                    Assert.Same(targetEp.Body.Instructions[10], targetEp.Body.ExceptionHandlers[0].TryEnd);
                    Assert.Same(targetEp.Body.Instructions[10], targetEp.Body.ExceptionHandlers[0].HandlerStart);
                    Assert.Same(targetEp.Body.Instructions[12], targetEp.Body.ExceptionHandlers[0].HandlerEnd);
                }
            }
        }

        [Fact]
        public void DecompressBounded_ExceedingSizeLimit_ReturnsNullAndProtectsMemory()
        {
            byte[] original = new byte[1024 * 1024];
            for (int i = 0; i < original.Length; i++)
                original[i] = (byte)(i % 251);

            byte[] compressed;
            using (var ms = new MemoryStream())
            {
                using (var deflate = new System.IO.Compression.DeflateStream(ms, System.IO.Compression.CompressionMode.Compress, true))
                {
                    deflate.Write(original, 0, original.Length);
                }
                compressed = ms.ToArray();
            }

            byte[] decompNormal = CompressorUnpacker.TryDeflateDecompress(compressed, maxSize: 2 * 1024 * 1024);
            Assert.NotNull(decompNormal);
            Assert.Equal(original.Length, decompNormal.Length);
            Assert.Equal(original, decompNormal);

            byte[] decompExceeded = CompressorUnpacker.TryDeflateDecompress(compressed, maxSize: 50 * 1024);
            Assert.Null(decompExceeded);
        }

        [Fact]
        public void TryGzipDecompress_ExceedingSizeLimit_ReturnsNull()
        {
            byte[] original = new byte[512 * 1024];
            for (int i = 0; i < original.Length; i++)
                original[i] = (byte)(i % 17);

            byte[] compressed;
            using (var ms = new MemoryStream())
            {
                using (var gzip = new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionMode.Compress, true))
                {
                    gzip.Write(original, 0, original.Length);
                }
                compressed = ms.ToArray();
            }

            byte[] decompNormal = CompressorUnpacker.TryGzipDecompress(compressed, maxSize: 1024 * 1024);
            Assert.NotNull(decompNormal);
            Assert.Equal(original.Length, decompNormal.Length);

            byte[] decompExceeded = CompressorUnpacker.TryGzipDecompress(compressed, maxSize: 10 * 1024);
            Assert.Null(decompExceeded);
        }

        private static byte[] CreateValidSmallNetPe(string asmName = "InnerPayloadAsm")
        {
            var innerMod = new ModuleDefUser(asmName + ".dll");
            var innerAsm = new AssemblyDefUser(asmName);
            innerAsm.Modules.Add(innerMod);

            var sampleType = new TypeDefUser("InnerNamespace", "InnerClass", innerMod.CorLibTypes.Object.TypeDefOrRef);
            innerMod.Types.Add(sampleType);

            using (var ms = new MemoryStream())
            {
                innerMod.Write(ms, new dnlib.DotNet.Writer.ModuleWriterOptions(innerMod) { Logger = DummyLogger.NoThrowInstance });
                return ms.ToArray();
            }
        }

        [Fact]
        public void TryUnpack_CosturaFodyApplication_IsDetectedAndSkippedWithoutHijackingAssembly()
        {
            // Simulate an application packaged with Costura.Fody
            var module = new ModuleDefUser("MainCosturaApp.exe");
            var asm = new AssemblyDefUser("MainCosturaApp");
            asm.Modules.Add(module);

            // 1. Costura AssemblyLoader type
            var costuraType = new TypeDefUser("Costura", "AssemblyLoader", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(costuraType);

            // 2. Normal application domain types
            var appType1 = new TypeDefUser("App.Services", "OrderService", module.CorLibTypes.Object.TypeDefOrRef);
            var appType2 = new TypeDefUser("App.Views", "MainWindow", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(appType1);
            module.Types.Add(appType2);

            // 3. Embedded compressed dependency (e.g. Newtonsoft.Json)
            byte[] innerPe = CreateValidSmallNetPe("Newtonsoft.Json");
            byte[] compressedDependency;
            using (var ms = new MemoryStream())
            {
                using (var deflate = new System.IO.Compression.DeflateStream(ms, System.IO.Compression.CompressionLevel.Optimal, true))
                {
                    deflate.Write(innerPe, 0, innerPe.Length);
                }
                compressedDependency = ms.ToArray();
            }
            module.Resources.Add(new EmbeddedResource("costura.newtonsoft.json.dll.compressed", compressedDependency));

            // 4. Application EntryPoint
            var ep = new MethodDefUser("Main", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            ep.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            module.GlobalType.Methods.Add(ep);
            module.EntryPoint = ep;

            using (var ms = new MemoryStream())
            {
                module.Write(ms, new dnlib.DotNet.Writer.ModuleWriterOptions(module) { Logger = DummyLogger.NoThrowInstance });
                using (var modMD = ModuleDefMD.Load(ms.ToArray()))
                {
                    var result = CompressorUnpacker.TryUnpack(modMD, ms.ToArray(), allowExecution: false);

                    // Must NOT be unpacked, must NOT hijack host application
                    Assert.False(result.SuccessfullyUnpacked);
                    Assert.False(result.IsCompressed);
                    Assert.Equal(PackerClassification.CosturaFodyPacker, result.Classification);
                    Assert.Null(result.UnpackedAssemblyBytes);
                    Assert.Contains("Costura.Fody", result.Message);
                }
            }
        }

        [Fact]
        public void TryUnpack_BenignAssemblyWithRawEmbeddedPe_IsSkippedWithoutReplacingTarget()
        {
            var module = new ModuleDefUser("PluginHostApp.exe");
            var asm = new AssemblyDefUser("PluginHostApp");
            asm.Modules.Add(module);

            // Normal application types
            module.Types.Add(new TypeDefUser("App.Core", "PluginManager", module.CorLibTypes.Object.TypeDefOrRef));
            module.Types.Add(new TypeDefUser("App.Core", "ConfigService", module.CorLibTypes.Object.TypeDefOrRef));
            module.Types.Add(new TypeDefUser("App.Core", "UiPresenter", module.CorLibTypes.Object.TypeDefOrRef));
            module.Types.Add(new TypeDefUser("App.Core", "DataRepository", module.CorLibTypes.Object.TypeDefOrRef));

            // Embed raw PE plugin
            byte[] innerPe = CreateValidSmallNetPe("SamplePlugin");
            module.Resources.Add(new EmbeddedResource("MyEmbeddedPlugin.dll", innerPe));

            var ep = new MethodDefUser("Main", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            ep.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            module.GlobalType.Methods.Add(ep);
            module.EntryPoint = ep;

            using (var ms = new MemoryStream())
            {
                module.Write(ms, new dnlib.DotNet.Writer.ModuleWriterOptions(module) { Logger = DummyLogger.NoThrowInstance });
                using (var modMD = ModuleDefMD.Load(ms.ToArray()))
                {
                    var result = CompressorUnpacker.TryUnpack(modMD, ms.ToArray(), allowExecution: false);

                    Assert.False(result.SuccessfullyUnpacked);
                    Assert.False(result.IsCompressed);
                    Assert.Equal(PackerClassification.GenericApplicationWithEmbeddedPayload, result.Classification);
                    Assert.Null(result.UnpackedAssemblyBytes);
                }
            }
        }

        [Fact]
        public void TryUnpack_BenignAssemblyWithDeflateCompressedPe_IsSkippedWithoutReplacingTarget()
        {
            var module = new ModuleDefUser("BackupUtilityApp.exe");
            var asm = new AssemblyDefUser("BackupUtilityApp");
            asm.Modules.Add(module);

            // Normal application types
            module.Types.Add(new TypeDefUser("Backup.Engine", "Worker", module.CorLibTypes.Object.TypeDefOrRef));
            module.Types.Add(new TypeDefUser("Backup.Engine", "Archiver", module.CorLibTypes.Object.TypeDefOrRef));
            module.Types.Add(new TypeDefUser("Backup.Engine", "ReportGenerator", module.CorLibTypes.Object.TypeDefOrRef));
            module.Types.Add(new TypeDefUser("Backup.Engine", "Settings", module.CorLibTypes.Object.TypeDefOrRef));

            // Embed deflated PE
            byte[] innerPe = CreateValidSmallNetPe("HelperAssembly");
            byte[] compressed;
            using (var compMs = new MemoryStream())
            {
                using (var deflate = new System.IO.Compression.DeflateStream(compMs, System.IO.Compression.CompressionLevel.Optimal, true))
                {
                    deflate.Write(innerPe, 0, innerPe.Length);
                }
                compressed = compMs.ToArray();
            }
            module.Resources.Add(new EmbeddedResource("ZippedHelper.bin", compressed));

            var ep = new MethodDefUser("Main", MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            ep.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            module.GlobalType.Methods.Add(ep);
            module.EntryPoint = ep;

            using (var ms = new MemoryStream())
            {
                module.Write(ms, new dnlib.DotNet.Writer.ModuleWriterOptions(module) { Logger = DummyLogger.NoThrowInstance });
                using (var modMD = ModuleDefMD.Load(ms.ToArray()))
                {
                    var result = CompressorUnpacker.TryUnpack(modMD, ms.ToArray(), allowExecution: false);

                    Assert.False(result.SuccessfullyUnpacked);
                    Assert.False(result.IsCompressed);
                    Assert.Null(result.UnpackedAssemblyBytes);
                }
            }
        }

        [Fact]
        public void TryUnpack_OtherPacker_LibZ_IsDetectedAndSkipped()
        {
            var module = new ModuleDefUser("LibZPackedApp.exe");
            var asm = new AssemblyDefUser("LibZPackedApp");
            asm.Modules.Add(module);

            var libzType = new TypeDefUser("LibZ", "Loader", module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(libzType);

            using (var ms = new MemoryStream())
            {
                module.Write(ms, new dnlib.DotNet.Writer.ModuleWriterOptions(module) { Logger = DummyLogger.NoThrowInstance });
                using (var modMD = ModuleDefMD.Load(ms.ToArray()))
                {
                    var result = CompressorUnpacker.TryUnpack(modMD, ms.ToArray(), allowExecution: false);

                    Assert.False(result.SuccessfullyUnpacked);
                    Assert.False(result.IsCompressed);
                    Assert.Equal(PackerClassification.OtherPackagingFormat, result.Classification);
                    Assert.Contains("LibZ", result.Message);
                }
            }
        }

        [Fact]
        public void TryUnpack_AuthenticConfuserExDeflateStub_SuccessfullyUnpacks()
        {
            byte[] innerPe = CreateValidSmallNetPe("RealTargetApp");
            byte[] compressed;
            using (var compMs = new MemoryStream())
            {
                using (var deflate = new System.IO.Compression.DeflateStream(compMs, System.IO.Compression.CompressionLevel.Optimal, true))
                {
                    deflate.Write(innerPe, 0, innerPe.Length);
                }
                compressed = compMs.ToArray();
            }

            var stubMod = new ModuleDefUser("ConfuserStub.exe");
            var stubAsm = new AssemblyDefUser("ConfuserStub");
            stubAsm.Modules.Add(stubMod);

            stubMod.Resources.Add(new EmbeddedResource("ConfuserEx.CompressedPayload", compressed));

            // Bootstrap EntryPoint
            var ep = new MethodDefUser("Main", MethodSig.CreateStatic(stubMod.CorLibTypes.Void),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static)
            {
                Body = new CilBody()
            };
            var asmLoadRef = stubMod.Import(typeof(System.Reflection.Assembly).GetMethod("Load", new[] { typeof(byte[]) }));
            ep.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            ep.Body.Instructions.Add(Instruction.Create(OpCodes.Call, asmLoadRef));
            ep.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
            ep.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            stubMod.GlobalType.Methods.Add(ep);
            stubMod.EntryPoint = ep;

            using (var ms = new MemoryStream())
            {
                stubMod.Write(ms, new dnlib.DotNet.Writer.ModuleWriterOptions(stubMod) { Logger = DummyLogger.NoThrowInstance });
                using (var modMD = ModuleDefMD.Load(ms.ToArray()))
                {
                    var result = CompressorUnpacker.TryUnpack(modMD, ms.ToArray(), allowExecution: false);

                    Assert.True(result.IsCompressed);
                    Assert.True(result.SuccessfullyUnpacked);
                    Assert.Equal(PackerClassification.ConfuserExCompressorStub, result.Classification);
                    Assert.NotNull(result.UnpackedAssemblyBytes);
                    Assert.True(result.UnpackedAssemblyBytes.Length > 0);

                    // Verify unpacked bytes load cleanly as the target assembly
                    using (var unpackedMod = ModuleDefMD.Load(result.UnpackedAssemblyBytes))
                    {
                        Assert.Equal("RealTargetApp", unpackedMod.Assembly.Name);
                    }
                }
            }
        }

        [Fact]
        public void ValidateUnpackedPe_CorruptedAndTruncated_ReturnsFalse()
        {
            Assert.False(CompressorUnpacker.ValidateUnpackedPe(null, out _));
            Assert.False(CompressorUnpacker.ValidateUnpackedPe(new byte[10], out _));
            Assert.False(CompressorUnpacker.ValidateUnpackedPe(new byte[600], out _)); // All zeros

            // MZ with out of bounds e_lfanew
            byte[] badLfanew = new byte[600];
            badLfanew[0] = 0x4D; badLfanew[1] = 0x5A;
            BitConverter.GetBytes(0x7FFFFFFF).CopyTo(badLfanew, 0x3C);
            Assert.False(CompressorUnpacker.ValidateUnpackedPe(badLfanew, out _));

            // MZ with valid e_lfanew but wrong PE signature
            byte[] badSig = new byte[600];
            badSig[0] = 0x4D; badSig[1] = 0x5A;
            BitConverter.GetBytes(128).CopyTo(badSig, 0x3C);
            badSig[128] = (byte)'N'; badSig[129] = (byte)'O'; badSig[130] = (byte)'P'; badSig[131] = (byte)'E';
            Assert.False(CompressorUnpacker.ValidateUnpackedPe(badSig, out _));

            // Valid PE header but random non-.NET garbage in data sections
            byte[] fakePe = new byte[1024];
            fakePe[0] = 0x4D; fakePe[1] = 0x5A;
            BitConverter.GetBytes(128).CopyTo(fakePe, 0x3C);
            fakePe[128] = (byte)'P'; fakePe[129] = (byte)'E'; fakePe[130] = 0; fakePe[131] = 0;
            Assert.False(CompressorUnpacker.ValidateUnpackedPe(fakePe, out _));
        }
    }
}
