using System;
using System.IO;
using System.Linq;
using ConfuserExKillerRunner.Killers;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
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

            // Entry point method with:
            // - Signature: static int Main(string arg)
            // - Locals: int, bool
            // - Instructions: branch target, exception throw, Assembly.Load call
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
            // [2] instBr: br.s targetBranch
            // [3] instDummy: nop
            // [4] targetBranch: ldstr "Forced reflection failure"
            // [5] instNewobj: newobj InvalidOperationException(string)
            // [6] instThrow: throw (forces TargetInvocationException during reflMethod.Invoke)
            // [7] instLdnull: ldnull
            // [8] callLoad: call Assembly.Load(byte[]) -> patched to Ret/null operand by TryDynamicMethodRewriteUnpack
            // [9] instRetVal: ldc.i4.1
            // [10] instRet: ret
            var targetBranch = Instruction.Create(OpCodes.Ldstr, "Forced reflection failure");
            var inst0 = Instruction.Create(OpCodes.Ldc_I4_0);
            var inst1 = Instruction.Create(OpCodes.Stloc, local0);
            var instBr = Instruction.Create(OpCodes.Br_S, targetBranch);
            var instDummy = Instruction.Create(OpCodes.Nop);
            var instNewobj = Instruction.Create(OpCodes.Newobj, exceptionCtorRef);
            var instThrow = Instruction.Create(OpCodes.Throw);
            var instLdnull = Instruction.Create(OpCodes.Ldnull);
            var callLoad = Instruction.Create(OpCodes.Call, asmLoadRef);
            var instRetVal = Instruction.Create(OpCodes.Ldc_I4_1);
            var instRet = Instruction.Create(OpCodes.Ret);

            epMethod.Body.Instructions.Add(inst0);
            epMethod.Body.Instructions.Add(inst1);
            epMethod.Body.Instructions.Add(instBr);
            epMethod.Body.Instructions.Add(instDummy);
            epMethod.Body.Instructions.Add(targetBranch);
            epMethod.Body.Instructions.Add(instNewobj);
            epMethod.Body.Instructions.Add(instThrow);
            epMethod.Body.Instructions.Add(instLdnull);
            epMethod.Body.Instructions.Add(callLoad);
            epMethod.Body.Instructions.Add(instRetVal);
            epMethod.Body.Instructions.Add(instRet);

            var handler = new ExceptionHandler(ExceptionHandlerType.Catch)
            {
                TryStart = inst0,
                TryEnd = targetBranch,
                HandlerStart = targetBranch,
                HandlerEnd = instLdnull,
                CatchType = module.CorLibTypes.Object.TypeDefOrRef
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
                    var origInstCount = targetEp.Body.Instructions.Count;
                    var origVarCount = targetEp.Body.Variables.Count;
                    var origHandlerCount = targetEp.Body.ExceptionHandlers.Count;
                    var origCallInst = targetEp.Body.Instructions[8];
                    var origCallOpCode = origCallInst.OpCode;

                    // When invoked, targetEp executes and throws inside tempAsm, forcing an exception inside TryDynamicMethodRewriteUnpack
                    // The finally block must execute and restore the original method body and signature
                    Assert.ThrowsAny<Exception>(() => CompressorUnpacker.TryDynamicMethodRewriteUnpack(modMD));

                    // 1. Verify return type and signature are restored (not SZArray byte[])
                    Assert.Equal(origReturnType.FullName, targetEp.ReturnType.FullName);
                    Assert.Equal(origMethodSig, targetEp.MethodSig.ToString());
                    Assert.Equal(ElementType.I4, targetEp.ReturnType.ElementType);

                    // 2. Verify instruction count and that the patched Call instruction was unpatched (not left as Ret with null operand)
                    Assert.Equal(origInstCount, targetEp.Body.Instructions.Count);
                    var restoredCall = targetEp.Body.Instructions[8];
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
                    Assert.Same(targetEp.Body.Instructions[0], targetEp.Body.ExceptionHandlers[0].TryStart);
                    Assert.Same(targetEp.Body.Instructions[4], targetEp.Body.ExceptionHandlers[0].TryEnd);
                    Assert.Same(targetEp.Body.Instructions[4], targetEp.Body.ExceptionHandlers[0].HandlerStart);
                    Assert.Same(targetEp.Body.Instructions[7], targetEp.Body.ExceptionHandlers[0].HandlerEnd);
                }
            }
        }
    }
}
