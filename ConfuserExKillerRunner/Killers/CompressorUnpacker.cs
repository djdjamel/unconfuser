using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using Tool;

namespace ConfuserExKillerRunner.Killers
{
    public sealed class UnpackResult
    {
        public bool IsCompressed { get; set; }
        public bool SuccessfullyUnpacked { get; set; }
        public byte[] UnpackedAssemblyBytes { get; set; }
        public string CompressorType { get; set; }
        public uint RecoveredEntryPointToken { get; set; }
        public string Message { get; set; }
    }

    public static class CompressorUnpacker
    {
        private static readonly string[] KnownFileTableModuleNames = { "koi", "netmodule" };

        public static UnpackResult TryUnpack(ModuleDefMD module, byte[] rawBytes, bool allowExecution = false)
        {
            if (module == null) throw new ArgumentNullException(nameof(module));
            var result = new UnpackResult { IsCompressed = false, SuccessfullyUnpacked = false };

            bool isPackedByFileTable = CheckFileTable(module, out string packedModuleName);
            bool hasAssemblyLoad = false;
            bool hasCompressionRef = false;

            foreach (var memberRef in module.GetMemberRefs())
            {
                if (memberRef.Name == "Load" && memberRef.DeclaringType.FullName == "System.Reflection.Assembly")
                    hasAssemblyLoad = true;
                if (memberRef.DeclaringType.FullName.IndexOf("Compression", StringComparison.OrdinalIgnoreCase) >= 0)
                    hasCompressionRef = true;
            }

            if (!isPackedByFileTable && !hasAssemblyLoad && !hasCompressionRef)
            {
                result.Message = "Not a compressor stub (no FileTable markers, Assembly.Load, or Compression references)";
                return result;
            }

            result.IsCompressed = true;
            if (isPackedByFileTable)
                Logger.LogInfo($"[CompressorUnpacker] Detected ConfuserEx FileTable packed module: '{packedModuleName}'");

            // Attempt to resolve real entrypoint token from compressor stub
            uint entryPointToken = ResolveOriginalEntryPoint(module);
            if (entryPointToken != 0)
            {
                result.RecoveredEntryPointToken = entryPointToken;
                Logger.LogInfo($"[CompressorUnpacker] Recovered original EntryPoint token: 0x{entryPointToken:X8}");
            }

            // Stage 1: Inspect embedded resources for compressed assembly payload
            byte[] unpackedBytes = null;
            string compressorKind = null;

            foreach (var res in module.Resources.OfType<EmbeddedResource>())
            {
                byte[] data = null;
                if (res.Data != null)
                {
                    res.Data.Position = 0;
                    data = res.Data.ReadBytes((int)res.Data.Length);
                }

                if (data == null || data.Length < 128)
                    continue;

                // Raw PE
                if (IsPeFile(data))
                {
                    unpackedBytes = data;
                    compressorKind = "Raw Resource Container";
                    break;
                }

                // Standard Deflate
                byte[] deflated = TryDeflateDecompress(data);
                if (deflated != null && IsPeFile(deflated))
                {
                    unpackedBytes = deflated;
                    compressorKind = "ConfuserEx Deflate Compressor";
                    break;
                }

                // Deflate with 4-byte length prefix
                if (data.Length > 4)
                {
                    byte[] dataNoHeader = new byte[data.Length - 4];
                    Buffer.BlockCopy(data, 4, dataNoHeader, 0, dataNoHeader.Length);
                    byte[] deflated2 = TryDeflateDecompress(dataNoHeader);
                    if (deflated2 != null && IsPeFile(deflated2))
                    {
                        unpackedBytes = deflated2;
                        compressorKind = "ConfuserEx Deflate (Length Prefixed)";
                        break;
                    }
                }

                // GZip
                byte[] gzipped = TryGzipDecompress(data);
                if (gzipped != null && IsPeFile(gzipped))
                {
                    unpackedBytes = gzipped;
                    compressorKind = "GZip Compressor";
                    break;
                }
            }

            // Stage 2: Dynamic method-rewrite unpacking fallback if static extraction didn't yield a PE
            if (unpackedBytes == null && isPackedByFileTable && module.EntryPoint != null && module.EntryPoint.HasBody)
            {
                if (!allowExecution)
                {
                    Logger.LogInfo("[CompressorUnpacker] Dynamic execution disabled (omitted --allow-execution); skipping dynamic unpacker fallback.");
                }
                else
                {
                    try
                    {
                        unpackedBytes = TryDynamicMethodRewriteUnpack(module);
                        if (unpackedBytes != null && IsPeFile(unpackedBytes))
                            compressorKind = "Dynamic Method-Rewrite Unpacker";
                    }
                    catch (Exception ex)
                    {
                        Logger.LogWarning($"[CompressorUnpacker] Dynamic rewrite unpack fallback failed: {ex.Message}");
                    }
                }
            }

            if (unpackedBytes != null && IsPeFile(unpackedBytes))
            {
                // Finalize unpacked module: restore EntryPoint and transplant manifest resources
                try
                {
                    using (var unpackedMod = ModuleDefMD.Load(unpackedBytes))
                    {
                        if (entryPointToken != 0)
                        {
                            try
                            {
                                var epMethod = unpackedMod.ResolveMethod(new MDToken(entryPointToken).Rid);
                                if (epMethod != null)
                                {
                                    unpackedMod.EntryPoint = epMethod;
                                    Logger.LogInfo($"[CompressorUnpacker] Successfully assigned original entrypoint: {epMethod.FullName}");
                                }
                            }
                            catch (Exception ex)
                            {
                                Logger.LogWarning($"[CompressorUnpacker] Failed to resolve entrypoint token 0x{entryPointToken:X8}: {ex.Message}");
                            }
                        }

                        // Copy outer resources to unpacked inner module if missing
                        int copiedRes = 0;
                        foreach (var outerRes in module.Resources)
                        {
                            if (unpackedMod.Resources.Find(outerRes.Name) == null)
                            {
                                unpackedMod.Resources.Add(outerRes);
                                copiedRes++;
                            }
                        }
                        if (copiedRes > 0)
                            Logger.LogInfo($"[CompressorUnpacker] Transplanted {copiedRes} manifest resources into unpacked module.");

                        using (var ms = new MemoryStream())
                        {
                            var writerOpts = new ModuleWriterOptions(unpackedMod) { Logger = DummyLogger.NoThrowInstance };
                            unpackedMod.Write(ms, writerOpts);
                            unpackedBytes = ms.ToArray();
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.LogWarning($"[CompressorUnpacker] Post-processing unpacked module warning: {ex.Message}");
                }

                result.SuccessfullyUnpacked = true;
                result.UnpackedAssemblyBytes = unpackedBytes;
                result.CompressorType = compressorKind ?? "ConfuserEx Compressor";
                result.Message = $"Successfully unpacked {result.CompressorType} ({unpackedBytes.Length} bytes)";
                Logger.LogInfo($"[CompressorUnpacker] {result.Message}");
                return result;
            }

            result.Message = isPackedByFileTable
                ? "ConfuserEx Compressor detected via FileTable, but decompression failed or required runtime execution."
                : "Compressor stub detected with unsupported encoding.";
            return result;
        }

        private static bool CheckFileTable(ModuleDefMD module, out string packedModuleName)
        {
            packedModuleName = null;
            if (module.MetaData?.TablesStream?.FileTable == null)
                return false;

            for (uint rid = 1; rid <= module.MetaData.TablesStream.FileTable.Rows; rid++)
            {
                var row = module.TablesStream.ReadFileRow(rid);
                string name = module.StringsStream.ReadNoNull(row.Name);
                foreach (var known in KnownFileTableModuleNames)
                {
                    if (string.Equals(name, known, StringComparison.OrdinalIgnoreCase))
                    {
                        packedModuleName = name;
                        return true;
                    }
                }
            }
            return false;
        }

        private static uint ResolveOriginalEntryPoint(ModuleDefMD module)
        {
            if (module.EntryPoint == null || !module.EntryPoint.HasBody)
                return 0;

            var instructions = module.EntryPoint.Body.Instructions;
            for (int i = 0; i < instructions.Count; i++)
            {
                if (instructions[i].OpCode != OpCodes.Callvirt && instructions[i].OpCode != OpCodes.Call)
                    continue;

                string opStr = instructions[i].Operand?.ToString();
                if (opStr != null && opStr.Contains("System.Reflection.Module::ResolveSignature(System.Int32)"))
                {
                    for (int j = i - 1; j >= 0; j--)
                    {
                        if (instructions[j].IsLdcI4())
                        {
                            uint signatureToken = (uint)instructions[j].GetLdcI4Value();
                            byte[] blob = module.ReadBlob(signatureToken);
                            if (blob != null && blob.Length >= 4)
                            {
                                return (uint)(blob[0] | (blob[1] << 8) | (blob[2] << 16) | (blob[3] << 24));
                            }
                        }
                    }
                }
            }
            return 0;
        }

        private static byte[] TryDynamicMethodRewriteUnpack(ModuleDefMD module)
        {
            var ep = module.EntryPoint;
            if (ep == null || !ep.HasBody)
                return null;

            var corLibByteArr = module.CorLibTypes.Byte.ToSZArraySig();
            var originalReturnType = ep.ReturnType;
            var originalInstructions = ep.Body.Instructions.ToList();

            try
            {
                ep.ReturnType = corLibByteArr;
                bool patched = false;

                for (int i = 0; i < ep.Body.Instructions.Count; i++)
                {
                    var inst = ep.Body.Instructions[i];
                    if (inst.OpCode == OpCodes.Call && inst.Operand != null)
                    {
                        string opStr = inst.Operand.ToString();
                        if (opStr.Contains("GCHandle::get_Target()"))
                        {
                            ep.Body.Instructions.Insert(i + 1, Instruction.Create(OpCodes.Castclass, module.CorLibTypes.Byte.ToSZArraySig().ToTypeDefOrRef()));
                            ep.Body.Instructions.Insert(i + 2, Instruction.Create(OpCodes.Ret));
                            patched = true;
                            break;
                        }
                        if (opStr.Contains("Assembly::Load(System.Byte[])") || opStr.Contains("Assembly::Load"))
                        {
                            inst.OpCode = OpCodes.Ret;
                            inst.Operand = null;
                            patched = true;
                            break;
                        }
                    }
                }

                if (!patched)
                    return null;

                using (var ms = new MemoryStream())
                {
                    var writerOpts = new ModuleWriterOptions(module) { Logger = DummyLogger.NoThrowInstance };
                    module.Write(ms, writerOpts);

                    var tempAsm = Assembly.Load(ms.ToArray());
                    var reflMethod = tempAsm.ManifestModule.ResolveMethod(ep.MDToken.ToInt32());
                    var parameters = reflMethod.GetParameters();
                    object[] invokeArgs = parameters.Length > 0 ? new object[parameters.Length] : null;
                    return (byte[])reflMethod.Invoke(null, invokeArgs);
                }
            }
            finally
            {
                ep.ReturnType = originalReturnType;
                ep.Body.Instructions.Clear();
                foreach (var inst in originalInstructions)
                    ep.Body.Instructions.Add(inst);
            }
        }

        private static bool IsPeFile(byte[] bytes)
        {
            if (bytes == null || bytes.Length < 64)
                return false;
            if (bytes[0] != 0x4D || bytes[1] != 0x5A) // 'MZ'
                return false;

            uint e_lfanew = BitConverter.ToUInt32(bytes, 0x3C);
            if (e_lfanew + 4 > bytes.Length)
                return false;

            uint peSig = BitConverter.ToUInt32(bytes, (int)e_lfanew);
            return peSig == 0x00004550; // 'PE\0\0'
        }

        private static byte[] TryDeflateDecompress(byte[] compressed)
        {
            try
            {
                using (var input = new MemoryStream(compressed))
                using (var deflate = new DeflateStream(input, CompressionMode.Decompress))
                using (var output = new MemoryStream())
                {
                    deflate.CopyTo(output);
                    return output.ToArray();
                }
            }
            catch
            {
                return null;
            }
        }

        private static byte[] TryGzipDecompress(byte[] compressed)
        {
            try
            {
                using (var input = new MemoryStream(compressed))
                using (var gzip = new GZipStream(input, CompressionMode.Decompress))
                using (var output = new MemoryStream())
                {
                    gzip.CopyTo(output);
                    return output.ToArray();
                }
            }
            catch
            {
                return null;
            }
        }
    }
}
