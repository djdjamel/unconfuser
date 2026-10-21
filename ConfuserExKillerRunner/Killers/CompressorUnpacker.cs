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
    public enum PackerClassification
    {
        NotACompressorStub,
        CosturaFodyPacker,
        GenericApplicationWithEmbeddedPayload,
        OtherPackagingFormat,
        ConfuserExCompressorStub
    }

    public sealed class UnpackResult
    {
        public bool IsCompressed { get; set; }
        public bool SuccessfullyUnpacked { get; set; }
        public byte[] UnpackedAssemblyBytes { get; set; }
        public string CompressorType { get; set; }
        public uint RecoveredEntryPointToken { get; set; }
        public string Message { get; set; }
        public PackerClassification Classification { get; set; } = PackerClassification.NotACompressorStub;
    }

    public static class CompressorUnpacker
    {
        private static readonly string[] KnownFileTableModuleNames = { "koi", "netmodule" };

        /// <summary>
        /// Default maximum allowed decompressed size (128 MB) to prevent decompression bomb vulnerabilities.
        /// </summary>
        public const int DefaultMaxDecompressedSize = 128 * 1024 * 1024; // 128 MB

        /// <summary>
        /// Configurable maximum allowed decompressed size in bytes.
        /// </summary>
        public static int MaxDecompressedSize { get; set; } = DefaultMaxDecompressedSize;

        public static UnpackResult TryUnpack(ModuleDefMD module, byte[] rawBytes, bool allowExecution = false)
        {
            if (module == null) throw new ArgumentNullException(nameof(module));
            var result = new UnpackResult { IsCompressed = false, SuccessfullyUnpacked = false };

            // 1. Check for Costura.Fody or other third-party packaging patterns
            if (IsCosturaFody(module, out string costuraDetail))
            {
                result.Classification = PackerClassification.CosturaFodyPacker;
                result.IsCompressed = false;
                result.SuccessfullyUnpacked = false;
                result.Message = $"Identified Costura.Fody embedded dependency packaging ({costuraDetail}). ConfuserEx unpacker skipped to preserve host application integrity.";
                Logger.LogInfo($"[CompressorUnpacker] {result.Message}");
                return result;
            }

            if (IsOtherKnownPacker(module, out string otherPackerName))
            {
                result.Classification = PackerClassification.OtherPackagingFormat;
                result.IsCompressed = false;
                result.SuccessfullyUnpacked = false;
                result.Message = $"Identified non-ConfuserEx packaging format ({otherPackerName}). Unpacker skipped.";
                Logger.LogInfo($"[CompressorUnpacker] {result.Message}");
                return result;
            }

            // 2. Classify whether this is an authentic ConfuserEx compressor stub
            bool isPackedByFileTable = CheckFileTable(module, out string packedModuleName);
            uint entryPointToken = ResolveOriginalEntryPoint(module);
            bool isEntryPointStub = IsBootstrapEntryPointStub(module);
            bool hasConfuserPayloadResource = HasConfuserPayloadResource(module, out var confuserResource);

            // Strict determination of whether this module is a ConfuserEx compressor stub:
            // Must have FileTable marker, OR ResolveSignature in EntryPoint, OR (Bootstrap stub + Confuser payload resource).
            bool isConfuserExStub = isPackedByFileTable ||
                                    (entryPointToken != 0) ||
                                    (isEntryPointStub && hasConfuserPayloadResource);

            if (!isConfuserExStub)
            {
                result.Classification = HasAnyEmbeddedPe(module)
                    ? PackerClassification.GenericApplicationWithEmbeddedPayload
                    : PackerClassification.NotACompressorStub;
                result.IsCompressed = false;
                result.SuccessfullyUnpacked = false;
                result.Message = "Target assembly is not an authentic ConfuserEx compressor stub (unrelated application or arbitrary embedded resources preserved).";
                return result;
            }

            result.Classification = PackerClassification.ConfuserExCompressorStub;
            result.IsCompressed = true;

            if (isPackedByFileTable)
                Logger.LogInfo($"[CompressorUnpacker] Detected ConfuserEx FileTable packed module: '{packedModuleName}'");

            if (entryPointToken != 0)
            {
                result.RecoveredEntryPointToken = entryPointToken;
                Logger.LogInfo($"[CompressorUnpacker] Recovered original EntryPoint token: 0x{entryPointToken:X8}");
            }

            // Stage 1: Inspect embedded resources for compressed assembly payload
            byte[] unpackedBytes = null;
            string compressorKind = null;

            // Prioritize explicitly recognized ConfuserEx payload resources
            var candidateResources = module.Resources.OfType<EmbeddedResource>().ToList();
            if (hasConfuserPayloadResource && confuserResource != null)
            {
                candidateResources.Remove(confuserResource);
                candidateResources.Insert(0, confuserResource);
            }

            foreach (var res in candidateResources)
            {
                // If not FileTable and no entryPointToken, strictly only unpack resources with Confuser naming
                if (!isPackedByFileTable && entryPointToken == 0)
                {
                    if (!IsConfuserResourceName(res.Name.String))
                        continue;
                }

                byte[] data = null;
                if (res.Data != null)
                {
                    res.Data.Position = 0;
                    data = res.Data.ReadBytes((int)res.Data.Length);
                }

                if (data == null || data.Length < 128)
                    continue;

                // Raw PE
                if (ValidateUnpackedPe(data, out _))
                {
                    unpackedBytes = data;
                    compressorKind = "Raw Resource Container";
                    break;
                }

                // Standard Deflate
                byte[] deflated = TryDeflateDecompress(data, MaxDecompressedSize);
                if (deflated != null && ValidateUnpackedPe(deflated, out _))
                {
                    unpackedBytes = deflated;
                    compressorKind = "ConfuserEx Deflate Compressor";
                    break;
                }

                // Deflate with 4-byte length prefix
                if (data.Length > 4)
                {
                    int declaredLength = BitConverter.ToInt32(data, 0);
                    if (declaredLength > 0 && declaredLength <= MaxDecompressedSize)
                    {
                        byte[] dataNoHeader = new byte[data.Length - 4];
                        Buffer.BlockCopy(data, 4, dataNoHeader, 0, dataNoHeader.Length);
                        byte[] deflated2 = TryDeflateDecompress(dataNoHeader, MaxDecompressedSize);
                        if (deflated2 != null && ValidateUnpackedPe(deflated2, out _))
                        {
                            unpackedBytes = deflated2;
                            compressorKind = "ConfuserEx Deflate (Length Prefixed)";
                            break;
                        }
                    }
                }

                // GZip
                byte[] gzipped = TryGzipDecompress(data, MaxDecompressedSize);
                if (gzipped != null && ValidateUnpackedPe(gzipped, out _))
                {
                    unpackedBytes = gzipped;
                    compressorKind = "GZip Compressor";
                    break;
                }
            }

            // Stage 2: Dynamic method-rewrite unpacking fallback if static extraction didn't yield a PE
            if (unpackedBytes == null && isConfuserExStub && module.EntryPoint != null && module.EntryPoint.HasBody)
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
                        if (unpackedBytes != null && ValidateUnpackedPe(unpackedBytes, out _))
                            compressorKind = "Dynamic Method-Rewrite Unpacker";
                        else
                            unpackedBytes = null;
                    }
                    catch (Exception ex)
                    {
                        Logger.LogWarning($"[CompressorUnpacker] Dynamic rewrite unpack fallback failed: {ex.Message}");
                    }
                }
            }

            // Stage 3: Verification and Finalization
            if (unpackedBytes != null && ValidateUnpackedPe(unpackedBytes, out string peValidationErr))
            {
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

                    result.SuccessfullyUnpacked = true;
                    result.UnpackedAssemblyBytes = unpackedBytes;
                    result.CompressorType = compressorKind ?? "ConfuserEx Compressor";
                    result.Message = $"Successfully unpacked {result.CompressorType} ({unpackedBytes.Length} bytes)";
                    Logger.LogInfo($"[CompressorUnpacker] {result.Message}");
                    return result;
                }
                catch (Exception ex)
                {
                    Logger.LogWarning($"[CompressorUnpacker] Post-processing unpacked module error: {ex.Message}");
                }
            }

            // Return "Detected but not unpacked" state safely
            result.SuccessfullyUnpacked = false;
            result.CompressorType = isPackedByFileTable ? "ConfuserEx Compressor (FileTable)" : (entryPointToken != 0 ? "ConfuserEx Compressor (Signature)" : "ConfuserEx Compressor (Resource Payload)");
            result.Message = "ConfuserEx Compressor stub detected, but payload could not be unpacked safely (requires unsupported cipher, LZMA format, or dynamic execution). Target assembly preserved.";
            Logger.LogWarning($"[CompressorUnpacker] {result.Message}");
            return result;
        }

        public static bool IsCosturaFody(ModuleDefMD module, out string detail)
        {
            detail = null;
            if (module == null) return false;

            // 1. Check for Costura types
            foreach (var type in module.Types)
            {
                if (type.FullName.StartsWith("Costura.", StringComparison.OrdinalIgnoreCase) ||
                    type.FullName.IndexOf("Costura", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    detail = $"type '{type.FullName}'";
                    return true;
                }
            }

            // 2. Check for Costura embedded resource conventions
            foreach (var res in module.Resources)
            {
                string rName = res.Name.String;
                if (rName.StartsWith("costura.", StringComparison.OrdinalIgnoreCase) ||
                    rName.StartsWith("costura32.", StringComparison.OrdinalIgnoreCase) ||
                    rName.StartsWith("costura64.", StringComparison.OrdinalIgnoreCase))
                {
                    detail = $"resource '{rName}'";
                    return true;
                }
            }

            return false;
        }

        public static bool IsOtherKnownPacker(ModuleDefMD module, out string packerName)
        {
            packerName = null;
            if (module == null) return false;

            foreach (var type in module.Types)
            {
                if (type.FullName.StartsWith("LibZ.", StringComparison.OrdinalIgnoreCase))
                {
                    packerName = "LibZ";
                    return true;
                }
                if (type.FullName.IndexOf("BoxedApp", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    packerName = "BoxedApp";
                    return true;
                }
            }

            return false;
        }

        private static bool IsBootstrapEntryPointStub(ModuleDefMD module)
        {
            var ep = module.EntryPoint;
            if (ep == null || !ep.HasBody)
                return false;

            // True compressor stubs have at most 2-3 user types (the stub type, <Module>, maybe an inner decoder class)
            int userTypes = module.Types.Count(t => !t.IsGlobalModuleType &&
                                                    !t.FullName.StartsWith("<PrivateImplementationDetails>") &&
                                                    !t.FullName.StartsWith("<>c"));
            if (userTypes > 3)
                return false;

            // Check if EntryPoint body has compressor bootstrap characteristics
            var insts = ep.Body.Instructions;
            if (insts.Count > 60)
                return false;

            bool callsAssemblyLoad = false;
            bool callsResolveSignature = false;
            bool usesGcHandle = false;

            foreach (var inst in insts)
            {
                if (inst.OpCode == OpCodes.Call || inst.OpCode == OpCodes.Callvirt)
                {
                    string target = inst.Operand?.ToString() ?? string.Empty;
                    if (target.Contains("Assembly::Load"))
                        callsAssemblyLoad = true;
                    if (target.Contains("ResolveSignature"))
                        callsResolveSignature = true;
                    if (target.Contains("GCHandle"))
                        usesGcHandle = true;
                }
            }

            return callsAssemblyLoad || callsResolveSignature || usesGcHandle;
        }

        private static bool HasConfuserPayloadResource(ModuleDefMD module, out EmbeddedResource resource)
        {
            resource = null;
            foreach (var r in module.Resources.OfType<EmbeddedResource>())
            {
                if (IsConfuserResourceName(r.Name.String))
                {
                    resource = r;
                    return true;
                }
            }
            return false;
        }

        private static bool IsConfuserResourceName(string name)
        {
            if (string.IsNullOrEmpty(name)) return false;
            return name.Equals("ConfuserEx.CompressedPayload", StringComparison.OrdinalIgnoreCase) ||
                   name.StartsWith("Confuser.", StringComparison.OrdinalIgnoreCase) ||
                   name.StartsWith("koi.", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("koi", StringComparison.OrdinalIgnoreCase);
        }

        private static bool HasAnyEmbeddedPe(ModuleDefMD module)
        {
            foreach (var res in module.Resources.OfType<EmbeddedResource>())
            {
                if (res.Data != null && res.Data.Length >= 64)
                {
                    res.Data.Position = 0;
                    byte[] header = res.Data.ReadBytes(64);
                    if (header.Length >= 2 && header[0] == 0x4D && header[1] == 0x5A)
                        return true;
                }
            }
            return false;
        }

        public static bool ValidateUnpackedPe(byte[] bytes, out string error)
        {
            error = null;
            if (bytes == null || bytes.Length < 512)
            {
                error = "Payload is null or smaller than minimum PE header size.";
                return false;
            }

            if (bytes[0] != 0x4D || bytes[1] != 0x5A) // 'MZ'
            {
                error = "Missing MZ DOS header signature.";
                return false;
            }

            uint e_lfanew = BitConverter.ToUInt32(bytes, 0x3C);
            if (e_lfanew > (uint)(bytes.Length - 0x100))
            {
                error = $"e_lfanew offset (0x{e_lfanew:X}) out of bounds (length: {bytes.Length}).";
                return false;
            }

            uint peSig = BitConverter.ToUInt32(bytes, (int)e_lfanew);
            if (peSig != 0x00004550) // 'PE\0\0'
            {
                error = $"Invalid PE NT signature (expected 0x00004550, got 0x{peSig:X8}).";
                return false;
            }

            // Verify with dnlib that it parses as a valid .NET assembly
            try
            {
                using (var testMod = ModuleDefMD.Load(bytes))
                {
                    if (testMod.Assembly == null && testMod.Types.Count == 0)
                    {
                        error = "PE contains no .NET assembly manifest or types.";
                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                error = $"Failed to parse payload as a valid .NET module: {ex.Message}";
                return false;
            }

            return true;
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

        internal static byte[] TryDynamicMethodRewriteUnpack(ModuleDefMD module)
        {
            var ep = module.EntryPoint;
            if (ep == null || !ep.HasBody)
                return null;

            var corLibByteArr = new SZArraySig(module.CorLibTypes.Byte);
            var originalReturnType = ep.ReturnType;
            var originalMethodSig = ep.MethodSig;
            var originalBody = ConfuserExKillerRunner.Core.MethodBodyCloner.Clone(ep.Body);

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
                            ep.Body.Instructions.Insert(i + 1, Instruction.Create(OpCodes.Castclass, corLibByteArr.ToTypeDefOrRef()));
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
                ep.MethodSig = originalMethodSig;
                ep.Body = ConfuserExKillerRunner.Core.MethodBodyCloner.Clone(originalBody);
            }
        }

        private static byte[] DecompressBounded(Stream decompressStream, int maxSize)
        {
            byte[] buffer = new byte[81920]; // 80 KB chunks
            using (var output = new MemoryStream())
            {
                int read;
                long totalRead = 0;
                while ((read = decompressStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    totalRead += read;
                    if (totalRead > maxSize)
                    {
                        Logger.LogWarning($"[CompressorUnpacker] Decompressed payload exceeded safety limit ({maxSize} bytes, read {totalRead}). Potential decompression bomb detected; aborting decompression.");
                        return null;
                    }
                    output.Write(buffer, 0, read);
                }
                return output.ToArray();
            }
        }

        public static byte[] TryDeflateDecompress(byte[] compressed, int maxSize = DefaultMaxDecompressedSize)
        {
            if (compressed == null || compressed.Length == 0) return null;
            try
            {
                using (var input = new MemoryStream(compressed))
                using (var deflate = new DeflateStream(input, CompressionMode.Decompress))
                {
                    return DecompressBounded(deflate, maxSize);
                }
            }
            catch
            {
                return null;
            }
        }

        public static byte[] TryGzipDecompress(byte[] compressed, int maxSize = DefaultMaxDecompressedSize)
        {
            if (compressed == null || compressed.Length == 0) return null;
            try
            {
                using (var input = new MemoryStream(compressed))
                using (var gzip = new GZipStream(input, CompressionMode.Decompress))
                {
                    return DecompressBounded(gzip, maxSize);
                }
            }
            catch
            {
                return null;
            }
        }
    }
}
