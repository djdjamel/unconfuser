using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using ConfuserExKillerRunner.Analysis;
using Tool;

namespace ConfuserExKillerRunner.Killers
{
    public enum AntiTamperStatus
    {
        NotAttempted,
        NoChangesDetected,
        ChangesDetected,
        DecryptionConfirmed,
        Failed
    }

    public sealed class DecryptedSectionInfo
    {
        public string Name { get; set; }
        public uint VirtualAddress { get; set; }
        public uint VirtualSize { get; set; }
        public uint SizeOfRawData { get; set; }
        public uint PointerToRawData { get; set; }
    }

    public sealed class AntiTamperResult
    {
        public bool Modified { get; set; }
        public AntiTamperStatus Status { get; set; } = AntiTamperStatus.NotAttempted;
        public byte[] DecryptedPeImage { get; set; }
        public List<string> DecryptedSections { get; set; } = new List<string>();
        public List<DecryptedSectionInfo> DecryptedSectionInfos { get; set; } = new List<DecryptedSectionInfo>();
        public bool JitModeDetected { get; set; }
        public string Message { get; set; }
    }

    public static unsafe class AntiTamperKiller
    {
        public static AntiTamperResult Execute(Module module, byte[] peImage)
        {
            if (module == null) throw new ArgumentNullException(nameof(module));
            if (peImage == null) throw new ArgumentNullException(nameof(peImage));

            var result = new AntiTamperResult
            {
                Modified = false,
                Status = AntiTamperStatus.NotAttempted,
                DecryptedPeImage = (byte[])peImage.Clone()
            };

            // Run module constructor to let runtime AntiTamper unpack sections in memory
            bool cctorSucceeded = false;
            string cctorError = null;
            try
            {
                RuntimeHelpers.RunModuleConstructor(module.ModuleHandle);
                cctorSucceeded = true;
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"[AntiTamper] Runtime module constructor execution warning: {ex.Message}");
                cctorSucceeded = false;
                cctorError = ex.Message;
            }

            void* hModule = (void*)Marshal.GetHINSTANCE(module);
            if (hModule == null)
            {
                result.Status = AntiTamperStatus.Failed;
                result.Message = "Failed to obtain HINSTANCE for target module";
                result.DecryptedPeImage = (byte[])peImage.Clone();
                return result;
            }

            byte* baseAddr = (byte*)hModule;

            // Safe parsing of in-memory PE headers
            try
            {
                uint e_lfanew = *(uint*)(baseAddr + 0x3C);
                byte* ntHeader = baseAddr + e_lfanew;

                // Validate PE signature
                if (*(uint*)ntHeader != 0x00004550)
                {
                    result.Status = AntiTamperStatus.Failed;
                    result.Message = "Invalid in-memory PE header signature";
                    result.DecryptedPeImage = (byte[])peImage.Clone();
                    return result;
                }

                ushort numSections = *(ushort*)(ntHeader + 4 + 2);
                ushort optHeaderSize = *(ushort*)(ntHeader + 4 + 16);
                byte* sectionHeaderBase = ntHeader + 4 + 20 + optHeaderSize;

                var peModel = PEUtils.ParsePE(peImage);

                for (int i = 0; i < numSections; i++)
                {
                    byte* secPtr = sectionHeaderBase + (i * 40);

                    // Extract 8-byte section name from memory
                    byte[] nameBytes = new byte[8];
                    Marshal.Copy((IntPtr)secPtr, nameBytes, 0, 8);
                    string secName = Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');

                    // If in-memory section name was zeroed out by Anti-Dump, recover name from on-disk PE headers
                    string diskSecName = (peModel.IsValid && i < peModel.Sections.Count) ? peModel.Sections[i].Name : string.Empty;
                    string effectiveName = !string.IsNullOrEmpty(secName) ? secName : diskSecName;

                    uint virtualSize = *(uint*)(secPtr + 8);
                    uint virtualAddress = *(uint*)(secPtr + 12);
                    uint sizeOfRawData = *(uint*)(secPtr + 16);
                    uint pointerToRawData = *(uint*)(secPtr + 20);

                    // ConfuserEx anti-tamper operates on custom sections; standard sections (.text, .rsrc, .reloc)
                    // contain memory-mapped IATs and virtual layouts that must not overwrite raw file tables.
                    if (effectiveName.Equals(".text", StringComparison.OrdinalIgnoreCase) ||
                        effectiveName.Equals(".rsrc", StringComparison.OrdinalIgnoreCase) ||
                        effectiveName.Equals(".reloc", StringComparison.OrdinalIgnoreCase) ||
                        diskSecName.Equals(".text", StringComparison.OrdinalIgnoreCase) ||
                        diskSecName.Equals(".rsrc", StringComparison.OrdinalIgnoreCase) ||
                        diskSecName.Equals(".reloc", StringComparison.OrdinalIgnoreCase))
                        continue;

                    // Also ensure section does not encompass the COR20 directory (CLR header)
                    if (peModel.IsValid && peModel.Cor20Rva != 0 &&
                        virtualAddress <= peModel.Cor20Rva && peModel.Cor20Rva < virtualAddress + sizeOfRawData)
                        continue;

                    if (pointerToRawData == 0 || sizeOfRawData == 0 || pointerToRawData + sizeOfRawData > result.DecryptedPeImage.Length)
                        continue;

                    byte* inMemorySection = baseAddr + virtualAddress;

                    // Compare memory bytes with original raw bytes
                    bool sectionDiffers = false;
                    for (int b = 0; b < sizeOfRawData; b++)
                    {
                        if (result.DecryptedPeImage[pointerToRawData + b] != inMemorySection[b])
                        {
                            sectionDiffers = true;
                            break;
                        }
                    }

                    if (sectionDiffers)
                    {
                        Marshal.Copy((IntPtr)inMemorySection, result.DecryptedPeImage, (int)pointerToRawData, (int)sizeOfRawData);
                        string displayName = !string.IsNullOrEmpty(effectiveName) ? effectiveName : $"Section_{i}";
                        result.DecryptedSections.Add(displayName);
                        result.DecryptedSectionInfos.Add(new DecryptedSectionInfo
                        {
                            Name = displayName,
                            VirtualAddress = virtualAddress,
                            VirtualSize = virtualSize,
                            SizeOfRawData = sizeOfRawData,
                            PointerToRawData = pointerToRawData
                        });
                        result.Modified = true;
                        Logger.LogInfo($"[AntiTamper] Decrypted section '{displayName}' (RVA=0x{virtualAddress:X}, Raw=0x{pointerToRawData:X}, Size={sizeOfRawData} bytes)");
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"[AntiTamper] Section diffing failed: {ex.Message}");
                result.Status = AntiTamperStatus.Failed;
                result.Message = $"Anti-tamper dynamic execution failed: {ex.Message}";
                result.DecryptedPeImage = (byte[])peImage.Clone();
                return result;
            }

            // If module constructor threw an exception, dynamic execution failed.
            // Even if differences were detected in memory, return Failed and restore original image.
            if (!cctorSucceeded)
            {
                result.Status = AntiTamperStatus.Failed;
                result.Modified = false;
                result.DecryptedPeImage = (byte[])peImage.Clone();
                result.Message = "Anti-tamper dynamic execution failed: module constructor threw an exception" + (cctorError != null ? $": {cctorError}" : "");
                return result;
            }

            int restoredMethodsCount = 0;
            if (result.Modified)
            {
                result.Status = AntiTamperStatus.ChangesDetected;
                var verify = VerifyDecryptedImage(result.DecryptedPeImage, result.DecryptedSectionInfos);
                result.Status = verify.status;
                restoredMethodsCount = verify.restoredMethodCount;

                if (result.Status != AntiTamperStatus.DecryptionConfirmed)
                {
                    // Validation failed or unconfirmed: restore original PE image so partial or broken bytes are not propagated.
                    result.DecryptedPeImage = (byte[])peImage.Clone();
                }
            }
            else
            {
                result.Status = AntiTamperStatus.NoChangesDetected;
            }

            switch (result.Status)
            {
                case AntiTamperStatus.DecryptionConfirmed:
                    result.Message = $"Successfully decrypted and verified {result.DecryptedSections.Count} section(s) ({string.Join(", ", result.DecryptedSections)}) containing {restoredMethodsCount} restored method(s)";
                    break;
                case AntiTamperStatus.ChangesDetected:
                    result.Message = $"Memory differences detected in {result.DecryptedSections.Count} section(s) ({string.Join(", ", result.DecryptedSections)}), but method decryption could not be confirmed";
                    break;
                case AntiTamperStatus.NoChangesDetected:
                    result.Message = "Dynamic execution completed; no section differences detected";
                    break;
                case AntiTamperStatus.Failed:
                    result.Message = string.IsNullOrEmpty(result.Message) ? "Anti-tamper dynamic execution failed" : result.Message;
                    break;
                case AntiTamperStatus.NotAttempted:
                default:
                    result.Message = "Anti-tamper dynamic execution was not attempted";
                    break;
            }

            return result;
        }

        /// <summary>
        /// Validates the decrypted PE image by checking that methods located within the restored section boundaries
        /// can be successfully decoded by dnlib and pass structural IL, branch boundary, exception handler,
        /// and evaluation stack verification.
        ///
        /// Note on verification boundaries:
        /// This in-memory pass validates IL instruction integrity, branch &amp; switch bounds, exception handler boundaries,
        /// and evaluation stack balance (including CFG max stack calculation via dnlib). Complete CLI ECMA-335 verification
        /// (e.g. type-safety of method argument signatures, ref/by-ref constraints, and member accessibility rules typically
        /// verified by ILVerify or PEVerify) is not performed at this stage because the module is verified in-memory prior to
        /// writing to disk and external assembly resolution.
        /// </summary>
        public static (AntiTamperStatus status, int restoredMethodCount) VerifyDecryptedImage(byte[] peImage, IReadOnlyList<DecryptedSectionInfo> restoredSections)
        {
            if (peImage == null || restoredSections == null || restoredSections.Count == 0)
                return (AntiTamperStatus.ChangesDetected, 0);

            try
            {
                using (var verifyMod = dnlib.DotNet.ModuleDefMD.Load(peImage))
                {
                    var allMethods = verifyMod.GetTypes().SelectMany(t => t.Methods).ToList();

                    // Identify methods whose RVA falls specifically inside any restored section's virtual span
                    var methodsInRestoredSections = allMethods.Where(m =>
                    {
                        if (m.RVA == 0) return false;
                        uint rva = (uint)m.RVA;
                        return restoredSections.Any(s =>
                        {
                            uint span = Math.Max(s.VirtualSize, s.SizeOfRawData);
                            return rva >= s.VirtualAddress && rva < s.VirtualAddress + span;
                        });
                    }).ToList();

                    if (methodsInRestoredSections.Count == 0)
                    {
                        Logger.LogWarning($"[AntiTamper] Section changes detected, but no methods were mapped within the restored section boundaries. Keeping ChangesDetected.");
                        return (AntiTamperStatus.ChangesDetected, 0);
                    }

                    bool allRestoredMethodsValid = true;
                    foreach (var m in methodsInRestoredSections)
                    {
                        if (!m.HasBody || m.Body == null || m.Body.Instructions == null || m.Body.Instructions.Count == 0)
                        {
                            allRestoredMethodsValid = false;
                            Logger.LogWarning($"[AntiTamper] Restored method {m.FullName} has empty or null body.");
                            break;
                        }

                        try
                        {
                            var auditReport = new AuditReport { CanLoad = true };
                            QualityAuditor.AuditMethod(m, auditReport);
                            if (!auditReport.StructuralAuditPassed)
                            {
                                allRestoredMethodsValid = false;
                                Logger.LogWarning($"[AntiTamper] Restored method {m.FullName} failed IL validation: {string.Join("; ", auditReport.Errors)}");
                                break;
                            }
                        }
                        catch (Exception ex)
                        {
                            allRestoredMethodsValid = false;
                            Logger.LogWarning($"[AntiTamper] Restored method {m.FullName} threw during IL audit: {ex.Message}");
                            break;
                        }
                    }

                    if (allRestoredMethodsValid)
                    {
                        return (AntiTamperStatus.DecryptionConfirmed, methodsInRestoredSections.Count);
                    }
                    else
                    {
                        Logger.LogWarning($"[AntiTamper] Sections were restored, but some methods inside them have invalid IL bodies, stack mismatches, or invalid branch/EH targets.");
                        return (AntiTamperStatus.ChangesDetected, 0);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"[AntiTamper] Decrypted image validation warning: {ex.Message}");
                return (AntiTamperStatus.ChangesDetected, 0);
            }
        }

        public static bool DetectJitMode(dnlib.DotNet.ModuleDef module)
        {
            if (module == null) return false;

            // Check module references for native JIT hooks or AntiTamper.JIT
            foreach (var modRef in module.GetModuleRefs())
            {
                if (modRef.Name.String.IndexOf("AntiTamper", StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }

            // Check P/Invoke methods in <Module> for native VirtualProtect / JIT compileMethod
            if (module.GlobalType != null)
            {
                foreach (var method in module.GlobalType.Methods)
                {
                    if (method.IsPinvokeImpl && method.ImplMap != null)
                    {
                        string name = method.ImplMap.Name.String;
                        if (string.Equals(name, "VirtualProtect", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "SetUnhandledExceptionFilter", StringComparison.OrdinalIgnoreCase))
                        {
                            // Further inspect if compileMethod is referenced
                            return true;
                        }
                    }
                }
            }

            return false;
        }
    }
}
