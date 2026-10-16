using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using ConfuserExKillerRunner.Analysis;
using Tool;

namespace ConfuserExKillerRunner.Killers
{
    public sealed class AntiTamperResult
    {
        public bool Modified { get; set; }
        public byte[] DecryptedPeImage { get; set; }
        public List<string> DecryptedSections { get; set; } = new List<string>();
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
                DecryptedPeImage = (byte[])peImage.Clone()
            };

            // Run module constructor to let runtime AntiTamper unpack sections in memory
            try
            {
                RuntimeHelpers.RunModuleConstructor(module.ModuleHandle);
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"[AntiTamper] Runtime module constructor execution warning: {ex.Message}");
            }

            void* hModule = (void*)Marshal.GetHINSTANCE(module);
            if (hModule == null)
            {
                result.Message = "Failed to obtain HINSTANCE for target module";
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
                    result.Message = "Invalid in-memory PE header signature";
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
                        result.Modified = true;
                        Logger.LogInfo($"[AntiTamper] Decrypted section '{displayName}' (RVA=0x{virtualAddress:X}, Raw=0x{pointerToRawData:X}, Size={sizeOfRawData} bytes)");
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"[AntiTamper] Section diffing failed: {ex.Message}");
                result.Message = ex.Message;
                return result;
            }

            result.Message = result.Modified
                ? $"Successfully decrypted {result.DecryptedSections.Count} sections: {string.Join(", ", result.DecryptedSections)}"
                : "No section differences detected";

            return result;
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
