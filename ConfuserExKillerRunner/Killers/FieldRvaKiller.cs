using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;
using ConfuserExKillerRunner.Analysis;
using dnlib.DotNet;
using Tool;

namespace ConfuserExKillerRunner.Killers
{
    public sealed class FieldRvaKillerResult
    {
        public int RestoredFieldsCount { get; set; }
        public List<string> RestoredFields { get; set; } = new List<string>();
        public string Message { get; set; }
    }

    public static unsafe class FieldRvaKiller
    {
        public static FieldRvaKillerResult Execute(ModuleDefMD module, Module reflModule, byte[] peImage)
        {
            if (module == null) throw new ArgumentNullException(nameof(module));
            if (peImage == null) throw new ArgumentNullException(nameof(peImage));

            var result = new FieldRvaKillerResult();

            if (reflModule == null)
            {
                result.Message = "Dynamic execution disabled; skipping runtime FieldRVA restoration.";
                Logger.LogInfo($"[FieldRvaKiller] {result.Message}");
                return result;
            }

            void* hModule = (void*)Marshal.GetHINSTANCE(reflModule);
            if (hModule == null)
            {
                result.Message = "Failed to obtain HINSTANCE for target reflection module.";
                Logger.LogWarning($"[FieldRvaKiller] {result.Message}");
                return result;
            }

            byte* baseAddr = (byte*)hModule;
            var peModel = PEUtils.ParsePE(peImage);
            if (!peModel.IsValid)
            {
                result.Message = "PE headers could not be parsed for FieldRVA resolution.";
                Logger.LogWarning($"[FieldRvaKiller] {result.Message}");
                return result;
            }

            foreach (var type in module.GetTypes())
            {
                foreach (var field in type.Fields)
                {
                    if (!field.HasFieldRVA || field.RVA == 0)
                        continue;

                    uint size = GetFieldSize(field);
                    if (size == 0)
                        continue;

                    uint rva = (uint)field.RVA;
                    uint fileOffset = PEUtils.RvaToFileOffset(peModel, rva);
                    if (fileOffset == 0 || fileOffset + size > peImage.Length)
                        continue;

                    // Verify RVA falls within a recognized section boundary
                    bool validSection = false;
                    foreach (var sec in peModel.Sections)
                    {
                        if (rva >= sec.VirtualAddress && rva + size <= sec.VirtualAddress + Math.Max(sec.VirtualSize, sec.SizeOfRawData))
                        {
                            validSection = true;
                            break;
                        }
                    }

                    if (!validSection)
                        continue;

                    try
                    {
                        byte* memPtr = baseAddr + rva;
                        byte[] memBytes = new byte[size];
                        Marshal.Copy((IntPtr)memPtr, memBytes, 0, (int)size);

                        bool differs = false;
                        bool allZero = true;
                        for (int i = 0; i < size; i++)
                        {
                            if (memBytes[i] != 0)
                                allZero = false;
                            if (peImage[fileOffset + i] != memBytes[i])
                                differs = true;
                        }

                        if (differs && !allZero)
                        {
                            Buffer.BlockCopy(memBytes, 0, peImage, (int)fileOffset, (int)size);
                            field.InitialValue = memBytes;
                            result.RestoredFieldsCount++;
                            result.RestoredFields.Add($"{field.DeclaringType.Name}::{field.Name} (RVA=0x{rva:X8}, Size={size}b)");
                            Logger.LogInfo($"[FieldRvaKiller] Restored static field initializer: {field.FullName} (RVA: 0x{rva:X8}, Size: {size} bytes)");
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.LogWarning($"[FieldRvaKiller] Memory read error for field {field.FullName} at RVA 0x{rva:X8}: {ex.Message}");
                    }
                }
            }

            result.Message = result.RestoredFieldsCount > 0
                ? $"Successfully restored {result.RestoredFieldsCount} static field initializers from memory."
                : "No FieldRVA buffer mismatches detected.";

            return result;
        }

        private static uint GetFieldSize(FieldDef field)
        {
            if (field.InitialValue != null && field.InitialValue.Length > 0)
                return (uint)field.InitialValue.Length;

            var sig = field.FieldSig?.Type;
            if (sig == null)
                return 0;

            switch (sig.ElementType)
            {
                case ElementType.Boolean:
                case ElementType.I1:
                case ElementType.U1:
                    return 1;
                case ElementType.Char:
                case ElementType.I2:
                case ElementType.U2:
                    return 2;
                case ElementType.I4:
                case ElementType.U4:
                case ElementType.R4:
                    return 4;
                case ElementType.I8:
                case ElementType.U8:
                case ElementType.R8:
                    return 8;
                case ElementType.ValueType:
                    var td = sig.ToTypeDefOrRef()?.ResolveTypeDef();
                    if (td != null && td.ClassLayout != null && td.ClassLayout.ClassSize > 0)
                        return td.ClassLayout.ClassSize;
                    break;
            }

            return 0;
        }
    }
}
