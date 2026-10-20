using System;
using System.Collections.Generic;
using System.IO;

namespace ConfuserExKillerRunner.Analysis
{
    public struct SectionHeader
    {
        public string Name;
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint Characteristics;
    }

    public sealed class PEInfoModel
    {
        public bool IsValid { get; set; }
        public bool IsPe32Plus { get; set; }
        public ushort Machine { get; set; }
        public uint PEHeaderOffset { get; set; }
        public uint OptionalHeaderOffset { get; set; }
        public ushort OptionalHeaderSize { get; set; }
        public ushort NumberOfSections { get; set; }
        public List<SectionHeader> Sections { get; set; } = new List<SectionHeader>();
        public uint Cor20Rva { get; set; }
        public uint Cor20Size { get; set; }
        public uint Cor20FileOffset { get; set; }
    }

    public static class PEUtils
    {
        public static PEInfoModel ParsePE(byte[] peBytes)
        {
            if (peBytes == null) throw new ArgumentNullException(nameof(peBytes));
            var model = new PEInfoModel { IsValid = false };

            if (peBytes.Length < 0x40)
                return model;

            // Check DOS signature MZ (0x5A4D)
            if (peBytes[0] != 0x4D || peBytes[1] != 0x5A)
                return model;

            uint e_lfanew = BitConverter.ToUInt32(peBytes, 0x3C);
            // Bounds check e_lfanew: must be at or after DOS header (0x40) and prevent uint arithmetic overflow
            if (e_lfanew < 0x40 || (ulong)e_lfanew + 256 > (ulong)peBytes.Length)
                return model;

            model.PEHeaderOffset = e_lfanew;

            // Check PE signature 'PE\0\0' (0x00004550)
            if (BitConverter.ToUInt32(peBytes, (int)e_lfanew) != 0x00004550)
                return model;

            int fileHeaderOffset = (int)e_lfanew + 4;
            if ((ulong)fileHeaderOffset + 20 > (ulong)peBytes.Length)
                return model;

            model.Machine = BitConverter.ToUInt16(peBytes, fileHeaderOffset);
            model.NumberOfSections = BitConverter.ToUInt16(peBytes, fileHeaderOffset + 2);
            model.OptionalHeaderSize = BitConverter.ToUInt16(peBytes, fileHeaderOffset + 16);

            int optHeaderOffset = fileHeaderOffset + 20;
            model.OptionalHeaderOffset = (uint)optHeaderOffset;

            if ((ulong)optHeaderOffset + (ulong)model.OptionalHeaderSize > (ulong)peBytes.Length)
                return model;

            if (model.OptionalHeaderSize < 96)
                return model;

            ushort magic = BitConverter.ToUInt16(peBytes, optHeaderOffset);
            model.IsPe32Plus = (magic == 0x020B);

            // Read NumberOfRvaAndSizes to ensure directory index 14 (CLR runtime header) is physically present
            int numRvaOffset = optHeaderOffset + (model.IsPe32Plus ? 108 : 92);
            uint numberOfRvaAndSizes = 0;
            if ((ulong)numRvaOffset + 4 <= (ulong)peBytes.Length &&
                (ulong)optHeaderOffset + (ulong)model.OptionalHeaderSize >= (ulong)(model.IsPe32Plus ? 108 : 92) + 4)
            {
                numberOfRvaAndSizes = BitConverter.ToUInt32(peBytes, numRvaOffset);
            }

            int cor20RelOffset = model.IsPe32Plus ? 224 : 208;
            if (numberOfRvaAndSizes > 14 &&
                model.OptionalHeaderSize >= cor20RelOffset + 8 &&
                (ulong)optHeaderOffset + (ulong)cor20RelOffset + 8 <= (ulong)peBytes.Length)
            {
                int cor20DirOffset = optHeaderOffset + cor20RelOffset;
                model.Cor20Rva = BitConverter.ToUInt32(peBytes, cor20DirOffset);
                model.Cor20Size = BitConverter.ToUInt32(peBytes, cor20DirOffset + 4);
            }

            int sectionHeadersOffset = optHeaderOffset + model.OptionalHeaderSize;
            if ((ulong)sectionHeadersOffset + (ulong)model.NumberOfSections * 40 > (ulong)peBytes.Length)
                return model;

            for (int i = 0; i < model.NumberOfSections; i++)
            {
                int secOffset = sectionHeadersOffset + i * 40;
                string secName = System.Text.Encoding.ASCII.GetString(peBytes, secOffset, 8).TrimEnd('\0');
                uint virtSize = BitConverter.ToUInt32(peBytes, secOffset + 8);
                uint virtAddr = BitConverter.ToUInt32(peBytes, secOffset + 12);
                uint rawSize = BitConverter.ToUInt32(peBytes, secOffset + 16);
                uint rawPtr = BitConverter.ToUInt32(peBytes, secOffset + 20);
                uint chars = BitConverter.ToUInt32(peBytes, secOffset + 36);

                model.Sections.Add(new SectionHeader
                {
                    Name = secName,
                    VirtualSize = virtSize,
                    VirtualAddress = virtAddr,
                    SizeOfRawData = rawSize,
                    PointerToRawData = rawPtr,
                    Characteristics = chars
                });

                // Cor20FileOffset can only map if Cor20Rva is within the raw on-disk bytes of the section
                if (model.Cor20Rva != 0 && model.Cor20Rva >= virtAddr)
                {
                    ulong rel = (ulong)model.Cor20Rva - (ulong)virtAddr;
                    if (rel < (ulong)rawSize && (ulong)rawPtr + rel + 72 <= (ulong)peBytes.Length)
                    {
                        model.Cor20FileOffset = (uint)((ulong)rawPtr + rel);
                    }
                }
            }

            model.IsValid = true;
            return model;
        }

        public static uint RvaToFileOffset(PEInfoModel model, uint rva)
        {
            if (model == null || model.Sections == null) return 0;
            foreach (var sec in model.Sections)
            {
                ulong span = Math.Max((ulong)sec.VirtualSize, (ulong)sec.SizeOfRawData);
                if (rva >= sec.VirtualAddress && (ulong)rva < (ulong)sec.VirtualAddress + span)
                {
                    ulong rel = (ulong)rva - (ulong)sec.VirtualAddress;
                    if (rel < (ulong)sec.SizeOfRawData)
                    {
                        ulong fileOffset = (ulong)sec.PointerToRawData + rel;
                        if (fileOffset <= uint.MaxValue)
                            return (uint)fileOffset;
                    }
                }
            }
            return 0;
        }

        public static uint FileOffsetToRva(PEInfoModel model, uint fileOffset)
        {
            if (model == null || model.Sections == null) return 0;
            foreach (var sec in model.Sections)
            {
                if (fileOffset >= sec.PointerToRawData && (ulong)fileOffset < (ulong)sec.PointerToRawData + (ulong)sec.SizeOfRawData)
                {
                    ulong rel = (ulong)fileOffset - (ulong)sec.PointerToRawData;
                    ulong rva = (ulong)sec.VirtualAddress + rel;
                    if (rva <= uint.MaxValue)
                        return (uint)rva;
                }
            }
            return 0;
        }

        public static bool IsValidMetadataHeader(byte[] peBytes, uint offset)
        {
            if (peBytes == null || (ulong)offset + 16 > (ulong)peBytes.Length)
                return false;

            // Signature must be BSJB (0x424A5342)
            if (BitConverter.ToUInt32(peBytes, (int)offset) != 0x424A5342)
                return false;

            uint versionStringLength = BitConverter.ToUInt32(peBytes, (int)offset + 12);
            if (versionStringLength > 256 || (ulong)offset + 16 + (ulong)versionStringLength > (ulong)peBytes.Length)
                return false;

            return true;
        }
    }
}
