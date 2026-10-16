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

            // Check DOS signature MZ
            if (peBytes[0] != 0x4D || peBytes[1] != 0x5A)
                return model;

            uint e_lfanew = BitConverter.ToUInt32(peBytes, 0x3C);
            if (e_lfanew + 256 > peBytes.Length)
                return model;

            model.PEHeaderOffset = e_lfanew;

            // Check PE signature
            if (BitConverter.ToUInt32(peBytes, (int)e_lfanew) != 0x00004550)
                return model;

            int fileHeaderOffset = (int)e_lfanew + 4;
            model.Machine = BitConverter.ToUInt16(peBytes, fileHeaderOffset);
            model.NumberOfSections = BitConverter.ToUInt16(peBytes, fileHeaderOffset + 2);
            model.OptionalHeaderSize = BitConverter.ToUInt16(peBytes, fileHeaderOffset + 16);

            int optHeaderOffset = fileHeaderOffset + 20;
            model.OptionalHeaderOffset = (uint)optHeaderOffset;

            if (optHeaderOffset + model.OptionalHeaderSize > peBytes.Length)
                return model;

            ushort magic = BitConverter.ToUInt16(peBytes, optHeaderOffset);
            model.IsPe32Plus = (magic == 0x020B);

            int cor20DirOffset = optHeaderOffset + (model.IsPe32Plus ? 224 : 208);
            if (optHeaderOffset + model.OptionalHeaderSize >= (model.IsPe32Plus ? 224 : 208) + 8)
            {
                model.Cor20Rva = BitConverter.ToUInt32(peBytes, cor20DirOffset);
                model.Cor20Size = BitConverter.ToUInt32(peBytes, cor20DirOffset + 4);
            }

            int sectionHeadersOffset = optHeaderOffset + model.OptionalHeaderSize;
            if (sectionHeadersOffset + model.NumberOfSections * 40 > peBytes.Length)
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

                if (model.Cor20Rva >= virtAddr && model.Cor20Rva < virtAddr + rawSize)
                {
                    model.Cor20FileOffset = rawPtr + (model.Cor20Rva - virtAddr);
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
                if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + Math.Max(sec.VirtualSize, sec.SizeOfRawData))
                {
                    return sec.PointerToRawData + (rva - sec.VirtualAddress);
                }
            }
            return 0;
        }

        public static uint FileOffsetToRva(PEInfoModel model, uint fileOffset)
        {
            if (model == null || model.Sections == null) return 0;
            foreach (var sec in model.Sections)
            {
                if (fileOffset >= sec.PointerToRawData && fileOffset < sec.PointerToRawData + sec.SizeOfRawData)
                {
                    return sec.VirtualAddress + (fileOffset - sec.PointerToRawData);
                }
            }
            return 0;
        }

        public static bool IsValidMetadataHeader(byte[] peBytes, uint offset)
        {
            if (peBytes == null || offset + 16 > peBytes.Length)
                return false;

            // Signature must be BSJB (0x424A5342)
            if (BitConverter.ToUInt32(peBytes, (int)offset) != 0x424A5342)
                return false;

            uint versionStringLength = BitConverter.ToUInt32(peBytes, (int)offset + 12);
            if (versionStringLength > 256 || offset + 16 + versionStringLength > peBytes.Length)
                return false;

            return true;
        }
    }
}
