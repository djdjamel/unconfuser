using System;
using System.IO;

namespace ConfuserExKillerRunner.Core
{
    public enum TargetArchitecture
    {
        Unknown,
        AnyCPU,
        X86Required,
        X86Preferred,
        X64
    }

    public sealed class ArchitectureInfo
    {
        public TargetArchitecture Architecture { get; set; }
        public ushort Machine { get; set; }
        public bool IsPe32Plus { get; set; }
        public bool HasClrHeader { get; set; }
        public uint ClrFlags { get; set; }
        public bool IsIlOnly => (ClrFlags & 0x00000001) != 0;
        public bool Is32BitRequired => (ClrFlags & 0x00000002) != 0;
        public bool Is32BitPreferred => (ClrFlags & 0x00020000) != 0;

        public bool IsCompatibleWithCurrentProcess()
        {
            bool is64BitProcess = Environment.Is64BitProcess;
            if (Architecture == TargetArchitecture.X64)
                return is64BitProcess;
            if (Architecture == TargetArchitecture.X86Required)
                return !is64BitProcess;
            // AnyCPU or X86Preferred can run in either bitness
            return true;
        }

        public override string ToString()
        {
            return $"{Architecture} (Machine=0x{Machine:X4}, PE32+={IsPe32Plus}, 32BitReq={Is32BitRequired}, 32BitPref={Is32BitPreferred})";
        }
    }

    public static class ArchitectureDetector
    {
        public static ArchitectureInfo Detect(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                throw new FileNotFoundException("File not found", filePath);

            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (var reader = new BinaryReader(fs))
            {
                return Detect(reader);
            }
        }

        public static ArchitectureInfo Detect(byte[] peBytes)
        {
            if (peBytes == null) throw new ArgumentNullException(nameof(peBytes));
            using (var ms = new MemoryStream(peBytes, false))
            using (var reader = new BinaryReader(ms))
            {
                return Detect(reader);
            }
        }

        public static ArchitectureInfo Detect(BinaryReader reader)
        {
            var info = new ArchitectureInfo
            {
                Architecture = TargetArchitecture.Unknown
            };

            if (reader.BaseStream.Length < 64)
                return info;

            reader.BaseStream.Seek(0, SeekOrigin.Begin);
            ushort mz = reader.ReadUInt16();
            if (mz != 0x5A4D) // 'MZ'
                return info;

            reader.BaseStream.Seek(0x3C, SeekOrigin.Begin);
            uint e_lfanew = reader.ReadUInt32();
            if (e_lfanew + 256 > reader.BaseStream.Length)
                return info;

            reader.BaseStream.Seek(e_lfanew, SeekOrigin.Begin);
            uint peSig = reader.ReadUInt32();
            if (peSig != 0x00004550) // 'PE\0\0'
                return info;

            info.Machine = reader.ReadUInt16();
            ushort numSections = reader.ReadUInt16();
            reader.BaseStream.Seek(12, SeekOrigin.Current); // Skip TimeDateStamp + PointerToSymbolTable + NumberOfSymbols
            ushort optHeaderSize = reader.ReadUInt16();
            ushort characteristics = reader.ReadUInt16();

            long optHeaderPos = reader.BaseStream.Position;
            ushort magic = reader.ReadUInt16();
            info.IsPe32Plus = (magic == 0x020B);

            // COM+ Runtime descriptor is at offset 208 for PE32, 224 for PE32+
            int cor20DirOffset = info.IsPe32Plus ? 224 : 208;
            uint cor20Rva = 0;
            uint cor20Size = 0;

            if (optHeaderSize >= cor20DirOffset + 8)
            {
                reader.BaseStream.Seek(optHeaderPos + cor20DirOffset, SeekOrigin.Begin);
                cor20Rva = reader.ReadUInt32();
                cor20Size = reader.ReadUInt32();
            }

            info.HasClrHeader = (cor20Rva != 0 && cor20Size >= 72);

            // Read section headers to map cor20Rva to raw offset
            long sectionHeadersPos = optHeaderPos + optHeaderSize;
            uint cor20RawOffset = 0;

            if (info.HasClrHeader && sectionHeadersPos + numSections * 40 <= reader.BaseStream.Length)
            {
                for (int i = 0; i < numSections; i++)
                {
                    reader.BaseStream.Seek(sectionHeadersPos + i * 40, SeekOrigin.Begin);
                    reader.BaseStream.Seek(12, SeekOrigin.Current); // Skip Name(8) + VirtualSize(4)
                    uint virtualAddress = reader.ReadUInt32();
                    uint sizeOfRawData = reader.ReadUInt32();
                    uint pointerToRawData = reader.ReadUInt32();

                    if (cor20Rva >= virtualAddress && cor20Rva < virtualAddress + sizeOfRawData)
                    {
                        cor20RawOffset = pointerToRawData + (cor20Rva - virtualAddress);
                        break;
                    }
                }
            }

            if (cor20RawOffset != 0 && cor20RawOffset + 72 <= reader.BaseStream.Length)
            {
                // Read IMAGE_COR20_HEADER Flags at offset 16
                reader.BaseStream.Seek(cor20RawOffset + 16, SeekOrigin.Begin);
                info.ClrFlags = reader.ReadUInt32();
            }

            // Determine TargetArchitecture
            if (info.Machine == 0x8664) // AMD64
            {
                info.Architecture = TargetArchitecture.X64;
            }
            else if (info.Machine == 0x014C) // i386
            {
                if (info.Is32BitRequired)
                    info.Architecture = TargetArchitecture.X86Required;
                else if (info.Is32BitPreferred)
                    info.Architecture = TargetArchitecture.X86Preferred;
                else
                    info.Architecture = TargetArchitecture.AnyCPU;
            }
            else
            {
                info.Architecture = TargetArchitecture.Unknown;
            }

            return info;
        }
    }
}
