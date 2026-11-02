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
        X64,
        Arm64
    }

    public enum TargetRuntimeFamily
    {
        Unknown = 0,
        NetFramework = 1,
        ModernDotNet = 2
    }

    public sealed class ArchitectureInfo
    {
        public TargetArchitecture Architecture { get; set; }
        public ushort Machine { get; set; }
        public bool IsPe32Plus { get; set; }
        public string PeFormat => IsPe32Plus ? "PE32+" : "PE32";
        public bool HasClrHeader { get; set; }
        public uint ClrFlags { get; set; }
        public bool IsIlOnly => (ClrFlags & 0x00000001) != 0;
        public bool Is32BitRequired => (ClrFlags & 0x00000002) != 0;
        public bool Is32BitPreferred => (ClrFlags & 0x00020000) != 0;
        public bool HasArchitectureConflict { get; set; }

        public bool IsCompatibleWithCurrentProcess()
        {
            if (Architecture == TargetArchitecture.Unknown || HasArchitectureConflict)
                return false;
            bool is64BitProcess = Environment.Is64BitProcess;
            if (Architecture == TargetArchitecture.X64)
                return is64BitProcess && System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture == System.Runtime.InteropServices.Architecture.X64;
            if (Architecture == TargetArchitecture.X86Required)
                return !is64BitProcess && System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture == System.Runtime.InteropServices.Architecture.X86;
            if (Architecture == TargetArchitecture.Arm64)
                return System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture == System.Runtime.InteropServices.Architecture.Arm64;
            // AnyCPU or X86Preferred can run in either bitness
            return true;
        }

        public override string ToString()
        {
            return $"{Architecture} (Machine=0x{Machine:X4}, PE32+={IsPe32Plus}, 32BitReq={Is32BitRequired}, 32BitPref={Is32BitPreferred}, Conflict={HasArchitectureConflict})";
        }
    }

    public static class ArchitectureDetector
    {
        public static ArchitectureInfo Detect(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                throw new FileNotFoundException("File not found", filePath);

            ArchitectureInfo info;
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (var reader = new BinaryReader(fs))
            {
                info = Detect(reader);
            }

            // If filePath is a native apphost (.exe without CLR header) accompanied by a managed sibling .dll,
            // inspect the sibling .dll to enrich CLR flags and enforce strict architecture coherence between host and payload.
            if (!info.HasClrHeader && filePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                string siblingDll = Path.ChangeExtension(filePath, ".dll");
                if (File.Exists(siblingDll))
                {
                    try
                    {
                        using (var dllFs = new FileStream(siblingDll, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        using (var dllReader = new BinaryReader(dllFs))
                        {
                            var dllInfo = Detect(dllReader);
                            if (dllInfo.HasClrHeader)
                            {
                                info.ClrFlags = dllInfo.ClrFlags;
                                if (!AreHostAndPayloadArchitecturesCompatible(info.Architecture, dllInfo.Architecture))
                                {
                                    info.HasArchitectureConflict = true;
                                    info.Architecture = TargetArchitecture.Unknown;
                                }
                            }
                        }
                    }
                    catch
                    {
                    }
                }
            }

            return info;
        }

        public static bool AreHostAndPayloadArchitecturesCompatible(TargetArchitecture hostArch, TargetArchitecture payloadArch)
        {
            if (hostArch == TargetArchitecture.Unknown || payloadArch == TargetArchitecture.Unknown)
                return false;

            // A pure-IL AnyCPU or X86Preferred managed payload can be hosted by an x86, x64, or ARM64 native apphost.
            if (payloadArch == TargetArchitecture.AnyCPU || payloadArch == TargetArchitecture.X86Preferred)
                return true;

            // If the managed payload requires a specific CPU architecture (X86Required, X64, or Arm64),
            // the native apphost must match that exact architecture.
            return hostArch == payloadArch;
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
            if (e_lfanew < 0x40 || (ulong)e_lfanew + 256 > (ulong)reader.BaseStream.Length)
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
            if (optHeaderSize < 96 || (ulong)optHeaderPos + (ulong)optHeaderSize > (ulong)reader.BaseStream.Length)
                return info;

            ushort magic = reader.ReadUInt16();
            info.IsPe32Plus = (magic == 0x020B);

            // Read NumberOfRvaAndSizes to verify directory count
            int numRvaOffset = info.IsPe32Plus ? 108 : 92;
            uint numRvaAndSizes = 0;
            if (optHeaderSize >= numRvaOffset + 4 && (ulong)optHeaderPos + (ulong)numRvaOffset + 4 <= (ulong)reader.BaseStream.Length)
            {
                reader.BaseStream.Seek(optHeaderPos + numRvaOffset, SeekOrigin.Begin);
                numRvaAndSizes = reader.ReadUInt32();
            }

            // COM+ Runtime descriptor is at offset 208 for PE32, 224 for PE32+
            int cor20DirOffset = info.IsPe32Plus ? 224 : 208;
            uint cor20Rva = 0;
            uint cor20Size = 0;

            if (numRvaAndSizes > 14 && optHeaderSize >= cor20DirOffset + 8 && (ulong)optHeaderPos + (ulong)cor20DirOffset + 8 <= (ulong)reader.BaseStream.Length)
            {
                reader.BaseStream.Seek(optHeaderPos + cor20DirOffset, SeekOrigin.Begin);
                cor20Rva = reader.ReadUInt32();
                cor20Size = reader.ReadUInt32();
            }

            info.HasClrHeader = (cor20Rva != 0 && cor20Size >= 72);

            // Read section headers to map cor20Rva to raw offset
            long sectionHeadersPos = optHeaderPos + optHeaderSize;
            uint cor20RawOffset = 0;

            if (info.HasClrHeader && (ulong)sectionHeadersPos + (ulong)numSections * 40 <= (ulong)reader.BaseStream.Length)
            {
                for (int i = 0; i < numSections; i++)
                {
                    reader.BaseStream.Seek(sectionHeadersPos + i * 40, SeekOrigin.Begin);
                    reader.BaseStream.Seek(12, SeekOrigin.Current); // Skip Name(8) + VirtualSize(4)
                    uint virtualAddress = reader.ReadUInt32();
                    uint sizeOfRawData = reader.ReadUInt32();
                    uint pointerToRawData = reader.ReadUInt32();

                    if (cor20Rva >= virtualAddress && (ulong)cor20Rva < (ulong)virtualAddress + (ulong)sizeOfRawData)
                    {
                        ulong rel = (ulong)cor20Rva - (ulong)virtualAddress;
                        if ((ulong)pointerToRawData + rel + 72 <= (ulong)reader.BaseStream.Length)
                        {
                            cor20RawOffset = (uint)((ulong)pointerToRawData + rel);
                            break;
                        }
                    }
                }
            }

            if (cor20RawOffset != 0 && (ulong)cor20RawOffset + 72 <= (ulong)reader.BaseStream.Length)
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
            else if (info.Machine == 0xAA64) // ARM64
            {
                info.Architecture = TargetArchitecture.Arm64;
            }
            else if (info.Machine == 0x014C) // i386
            {
                // A native i386 PE without a CLR header (e.g., an x86 native apphost) is strictly 32-bit x86, never AnyCPU.
                if (!info.HasClrHeader || info.Is32BitRequired)
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

        public static string DetectTargetFramework(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return "Unknown";

            try
            {
                using (var mod = dnlib.DotNet.ModuleDefMD.Load(filePath))
                {
                    return DetectTargetFramework(mod);
                }
            }
            catch
            {
                if (filePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                {
                    string siblingDll = Path.ChangeExtension(filePath, ".dll");
                    if (File.Exists(siblingDll))
                    {
                        try
                        {
                            using (var mod = dnlib.DotNet.ModuleDefMD.Load(siblingDll))
                            {
                                return DetectTargetFramework(mod);
                            }
                        }
                        catch
                        {
                        }
                    }
                }
                return "Unknown";
            }
        }

        public static string DetectTargetFramework(dnlib.DotNet.ModuleDef module)
        {
            if (module == null)
                return "Unknown";

            try
            {
                if (module.Assembly != null && module.Assembly.HasCustomAttributes)
                {
                    foreach (var ca in module.Assembly.CustomAttributes)
                    {
                        if (ca != null && ca.TypeFullName == "System.Runtime.Versioning.TargetFrameworkAttribute")
                        {
                            if (ca.ConstructorArguments.Count > 0 && ca.ConstructorArguments[0].Value != null)
                            {
                                string tf = ca.ConstructorArguments[0].Value.ToString();
                                if (!string.IsNullOrWhiteSpace(tf))
                                    return tf;
                            }
                        }
                    }
                }

                if (!string.IsNullOrWhiteSpace(module.RuntimeVersion))
                {
                    return module.RuntimeVersion;
                }
            }
            catch
            {
            }

            return "Unknown";
        }

        /// <summary>
        /// Classifies the target runtime family (.NET Framework, Modern .NET, or Unknown) of the specified assembly or apphost.
        /// </summary>
        public static TargetRuntimeFamily DetectRuntimeFamily(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return TargetRuntimeFamily.Unknown;

            try
            {
                using (var mod = dnlib.DotNet.ModuleDefMD.Load(filePath))
                {
                    return DetectRuntimeFamily(mod);
                }
            }
            catch
            {
                if (filePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                {
                    string siblingDll = Path.ChangeExtension(filePath, ".dll");
                    if (File.Exists(siblingDll))
                    {
                        try
                        {
                            using (var mod = dnlib.DotNet.ModuleDefMD.Load(siblingDll))
                            {
                                return DetectRuntimeFamily(mod);
                            }
                        }
                        catch
                        {
                        }
                    }
                }
                return TargetRuntimeFamily.Unknown;
            }
        }

        public static TargetRuntimeFamily DetectRuntimeFamily(byte[] peBytes)
        {
            if (peBytes == null || peBytes.Length == 0)
                return TargetRuntimeFamily.Unknown;

            try
            {
                using (var mod = dnlib.DotNet.ModuleDefMD.Load(peBytes))
                {
                    return DetectRuntimeFamily(mod);
                }
            }
            catch
            {
                return TargetRuntimeFamily.Unknown;
            }
        }

        public static TargetRuntimeFamily DetectRuntimeFamily(dnlib.DotNet.ModuleDef module)
        {
            if (module == null)
                return TargetRuntimeFamily.Unknown;

            try
            {
                bool hasNetFrameworkCorLib = false;

                foreach (var asmRef in module.GetAssemblyRefs())
                {
                    if (asmRef == null || string.IsNullOrEmpty(asmRef.Name))
                        continue;

                    string name = asmRef.Name.String;
                    if (string.Equals(name, "System.Private.CoreLib", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(name, "Microsoft.NETCore.App", StringComparison.OrdinalIgnoreCase))
                    {
                        return TargetRuntimeFamily.ModernDotNet;
                    }

                    if ((string.Equals(name, "System.Runtime", StringComparison.OrdinalIgnoreCase) ||
                         string.Equals(name, "System.Console", StringComparison.OrdinalIgnoreCase) ||
                         string.Equals(name, "System.Collections", StringComparison.OrdinalIgnoreCase)) &&
                        asmRef.Version != null && asmRef.Version.Major >= 5)
                    {
                        return TargetRuntimeFamily.ModernDotNet;
                    }

                    if (string.Equals(name, "mscorlib", StringComparison.OrdinalIgnoreCase) &&
                        (asmRef.Version == null || asmRef.Version.Major <= 4))
                    {
                        hasNetFrameworkCorLib = true;
                    }
                }

                string tfm = DetectTargetFramework(module);
                if (!string.IsNullOrEmpty(tfm))
                {
                    if (tfm.StartsWith(".NETCoreApp", StringComparison.OrdinalIgnoreCase) ||
                        tfm.StartsWith(".NETStandard,Version=v2.1", StringComparison.OrdinalIgnoreCase))
                    {
                        return TargetRuntimeFamily.ModernDotNet;
                    }

                    if (tfm.StartsWith(".NETFramework", StringComparison.OrdinalIgnoreCase))
                    {
                        return TargetRuntimeFamily.NetFramework;
                    }
                }

                if (hasNetFrameworkCorLib)
                {
                    return TargetRuntimeFamily.NetFramework;
                }

                var corLibRef = module.CorLibTypes?.AssemblyRef;
                if (corLibRef != null && string.Equals(corLibRef.Name, "mscorlib", StringComparison.OrdinalIgnoreCase) &&
                    !string.IsNullOrWhiteSpace(module.RuntimeVersion) &&
                    (module.RuntimeVersion.StartsWith("v4.", StringComparison.OrdinalIgnoreCase) ||
                     module.RuntimeVersion.StartsWith("v2.", StringComparison.OrdinalIgnoreCase) ||
                     module.RuntimeVersion.StartsWith("v1.", StringComparison.OrdinalIgnoreCase)))
                {
                    return TargetRuntimeFamily.NetFramework;
                }
            }
            catch
            {
            }

            return TargetRuntimeFamily.Unknown;
        }

        /// <summary>
        /// Determines whether the specified assembly or executable requires a modern .NET runtime
        /// (.NET Core / .NET 5+) rather than .NET Framework 4.x.
        /// </summary>
        public static bool RequiresModernDotNetRuntime(string filePath)
        {
            return DetectRuntimeFamily(filePath) == TargetRuntimeFamily.ModernDotNet;
        }

        public static bool RequiresModernDotNetRuntime(byte[] peBytes)
        {
            return DetectRuntimeFamily(peBytes) == TargetRuntimeFamily.ModernDotNet;
        }

        public static bool RequiresModernDotNetRuntime(dnlib.DotNet.ModuleDef module)
        {
            return DetectRuntimeFamily(module) == TargetRuntimeFamily.ModernDotNet;
        }
    }
}
