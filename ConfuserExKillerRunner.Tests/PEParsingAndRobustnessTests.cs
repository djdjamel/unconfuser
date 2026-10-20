using System;
using System.IO;
using ConfuserExKillerRunner.Analysis;
using ConfuserExKillerRunner.Core;
using ConfuserExTools.AntiTamperKiller;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public class PEParsingAndRobustnessTests
    {
        [Fact]
        public void PEUtils_ParsePE_IntegerOverflow_e_lfanew_ReturnsInvalidWithoutCrashing()
        {
            byte[] pe = new byte[512];
            pe[0] = 0x4D; // M
            pe[1] = 0x5A; // Z

            // e_lfanew = 0xFFFFFFF0 (adding 256 would wrap around to 240 in 32-bit unchecked uint)
            Buffer.BlockCopy(BitConverter.GetBytes(0xFFFFFFF0U), 0, pe, 0x3C, 4);

            var model = PEUtils.ParsePE(pe);

            Assert.False(model.IsValid);
        }

        [Fact]
        public void PEUtils_ParsePE_e_lfanew_LessThan0x40_ReturnsInvalid()
        {
            byte[] pe = new byte[512];
            pe[0] = 0x4D;
            pe[1] = 0x5A;

            // e_lfanew pointing into DOS header
            Buffer.BlockCopy(BitConverter.GetBytes(0x20U), 0, pe, 0x3C, 4);

            var model = PEUtils.ParsePE(pe);

            Assert.False(model.IsValid);
        }

        [Fact]
        public void PEUtils_ParsePE_TruncatedOptionalHeader_ReturnsInvalid()
        {
            byte[] pe = new byte[200];
            pe[0] = 0x4D;
            pe[1] = 0x5A;
            Buffer.BlockCopy(BitConverter.GetBytes(0x80U), 0, pe, 0x3C, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(0x00004550U), 0, pe, 0x80, 4); // PE\0\0

            // FileHeader: Machine=0x14C, Sections=1, OptionalHeaderSize=240
            Buffer.BlockCopy(BitConverter.GetBytes((ushort)0x014C), 0, pe, 0x84, 2);
            Buffer.BlockCopy(BitConverter.GetBytes((ushort)1), 0, pe, 0x86, 2);
            Buffer.BlockCopy(BitConverter.GetBytes((ushort)240), 0, pe, 0x94, 2);

            // OptionalHeader starts at 0x98, but pe.Length is only 200 (0x98 + 240 = 0x188 > 200)
            var model = PEUtils.ParsePE(pe);

            Assert.False(model.IsValid);
        }

        [Fact]
        public void PEUtils_ParsePE_NumberOfRvaAndSizes_LessThan15_DoesNotReadCor20Header()
        {
            // Valid minimal PE structure
            var mod = new ModuleDefUser("TestModSmallDir");
            byte[] peBytes;
            using (var ms = new MemoryStream())
            {
                mod.Write(ms);
                peBytes = ms.ToArray();
            }

            var baseModel = PEUtils.ParsePE(peBytes);
            Assert.True(baseModel.IsValid);
            Assert.True(baseModel.Cor20Rva > 0);

            // Locate NumberOfRvaAndSizes in OptionalHeader (offset 92 in PE32, 108 in PE32+)
            int numRvaOffset = (int)baseModel.OptionalHeaderOffset + (baseModel.IsPe32Plus ? 108 : 92);
            // Overwrite NumberOfRvaAndSizes with 14 (so directory index 14 is missing)
            Buffer.BlockCopy(BitConverter.GetBytes((uint)14), 0, peBytes, numRvaOffset, 4);

            var modifiedModel = PEUtils.ParsePE(peBytes);
            Assert.True(modifiedModel.IsValid);
            Assert.Equal((uint)0, modifiedModel.Cor20Rva);
            Assert.Equal((uint)0, modifiedModel.Cor20Size);
            Assert.Equal((uint)0, modifiedModel.Cor20FileOffset);
        }

        [Fact]
        public void PEUtils_RvaToFileOffset_OverflowProtection_ReturnsZero()
        {
            var model = new PEInfoModel
            {
                IsValid = true,
                Sections = {
                    new SectionHeader
                    {
                        Name = ".text",
                        VirtualAddress = 0xFFFF0000,
                        VirtualSize = 0x2000,
                        PointerToRawData = 0xFFFFFF00,
                        SizeOfRawData = 0x2000
                    }
                }
            };

            // RVA far out of bounds
            uint offset = PEUtils.RvaToFileOffset(model, 0x1000);
            Assert.Equal((uint)0, offset);

            // FileOffset far out of bounds
            uint rva = PEUtils.FileOffsetToRva(model, 0x1000);
            Assert.Equal((uint)0, rva);
        }

        [Fact]
        public void ArchitectureDetector_Detect_Arm64_DetectsArm64Machine()
        {
            byte[] pe = new byte[512];
            pe[0] = 0x4D;
            pe[1] = 0x5A;
            Buffer.BlockCopy(BitConverter.GetBytes(0x80U), 0, pe, 0x3C, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(0x00004550U), 0, pe, 0x80, 4);

            // FileHeader: Machine=0xAA64 (ARM64), Sections=0, OptHeaderSize=96
            Buffer.BlockCopy(BitConverter.GetBytes((ushort)0xAA64), 0, pe, 0x84, 2);
            Buffer.BlockCopy(BitConverter.GetBytes((ushort)0), 0, pe, 0x86, 2);
            Buffer.BlockCopy(BitConverter.GetBytes((ushort)96), 0, pe, 0x94, 2);
            Buffer.BlockCopy(BitConverter.GetBytes((ushort)0x020B), 0, pe, 0x98, 2); // PE32+

            var info = ArchitectureDetector.Detect(pe);

            Assert.Equal((ushort)0xAA64, info.Machine);
            Assert.Equal(TargetArchitecture.Arm64, info.Architecture);
        }

        [Fact]
        public void ArchitectureDetector_Detect_UnknownMachine_ReturnsUnknownWithoutThrowing()
        {
            byte[] pe = new byte[512];
            pe[0] = 0x4D;
            pe[1] = 0x5A;
            Buffer.BlockCopy(BitConverter.GetBytes(0x80U), 0, pe, 0x3C, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(0x00004550U), 0, pe, 0x80, 4);

            // Machine=0x9999 (Unknown)
            Buffer.BlockCopy(BitConverter.GetBytes((ushort)0x9999), 0, pe, 0x84, 2);
            Buffer.BlockCopy(BitConverter.GetBytes((ushort)0), 0, pe, 0x86, 2);
            Buffer.BlockCopy(BitConverter.GetBytes((ushort)96), 0, pe, 0x94, 2);

            var info = ArchitectureDetector.Detect(pe);

            Assert.Equal((ushort)0x9999, info.Machine);
            Assert.Equal(TargetArchitecture.Unknown, info.Architecture);
        }

        [Fact]
        public void ArchitectureDetector_Detect_IntegerOverflow_e_lfanew_ReturnsUnknown()
        {
            byte[] pe = new byte[512];
            pe[0] = 0x4D;
            pe[1] = 0x5A;
            Buffer.BlockCopy(BitConverter.GetBytes(0xFFFFFFF0U), 0, pe, 0x3C, 4);

            var info = ArchitectureDetector.Detect(pe);

            Assert.Equal(TargetArchitecture.Unknown, info.Architecture);
        }

        [Fact]
        public unsafe void PEInfo_NullPointer_HandlesGracefullyWithoutCrashing()
        {
            var peInfo = new PEInfo(null, 0);

            Assert.Equal(0U, peInfo.SectionsCount);
            Assert.True(peInfo.SectionHeaders == null);
        }

        [Fact]
        public unsafe void PEInfo_GarbageBuffer_HandlesGracefullyWithoutCrashing()
        {
            byte[] garbage = new byte[256];
            garbage[0] = 0xFF;
            fixed (byte* p = garbage)
            {
                var peInfo = new PEInfo(p, (uint)garbage.Length);

                Assert.Equal(0U, peInfo.SectionsCount);
                Assert.True(peInfo.SectionHeaders == null);
            }
        }

        [Fact]
        public void AntiTamperKiller_DetectJitMode_IdentifiesNativeVirtualProtectInGlobalType()
        {
            var mod = new ModuleDefUser("TestModJit");
            var globalType = mod.GlobalType;

            var pinvokeMethod = new MethodDefUser("VirtualProtectHook",
                MethodSig.CreateStatic(mod.CorLibTypes.Boolean, mod.CorLibTypes.IntPtr, mod.CorLibTypes.UInt32, mod.CorLibTypes.UInt32, mod.CorLibTypes.UInt32.ToByRefSig()),
                MethodImplAttributes.IL,
                MethodAttributes.PinvokeImpl | MethodAttributes.Public | MethodAttributes.Static);

            pinvokeMethod.ImplMap = new ImplMapUser(new ModuleRefUser(mod, "kernel32.dll"), "VirtualProtect", PInvokeAttributes.CallConvWinapi);
            globalType.Methods.Add(pinvokeMethod);

            bool detected = Killers.AntiTamperKiller.DetectJitMode(mod);
            Assert.True(detected);
        }

        [Fact]
        public void AntiTamperKiller_DetectJitMode_CleanModule_ReturnsFalse()
        {
            var mod = new ModuleDefUser("TestModClean");
            bool detected = Killers.AntiTamperKiller.DetectJitMode(mod);
            Assert.False(detected);
        }
    }
}
