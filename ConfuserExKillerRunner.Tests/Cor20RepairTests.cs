using System;
using System.IO;
using ConfuserExKillerRunner.Analysis;
using ConfuserExKillerRunner.Killers;
using dnlib.DotNet;
using Xunit;

namespace ConfuserExKillerRunner.Tests
{
    public class Cor20RepairTests
    {
        private static byte[] CreateValidPeBytes()
        {
            var module = new ModuleDefUser("TestMod");
            using (var ms = new MemoryStream())
            {
                module.Write(ms);
                return ms.ToArray();
            }
        }

        [Fact]
        public void Cor20Repair_InvalidPE_ReturnsFailure()
        {
            byte[] garbage = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            var result = Cor20Repair.Repair(garbage);

            Assert.False(result.Success);
            Assert.Contains("Invalid PE", result.Message);
        }

        [Fact]
        public void Cor20Repair_CorruptedCb_RepairsTo72AndLoadsSuccessfully()
        {
            byte[] peBytes = CreateValidPeBytes();
            var pe = PEUtils.ParsePE(peBytes);
            Assert.True(pe.IsValid);
            Assert.True(pe.Cor20FileOffset > 0);

            // Corrupt cb field (first 4 bytes of COR20 header)
            int offset = (int)pe.Cor20FileOffset;
            Buffer.BlockCopy(BitConverter.GetBytes((uint)0), 0, peBytes, offset, 4);

            // Verify corrupted image fails ModuleDefMD.Load
            Assert.ThrowsAny<Exception>(() =>
            {
                using (var mod = ModuleDefMD.Load(peBytes)) { }
            });

            // Perform repair
            var result = Cor20Repair.Repair(peBytes);

            Assert.True(result.Success);
            Assert.True(result.CbRepaired);
            Assert.Equal((uint)0, result.OriginalCb);
            Assert.Equal((uint)72, BitConverter.ToUInt32(peBytes, offset));

            // Verify repaired image loads cleanly in dnlib
            using (var mod = ModuleDefMD.Load(peBytes))
            {
                Assert.NotNull(mod);
                Assert.Equal("TestMod", mod.Name);
            }
        }

        [Fact]
        public void Cor20Repair_CorruptedMetaDataRva_RestoresFromOriginal()
        {
            byte[] originalBytes = CreateValidPeBytes();
            byte[] peBytes = (byte[])originalBytes.Clone();

            var pe = PEUtils.ParsePE(peBytes);
            int offset = (int)pe.Cor20FileOffset;
            uint originalRva = BitConverter.ToUInt32(peBytes, offset + 8);
            Assert.True(originalRva > 0);

            // Wipe MetaData RVA to 0 in peBytes
            Buffer.BlockCopy(BitConverter.GetBytes((uint)0), 0, peBytes, offset + 8, 4);

            // Repair with originalBytes
            var result = Cor20Repair.Repair(peBytes, originalBytes);

            Assert.True(result.Success);
            Assert.True(result.MetaDataRvaRepaired);
            Assert.Equal((uint)0, result.OriginalMetaDataRva);
            Assert.Equal(originalRva, result.RepairedMetaDataRva);
            Assert.Equal(originalRva, BitConverter.ToUInt32(peBytes, offset + 8));

            using (var mod = ModuleDefMD.Load(peBytes))
            {
                Assert.NotNull(mod);
            }
        }

        [Fact]
        public void Cor20Repair_CorruptedMetaDataRva_NoOriginalNoBsjb_RepairInsufficient()
        {
            byte[] peBytes = CreateValidPeBytes();
            var pe = PEUtils.ParsePE(peBytes);
            int offset = (int)pe.Cor20FileOffset;

            // Wipe MetaData RVA to 0
            Buffer.BlockCopy(BitConverter.GetBytes((uint)0), 0, peBytes, offset + 8, 4);

            // Also wipe any BSJB signature so Fallback 2 cannot find it
            const uint bsjbSig = 0x424A5342;
            for (int i = 0; i + 4 <= peBytes.Length; i++)
            {
                if (BitConverter.ToUInt32(peBytes, i) == bsjbSig)
                {
                    Buffer.BlockCopy(BitConverter.GetBytes((uint)0), 0, peBytes, i, 4);
                }
            }

            // Repair without originalBytes
            var result = Cor20Repair.Repair(peBytes, originalBytes: null);

            // Cb was 72 so not repaired, MetaDataRva was not repairable
            Assert.False(result.Success);
            Assert.False(result.MetaDataRvaRepaired);

            // ModuleDefMD.Load must still fail
            Assert.ThrowsAny<Exception>(() =>
            {
                using (var mod = ModuleDefMD.Load(peBytes)) { }
            });
        }
    }
}
