using System;
using ConfuserExKillerRunner.Analysis;

namespace ConfuserExKillerRunner.Killers
{
    public sealed class Cor20RepairResult
    {
        public bool Success { get; set; }
        public bool CbRepaired { get; set; }
        public uint OriginalCb { get; set; }
        public bool MetaDataRvaRepaired { get; set; }
        public uint OriginalMetaDataRva { get; set; }
        public uint RepairedMetaDataRva { get; set; }
        public string Message { get; set; }
    }

    public static class Cor20Repair
    {
        public static Cor20RepairResult Repair(byte[] peBytes, byte[] originalBytes = null)
        {
            if (peBytes == null) throw new ArgumentNullException(nameof(peBytes));

            var result = new Cor20RepairResult { Success = false };
            var pe = PEUtils.ParsePE(peBytes);
            if (!pe.IsValid)
            {
                result.Message = "Invalid PE file structure";
                return result;
            }

            if (pe.Cor20FileOffset == 0 || pe.Cor20FileOffset + 72 > peBytes.Length)
            {
                result.Message = "COR20 header offset not found or out of bounds";
                return result;
            }

            int offset = (int)pe.Cor20FileOffset;
            uint cb = BitConverter.ToUInt32(peBytes, offset);
            result.OriginalCb = cb;

            if (cb != 72)
            {
                byte[] cbBytes = BitConverter.GetBytes((uint)72);
                Buffer.BlockCopy(cbBytes, 0, peBytes, offset, 4);
                result.CbRepaired = true;
            }

            uint metaRva = BitConverter.ToUInt32(peBytes, offset + 8);
            result.OriginalMetaDataRva = metaRva;

            if (metaRva == 0)
            {
                // Fallback 1: Restore from originalBytes if available
                if (originalBytes != null && originalBytes.Length >= offset + 12)
                {
                    var origPe = PEUtils.ParsePE(originalBytes);
                    if (origPe.IsValid && origPe.Cor20FileOffset != 0 && origPe.Cor20FileOffset + 12 <= originalBytes.Length)
                    {
                        uint origMetaRva = BitConverter.ToUInt32(originalBytes, (int)origPe.Cor20FileOffset + 8);
                        if (origMetaRva != 0)
                        {
                            byte[] rvaBytes = BitConverter.GetBytes(origMetaRva);
                            Buffer.BlockCopy(rvaBytes, 0, peBytes, offset + 8, 4);
                            result.MetaDataRvaRepaired = true;
                            result.RepairedMetaDataRva = origMetaRva;
                            metaRva = origMetaRva;
                        }
                    }
                }

                // Fallback 2: Scan for BSJB signature across the binary
                if (metaRva == 0)
                {
                    const uint bsjbSig = 0x424A5342;
                    uint foundOffset = 0;
                    for (uint i = 0; i + 16 < peBytes.Length; i++)
                    {
                        if (BitConverter.ToUInt32(peBytes, (int)i) == bsjbSig)
                        {
                            if (PEUtils.IsValidMetadataHeader(peBytes, i))
                            {
                                foundOffset = i;
                                break;
                            }
                        }
                    }

                    if (foundOffset != 0)
                    {
                        uint calculatedRva = PEUtils.FileOffsetToRva(pe, foundOffset);
                        if (calculatedRva != 0)
                        {
                            byte[] rvaBytes = BitConverter.GetBytes(calculatedRva);
                            Buffer.BlockCopy(rvaBytes, 0, peBytes, offset + 8, 4);
                            result.MetaDataRvaRepaired = true;
                            result.RepairedMetaDataRva = calculatedRva;
                        }
                    }
                }
            }

            if (metaRva == 0)
            {
                result.Success = false;
                result.Message = "COR20 MetaData RVA is 0 and could not be recovered.";
                return result;
            }

            result.Success = true;
            result.Message = $"Repaired: Cb={result.CbRepaired}, MetaDataRva={result.MetaDataRvaRepaired}";
            return result;
        }
    }
}
