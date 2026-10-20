using System.Runtime.InteropServices;

namespace ConfuserExTools.AntiTamperKiller {
	[StructLayout(LayoutKind.Sequential)]
	internal unsafe struct IMAGE_SECTION_HEADER {
		public fixed byte Name[8];
		public uint VirtualSize;
		public uint VirtualAddress;
		public uint SizeOfRawData;
		public uint PointerToRawData;
		public uint PointerToRelocations;
		public uint PointerToLinenumbers;
		public ushort NumberOfRelocations;
		public ushort NumberOfLinenumbers;
		public uint Characteristics;
	}

	internal sealed unsafe class PEInfo {
		private readonly void* _pPEImage;
		private readonly uint _sectionsCount;
		private readonly IMAGE_SECTION_HEADER* _pSectionHeaders;

		public void* PEImage => _pPEImage;

		public uint SectionsCount => _sectionsCount;

		public IMAGE_SECTION_HEADER* SectionHeaders => _pSectionHeaders;

		public PEInfo(void* pPEImage, uint imageLength = 0) {
			_pPEImage = pPEImage;
			if (pPEImage == null)
				return;

			byte* p = (byte*)pPEImage;
			if (imageLength > 0 && imageLength < 0x40)
				return;

			// Verify MZ signature (0x5A4D)
			if (*(ushort*)p != 0x5A4D)
				return;

			uint e_lfanew = *(uint*)(p + 0x3C);
			if (e_lfanew < 0x40 || (imageLength > 0 && (ulong)e_lfanew + 256 > imageLength))
				return;

			byte* ntHeader = p + e_lfanew;
			// Verify PE signature 'PE\0\0' (0x00004550)
			if (*(uint*)ntHeader != 0x00004550)
				return;

			byte* cur = ntHeader + 4 + 2; // Skip Signature + Machine
			_sectionsCount = *(ushort*)cur;
			cur += 2 + 12; // Skip NumberOfSections + TimeDateStamp + PointerToSymbolTable + NumberOfSymbols
			ushort optionalHeaderSize = *(ushort*)cur;
			cur += 2 + 2; // Skip SizeOfOptionalHeader + Characteristics
			cur += optionalHeaderSize; // Skip OptionalHeader
			_pSectionHeaders = (IMAGE_SECTION_HEADER*)cur;
		}
	}
}
