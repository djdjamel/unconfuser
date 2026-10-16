"""
Signatures and patterns for known .NET Obfuscators, Packers, Protectors, and Virtualizers (Schema v2).

Schema per entry:
    layer              - 'packer' | 'protector' | 'obfuscator' | 'virtualizer' | 'licensing' | 'bundler' | 'info'
    attributes         - custom attribute type names
    type_names         - TypeDef name patterns
    namespaces         - TypeDef namespace patterns
    assembly_refs      - AssemblyRef name patterns
    strings            - user-string / metadata-string patterns (>= 8 chars for contains, or token)
    resource_names     - .NET manifest resource name prefix/patterns
    resource_magic     - leading bytes of resource data (hex strings, lower-case)
    import_names       - PE IAT DLL name patterns (native imports)
    clr_stream_markers - non-standard CLR metadata stream names
    characteristics    - human-readable description list
    verified           - bool (True if verified on real sample, else False)
    confidence_cap     - Optional['LOW' | 'MEDIUM'] to cap confidence of experimental rules
    version_regex      - Optional[str] regex to extract version
"""

from typing import Dict, List, Any, Optional
from .matching import compile_pattern

# ---------------------------------------------------------------------------
# Trusted Microsoft public-key tokens (clean framework & BCL suppression)
# ---------------------------------------------------------------------------
MICROSOFT_PUBLIC_KEY_TOKENS = frozenset([
    "b77a5c561934e089",  # ECMA / mscorlib / System
    "b03f5f7f11d50a3a",  # Microsoft .NET Framework
    "31bf3856ad364e35",  # Microsoft Reference
    "cc7b13ffcd2ddd51",  # .NET Core / System.*
    "7cec85d7bea7798e",  # ASP.NET Core
    "adb9793829ddae60",  # Microsoft.Extensions
])

# ---------------------------------------------------------------------------
# Aliases and finding normalization
# ---------------------------------------------------------------------------
FINDING_ALIASES: Dict[str, str] = {
    "EzirizVM (.NET Reactor Virtualizer)": ".NET Reactor (EzirizVM)",
    ".NET Reactor (Eziriz)": ".NET Reactor (EzirizVM)",
    "Custom CLR Stream (#EzirizVM)": ".NET Reactor (EzirizVM)",
    "Custom CLR Stream (#Koi)": "KoiVM",
    "Custom CLR Stream (#ConfuserEx)": "ConfuserEx / Confuser / Bed",
}

# ---------------------------------------------------------------------------
# Obfuscator Signatures Database (Schema v2)
# ---------------------------------------------------------------------------
OBFUSCATOR_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "ConfuserEx / Confuser / Bed": {
        "layer": "obfuscator",
        "verified": True,
        "attributes": [
            "ConfusedByAttribute",
            "Confuser.Core",
            "ConfusedBy",
        ],
        "type_names": [
            "<ConfusedBy>",
        ],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            "Confuser.Core",
            "ConfuserEx",
            "ConfusedByAttribute",
            "Confuser v",
            "BED - Bed Obfuscator",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Zero-width and invisible unicode characters in identifiers",
            "Complex <Module>..cctor with anti-tamper and dynamic decryption",
            "Invalid UTF-8 metadata strings or mangled table entries",
        ],
    },
    "SmartAssembly (Red Gate)": {
        "layer": "obfuscator",
        "verified": True,
        "attributes": [
            "PoweredByAttribute",
            "DoNotMoveAttribute",
            "DoNotPruneAttribute",
            "StayPublicAttribute",
            "DoNotCaptureAttribute",
            "DoNotObfuscateTypeAttribute",
            "DoNotObfuscateControlFlowAttribute",
            "ReportExceptionAttribute",
        ],
        "type_names": [
            "{SmartAssembly}",
            "SmartAssembly.Attributes",
            "SmartAssembly.Zip",
            "SmartAssembly.Delegates",
            "SmartAssembly.MemoryManagement",
            "SmartAssembly.Housekeeping",
        ],
        "namespaces": [
            "SmartAssembly.Attributes",
            "SmartAssembly.Zip",
            "SmartAssembly.Delegates",
            "SmartAssembly.MemoryManagement",
        ],
        "assembly_refs": [
            "SmartAssembly",
        ],
        "strings": [
            "Powered by SmartAssembly",
            "{SmartAssembly}",
            "SmartAssembly.SmartExceptionsCore",
        ],
        "resource_names": [
            "{SmartAssembly}",
            "{SA_",
        ],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Automated exception reporting hooks",
            "Encrypted zip resources with embedded DLLs",
            "String decryption via delegate indirection",
        ],
    },
    ".NET Reactor (Eziriz)": {
        "layer": "protector",
        "verified": True,
        "attributes": [
            "Reactor",
            "Eziriz",
            "NET_Reactor",
        ],
        "type_names": [
            "__Reactor",
            "Eziriz.Reactor",
        ],
        "namespaces": [
            "Eziriz",
            "Reactor",
        ],
        "assembly_refs": [],
        "strings": [
            ".NET Reactor",
            "Protected with .NET Reactor",
            "Licensed with .NET Reactor",
            "reactor_embedded",
        ],
        "resource_names": [
            "reactor_embedded",
        ],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [
            "#EzirizVM",
        ],
        "characteristics": [
            "Native x86/x64 stub or mixed-mode bootstrap",
            "Native library decryption from resource heap",
            "Virtualization / dynamic method body re-mapping",
        ],
    },
    "IntelliLock (Eziriz)": {
        "layer": "licensing",
        "verified": True,
        "attributes": [
            "IntelliLock",
        ],
        "type_names": [
            "IntelliLock",
            "IntelliLock.Licensing",
        ],
        "namespaces": [
            "IntelliLock",
        ],
        "assembly_refs": [
            "IntelliLock",
        ],
        "strings": [
            "Protected by IntelliLock",
            "Eziriz IntelliLock",
            "Licensed with IntelliLock",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Advanced license locking and hardware dongle protection",
            "Embedded evaluation license dialogs and expiration hooks",
        ],
    },
    "Eazfuscator.NET": {
        "layer": "obfuscator",
        "verified": True,
        "attributes": [
            "ObfuscatedByAttribute",
        ],
        "type_names": [
            "_eaz_",
        ],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            "Eazfuscator.NET",
            "http://www.gapotchenko.com/eazfuscator.net",
            "gapotchenko.com/eazfuscator",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Sequential/hashed identifier generation",
            "Custom dynamic assembly resolve events",
            "Virtual Machine code virtualization",
        ],
    },
    "de4dot (Deobfuscated Output)": {
        "layer": "info",
        "verified": True,
        "attributes": [],
        "type_names": [
            {"p": r"^G(Class|Struct|Interface|Enum|Delegate)\d+$", "mode": "regex"},
        ],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            {"p": r"^(smethod|method|field|int|string)_\d+$", "mode": "regex"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Assembly has been processed and renamed by the de4dot deobfuscator",
            "Standard de4dot symbol patterns: GClass<N>, smethod_<N>, etc.",
        ],
    },
    "Dotfuscator (PreEmptive Solutions)": {
        "layer": "obfuscator",
        "verified": True,
        "attributes": [
            "DotfuscatorAttribute",
        ],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            "Dotfuscator",
            "PreEmptive Solutions",
            "Dotfuscator Community Edition",
            "Dotfuscator Professional",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Short alphabetical renaming (a, b, c, A, B, C)",
            "Control flow obfuscation using induction variables",
            "Metadata stripping (removal of parameter names, debug info)",
        ],
    },
    "Babel .NET": {
        "layer": "obfuscator",
        "verified": True,
        "attributes": [
            "BabelAttribute",
            "BabelSignatureAttribute",
        ],
        "type_names": [],
        "namespaces": [
            "Babel",
        ],
        "assembly_refs": [
            "Babel",
        ],
        "strings": [
            "Babel Obfuscator",
            "Babel.Net",
            "BabelAttribute",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Reflection-based string decryption helper calls",
            "Resource encryption and dynamic assembly loading",
        ],
    },
    "Agile.NET (CliSecure)": {
        "layer": "protector",
        "verified": True,
        "attributes": [
            "AgileDotNet.VMAttribute",
            "CliSecureAttribute",
            "CliSecure",
        ],
        "type_names": [
            "<AgileDotNet>",
            "CliSecure",
        ],
        "namespaces": [
            "AgileDotNet",
            "CliSecure",
        ],
        "assembly_refs": [
            "AgileDotNet",
            "CliSecure",
        ],
        "strings": [
            "Agile.NET",
            "CliSecure",
            "SecureTeam",
            "AgileDotNet.VM",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Mixed-mode C++/CLI stubs",
            "Metadata structure hiding (tampered stream headers)",
            "Method body virtualization",
        ],
    },
    "ArmDot": {
        "layer": "virtualizer",
        "verified": True,
        "attributes": [
            "ArmDot",
            "ArmDot.Client",
        ],
        "type_names": [
            "ArmDot",
        ],
        "namespaces": [
            "ArmDot",
        ],
        "assembly_refs": [
            "ArmDot.Client",
        ],
        "strings": [
            "ArmDot.Client",
            "Protected by ArmDot",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "CIL to native compilation / virtualization",
            "Method body stripping into native dynamic dispatch",
        ],
    },
    "KoiVM / Virtualization": {
        "layer": "virtualizer",
        "verified": True,
        "attributes": [],
        "type_names": [
            "KoiVM",
            "Koi",
        ],
        "namespaces": [
            "KoiVM",
        ],
        "assembly_refs": [],
        "strings": [
            "KoiVM",
            "Koi VM",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "IL translated to custom bytecode executed by a virtual machine interpreter",
            "High opacity control flow graphs and dynamic opcode decoding",
        ],
    },
    "NetGuard / NetGuard.IO": {
        "layer": "protector",
        "verified": True,
        "attributes": [
            "NetGuard",
            "NetGuardAttribute",
        ],
        "type_names": [
            "NetGuard",
        ],
        "namespaces": [
            "NetGuard",
        ],
        "assembly_refs": [],
        "strings": [
            "NetGuard.IO",
            "Protected by NetGuard",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Anti-tamper checks, dynamic method loading, string encryption",
        ],
    },
    "Xenocode Postbuild": {
        "layer": "bundler",
        "verified": True,
        "attributes": [
            "Xenocode",
            "Xenocode.Client",
        ],
        "type_names": [
            "_Xenocode_",
        ],
        "namespaces": [
            "Xenocode",
        ],
        "assembly_refs": [],
        "strings": [
            "Xenocode.Client.Attributes",
            "Xenocode Postbuild",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Application virtualization / single-file bundling",
            "Control flow scrambling and metadata suppression",
        ],
    },
    "Enigma Protector / Enigma Virtual Box": {
        "layer": "packer",
        "verified": True,
        "attributes": [],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            "Enigma Protector",
            "Enigma Virtual Box",
            "enigma_stub",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [
            "enigma_mscoree",
        ],
        "clr_stream_markers": [],
        "characteristics": [
            "Virtual file system in PE overlay",
            "Anti-dumping, anti-tracing, and hardware ID licensing",
            "enigma_mscoree.dll native import injection",
        ],
    },
    "BoxedApp Packer": {
        "layer": "bundler",
        "verified": True,
        "attributes": [],
        "type_names": [
            "BoxedApp",
        ],
        "namespaces": [
            "BoxedApp",
        ],
        "assembly_refs": [],
        "strings": [
            "BoxedAppSDK",
            "boxedapp",
        ],
        "resource_names": [],
        "resource_magic": [
            "424f584544415050",
        ],
        "import_names": [
            "boxedapp",
        ],
        "clr_stream_markers": [],
        "characteristics": [
            "Single-file virtual file system embedding all dependencies in memory",
            "BOXEDAPP magic bytes (424f584544415050) in virtual FS payload",
        ],
    },
    "DNGuard / DNGuard HVM": {
        "layer": "virtualizer",
        "verified": True,
        "attributes": [],
        "type_names": [
            "DNGuard",
        ],
        "namespaces": [
            "DNGuard",
        ],
        "assembly_refs": [],
        "strings": [
            "DNGuard HVM",
            "Protected by DNGuard",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Hardware-bound virtual machine",
            "JIT-level method body decryption hooks",
        ],
    },
    "Crypto Obfuscator (LogicNP)": {
        "layer": "obfuscator",
        "verified": True,
        "attributes": [
            "ProtectedWithCryptoObfuscatorAttribute",
        ],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            "Crypto Obfuscator",
            "LogicNP Software",
            "ProtectedWithCryptoObfuscatorAttribute",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "AES/DES string encryption with inline decoders",
            "Anti-reflection and anti-decompiler metadata hooks",
        ],
    },
    "CryptoLicensing (LogicNP)": {
        "layer": "licensing",
        "verified": True,
        "attributes": [
            "CryptoLicensing",
        ],
        "type_names": [
            "CryptoLicense",
        ],
        "namespaces": [
            "LogicNP.CryptoLicensing",
        ],
        "assembly_refs": [
            "LogicNP.CryptoLicensing",
        ],
        "strings": [
            "CryptoLicensing",
            "LogicNP Software",
            "CryptoLicense",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Commercial licensing engine with cryptographic key validation",
        ],
    },
    "ILProtector": {
        "layer": "protector",
        "verified": True,
        "attributes": [],
        "type_names": [
            "ILProtector",
        ],
        "namespaces": [
            "ILProtector",
        ],
        "assembly_refs": [],
        "strings": [
            "ILProtector",
            "ILProtect",
            "protect32.dll",
            "protect64.dll",
        ],
        "resource_names": [
            "ILProtect",
        ],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [
            "ILProtect",
        ],
        "characteristics": [
            "Dynamic runtime method decryption via native DLL injection",
            "Method bodies in assembly are empty stubs at static time",
            "ILProtect custom CLR metadata stream may be present",
        ],
    },
    "Costura (Fody Assembly Embedder)": {
        "layer": "bundler",
        "verified": True,
        "attributes": [],
        "type_names": [
            "Costura.AssemblyLoader",
        ],
        "namespaces": [
            "Costura",
        ],
        "assembly_refs": [],
        "strings": [
            "costura32.dll",
            "costura64.dll",
            "Costura.AssemblyLoader",
        ],
        "resource_names": [
            "costura.",
        ],
        "resource_magic": [
            "1f8b",
        ],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Compressed embedded assemblies stored inside resources",
            "Automatic AssemblyResolve hook to unpack DLLs on demand into memory",
            "Resources prefixed with 'costura.' and GZip/Deflate-compressed",
        ],
    },
    "Spices.Net (NineRays)": {
        "layer": "obfuscator",
        "verified": True,
        "attributes": [
            "NineRays.Obfuscator",
            "Spices.Net",
        ],
        "type_names": [],
        "namespaces": [
            "NineRays",
        ],
        "assembly_refs": [],
        "strings": [
            "NineRays.Obfuscator",
            "Spices.Net",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Flow mutation and control branch redirection",
            "Assembly watermark attributes",
        ],
    },
    "DeepSea Obfuscator": {
        "layer": "obfuscator",
        "verified": True,
        "attributes": [
            "DeepSeaObfuscator",
        ],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            "DeepSea Obfuscator",
            "Protected by DeepSea",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "High-grade control flow flattening and string encryption",
        ],
    },
    "Goliath .NET": {
        "layer": "obfuscator",
        "verified": True,
        "attributes": [
            "ObfuscatedByGoliath",
        ],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            "Goliath .NET",
            "ObfuscatedByGoliath",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Renaming and control flow mangling",
        ],
    },
    "Skater .NET": {
        "layer": "obfuscator",
        "verified": True,
        "attributes": [
            "RustemSoft.Skater",
        ],
        "type_names": [],
        "namespaces": [
            "RustemSoft",
        ],
        "assembly_refs": [
            "RustemSoft",
        ],
        "strings": [
            "RustemSoft",
            "Skater .NET",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Private reflection proxies",
        ],
    },
    "CodeVeil": {
        "layer": "protector",
        "verified": True,
        "attributes": [
            "CodeVeil",
        ],
        "type_names": [],
        "namespaces": [
            "CodeVeil",
        ],
        "assembly_refs": [],
        "strings": [
            "Protected by CodeVeil",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Encrypted IL code with runtime decryption",
        ],
    },
    "Inquartos Obfuscator": {
        "layer": "obfuscator",
        "verified": True,
        "attributes": [
            "Inquartos",
        ],
        "type_names": [],
        "namespaces": [
            "Inquartos",
        ],
        "assembly_refs": [],
        "strings": [
            "Inquartos Obfuscator",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Renaming, string encryption, and control flow mutation",
        ],
    },
    "Manco .NET Licensing": {
        "layer": "licensing",
        "verified": True,
        "attributes": [
            "Manco",
        ],
        "type_names": [
            "MancoLicensing",
        ],
        "namespaces": [
            "Manco",
        ],
        "assembly_refs": [
            "Manco",
        ],
        "strings": [
            "Manco Software",
            "Manco Licensing",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Hardware-locked licensing enforcement system",
        ],
    },
    "MaxToCode": {
        "layer": "protector",
        "verified": True,
        "attributes": [],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            "MaxToCode",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Native execution loader and method body encryption",
        ],
    },
    "VMProtect (.NET Mode)": {
        "layer": "virtualizer",
        "verified": True,
        "attributes": [],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            "VMProtect",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Virtualization of execution into custom virtual architecture",
            "Mutation of instructions and anti-debugging protection",
            ".vmp* prefixed PE sections",
        ],
    },
    "Themida / WinLicense": {
        "layer": "packer",
        "verified": True,
        "attributes": [],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            "Oreans Technologies",
            "Themida Professional",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [
            "themida",
            "winlicense",
            "oreans",
        ],
        "clr_stream_markers": [],
        "characteristics": [
            "Multi-layer code virtualization and advanced kernel-level anti-analysis",
            "IAT zeroed or replaced with virtualized dispatch (no visible imports)",
        ],
    },
    "Yano Obfuscator": {
        "layer": "obfuscator",
        "verified": True,
        "attributes": [
            "YanoAttribute",
        ],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            "YanoAttribute",
            "Yano Obfuscator",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Resource encryption and control flow permutation",
        ],
    },
    "Obfuscar (Open Source)": {
        "layer": "obfuscator",
        "verified": True,
        "attributes": [],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            "Obfuscar",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Renaming to generic short identifiers (A, B, C, etc.)",
            "Namespace flattening / removal",
        ],
    },
    "Phoenix Protector": {
        "layer": "protector",
        "verified": True,
        "attributes": [
            "PhoenixAttribute",
            "ObfuscatedByPhoenix",
        ],
        "type_names": [
            "PhoenixVM",
            "<Phoenix>",
        ],
        "namespaces": [
            "Phoenix",
        ],
        "assembly_refs": [
            "Phoenix",
        ],
        "strings": [
            "Phoenix Protector",
            "phoenix_protected",
            "PhoenixAttribute",
        ],
        "resource_names": [
            "phoenix_",
        ],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "String encryption with runtime decoder delegates",
            "Control flow flattening via state-machine switch",
            "Anti-tamper CRC checks in <Module>.cctor",
        ],
    },
    "Netz (.NET Compressor)": {
        "layer": "bundler",
        "verified": True,
        "attributes": [],
        "type_names": [
            {"p": "netz", "mode": "token"},
        ],
        "namespaces": [
            {"p": "netz", "mode": "token"},
        ],
        "assembly_refs": [],
        "strings": [
            "netz packer",
        ],
        "resource_names": [
            "netz_r",
        ],
        "resource_magic": [
            "1f8b",
        ],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Single resource containing GZip-compressed original assembly",
            "Tiny stub exe that decompresses and loads the payload in memory",
        ],
    },
    "NetShrink": {
        "layer": "packer",
        "verified": True,
        "attributes": [],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            "netshrink",
        ],
        "resource_names": [
            "netshrink",
        ],
        "resource_magic": [],
        "import_names": [
            "netshrink",
        ],
        "clr_stream_markers": [],
        "characteristics": [
            "Native wrapper packing the .NET assembly",
            "High-entropy .text section containing compressed managed code",
        ],
    },
    "MindLated (ConfuserEx Fork)": {
        "layer": "obfuscator",
        "verified": True,
        "attributes": [
            "MindLatedAttribute",
        ],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            "MindLated",
            "mindlated",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Invisible unicode identifiers (same as ConfuserEx)",
            "<Module>.cctor decryptor stub (same as ConfuserEx)",
            "Distinct resource naming pattern vs standard ConfuserEx",
        ],
    },
    "SafeEngine Shielden": {
        "layer": "packer",
        "verified": True,
        "attributes": [],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            "SafeEngine",
            "safengine",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [
            "safengine",
        ],
        "clr_stream_markers": [],
        "characteristics": [
            "safengine named PE section",
            "Anti-debug and VM-detection native wrapper",
        ],
    },
    "UPX Packer": {
        "layer": "packer",
        "verified": True,
        "attributes": [],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            "$Info: This file is packed with the UPX",
        ],
        "resource_names": [],
        "resource_magic": [
            "555058",
        ],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "upx0/upx1/upx2 PE sections",
            "UPX signature bytes in stub",
        ],
    },
    "MPRESS Packer": {
        "layer": "packer",
        "verified": True,
        "attributes": [],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            "This file is packed with the MPRESS",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            ".MPRESS1 / .MPRESS2 PE sections",
            "aPLib or LZMA compressed payload",
        ],
    },
    "ASPack / ASProtect": {
        "layer": "packer",
        "verified": True,
        "attributes": [],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            "Protected by ASProtect",
            "ASProtect v",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [
            "asprotect",
        ],
        "clr_stream_markers": [],
        "characteristics": [
            ".aspack PE section",
            "asprotect.dll native import",
        ],
    },
    "WPFObfuscator": {
        "layer": "obfuscator",
        "verified": False,
        "confidence_cap": "LOW",
        "attributes": [
            "WPFObfuscatorAttribute",
            "WPFObfuscated",
        ],
        "type_names": [],
        "namespaces": [
            "WPFObfuscator",
        ],
        "assembly_refs": [],
        "strings": [
            "WPFObfuscator",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "XAML resource dictionary obfuscation",
            "WPF binding path name mangling",
        ],
    },
    "EzirizVM (.NET Reactor Virtualizer)": {
        "layer": "virtualizer",
        "verified": True,
        "attributes": [],
        "type_names": [
            "EzirizVM",
        ],
        "namespaces": [
            "EzirizVM",
        ],
        "assembly_refs": [],
        "strings": [
            "#EzirizVM",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [
            "#EzirizVM",
        ],
        "characteristics": [
            "#EzirizVM custom CLR metadata stream present",
            "VM_ prefixed method stubs with no IL body",
            "Method bodies replaced by virtualized bytecode dispatched at runtime",
        ],
    },
    "Siticone (Kimasoft) .NET Protector": {
        "layer": "licensing",
        "verified": False,
        "confidence_cap": "LOW",
        "attributes": [
            "SiticoneAttribute",
            "KimasoftAttribute",
        ],
        "type_names": [],
        "namespaces": [
            "Kimasoft",
        ],
        "assembly_refs": [
            "Kimasoft",
        ],
        "strings": [
            "Protected by Siticone",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Hardware-binding licensing with trial enforcement",
            "String encryption and anti-tamper",
        ],
    },
    "Protect My App (.NET)": {
        "layer": "obfuscator",
        "verified": False,
        "confidence_cap": "LOW",
        "attributes": [
            "ProtectMyAppAttribute",
        ],
        "type_names": [
            "ProtectMyApp",
        ],
        "namespaces": [
            "ProtectMyApp",
        ],
        "assembly_refs": [
            "ProtectMyApp",
        ],
        "strings": [
            "Protected by ProtectMyApp",
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Assembly licensing and anti-decompilation",
        ],
    },
    "ConfuserEx 2 (mkaring)": {
        "layer": "protector",
        "verified": True,
        "attributes": [
            {"p": "ConfuserEx v", "mode": "prefix"},
        ],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            {"p": "mkaring/ConfuserEx", "mode": "contains"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [
            "#ConfuserEx",
        ],
        "version_regex": r"ConfuserEx\s+v?([\d.]+)",
        "characteristics": [
            "ConfuserEx2 fork by mkaring with updated .NET Core and .NET 5+ support",
            "#ConfuserEx custom CLR metadata stream",
        ],
    },
    "Neo-ConfuserEx": {
        "layer": "protector",
        "verified": True,
        "attributes": [],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            {"p": "Neo-ConfuserEx", "mode": "contains"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [
            "#ConfuserEx",
        ],
        "version_regex": r"Neo-ConfuserEx\s+v?([\d.]+)",
        "characteristics": [
            "Neo-ConfuserEx fork with modified constants, anti-tamper, and reference proxy",
        ],
    },
    "ModPhuserEx": {
        "layer": "protector",
        "verified": False,
        "confidence_cap": "LOW",
        "attributes": [],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            {"p": "ModPhuserEx", "mode": "contains"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "ModPhuserEx custom ConfuserEx modification",
        ],
    },
    "Beds-Protector": {
        "layer": "protector",
        "verified": True,
        "attributes": [],
        "type_names": [
            {"p": "BedsProtector", "mode": "token"},
        ],
        "namespaces": [
            {"p": "BedsProtector", "mode": "token"},
        ],
        "assembly_refs": [],
        "strings": [
            {"p": "Beds-Protector", "mode": "contains"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Beds-Protector ConfuserEx-based protector",
        ],
    },
    "AsStrongAsFuck": {
        "layer": "obfuscator",
        "verified": True,
        "attributes": [
            {"p": "AsStrongAsFuck", "mode": "exact"},
        ],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            {"p": "AsStrongAsFuck", "mode": "contains"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "AsStrongAsFuck open-source .NET obfuscator",
        ],
    },
    "Krawk": {
        "layer": "protector",
        "verified": False,
        "confidence_cap": "LOW",
        "attributes": [],
        "type_names": [
            {"p": "KrawkProtector", "mode": "token"},
        ],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            {"p": "KrawkProtector", "mode": "contains"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Krawk obfuscator / protector",
        ],
    },
    "CodeWall": {
        "layer": "obfuscator",
        "verified": True,
        "attributes": [
            {"p": "CodeWallAttribute", "mode": "exact"},
        ],
        "type_names": [],
        "namespaces": [
            {"p": "CodeWall", "mode": "token"},
        ],
        "assembly_refs": [],
        "strings": [
            {"p": "CodeWall", "mode": "contains"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "CodeWall .NET obfuscator and licensing runtime",
        ],
    },
    "CodeFort": {
        "layer": "obfuscator",
        "verified": True,
        "attributes": [
            {"p": "CodeFortAttribute", "mode": "exact"},
        ],
        "type_names": [],
        "namespaces": [
            {"p": "CodeFort", "mode": "token"},
        ],
        "assembly_refs": [],
        "strings": [
            {"p": "CodeFort", "mode": "contains"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "CodeFort .NET obfuscator",
        ],
    },
    "Rummage": {
        "layer": "obfuscator",
        "verified": True,
        "attributes": [
            {"p": "RummageKeepAttribute", "mode": "exact"},
        ],
        "type_names": [],
        "namespaces": [
            {"p": "Rummage", "mode": "token"},
        ],
        "assembly_refs": [],
        "strings": [
            {"p": "Rummage Keep", "mode": "contains"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Rummage .NET obfuscator by Rummage Software",
        ],
    },
    "Macrobject Obfuscator.NET": {
        "layer": "obfuscator",
        "verified": True,
        "attributes": [
            {"p": "Macrobject", "mode": "prefix"},
        ],
        "type_names": [],
        "namespaces": [
            {"p": "Macrobject", "mode": "token"},
        ],
        "assembly_refs": [],
        "strings": [
            {"p": "Macrobject", "mode": "contains"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Macrobject Obfuscator.NET watermark and attribute",
        ],
    },
    "Dotnet Patcher": {
        "layer": "obfuscator",
        "verified": False,
        "confidence_cap": "LOW",
        "attributes": [],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            {"p": "DotnetPatcher", "mode": "contains"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Dotnet Patcher obfuscator",
        ],
    },
    "Salamander (Remotesoft)": {
        "layer": "obfuscator",
        "verified": True,
        "attributes": [
            {"p": "SalamanderAttribute", "mode": "exact"},
        ],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            {"p": "Remotesoft Salamander", "mode": "contains"},
            {"p": "Salamander .NET", "mode": "contains"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Remotesoft Salamander .NET protector and native packager",
        ],
    },
    "Sixxpack": {
        "layer": "packer",
        "verified": True,
        "attributes": [],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            {"p": "sixxpack", "mode": "contains"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Sixxpack .NET executable packer and crypter",
        ],
    },
    "RPX": {
        "layer": "packer",
        "verified": True,
        "attributes": [],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            {"p": "RPX - Real-time Packer", "mode": "contains"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "RPX executable compressor for .NET",
        ],
    },
    "Fody (Generic)": {
        "layer": "bundler",
        "verified": True,
        "attributes": [
            {"p": "FodyVersion", "mode": "exact"},
        ],
        "type_names": [
            {"p": "Fody", "mode": "token"},
        ],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            {"p": "FodyVersion", "mode": "contains"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Fody IL weaving and assembly manipulation framework",
        ],
    },
    "ILMerge": {
        "layer": "bundler",
        "verified": True,
        "attributes": [
            {"p": "ILMergeAttribute", "mode": "exact"},
        ],
        "type_names": [
            {"p": "ILMerge", "mode": "token"},
        ],
        "namespaces": [
            {"p": "ILMerge", "mode": "token"},
        ],
        "assembly_refs": [],
        "strings": [
            {"p": "ILMerge.exe", "mode": "contains"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Microsoft ILMerge static assembly merging tool",
        ],
    },
    "ILRepack": {
        "layer": "bundler",
        "verified": True,
        "attributes": [],
        "type_names": [
            {"p": "ILRepack", "mode": "token"},
        ],
        "namespaces": [
            {"p": "ILRepack", "mode": "token"},
        ],
        "assembly_refs": [],
        "strings": [
            {"p": "ILRepack", "mode": "contains"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "ILRepack open-source assembly merging tool",
        ],
    },
    "Thales Sentinel Envelope .NET": {
        "layer": "licensing",
        "verified": True,
        "attributes": [],
        "type_names": [
            {"p": "SentinelEnvelope", "mode": "token"},
        ],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            {"p": "Sentinel Envelope", "mode": "contains"},
            {"p": "HASP Envelope", "mode": "contains"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [
            "hasp_windows",
        ],
        "clr_stream_markers": [],
        "characteristics": [
            "Thales Sentinel / SafeNet HASP hardware licensing envelope",
        ],
    },
    "Wibu CodeMeter AxProtector .NET": {
        "layer": "licensing",
        "verified": True,
        "attributes": [],
        "type_names": [
            {"p": "AxProtector", "mode": "token"},
        ],
        "namespaces": [
            {"p": "WibuCmNET", "mode": "token"},
        ],
        "assembly_refs": [
            {"p": "WibuCmNET", "mode": "exact"},
        ],
        "strings": [
            {"p": "AxProtector", "mode": "contains"},
            {"p": "WibuCmNET", "mode": "contains"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [
            "wibucm32",
            "wibucm64",
        ],
        "clr_stream_markers": [],
        "characteristics": [
            "Wibu-Systems CodeMeter AxProtector encryption envelope",
        ],
    },
    "Digital.ai / Arxan .NET": {
        "layer": "protector",
        "verified": True,
        "attributes": [],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            {"p": "TransformIT", "mode": "contains"},
            {"p": "Arxan Technologies", "mode": "contains"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Digital.ai / Arxan application protection and integrity checking",
        ],
    },
    "Agile.NET VM": {
        "layer": "virtualizer",
        "verified": True,
        "attributes": [],
        "type_names": [
            {"p": "AgileDotNetVM", "mode": "token"},
        ],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            {"p": "Agile.NET VM", "mode": "contains"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Agile.NET CIL virtualization engine",
        ],
    },
    "Babel VM": {
        "layer": "virtualizer",
        "verified": True,
        "attributes": [],
        "type_names": [
            {"p": "BabelVM", "mode": "token"},
        ],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            {"p": "Babel VM", "mode": "contains"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Babel Obfuscator MSIL instruction virtualizer",
        ],
    },
    "Eazfuscator VM": {
        "layer": "virtualizer",
        "verified": True,
        "attributes": [],
        "type_names": [],
        "namespaces": [],
        "assembly_refs": [],
        "strings": [
            {"p": "Eazfuscator.NET.VM", "mode": "contains"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [],
        "characteristics": [
            "Eazfuscator.NET virtual machine code virtualization",
        ],
    },
    "KoiVM": {
        "layer": "virtualizer",
        "verified": True,
        "attributes": [],
        "type_names": [
            {"p": "KoiVM", "mode": "token"},
        ],
        "namespaces": [
            {"p": "KoiVM", "mode": "token"},
        ],
        "assembly_refs": [],
        "strings": [
            {"p": "KoiVM", "mode": "token"},
        ],
        "resource_names": [],
        "resource_magic": [],
        "import_names": [],
        "clr_stream_markers": [
            "#Koi",
        ],
        "characteristics": [
            "KoiVM ConfuserEx virtual machine bytecode engine",
            "#Koi custom CLR metadata stream",
        ],
    },
}

# ---------------------------------------------------------------------------
# PE section name -> named tool mapping
# ---------------------------------------------------------------------------
SECTION_NAME_TO_TOOL: Dict[str, str] = {
    ".vmp":      "VMProtect",
    ".vmp0":     "VMProtect",
    ".vmp1":     "VMProtect",
    ".vmp2":     "VMProtect",
    ".themida":  "Themida / WinLicense",
    ".winlic":   "Themida / WinLicense",
    "upx0":      "UPX Packer",
    "upx1":      "UPX Packer",
    "upx2":      "UPX Packer",
    ".upx0":     "UPX Packer",
    ".upx1":     "UPX Packer",
    ".enigma1":  "Enigma Protector",
    ".enigma2":  "Enigma Protector",
    ".cflow":    "ConfuserEx (Native Stub)",
    ".aspack":   "ASPack / ASProtect",
    ".adata":    "ASPack / ASProtect",
    ".petite":   "Petite Packer",
    ".fsg":      "FSG Packer",
    ".mpress":   "MPRESS Packer",
    ".mpress1":  "MPRESS Packer",
    ".mpress2":  "MPRESS Packer",
    ".box":      "BoxedApp Packer",
    "boxedapp":  "BoxedApp Packer",
    "safengine": "SafeEngine Shielden",
    ".netshrink":"NetShrink",
    ".netz":     "Netz (.NET Compressor)",
}

# ---------------------------------------------------------------------------
# PE IAT DLL name fragment -> named tool mapping
# ---------------------------------------------------------------------------
KNOWN_PACKER_IMPORTS: Dict[str, str] = {
    "enigma_mscoree":  "Enigma Protector",
    "asprotect":       "ASPack / ASProtect",
    "netshrink":       "NetShrink",
    "safengine":       "SafeEngine Shielden",
    "themida":         "Themida / WinLicense",
    "winlicense":      "Themida / WinLicense",
    "boxedapp":        "BoxedApp Packer",
    "oreans":          "Themida / WinLicense",
}

# ---------------------------------------------------------------------------
# Suspicious PE section names (used by analyzer for flagging)
# ---------------------------------------------------------------------------
SUSPICIOUS_SECTIONS = [
    ".vmp",
    ".vmp0",
    ".vmp1",
    ".vmp2",
    ".themida",
    ".winlic",
    "upx0",
    "upx1",
    "upx2",
    ".enigma1",
    ".enigma2",
    ".cflow",
    "_text",
    ".aspack",
    ".adata",
    ".petite",
    ".fsg",
    ".mpress",
    ".mpress1",
    ".mpress2",
    ".box",
    "boxedapp",
    "safengine",
    ".netshrink",
    ".netz",
]

# ---------------------------------------------------------------------------
# Invisible / zero-width Unicode characters used by ConfuserEx / MindLated
# ---------------------------------------------------------------------------
INVISIBLE_CHARS = {
    "\u200B": "Zero-Width Space",
    "\u200C": "Zero-Width Non-Joiner",
    "\u200D": "Zero-Width Joiner",
    "\uFEFF": "Zero-Width No-Break Space (BOM)",
    "\u2060": "Word Joiner",
    "\u200E": "Left-to-Right Mark",
    "\u200F": "Right-to-Left Mark",
    "\u202A": "Left-to-Right Embedding",
    "\u202B": "Right-to-Left Embedding",
    "\u202C": "Pop Directional Formatting",
    "\u202D": "Left-to-Right Override",
    "\u202E": "Right-to-Left Override",
}


def validate_signatures() -> None:
    """
    Validates all signatures in OBFUSCATOR_SIGNATURES:
      - Valid layer defined
      - Compiles all patterns and catches short contains patterns or syntax errors
    """
    valid_layers = {"packer", "protector", "obfuscator", "virtualizer", "licensing", "bundler", "info"}
    for name, sig in OBFUSCATOR_SIGNATURES.items():
        layer = sig.get("layer")
        if layer not in valid_layers:
            raise ValueError(f"Signature '{name}' has invalid layer: '{layer}' (must be one of {valid_layers})")

        for key, def_mode in [
            ("attributes", "token"),
            ("type_names", "token"),
            ("namespaces", "token"),
            ("assembly_refs", "exact"),
            ("strings", "contains"),
            ("resource_names", "prefix"),
            ("resource_magic", "prefix"),
            ("import_names", "token"),
            ("clr_stream_markers", "exact"),
        ]:
            for item in sig.get(key, []):
                mode = def_mode
                if isinstance(item, str) and key == "strings" and len(item) < 8:
                    mode = "token"
                compile_pattern(item, default_mode=mode)
