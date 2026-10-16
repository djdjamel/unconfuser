"""
PE and .NET Metadata Analyzer using dnfile, dotnetfile, and pefile.
Phase 11: Deep extraction v2 (local attributes, CA blobs, ImplMap, FieldRVA, TypeDef Extends,
streams, heaps, Win32 resources, section characteristics, and entry point resolution).
"""

import os
from typing import Dict, Any, List, Optional
import pefile
import dnfile
import dnfile.utils
from dotnetfile import DotNetPE

from .heuristics import calculate_entropy, evaluate_identifier_collection
from .signatures import SUSPICIOUS_SECTIONS


def parse_ca_blob(data: bytes) -> List[str]:
    """
    Extracts leading SerString arguments from an ECMA-335 CustomAttribute Value blob.
    Prolog: 0x0001 (little endian).
    """
    if not data or len(data) < 3 or data[:2] != b"\x01\x00":
        return []
    args: List[str] = []
    offset = 2
    for _ in range(4):
        if offset >= len(data):
            break
        try:
            if data[offset] == 0xFF:  # null string in ECMA-335 SerString
                offset += 1
                continue
            str_len, bytes_read = dnfile.utils.read_compressed_int(data[offset:])
            offset += bytes_read
            if offset + str_len > len(data):
                break
            val = data[offset : offset + str_len].decode("utf-8", errors="ignore")
            offset += str_len
            if val:
                args.append(val)
        except Exception:
            break
    return args


class BinaryAnalyzer:
    """
    Performs deep static analysis on Windows PE and .NET binaries.
    """

    def __init__(self, file_path: str, skip_il: bool = False):
        self.file_path = file_path
        self.skip_il = skip_il
        self.file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

    def analyze(self) -> Dict[str, Any]:
        """
        Runs full analysis and returns a comprehensive metadata dictionary.
        """
        result: Dict[str, Any] = {
            "file_path": self.file_path,
            "file_size": self.file_size,
            "is_valid_pe": False,
            "is_dotnet": False,
            "machine": None,
            "subsystem": None,
            "pe_sections": [],
            "high_entropy_sections": [],
            "suspicious_sections": [],
            "has_overlay": False,
            "overlay_size": 0,
            "overlay_entropy": 0.0,
            "overlay_ratio": 0.0,
            "pe_timestamp": 0,
            "has_rich_header": False,
            "debug_directory_present": False,
            "import_dlls": [],
            "has_import_table": False,
            "ep_section": None,
            "native_ep_bytes": "",
            "ep_signature_match": None,
            "win32_resources": [],
            "overlay_indicators": [],
            "packaging_formats": [],
            "dotnet_info": {},
            "errors": [],
        }

        if not os.path.isfile(self.file_path):
            result["errors"].append(f"File not found: {self.file_path}")
            return result

        # 1. Parse PE with pefile
        try:
            pe = pefile.PE(self.file_path)
            result["is_valid_pe"] = True
            result["machine"] = hex(pe.FILE_HEADER.Machine)
            result["subsystem"] = pe.OPTIONAL_HEADER.Subsystem
            native_ep = getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0)

            # Analyze sections
            last_section_end = 0
            for sec in pe.sections:
                sec_name = sec.Name.decode("utf-8", errors="ignore").strip("\x00")
                sec_data = sec.get_data()
                sec_entropy = calculate_entropy(sec_data)
                is_rwx = bool((sec.Characteristics & 0xE0000000) == 0xE0000000)
                virtual_only = bool(sec.SizeOfRawData == 0 and sec.Misc_VirtualSize > 0)

                # Check if native EP is in this section
                sec_start = sec.VirtualAddress
                sec_end_v = sec.VirtualAddress + max(sec.Misc_VirtualSize, sec.SizeOfRawData)
                if sec_start <= native_ep < sec_end_v:
                    result["ep_section"] = sec_name

                sec_info = {
                    "name": sec_name,
                    "virtual_size": sec.Misc_VirtualSize,
                    "raw_size": sec.SizeOfRawData,
                    "entropy": sec_entropy,
                    "characteristics": sec.Characteristics,
                    "is_rwx": is_rwx,
                    "virtual_only": virtual_only,
                }
                result["pe_sections"].append(sec_info)

                if sec_entropy >= 7.1 and len(sec_data) > 1024:
                    result["high_entropy_sections"].append(sec_info)

                sec_name_lower = sec_name.lower()
                for sus in SUSPICIOUS_SECTIONS:
                    if sus in sec_name_lower:
                        result["suspicious_sections"].append(sec_info)
                        break

                sec_end = sec.PointerToRawData + sec.SizeOfRawData
                if sec_end > last_section_end:
                    last_section_end = sec_end

            # Check for overlay
            if self.file_size > last_section_end:
                result["has_overlay"] = True
                result["overlay_size"] = self.file_size - last_section_end
                result["overlay_ratio"] = round(result["overlay_size"] / self.file_size, 3)
                try:
                    with open(self.file_path, "rb") as f:
                        f.seek(last_section_end)
                        overlay_data = f.read(65536)
                        result["overlay_entropy"] = calculate_entropy(overlay_data)
                        from .overlay import inspect_overlay
                        result["overlay_indicators"] = inspect_overlay(overlay_data)
                except Exception:
                    pass

            # Native EP bytes and signature match
            if native_ep:
                try:
                    ep_bytes = pe.get_data(native_ep, 64)
                    if ep_bytes:
                        result["native_ep_bytes"] = ep_bytes.hex()
                        from .ep_signatures import EntryPointMatcher
                        matcher = EntryPointMatcher()
                        result["ep_signature_match"] = matcher.match(ep_bytes)
                except Exception:
                    pass

            # PE timestamp, Rich Header, debug directory
            result["pe_timestamp"] = pe.FILE_HEADER.TimeDateStamp
            result["has_rich_header"] = hasattr(pe, "RICH_HEADER") and pe.RICH_HEADER is not None
            result["debug_directory_present"] = hasattr(pe, "DIRECTORY_ENTRY_DEBUG")

            # Collect IAT import DLL names
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for imp_entry in pe.DIRECTORY_ENTRY_IMPORT:
                    try:
                        dll_name = imp_entry.dll.decode("utf-8", errors="ignore").lower().rstrip("\x00")
                        if dll_name:
                            result["import_dlls"].append(dll_name)
                    except Exception:
                        pass
            result["has_import_table"] = len(result["import_dlls"]) > 0

            # Win32 resources (RT_RCDATA / type 10 etc.)
            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    t_id = getattr(type_entry, "id", None)
                    t_name = str(getattr(type_entry, "name", "") or t_id)
                    if hasattr(type_entry, "directory"):
                        for name_entry in type_entry.directory.entries:
                            if hasattr(name_entry, "directory"):
                                for lang_entry in name_entry.directory.entries:
                                    try:
                                        data_rva = lang_entry.data.struct.OffsetToData
                                        data_sz = lang_entry.data.struct.Size
                                        raw_res = pe.get_data(data_rva, min(data_sz, 65536))
                                        result["win32_resources"].append({
                                            "type": t_name,
                                            "size": data_sz,
                                            "magic_bytes": raw_res[:8].hex(),
                                            "entropy": calculate_entropy(raw_res),
                                        })
                                    except Exception:
                                        pass

            pe.close()
        except pefile.PEFormatError as e:
            result["errors"].append(f"Not a valid PE executable: {e}")
            return result
        except Exception as e:
            result["errors"].append(f"PE parsing error: {e}")
            return result

        # 2. Parse .NET metadata with dnfile & dotnetfile
        try:
            dn_pe = dnfile.dnPE(self.file_path)
            if dn_pe.net is None:
                result["is_dotnet"] = False
                return result

            result["is_dotnet"] = True
            dotnet_info = self._extract_dotnet_metadata(dn_pe)

            # Collect CLR metadata stream names and heap entropies (Phase 11)
            stream_names: List[str] = []
            stream_list: List[Dict[str, Any]] = []
            heap_entropy: Dict[str, float] = {}
            stream_counts: Dict[str, int] = {}

            try:
                streams = getattr(dn_pe.net.metadata, "streams", None) or {}
                for s_key, st in streams.items():
                    s_name = s_key.decode("utf-8", errors="ignore").strip("\x00") if isinstance(s_key, bytes) else str(s_key)
                    if s_name:
                        stream_names.append(s_name)
                        stream_counts[s_name] = stream_counts.get(s_name, 0) + 1
                        st_sz_attr = getattr(st, "sizeof", 0)
                        if callable(st_sz_attr):
                            try:
                                st_sz = st_sz_attr()
                            except Exception:
                                st_sz = 0
                        else:
                            st_sz = st_sz_attr or 0
                        st_rva = getattr(st, "rva", 0)
                        stream_list.append({"name": s_name, "size": st_sz, "rva": st_rva})

                        # Heap entropy for #Blob, #US, #Strings
                        if s_name in ("#Blob", "#US", "#Strings") and st_sz > 0:
                            raw_heap = dn_pe.get_data(st_rva, min(st_sz, 65536))
                            if raw_heap:
                                heap_entropy[s_name] = calculate_entropy(raw_heap)
            except Exception:
                pass

            dotnet_info["clr_stream_names"] = stream_names
            dotnet_info["clr_streams"] = stream_list
            dotnet_info["heap_entropy"] = heap_entropy
            dotnet_info["duplicate_streams"] = [k for k, v in stream_counts.items() if v > 1]

            result["dotnet_info"] = dotnet_info
            dn_pe.close()
        except Exception as e:
            result["errors"].append(f"dnfile parsing error: {e}")

        # 3. Augment with dotnetfile for anti-metadata heuristics & public key tokens
        try:
            dotnet_file = DotNetPE(self.file_path)
            if result["is_dotnet"] and dotnet_file.is_dotnet_file():
                result["dotnet_info"]["anti_metadata"] = dotnet_file.dotnet_anti_metadata
                result["dotnet_info"]["is_mixed_assembly"] = dotnet_file.is_mixed_assembly()

                # User strings
                if not result["dotnet_info"].get("user_strings"):
                    raw_user_strings = dotnet_file.get_user_stream_strings() or []
                    raw_user_strings = [s for s in raw_user_strings if s]
                    if len(raw_user_strings) > 2000:
                        raw_user_strings = raw_user_strings[:2000]
                    result["dotnet_info"]["user_strings"] = raw_user_strings

                # Metadata strings
                if not result["dotnet_info"].get("metadata_strings"):
                    raw_strings = dotnet_file.get_strings_stream_strings() or []
                    result["dotnet_info"]["metadata_strings"] = [s for s in raw_strings if s]
            dotnet_file.close()
        except Exception as e:
            result["errors"].append(f"dotnetfile parsing warning: {e}")

        # 4. Packaging formats detection (Phase 14)
        try:
            from .formats import (
                detect_single_file_bundle,
                detect_native_aot,
                detect_readytorun,
                detect_mixed_mode,
            )
            with open(self.file_path, "rb") as f:
                head_data = f.read(min(self.file_size, 4 * 1024 * 1024))
            bundle = detect_single_file_bundle(head_data)
            if bundle:
                result["packaging_formats"].append(bundle)

            if result.get("is_dotnet"):
                r2r = detect_readytorun(result.get("dotnet_info", {}))
                if r2r:
                    result["packaging_formats"].append(r2r)
                mixed = detect_mixed_mode(result.get("dotnet_info", {}), result.get("import_dlls", []))
                if mixed:
                    result["packaging_formats"].append(mixed)
            else:
                aot = detect_native_aot(pe, result)
                if aot:
                    result["packaging_formats"].append(aot)
        except Exception:
            pass

        return result

    def _extract_dotnet_metadata(self, dn_pe: dnfile.dnPE) -> Dict[str, Any]:
        """
        Extracts tables, attributes, types, methods, P/Invoke, FieldRVA, and resources.
        """
        dn_data: Dict[str, Any] = {
            "runtime_version": None,
            "flags": {},
            "assembly_name": None,
            "assembly_version": None,
            "assembly_refs": [],
            "custom_attributes": [],
            "has_suppress_ildasm": False,
            "type_names": [],
            "namespaces": [],
            "types": [],
            "method_names": [],
            "field_names": [],
            "member_refs": [],
            "pinvoke_imports": [],
            "field_rva_blobs": [],
            "empty_rva_methods_count": 0,
            "cctor_count": 0,
            "module_methods": [],
            "has_module_cctor": False,
            "resources": [],
            "high_entropy_resources": [],
            "user_strings": [],
            "metadata_strings": [],
            "clr_stream_names": [],
            "clr_streams": [],
            "heap_entropy": {},
            "duplicate_streams": [],
            "identifier_metrics": {},
            "il_metrics": {},
            "entry_point_token": 0,
            "is_readytorun": False,
            "public_key_token": "",
        }

        # Runtime Version
        raw_version = getattr(dn_pe.net.metadata.struct, "Version", b"")
        if isinstance(raw_version, bytes):
            dn_data["runtime_version"] = raw_version.decode("utf-8", errors="ignore").strip("\x00")
        elif raw_version:
            dn_data["runtime_version"] = str(raw_version).strip("\x00")

        # Entry Point Token
        dn_data["entry_point_token"] = getattr(dn_pe.net.struct, "EntryPointToken", 0)

        # CLR Header Flags
        if hasattr(dn_pe.net, "Flags"):
            flags = dn_pe.net.Flags
            dn_data["flags"] = {
                "ILOnly": getattr(flags, "CLR_ILONLY", False),
                "32BitRequired": getattr(flags, "CLR_32BITREQUIRED", False),
                "NativeEntryPoint": getattr(flags, "CLR_NATIVE_ENTRYPOINT", False),
                "StrongNameSigned": getattr(flags, "CLR_STRONGNAMESIGNED", False),
            }

        # ReadyToRun detection
        if hasattr(dn_pe.net.struct, "ManagedNativeHeader") and dn_pe.net.struct.ManagedNativeHeader.VirtualAddress != 0:
            dn_data["is_readytorun"] = True

        mdtables = getattr(dn_pe.net, "mdtables", None)
        if not mdtables:
            return dn_data

        # Assembly Name & Version & Public Key Token
        if hasattr(mdtables, "Assembly") and mdtables.Assembly:
            rows = getattr(mdtables.Assembly, "rows", mdtables.Assembly)
            if rows:
                asm = rows[0]
                dn_data["assembly_name"] = str(getattr(asm, "Name", ""))
                v_maj = getattr(asm, "MajorVersion", 0)
                v_min = getattr(asm, "MinorVersion", 0)
                v_bld = getattr(asm, "BuildNumber", 0)
                v_rev = getattr(asm, "RevisionNumber", 0)
                dn_data["assembly_version"] = f"{v_maj}.{v_min}.{v_bld}.{v_rev}"

                # Calculate public key token if public key is present
                pk_val = getattr(asm, "PublicKey", None)
                pk_bytes = getattr(pk_val, "value", pk_val)
                if pk_bytes and isinstance(pk_bytes, (bytes, bytearray)) and len(pk_bytes) > 0:
                    import hashlib
                    h = hashlib.sha1(bytes(pk_bytes)).digest()
                    dn_data["public_key_token"] = h[-8:][::-1].hex().lower()

        # AssemblyRef (Table 0x23)
        if hasattr(mdtables, "AssemblyRef") and mdtables.AssemblyRef:
            ref_rows = getattr(mdtables.AssemblyRef, "rows", mdtables.AssemblyRef)
            for r in ref_rows:
                ref_name = str(getattr(r, "Name", ""))
                if ref_name and ref_name not in dn_data["assembly_refs"]:
                    dn_data["assembly_refs"].append(ref_name)

        # TypeDef (Table 0x02) - Pre-scan to build method -> typedef map and delegates
        method_to_typedef: Dict[int, Any] = {}
        delegate_methods: set = set()
        td_rows = getattr(mdtables.TypeDef, "rows", []) if hasattr(mdtables, "TypeDef") and mdtables.TypeDef else []

        for td in td_rows:
            t_name = str(getattr(td, "TypeName", ""))
            t_ns = str(getattr(td, "TypeNamespace", ""))

            # Resolve Extends
            extends_name = ""
            if hasattr(td, "Extends") and hasattr(td.Extends, "row") and td.Extends.row:
                extends_name = str(getattr(td.Extends.row, "TypeName", ""))
            is_del = extends_name in ("MulticastDelegate", "Delegate")

            if t_name and t_name != "<Module>":
                dn_data["type_names"].append(t_name)
                if t_ns and t_ns not in dn_data["namespaces"]:
                    dn_data["namespaces"].append(t_ns)
                dn_data["types"].append({
                    "name": t_name,
                    "namespace": t_ns,
                    "extends": extends_name,
                    "is_delegate": is_del,
                })

            # Map methods to this TypeDef
            if hasattr(td, "MethodList") and td.MethodList:
                for m in td.MethodList:
                    if hasattr(m, "row") and m.row:
                        method_to_typedef[id(m.row)] = td
                        if is_del:
                            delegate_methods.add(id(m.row))
                        if t_name == "<Module>":
                            m_name = str(getattr(m.row, "Name", ""))
                            dn_data["module_methods"].append(m_name)
                            if m_name == ".cctor":
                                dn_data["has_module_cctor"] = True

        # Custom Attributes (Table 0x0C) - Phase 11: resolves both TypeRef (external) and MethodDef (local)
        if hasattr(mdtables, "CustomAttribute") and mdtables.CustomAttribute:
            ca_rows = getattr(mdtables.CustomAttribute, "rows", mdtables.CustomAttribute)
            for ca in ca_rows:
                if hasattr(ca, "Type") and hasattr(ca.Type, "row") and ca.Type.row:
                    parent = ca.Type.row
                    attr_name = ""
                    attr_ns = ""
                    is_local = False

                    # External attribute via MemberRef -> TypeRef
                    if hasattr(parent, "Class") and hasattr(parent.Class, "row") and parent.Class.row:
                        cls = parent.Class.row
                        attr_name = str(getattr(cls, "TypeName", ""))
                        attr_ns = str(getattr(cls, "TypeNamespace", ""))
                    # Local attribute via MethodDef -> declaring TypeDef (Gap A2)
                    elif id(parent) in method_to_typedef:
                        declaring_td = method_to_typedef[id(parent)]
                        attr_name = str(getattr(declaring_td, "TypeName", ""))
                        attr_ns = str(getattr(declaring_td, "TypeNamespace", ""))
                        is_local = True

                    if attr_name:
                        full_name = f"{attr_ns}.{attr_name}" if attr_ns else attr_name
                        # Parse SerString argument values (Gap A3)
                        ca_val = getattr(ca, "Value", None)
                        raw_bytes = getattr(ca_val, "value", ca_val) or b""
                        blob_args = parse_ca_blob(raw_bytes if isinstance(raw_bytes, (bytes, bytearray)) else b"")
                        dn_data["custom_attributes"].append({
                            "name": attr_name,
                            "namespace": attr_ns,
                            "full_name": full_name,
                            "is_local": is_local,
                            "args": blob_args,
                        })
                        if "suppressildasm" in attr_name.lower():
                            dn_data["has_suppress_ildasm"] = True

        # MethodDef (Table 0x06) - Phase 11: checks ImplFlags (Gap A5) and delegate ownership
        empty_rva_count = 0
        cctor_count = 0
        if hasattr(mdtables, "MethodDef") and mdtables.MethodDef:
            md_rows = getattr(mdtables.MethodDef, "rows", mdtables.MethodDef)
            for md in md_rows:
                m_name = str(getattr(md, "Name", ""))
                if m_name:
                    dn_data["method_names"].append(m_name)
                    if m_name == ".cctor":
                        cctor_count += 1

                # Check for empty RVA method bodies (exclude abstract, pinvoke, runtime/internalcall, and delegates)
                rva = getattr(md, "Rva", 0)
                flags = getattr(md, "Flags", None)
                impl_flags = getattr(md, "ImplFlags", 0)
                is_abstract = getattr(flags, "mdAbstract", False) if flags else False
                is_pinvoke = getattr(flags, "mdPinvokeImpl", False) if flags else False
                # ECMA-335: miRuntime, miInternalCall, miNative have no RVA
                is_runtime_impl = (
                    getattr(impl_flags, "miRuntime", False)
                    or getattr(impl_flags, "miInternalCall", False)
                    or getattr(impl_flags, "miNative", False)
                    or getattr(impl_flags, "miOPTIL", False)
                ) if impl_flags else False
                is_del_method = id(md) in delegate_methods

                if rva == 0 and not is_abstract and not is_pinvoke and not is_runtime_impl and not is_del_method:
                    empty_rva_count += 1

        dn_data["empty_rva_methods_count"] = empty_rva_count
        dn_data["cctor_count"] = cctor_count

        # Field (Table 0x04)
        if hasattr(mdtables, "Field") and mdtables.Field:
            f_rows = getattr(mdtables.Field, "rows", mdtables.Field)
            for f in f_rows:
                f_name = str(getattr(f, "Name", ""))
                if f_name:
                    dn_data["field_names"].append(f_name)

        # ImplMap (Table 0x1C) - Phase 11: P/Invoke imports (Gap A4)
        if hasattr(mdtables, "ImplMap") and mdtables.ImplMap:
            for r in getattr(mdtables.ImplMap, "rows", []):
                imp_name = str(getattr(r, "ImportName", ""))
                mod_name = ""
                if hasattr(r, "ImportScope") and hasattr(r.ImportScope, "row") and r.ImportScope.row:
                    mod_name = str(getattr(r.ImportScope.row, "Name", ""))
                if imp_name or mod_name:
                    dn_data["pinvoke_imports"].append({"dll": mod_name, "name": imp_name})

        # FieldRVA (Table 0x1D) - Phase 11: static field data blobs (Gap A6)
        if hasattr(mdtables, "FieldRva") and mdtables.FieldRva:
            for r in getattr(mdtables.FieldRva, "rows", []):
                rva = getattr(r, "Rva", 0)
                if rva > 0:
                    raw_blob = dn_pe.get_data(rva, 65536) or b""
                    f_name = ""
                    if hasattr(r, "Field") and hasattr(r.Field, "row") and r.Field.row:
                        f_name = str(getattr(r.Field.row, "Name", ""))
                    dn_data["field_rva_blobs"].append({
                        "field": f_name,
                        "rva": rva,
                        "size": len(raw_blob),
                        "entropy": calculate_entropy(raw_blob),
                        "magic": raw_blob[:8].hex() if raw_blob else "",
                    })

        # MemberRef (Table 0x0A)
        if hasattr(mdtables, "MemberRef") and mdtables.MemberRef:
            mr_rows = getattr(mdtables.MemberRef, "rows", mdtables.MemberRef)
            for mr in mr_rows:
                mr_name = str(getattr(mr, "Name", ""))
                mr_class = getattr(mr, "Class", None)
                parent_str = ""
                if mr_class and hasattr(mr_class, "row") and mr_class.row:
                    parent_row = mr_class.row
                    p_name = str(getattr(parent_row, "TypeName", ""))
                    p_ns   = str(getattr(parent_row, "TypeNamespace", ""))
                    parent_str = f"{p_ns}.{p_name}" if p_ns else p_name
                if mr_name or parent_str:
                    dn_data["member_refs"].append({
                        "name":   mr_name,
                        "parent": parent_str,
                    })

        # Resources
        if hasattr(dn_pe.net, "resources") and dn_pe.net.resources:
            for res in dn_pe.net.resources:
                r_name = str(getattr(res, "name", "Unnamed"))
                r_size = getattr(res, "size", 0)
                res_obj = getattr(res, "data", None)
                if hasattr(res_obj, "_data") and isinstance(res_obj._data, (bytes, bytearray)):
                    r_bytes = bytes(res_obj._data)
                elif isinstance(res_obj, (bytes, bytearray)):
                    r_bytes = bytes(res_obj)
                else:
                    r_bytes = b""

                r_entropy = calculate_entropy(r_bytes) if r_bytes else 0.0
                r_magic = r_bytes[:16].hex() if r_bytes else ""
                res_info = {
                    "name": r_name,
                    "size": r_size,
                    "entropy": r_entropy,
                    "magic_bytes": r_magic,
                }
                dn_data["resources"].append(res_info)
                if r_entropy >= 7.2 and r_size > 512:
                    dn_data["high_entropy_resources"].append(res_info)

        # Identifier Heuristics across Type, Method, and Field names
        all_identifiers = (
            dn_data["type_names"]
            + dn_data["method_names"]
            + dn_data["field_names"]
        )
        dn_data["identifier_metrics"] = evaluate_identifier_collection(all_identifiers)

        # IL Method Body Analysis (Phase 13)
        if not self.skip_il and hasattr(mdtables, "MethodDef") and mdtables.MethodDef:
            try:
                from .il import evaluate_assembly_il
                method_rows = getattr(mdtables.MethodDef, "rows", mdtables.MethodDef)
                dn_data["il_metrics"] = evaluate_assembly_il(dn_pe, method_rows, max_methods=1000)
            except Exception:
                dn_data["il_metrics"] = {}

        return dn_data
