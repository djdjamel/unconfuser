"""
API indicators and behavioral pattern detection for .NET assemblies (Phase 12).
Evaluates MemberRef calls and P/Invoke (ImplMap) imports against known anti-analysis,
anti-tamper, dynamic method resolution, and runtime unpacking APIs.
"""

from typing import List, Dict, Any, Set


ANTI_DEBUG_APIS = {
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "ntqueryinformationprocess",
    "debugger.get_isattached",
    "debugger.islogging",
    "debugger.break",
}

ANTI_TAMPER_APIS = {
    "virtualprotect",
    "virtualalloc",
    "writeprocessmemory",
    "marshal.gethinstance",
    "getmodulehandle",
    "getmodulehandlew",
    "getmodulehandlea",
}

DYNAMIC_LOADING_APIS = {
    "assembly.load",
    "assembly.loadfrom",
    "appdomain.add_assemblyresolve",
    "assemblyresolve",
    "assembly.getmanifestresourcestream",
}

DYNAMIC_CODE_APIS = {
    "dynamicmethod",
    "ilgenerator.emit",
    "module.resolvemethod",
    "module.resolvefield",
    "module.resolvestring",
    "runtimehelpers.preparemethod",
    "methodbase.getmethodbody",
    "marshal.getdelegateforfunctionpointer",
}


def evaluate_api_indicators(
    member_refs: List[Dict[str, Any]],
    pinvoke_imports: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Scans declared MemberRefs and P/Invoke imports for combinations of APIs
    characteristic of protectors, packers, and dynamic decrypters.
    """
    techniques: List[Dict[str, Any]] = []

    # Build normalized API signature sets
    seen_apis: Set[str] = set()

    for mr in member_refs:
        name = mr.get("name", "").lower()
        parent = mr.get("parent", "").lower()
        seen_apis.add(name)
        if parent:
            seen_apis.add(f"{parent}.{name}")
            parent_short = parent.split(".")[-1]
            seen_apis.add(f"{parent_short}.{name}")

    for pi in pinvoke_imports:
        name = pi.get("name", "").lower()
        seen_apis.add(name)

    # 1. Anti-Debugging Check
    matched_anti_debug = [api for api in ANTI_DEBUG_APIS if api in seen_apis]
    if len(matched_anti_debug) >= 2 or ("isdebuggerpresent" in seen_apis and "checkremotedebuggerpresent" in seen_apis):
        techniques.append({
            "technique": "Anti-Debugging Checks",
            "severity": "HIGH",
            "weight": 3,
            "kind": "structural",
            "details": f"References debugger detection APIs: {', '.join(matched_anti_debug[:4])}",
        })

    # 2. Anti-Tamper / Memory Manipulation Check
    matched_anti_tamper = [api for api in ANTI_TAMPER_APIS if api in seen_apis]
    if "virtualprotect" in seen_apis or len(matched_anti_tamper) >= 2:
        techniques.append({
            "technique": "Memory Protection / Anti-Tamper APIs",
            "severity": "HIGH",
            "weight": 4,
            "kind": "structural",
            "details": f"Imports native memory modification APIs: {', '.join(matched_anti_tamper[:4])}",
        })

    # 3. Dynamic Runtime Assembly Decryptor / Loader
    has_load_bytes = "assembly.load" in seen_apis
    has_resolve = "assemblyresolve" in seen_apis or "appdomain.add_assemblyresolve" in seen_apis
    has_res_stream = "assembly.getmanifestresourcestream" in seen_apis

    if (has_load_bytes and (has_resolve or has_res_stream)) or (has_resolve and has_res_stream):
        techniques.append({
            "technique": "Dynamic Assembly Resolution & In-Memory Loading",
            "severity": "HIGH",
            "weight": 4,
            "kind": "structural",
            "details": "Combines AssemblyResolve / manifest resource streaming with in-memory assembly loading (Costura, Reactor, packer pattern).",
        })

    # 4. Runtime JIT / Dynamic Method Hooking
    matched_dynamic = [api for api in DYNAMIC_CODE_APIS if api in seen_apis]
    if len(matched_dynamic) >= 2 or "dynamicmethod" in seen_apis:
        techniques.append({
            "technique": "Runtime Dynamic Method Generation / JIT Hooking",
            "severity": "HIGH",
            "weight": 4,
            "kind": "structural",
            "details": f"Uses runtime IL generation / method body resolution APIs: {', '.join(matched_dynamic[:4])}",
        })

    return techniques
