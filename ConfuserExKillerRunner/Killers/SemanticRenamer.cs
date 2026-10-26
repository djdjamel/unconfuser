using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Tool;

namespace ConfuserExKillerRunner.Killers
{
    public sealed class SemanticRenamerResult
    {
        public int TypesRenamed { get; set; }
        public int FieldsRenamed { get; set; }
        public int MethodsRenamed { get; set; }
        public int PropertiesRenamed { get; set; }
        public int ResourcesRenamed { get; set; }
        public int UnprintableNormalized { get; set; }
        public string Message { get; set; }
    }

    /// <summary>
    /// Restores semantic symbol names for Forms, Controls, Handlers, and Resources
    /// from ECMA-335 metadata and WinForms / DevExpress initialization bytecode.
    /// Also normalizes any residual unprintable or Unicode-mangled identifiers.
    /// </summary>
    public static class SemanticRenamer
    {
        private static readonly Regex ValidIdentifierRegex = new Regex(@"^[A-Za-z_][A-Za-z0-9_]*$", RegexOptions.Compiled);

        public static SemanticRenamerResult Execute(ModuleDef module, bool verbose = false)
        {
            if (module == null) throw new ArgumentNullException(nameof(module));

            var result = new SemanticRenamerResult();

            var usedFullNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var t in module.GetTypes())
            {
                if (!string.IsNullOrEmpty(t.FullName))
                    usedFullNames.Add(t.FullName);
            }

            // Pass 1: Recover Form and UserControl type names & namespaces
            RenameFormsAndUserControls(module, usedFullNames, result, verbose);

            // Pass 1.5: Match unlinked/mangled resources against Form resource strings
            MatchAndRenameMangledResources(module, result, verbose);

            // Pass 2: Recover Control fields & event handler methods
            RenameControlFieldsAndEventHandlers(module, result, verbose);

            // Pass 3: Recover strongly-typed Properties.Resources classes and properties
            RenameStronglyTypedResources(module, usedFullNames, result, verbose);

            // Pass 4: Normalize any remaining unprintable / Unicode-mangled identifiers
            NormalizeRemainingMangledIdentifiers(module, usedFullNames, result, verbose);

            result.Message = $"Restored {result.TypesRenamed} types, {result.FieldsRenamed} fields, " +
                             $"{result.MethodsRenamed} methods, {result.PropertiesRenamed} properties, " +
                             $"{result.ResourcesRenamed} resources ({result.UnprintableNormalized} unprintable symbols normalized).";

            return result;
        }

        #region Pass 1: Forms & UserControls Renaming

        private static void RenameFormsAndUserControls(ModuleDef module, HashSet<string> usedFullNames, SemanticRenamerResult result, bool verbose)
        {
            var manifestResourceNames = new HashSet<string>(module.Resources.Select(r => r.Name.String));

            // Map: TypeDef -> Detected semantic (Namespace, Name)
            var candidates = new Dictionary<TypeDef, (string ns, string name)>();

            foreach (var type in module.GetTypes())
            {
                if (type.IsGlobalModuleType || type.DeclaringType != null)
                    continue;

                if (IsResourceWrapperClass(type))
                    continue;

                // Look for self set_Name call in methods (e.g. InitializeComponent)
                string discoveredName = null;
                string discoveredNamespace = null;

                foreach (var method in type.Methods)
                {
                    if (!method.HasBody || method.Body.Instructions == null)
                        continue;

                    var instrs = method.Body.Instructions;
                    for (int i = 2; i < instrs.Count; i++)
                    {
                        var ins = instrs[i];
                        if (ins.OpCode == OpCodes.Call || ins.OpCode == OpCodes.Callvirt)
                        {
                            if (ins.Operand is IMethod calledM && calledM.Name == "set_Name")
                            {
                                var p1 = instrs[i - 1];
                                var p2 = instrs[i - 2];
                                if (p2.OpCode == OpCodes.Ldarg_0 && p1.OpCode == OpCodes.Ldstr && p1.Operand is string strVal)
                                {
                                    strVal = strVal.Trim();
                                    if (IsValidIdentifier(strVal))
                                    {
                                        discoveredName = strVal;
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    if (discoveredName != null)
                        break;
                }

                // If not found in set_Name, check linked WinForm type in constructor:
                // e.g. this.winForm = typeof(WDRetourComptoirForm);
                if (discoveredName == null)
                {
                    var ctor = type.FindDefaultConstructor() ?? type.Methods.FirstOrDefault(m => m.IsConstructor);
                    if (ctor != null && ctor.HasBody)
                    {
                        foreach (var ins in ctor.Body.Instructions)
                        {
                            if (ins.OpCode == OpCodes.Ldtoken && ins.Operand is ITypeDefOrRef tokenType)
                            {
                                string tName = (string)tokenType.Name;
                                if (!string.IsNullOrEmpty(tName) && IsValidIdentifier(tName) &&
                                    (tName.EndsWith("Form", StringComparison.OrdinalIgnoreCase) ||
                                     tName.EndsWith("List", StringComparison.OrdinalIgnoreCase)))
                                {
                                    // Suffix or prefix check
                                    if (IsObfuscatedOrGenericTypeName(type.Name))
                                    {
                                        discoveredName = tName + "Control";
                                        discoveredNamespace = (string)tokenType.Namespace;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                // Try to associate discoveredName with manifest resources to get proper namespace
                if (discoveredName != null)
                {
                    // Find matching .resources file in manifest: e.g. "Xpert.Pharm.Forms.RetourComptoirList.resources"
                    string matchedResName = manifestResourceNames.FirstOrDefault(rn =>
                        rn.EndsWith("." + discoveredName + ".resources", StringComparison.OrdinalIgnoreCase) ||
                        rn.Equals(discoveredName + ".resources", StringComparison.OrdinalIgnoreCase));

                    if (matchedResName != null)
                    {
                        string withoutExt = matchedResName.Substring(0, matchedResName.Length - ".resources".Length);
                        int lastDot = withoutExt.LastIndexOf('.');
                        if (lastDot > 0)
                        {
                            discoveredNamespace = withoutExt.Substring(0, lastDot);
                            discoveredName = withoutExt.Substring(lastDot + 1);
                        }
                    }
                    else if (string.IsNullOrEmpty(discoveredNamespace))
                    {
                        // Use default root namespace of module if available
                        discoveredNamespace = GetAssemblyRootNamespace(module);
                    }

                    candidates[type] = (discoveredNamespace, discoveredName);
                }
            }

            // Apply discovered Form names
            foreach (var kvp in candidates)
            {
                var type = kvp.Key;
                var (targetNs, targetName) = kvp.Value;

                if (!IsObfuscatedOrGenericTypeName(type.Name) && type.Name == targetName)
                    continue;

                // Ensure unique name
                string finalName = targetName;
                int suffix = 1;
                while (usedFullNames.Contains(string.IsNullOrEmpty(targetNs) ? finalName : targetNs + "." + finalName))
                {
                    if (type.Name == finalName && type.Namespace == targetNs)
                        break;
                    finalName = $"{targetName}_{suffix++}";
                }

                string oldFullName = type.FullName;
                string oldName = type.Name.String;

                type.Name = finalName;
                if (!string.IsNullOrEmpty(targetNs))
                    type.Namespace = targetNs;

                usedFullNames.Add(type.FullName);
                result.TypesRenamed++;

                // Sync manifest resource if old name had a matching resource
                SyncResourceForType(module, type, oldFullName, oldName, result);

                if (verbose)
                    Tool.Logger.LogInfo($"[SemanticRenamer] Form Renamed: {oldFullName} -> {type.FullName}");
            }
        }

        private static void SyncResourceForType(ModuleDef module, TypeDef type, string oldFullName, string oldName, SemanticRenamerResult result)
        {
            string newResName = type.FullName + ".resources";

            // Check if resource already exists with new name
            if (module.Resources.Any(r => r.Name.Equals(newResName)))
                return;

            // Search for resource matching oldFullName or oldName
            var oldRes = module.Resources.FirstOrDefault(r =>
                r.Name.Equals(oldFullName + ".resources") ||
                r.Name.Equals(oldName + ".resources") ||
                (!string.IsNullOrEmpty(oldName) && r.Name.String.Contains(oldName)));

            if (oldRes != null && oldRes.Name != newResName)
            {
                oldRes.Name = newResName;
                result.ResourcesRenamed++;
            }
        }

        private static void MatchAndRenameMangledResources(ModuleDef module, SemanticRenamerResult result, bool verbose)
        {
            var mangledResources = module.Resources.OfType<EmbeddedResource>()
                .Where(r => r.Name.String.EndsWith(".resources") && IsMangledIdentifier(r.Name.String.Substring(0, r.Name.String.Length - 10)))
                .ToList();

            if (mangledResources.Count == 0) return;

            var resourceKeysMap = new Dictionary<EmbeddedResource, HashSet<string>>();
            foreach (var res in mangledResources)
            {
                try
                {
                    var keys = new HashSet<string>(StringComparer.Ordinal);
                    using (var stream = res.GetResourceStream())
                    using (var reader = new System.Resources.ResourceReader(stream))
                    {
                        var enumerator = reader.GetEnumerator();
                        while (enumerator.MoveNext())
                        {
                            if (enumerator.Key is string k)
                                keys.Add(k);
                        }
                    }
                    if (keys.Count > 0)
                        resourceKeysMap[res] = keys;
                }
                catch { }
            }

            if (resourceKeysMap.Count == 0) return;

            foreach (var type in module.GetTypes())
            {
                if (type.IsGlobalModuleType || type.DeclaringType != null) continue;
                if (IsResourceWrapperClass(type)) continue;

                string expectedResName = type.FullName + ".resources";
                if (module.Resources.Any(r => r.Name.Equals(expectedResName)))
                    continue;

                var typeStrings = new HashSet<string>(StringComparer.Ordinal);
                foreach (var m in type.Methods)
                {
                    if (!m.HasBody || m.Body.Instructions == null) continue;
                    foreach (var ins in m.Body.Instructions)
                    {
                        if (ins.OpCode == OpCodes.Ldstr && ins.Operand is string s)
                            typeStrings.Add(s);
                    }
                }

                EmbeddedResource bestRes = null;
                int maxMatches = 0;

                foreach (var kvp in resourceKeysMap)
                {
                    var res = kvp.Key;
                    var resKeys = kvp.Value;
                    int matches = resKeys.Count(k => typeStrings.Contains(k));
                    if (matches > 0 && matches > maxMatches)
                    {
                        maxMatches = matches;
                        bestRes = res;
                    }
                }

                if (bestRes != null && maxMatches >= Math.Min(2, resourceKeysMap[bestRes].Count))
                {
                    string oldResName = bestRes.Name.String;
                    bestRes.Name = expectedResName;
                    resourceKeysMap.Remove(bestRes);
                    result.ResourcesRenamed++;
                    if (verbose)
                        Tool.Logger.LogInfo($"[SemanticRenamer] Synced mangled resource: {oldResName} -> {expectedResName} (matches: {maxMatches})");
                }
            }
        }

        #endregion

        #region Pass 2: Controls & Event Handlers Renaming

        private static void RenameControlFieldsAndEventHandlers(ModuleDef module, SemanticRenamerResult result, bool verbose)
        {
            foreach (var type in module.GetTypes())
            {
                if (type.IsGlobalModuleType)
                    continue;

                var fieldControlNames = new Dictionary<FieldDef, string>();

                foreach (var method in type.Methods)
                {
                    if (!method.HasBody || method.Body.Instructions == null)
                        continue;

                    var instrs = method.Body.Instructions;
                    for (int i = 0; i < instrs.Count; i++)
                    {
                        var ins = instrs[i];

                        // Pattern 1: ldarg.0; ldfld <field>; ldstr "btnSave"; callvirt set_Name
                        if (ins.OpCode == OpCodes.Callvirt || ins.OpCode == OpCodes.Call)
                        {
                            if (ins.Operand is IMethod calledM && calledM.Name == "set_Name")
                            {
                                if (i >= 2 && instrs[i - 1].OpCode == OpCodes.Ldstr && instrs[i - 1].Operand is string ctrlName)
                                {
                                    ctrlName = ctrlName.Trim();
                                    if (IsValidIdentifier(ctrlName))
                                    {
                                        // Trace back to the field
                                        FieldDef targetField = null;
                                        if (instrs[i - 2].OpCode == OpCodes.Ldfld && instrs[i - 2].Operand is FieldDef fd1 && fd1.DeclaringType == type)
                                        {
                                            targetField = fd1;
                                        }
                                        else if (i >= 3 && instrs[i - 3].OpCode == OpCodes.Ldfld && instrs[i - 3].Operand is FieldDef fd2 && fd2.DeclaringType == type)
                                        {
                                            targetField = fd2;
                                        }

                                        if (targetField != null && !fieldControlNames.ContainsKey(targetField))
                                        {
                                            fieldControlNames[targetField] = ctrlName;
                                        }
                                    }
                                }
                            }
                        }

                        // Pattern 2: Event Subscription
                        // ldftn <Method>; newobj EventHandler; callvirt add_<Event>
                        if (ins.OpCode == OpCodes.Callvirt || ins.OpCode == OpCodes.Call)
                        {
                            if (ins.Operand is IMethod addEventMethod && addEventMethod.Name.StartsWith("add_"))
                            {
                                string eventName = addEventMethod.Name.Substring(4); // e.g. "Click"
                                if (i >= 2 && (instrs[i - 1].OpCode == OpCodes.Newobj) &&
                                    (instrs[i - 2].OpCode == OpCodes.Ldftn) &&
                                    instrs[i - 2].Operand is MethodDef handlerMethod && handlerMethod.DeclaringType == type)
                                {
                                    // Find which control this event is added to
                                    FieldDef eventControlField = null;
                                    for (int j = i - 3; j >= Math.Max(0, i - 6); j--)
                                    {
                                        if (instrs[j].OpCode == OpCodes.Ldfld && instrs[j].Operand is FieldDef fd && fd.DeclaringType == type)
                                        {
                                            eventControlField = fd;
                                            break;
                                        }
                                    }

                                    string prefix = null;
                                    if (eventControlField != null)
                                    {
                                        fieldControlNames.TryGetValue(eventControlField, out prefix);
                                        if (string.IsNullOrEmpty(prefix))
                                            prefix = eventControlField.Name.String;
                                    }
                                    else
                                    {
                                        prefix = type.Name.String;
                                    }

                                    if (!string.IsNullOrEmpty(prefix) && IsValidIdentifier(prefix) && IsObfuscatedOrGenericMethodName(handlerMethod.Name))
                                    {
                                        string newHandlerName = $"{prefix}_{eventName}";
                                        if (IsValidIdentifier(newHandlerName) && !type.Methods.Any(m => m.Name == newHandlerName))
                                        {
                                            handlerMethod.Name = newHandlerName;
                                            result.MethodsRenamed++;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Apply field renames
                var usedFieldNames = new HashSet<string>(type.Fields.Select(f => f.Name.String), StringComparer.Ordinal);
                foreach (var kvp in fieldControlNames)
                {
                    var field = kvp.Key;
                    string targetName = kvp.Value;

                    if (field.Name == targetName)
                        continue;

                    if (IsObfuscatedOrGenericFieldName(field.Name))
                    {
                        string finalFieldName = targetName;
                        int suffix = 1;
                        while (usedFieldNames.Contains(finalFieldName))
                        {
                            finalFieldName = $"{targetName}_{suffix++}";
                        }

                        usedFieldNames.Remove(field.Name.String);
                        field.Name = finalFieldName;
                        usedFieldNames.Add(finalFieldName);
                        result.FieldsRenamed++;
                    }
                }
            }
        }

        #endregion

        #region Pass 3: Properties.Resources Renaming

        private static bool IsResourceWrapperClass(TypeDef type)
        {
            if (type.IsGlobalModuleType || type.DeclaringType != null)
                return false;

            foreach (var f in type.Fields)
            {
                if (f.IsStatic && f.FieldType.FullName == "System.Resources.ResourceManager")
                    return true;
            }

            foreach (var p in type.Properties)
            {
                if (p.PropertySig?.RetType?.FullName == "System.Resources.ResourceManager")
                    return true;
            }

            return false;
        }

        private static void RenameStronglyTypedResources(ModuleDef module, HashSet<string> usedFullNames, SemanticRenamerResult result, bool verbose)
        {
            var resourceClasses = new List<TypeDef>();
            foreach (var type in module.GetTypes())
            {
                if (IsResourceWrapperClass(type))
                    resourceClasses.Add(type);
            }

            if (resourceClasses.Count == 0)
                return;

            // Sort so primary Resources class (with System.Drawing bitmaps / highest property count) is processed first
            resourceClasses.Sort((a, b) =>
            {
                int aDrawings = a.Properties.Count(p => p.PropertySig?.RetType?.FullName?.StartsWith("System.Drawing") == true);
                int bDrawings = b.Properties.Count(p => p.PropertySig?.RetType?.FullName?.StartsWith("System.Drawing") == true);
                if (aDrawings != bDrawings)
                    return bDrawings.CompareTo(aDrawings);
                return b.Properties.Count.CompareTo(a.Properties.Count);
            });

            string rootNs = GetAssemblyRootNamespace(module);
            string propNs = string.IsNullOrEmpty(rootNs) ? "Properties" : rootNs + ".Properties";
            bool resourcesAssigned = false;

            foreach (var type in resourceClasses)
            {
                string oldFullName = type.FullName;
                string oldName = type.Name.String;

                // Determine preferred name:
                // Primary class (sorted first by drawings, then property count) -> "Resources"
                // Secondary / subsequent classes -> "Messages"
                string preferredName;
                if (!resourcesAssigned)
                {
                    preferredName = "Resources";
                    resourcesAssigned = true;
                }
                else
                {
                    preferredName = "Messages";
                }

                // Disambiguate against usedFullNames
                string finalName = preferredName;
                string targetFullName = string.IsNullOrEmpty(propNs) ? finalName : propNs + "." + finalName;
                int suffix = 2;
                while (usedFullNames.Contains(targetFullName))
                {
                    if (type.FullName.Equals(targetFullName, StringComparison.OrdinalIgnoreCase))
                        break;
                    finalName = $"{preferredName}_{suffix++}";
                    targetFullName = string.IsNullOrEmpty(propNs) ? finalName : propNs + "." + finalName;
                }

                if (IsObfuscatedOrGenericTypeName(type.Name) || type.Name != finalName || type.Namespace != propNs)
                {
                    usedFullNames.Remove(type.FullName);
                    type.Name = finalName;
                    type.Namespace = propNs;
                    usedFullNames.Add(type.FullName);
                    result.TypesRenamed++;

                    if (verbose)
                        Tool.Logger.LogInfo($"[SemanticRenamer] Resource Wrapper: {oldFullName} -> {type.FullName}");
                }

                // Sync manifest resource and update ldstr in methods
                SyncResourceAndLdstr(module, type, oldFullName, oldName, result, verbose);

                // Rename properties
                RenameResourceProperties(type, result);
            }
        }

        private static void SyncResourceAndLdstr(ModuleDef module, TypeDef type, string oldFullName, string oldName, SemanticRenamerResult result, bool verbose)
        {
            string expectedResName = type.FullName + ".resources";

            // Find all ldstr instructions that pass baseName to newobj ResourceManager::.ctor(...)
            var rmBaseNameInstructions = new List<Instruction>();
            string oldBaseName = null;

            foreach (var m in type.Methods)
            {
                if (!m.HasBody || m.Body.Instructions == null) continue;
                var instrs = m.Body.Instructions;
                for (int i = 0; i < instrs.Count; i++)
                {
                    var ins = instrs[i];
                    if (ins.OpCode == OpCodes.Newobj && ins.Operand is IMethod ctor &&
                        ctor.DeclaringType?.FullName == "System.Resources.ResourceManager")
                    {
                        // In ResourceManager::.ctor(string baseName, Assembly assembly),
                        // search backwards in this method for the ldstr instruction that pushed baseName
                        for (int j = i - 1; j >= Math.Max(0, i - 6); j--)
                        {
                            if (instrs[j].OpCode == OpCodes.Ldstr && instrs[j].Operand is string s && !string.IsNullOrEmpty(s))
                            {
                                rmBaseNameInstructions.Add(instrs[j]);
                                if (oldBaseName == null)
                                    oldBaseName = s;
                                break;
                            }
                        }
                    }
                }
            }

            // Fallback: if oldBaseName not found via newobj pattern, scan any ldstr in methods that matches a resource name
            if (oldBaseName == null)
            {
                foreach (var m in type.Methods)
                {
                    if (!m.HasBody || m.Body.Instructions == null) continue;
                    foreach (var ins in m.Body.Instructions)
                    {
                        if (ins.OpCode == OpCodes.Ldstr && ins.Operand is string s && !string.IsNullOrEmpty(s))
                        {
                            if (module.Resources.Any(r => r.Name.Equals(s + ".resources") || r.Name.Equals(s)))
                            {
                                oldBaseName = s;
                                rmBaseNameInstructions.Add(ins);
                                break;
                            }
                        }
                    }
                    if (oldBaseName != null) break;
                }
            }

            // Find matching EmbeddedResource in module
            EmbeddedResource matchedRes = null;
            if (oldBaseName != null)
            {
                matchedRes = module.Resources.OfType<EmbeddedResource>()
                    .FirstOrDefault(r => r.Name.Equals(oldBaseName + ".resources") || r.Name.Equals(oldBaseName));
            }

            if (matchedRes == null)
            {
                matchedRes = module.Resources.OfType<EmbeddedResource>()
                    .FirstOrDefault(r => r.Name.Equals(oldFullName + ".resources") ||
                                         r.Name.Equals(oldName + ".resources") ||
                                         (!string.IsNullOrEmpty(oldName) && r.Name.String.Contains(oldName)));
            }

            // Fallback: match by resource entry keys vs property getter ldstr keys
            if (matchedRes == null)
            {
                var typeKeys = new HashSet<string>(StringComparer.Ordinal);
                foreach (var p in type.Properties)
                {
                    var getter = p.GetMethod;
                    if (getter != null && getter.HasBody && getter.Body.Instructions != null)
                    {
                        foreach (var ins in getter.Body.Instructions)
                        {
                            if (ins.OpCode == OpCodes.Ldstr && ins.Operand is string k && !string.IsNullOrEmpty(k))
                                typeKeys.Add(k);
                        }
                    }
                }

                if (typeKeys.Count > 0)
                {
                    EmbeddedResource bestRes = null;
                    int maxMatches = 0;
                    foreach (var res in module.Resources.OfType<EmbeddedResource>())
                    {
                        try
                        {
                            int matches = 0;
                            using (var stream = res.GetResourceStream())
                            using (var reader = new System.Resources.ResourceReader(stream))
                            {
                                var en = reader.GetEnumerator();
                                while (en.MoveNext())
                                {
                                    if (en.Key is string rk && typeKeys.Contains(rk))
                                        matches++;
                                }
                            }
                            if (matches > maxMatches)
                            {
                                maxMatches = matches;
                                bestRes = res;
                            }
                        }
                        catch { }
                    }

                    if (bestRes != null && maxMatches > 0)
                        matchedRes = bestRes;
                }
            }

            string matchedOldName = matchedRes?.Name.String;
            if (matchedRes != null && matchedRes.Name != expectedResName)
            {
                if (!module.Resources.Any(r => r.Name.Equals(expectedResName) && r != matchedRes))
                {
                    matchedRes.Name = expectedResName;
                    result.ResourcesRenamed++;
                    if (verbose)
                        Tool.Logger.LogInfo($"[SemanticRenamer] Synced resource: {matchedOldName} -> {expectedResName}");
                }
            }

            // Now update ALL ldstr instructions that pass baseName or reference oldBaseName
            foreach (var ins in rmBaseNameInstructions)
            {
                ins.Operand = type.FullName;
            }

            // Also check all methods in the class for any remaining ldstr equal to oldBaseName
            foreach (var m in type.Methods)
            {
                if (!m.HasBody || m.Body.Instructions == null) continue;
                foreach (var ins in m.Body.Instructions)
                {
                    if (ins.OpCode == OpCodes.Ldstr && ins.Operand is string s)
                    {
                        if ((oldBaseName != null && s == oldBaseName) ||
                            (matchedOldName != null && (s + ".resources" == matchedOldName || s == matchedOldName)))
                        {
                            ins.Operand = type.FullName;
                        }
                    }
                }
            }
        }

        private static void RenameResourceProperties(TypeDef type, SemanticRenamerResult result)
        {
            var usedPropNames = new HashSet<string>(StringComparer.Ordinal);

            // First pass: rename ResourceManager and Culture properties if present
            foreach (var prop in type.Properties)
            {
                if (prop.PropertySig?.RetType?.FullName == "System.Resources.ResourceManager")
                {
                    usedPropNames.Add("ResourceManager");
                    if (prop.Name != "ResourceManager")
                    {
                        prop.Name = "ResourceManager";
                        if (prop.GetMethod != null) prop.GetMethod.Name = "get_ResourceManager";
                        result.PropertiesRenamed++;
                    }
                }
                else if (prop.PropertySig?.RetType?.FullName == "System.Globalization.CultureInfo")
                {
                    usedPropNames.Add("Culture");
                    if (prop.Name != "Culture")
                    {
                        prop.Name = "Culture";
                        if (prop.GetMethod != null) prop.GetMethod.Name = "get_Culture";
                        if (prop.SetMethod != null) prop.SetMethod.Name = "set_Culture";
                        result.PropertiesRenamed++;
                    }
                }
            }

            // Second pass: rename data properties based on ldstr resource key
            foreach (var prop in type.Properties)
            {
                if (prop.Name == "ResourceManager" || prop.Name == "Culture")
                    continue;

                var getter = prop.GetMethod;
                if (getter == null || !getter.HasBody || getter.Body.Instructions == null)
                    continue;

                string resourceKey = null;
                foreach (var ins in getter.Body.Instructions)
                {
                    if (ins.OpCode == OpCodes.Ldstr && ins.Operand is string key && !string.IsNullOrEmpty(key))
                    {
                        resourceKey = key;
                        break;
                    }
                }

                if (!string.IsNullOrEmpty(resourceKey))
                {
                    string validPropName = SanitizeIdentifier(resourceKey);
                    string finalPropName = validPropName;
                    int suffix = 2;
                    while (usedPropNames.Contains(finalPropName))
                    {
                        if (prop.Name == finalPropName) break;
                        finalPropName = $"{validPropName}_{suffix++}";
                    }

                    usedPropNames.Add(finalPropName);

                    if (prop.Name != finalPropName)
                    {
                        prop.Name = finalPropName;
                        getter.Name = "get_" + finalPropName;
                        result.PropertiesRenamed++;
                        result.MethodsRenamed++;
                    }
                }
            }
        }

        #endregion

        #region Pass 4: Unprintable / Mangled Normalization

        private static void NormalizeRemainingMangledIdentifiers(ModuleDef module, HashSet<string> usedFullNames, SemanticRenamerResult result, bool verbose)
        {
            foreach (var type in module.GetTypes())
            {
                if (type.IsGlobalModuleType)
                    continue;

                // Normalize Type name
                if (IsMangledIdentifier(type.Name.String))
                {
                    string candidate = $"Class_{type.Rid}";
                    string candidateFull = string.IsNullOrEmpty(type.Namespace) ? candidate : type.Namespace + "." + candidate;
                    int sfx = 2;
                    while (usedFullNames.Contains(candidateFull))
                    {
                        candidate = $"Class_{type.Rid}_{sfx++}";
                        candidateFull = string.IsNullOrEmpty(type.Namespace) ? candidate : type.Namespace + "." + candidate;
                    }
                    usedFullNames.Remove(type.FullName);
                    type.Name = candidate;
                    usedFullNames.Add(type.FullName);
                    result.UnprintableNormalized++;
                }

                // Normalize Fields
                foreach (var field in type.Fields)
                {
                    if (IsMangledIdentifier(field.Name.String))
                    {
                        field.Name = $"field_{field.Rid}";
                        result.UnprintableNormalized++;
                    }
                }

                // Normalize Methods
                foreach (var method in type.Methods)
                {
                    if (method.IsConstructor || method.IsRuntimeSpecialName || method.Name == "Invoke" || method.Name == "BeginInvoke" || method.Name == "EndInvoke")
                        continue;

                    if (IsMangledIdentifier(method.Name.String))
                    {
                        if (method.IsGetter)
                            method.Name = $"get_Prop_{method.Rid}";
                        else if (method.IsSetter)
                            method.Name = $"set_Prop_{method.Rid}";
                        else
                            method.Name = $"Method_{method.Rid}";

                        result.UnprintableNormalized++;
                    }

                    // Normalize Parameters
                    if (method.Parameters != null)
                    {
                        foreach (var param in method.Parameters)
                        {
                            if (param.Name != null && IsMangledIdentifier(param.Name))
                            {
                                param.Name = $"p_{param.Index}";
                                result.UnprintableNormalized++;
                            }
                        }
                    }
                }

                // Normalize Properties
                foreach (var prop in type.Properties)
                {
                    if (IsMangledIdentifier(prop.Name.String))
                    {
                        prop.Name = $"Property_{prop.Rid}";
                        result.UnprintableNormalized++;
                    }
                }

                // Normalize Events
                foreach (var ev in type.Events)
                {
                    if (IsMangledIdentifier(ev.Name.String))
                    {
                        ev.Name = $"Event_{ev.Rid}";
                        result.UnprintableNormalized++;
                    }
                }
            }
        }

        #endregion

        #region Helpers

        public static bool IsMangledIdentifier(string name)
        {
            if (string.IsNullOrEmpty(name)) return false;

            foreach (char c in name)
            {
                int code = (int)c;
                // Zero-width and formatting unicode characters
                if (code >= 0x2000 && code <= 0x206F) return true;
                if (code >= 0xFE00 && code <= 0xFEFF) return true;
                if (char.IsControl(c) || char.GetUnicodeCategory(c) == UnicodeCategory.Format) return true;
                // ConfuserEx unprintable/ASCII scrambled chars
                if (c == '#' || c == '$' || c == '%' || c == '\'' || c == '\\' || c == '/' ||
                    c == '{' || c == '}' || c == '~' || c == '!' || c == '^' || c == '?' ||
                    c == '*' || c == '|' || c == '<' || c == '>' || c == ';' || c == '=')
                    return true;
            }

            return false;
        }

        public static bool IsValidIdentifier(string name)
        {
            if (string.IsNullOrEmpty(name)) return false;
            return ValidIdentifierRegex.IsMatch(name) && !IsMangledIdentifier(name);
        }

        public static string SanitizeIdentifier(string name)
        {
            if (string.IsNullOrEmpty(name)) return "Item";

            var sb = new StringBuilder();
            if (char.IsDigit(name[0]))
                sb.Append('_');

            foreach (char c in name)
            {
                if (char.IsLetterOrDigit(c) || c == '_')
                    sb.Append(c);
                else
                    sb.Append('_');
            }

            string result = sb.ToString();
            return IsValidIdentifier(result) ? result : "_" + result;
        }

        private static bool IsObfuscatedOrGenericTypeName(string name)
        {
            if (string.IsNullOrEmpty(name)) return true;
            if (IsMangledIdentifier(name)) return true;
            if (name.StartsWith("Class", StringComparison.OrdinalIgnoreCase) && int.TryParse(name.Substring(5), out _)) return true;
            if (name.StartsWith("Form", StringComparison.OrdinalIgnoreCase) && int.TryParse(name.Substring(4), out _)) return true;
            if (name.StartsWith("Struct", StringComparison.OrdinalIgnoreCase) && int.TryParse(name.Substring(6), out _)) return true;
            return false;
        }

        private static bool IsObfuscatedOrGenericFieldName(string name)
        {
            if (string.IsNullOrEmpty(name)) return true;
            if (IsMangledIdentifier(name)) return true;
            if (name.StartsWith("field_", StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private static bool IsObfuscatedOrGenericMethodName(string name)
        {
            if (string.IsNullOrEmpty(name)) return true;
            if (IsMangledIdentifier(name)) return true;
            if (name.StartsWith("method_", StringComparison.OrdinalIgnoreCase)) return true;
            if (name.StartsWith("smethod_", StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private static string GetAssemblyRootNamespace(ModuleDef module)
        {
            string asmName = module.Assembly?.Name?.String;
            if (!string.IsNullOrEmpty(asmName))
                return asmName;

            var firstWithNs = module.GetTypes().FirstOrDefault(t => !string.IsNullOrEmpty(t.Namespace));
            return firstWithNs?.Namespace?.String ?? "DeobfuscatedApp";
        }

        #endregion
    }
}
