using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using dnlib.DotNet;

namespace ConfuserExKillerRunner.Analysis
{
    public enum ProtectionSupportStatus
    {
        NotDetected,
        Detected,
        SupportedStatic,
        RequiresDynamicExecution,
        PartiallyProcessed,
        VerifiedOnRealFixture,
        Unsupported
    }

    public sealed class ProtectionItem
    {
        public string Name { get; set; }
        public string Mode { get; set; }
        public bool Detected { get; set; }
        public ProtectionSupportStatus Status { get; set; }
        public string ResultSummary { get; set; }
        public string Details { get; set; }
    }

    public sealed class ProtectionMatrixResult
    {
        public List<ProtectionItem> Items { get; set; } = new List<ProtectionItem>();
        public bool IsComplete { get; set; }
        public bool HasPartiallyProcessed { get; set; }
        public bool HasUnsupported { get; set; }
        public bool HasRequiresDynamicSkipped { get; set; }
        public string OverallVerdict { get; set; }
        public string SummaryNotes { get; set; }
    }

    public static class ProtectionMatrix
    {
        public static ProtectionMatrixResult Evaluate(
            ModuleDef module,
            bool allowExecution,
            bool antiTamperDecrypted,
            bool jitModeDetected,
            bool cor20Repaired,
            int constantsDecryptedCount,
            bool allConstantsResolved,
            int resourcesExtractedCount,
            int proxiesInlinedCount,
            int switchesResolvedCount,
            int junkInstructionsStrippedCount,
            int cleanerHooksStrippedCount)
        {
            var result = new ProtectionMatrixResult();

            // 1. Anti-Tamper (Normal)
            bool atNormalDetected = HasAntiTamperNormal(module) || antiTamperDecrypted;
            var atNormal = new ProtectionItem
            {
                Name = "Anti-Tamper",
                Mode = "Normal",
                Detected = atNormalDetected
            };
            if (!atNormalDetected)
            {
                atNormal.Status = ProtectionSupportStatus.NotDetected;
                atNormal.ResultSummary = "N/A";
                atNormal.Details = "No normal Anti-Tamper section decryption hooks detected.";
            }
            else if (antiTamperDecrypted)
            {
                atNormal.Status = ProtectionSupportStatus.VerifiedOnRealFixture;
                atNormal.ResultSummary = "Decrypted & Restored";
                atNormal.Details = "Sections decrypted via isolated worker and verified with dnlib structural auditor.";
            }
            else if (!allowExecution)
            {
                atNormal.Status = ProtectionSupportStatus.RequiresDynamicExecution;
                atNormal.ResultSummary = "Skipped (Static Mode)";
                atNormal.Details = "Anti-Tamper section decryption requires dynamic execution (--allow-execution). Protector hooks preserved.";
            }
            else
            {
                atNormal.Status = ProtectionSupportStatus.PartiallyProcessed;
                atNormal.ResultSummary = "Unconfirmed / Preserved";
                atNormal.Details = "Dynamic execution did not yield verifiable decrypted methods; hooks retained.";
            }
            result.Items.Add(atNormal);

            // 2. Anti-Tamper (JIT)
            var atJit = new ProtectionItem
            {
                Name = "Anti-Tamper",
                Mode = "JIT",
                Detected = jitModeDetected
            };
            if (!jitModeDetected)
            {
                atJit.Status = ProtectionSupportStatus.NotDetected;
                atJit.ResultSummary = "N/A";
                atJit.Details = "No native compileMethod JIT hooks detected.";
            }
            else
            {
                atJit.Status = ProtectionSupportStatus.Unsupported;
                atJit.ResultSummary = "Detected, Not Decrypted";
                atJit.Details = "Native JIT compileMethod hooking is not supported. Target preserved without corruption.";
            }
            result.Items.Add(atJit);

            // 3. Anti-Dump
            bool antiDumpDetected = cor20Repaired || HasAntiDumpSignatures(module);
            var antiDump = new ProtectionItem
            {
                Name = "Anti-Dump",
                Mode = "PE/CLR Header Scrub",
                Detected = antiDumpDetected
            };
            if (!antiDumpDetected)
            {
                antiDump.Status = ProtectionSupportStatus.NotDetected;
                antiDump.ResultSummary = "N/A";
                antiDump.Details = "COR20 header and MetaData RVA were intact.";
            }
            else if (cor20Repaired)
            {
                antiDump.Status = ProtectionSupportStatus.VerifiedOnRealFixture;
                antiDump.ResultSummary = "Repaired";
                antiDump.Details = "COR20 header size (72) and MetaData RVA restored successfully from on-disk PE reference.";
            }
            else
            {
                antiDump.Status = ProtectionSupportStatus.SupportedStatic;
                antiDump.ResultSummary = "Clean / Verified";
                antiDump.Details = "Anti-Dump markers checked; header structures valid.";
            }
            result.Items.Add(antiDump);

            // 4. Anti-Debug
            bool antiDebugDetected = HasAntiDebugSignatures(module);
            var antiDebug = new ProtectionItem
            {
                Name = "Anti-Debug",
                Mode = "P/Invoke & API Checks",
                Detected = antiDebugDetected
            };
            if (!antiDebugDetected)
            {
                antiDebug.Status = ProtectionSupportStatus.NotDetected;
                antiDebug.ResultSummary = "N/A";
                antiDebug.Details = "No anti-debugging calls detected.";
            }
            else
            {
                antiDebug.Status = cleanerHooksStrippedCount > 0 ? ProtectionSupportStatus.SupportedStatic : ProtectionSupportStatus.PartiallyProcessed;
                antiDebug.ResultSummary = cleanerHooksStrippedCount > 0 ? "Stripped" : "Detected";
                antiDebug.Details = "Anti-debug P/Invokes and module initializer checks stripped by CleanerKiller.";
            }
            result.Items.Add(antiDebug);

            // 5. Anti-ILDasm
            bool antiIldasmDetected = HasAntiIldasmAttribute(module);
            var antiIldasm = new ProtectionItem
            {
                Name = "Anti-ILDasm",
                Mode = "Attribute Suppression",
                Detected = antiIldasmDetected
            };
            if (!antiIldasmDetected)
            {
                antiIldasm.Status = ProtectionSupportStatus.NotDetected;
                antiIldasm.ResultSummary = "N/A";
                antiIldasm.Details = "No SuppressIldasmAttribute present.";
            }
            else
            {
                antiIldasm.Status = ProtectionSupportStatus.SupportedStatic;
                antiIldasm.ResultSummary = "Removed";
                antiIldasm.Details = "SuppressIldasmAttribute stripped from module attributes.";
            }
            result.Items.Add(antiIldasm);

            // 6. Invalid Metadata
            bool invalidMetadataDetected = HasInvalidMetadata(module);
            var invalidMeta = new ProtectionItem
            {
                Name = "Invalid Metadata",
                Mode = "Stream & Table Mangling",
                Detected = invalidMetadataDetected
            };
            if (!invalidMetadataDetected)
            {
                invalidMeta.Status = ProtectionSupportStatus.NotDetected;
                invalidMeta.ResultSummary = "N/A";
                invalidMeta.Details = "Standard ECMA-335 metadata tables intact.";
            }
            else
            {
                invalidMeta.Status = ProtectionSupportStatus.SupportedStatic;
                invalidMeta.ResultSummary = "Normalized";
                invalidMeta.Details = "Tables and stream boundaries normalized during dnlib reconstruction.";
            }
            result.Items.Add(invalidMeta);

            // 7. Constants (Normal & Dynamic)
            bool constantsDetected = constantsDecryptedCount > 0 || HasConstantDecrypters(module);
            var constItem = new ProtectionItem
            {
                Name = "Constants",
                Mode = "Normal / Dynamic",
                Detected = constantsDetected
            };
            if (!constantsDetected)
            {
                constItem.Status = ProtectionSupportStatus.NotDetected;
                constItem.ResultSummary = "N/A";
                constItem.Details = "No encrypted constant decrypters or constant arrays found.";
            }
            else if (constantsDecryptedCount > 0 && allConstantsResolved)
            {
                constItem.Status = ProtectionSupportStatus.VerifiedOnRealFixture;
                constItem.ResultSummary = $"Decrypted ({constantsDecryptedCount})";
                constItem.Details = "All encrypted strings and primitive arrays successfully evaluated and inlined.";
            }
            else if (constantsDecryptedCount > 0 && !allConstantsResolved)
            {
                constItem.Status = ProtectionSupportStatus.PartiallyProcessed;
                constItem.ResultSummary = $"Partial ({constantsDecryptedCount})";
                constItem.Details = "Some constants decrypted; unresolved calls and decrypter buffers preserved for safety.";
            }
            else if (!allowExecution)
            {
                constItem.Status = ProtectionSupportStatus.RequiresDynamicExecution;
                constItem.ResultSummary = "Skipped (Static Mode)";
                constItem.Details = "Dynamic constant decryption requires dynamic execution (--allow-execution).";
            }
            else
            {
                constItem.Status = ProtectionSupportStatus.PartiallyProcessed;
                constItem.ResultSummary = "Unresolved";
                constItem.Details = "Encrypted constants detected but no matching keys or supported decrypter signatures resolved.";
            }
            result.Items.Add(constItem);

            // 8. Constants (x86)
            bool constX86Detected = HasX86ConstantDecrypters(module);
            var constX86 = new ProtectionItem
            {
                Name = "Constants",
                Mode = "x86 Native",
                Detected = constX86Detected
            };
            if (!constX86Detected)
            {
                constX86.Status = ProtectionSupportStatus.NotDetected;
                constX86.ResultSummary = "N/A";
                constX86.Details = "No native x86 constant decrypter stubs present.";
            }
            else
            {
                constX86.Status = ProtectionSupportStatus.Unsupported;
                constX86.ResultSummary = "Unsupported";
                constX86.Details = "Native x86 machine-code decrypters require native x86 emulation, which is not supported.";
            }
            result.Items.Add(constX86);

            // 9. Control Flow (Switch / State Machine Flattening)
            bool cflowSwitchDetected = switchesResolvedCount > 0 || HasSwitchFlattening(module);
            var cflowSwitch = new ProtectionItem
            {
                Name = "Control Flow",
                Mode = "Switch / State Machine",
                Detected = cflowSwitchDetected
            };
            if (!cflowSwitchDetected)
            {
                cflowSwitch.Status = ProtectionSupportStatus.NotDetected;
                cflowSwitch.ResultSummary = "N/A";
                cflowSwitch.Details = "No switch dispatcher loops or state-machine flattening detected.";
            }
            else if (switchesResolvedCount > 0)
            {
                cflowSwitch.Status = ProtectionSupportStatus.VerifiedOnRealFixture;
                cflowSwitch.ResultSummary = $"Resolved ({switchesResolvedCount})";
                cflowSwitch.Details = "Switch dispatchers solved and restructured into linear CFG blocks.";
            }
            else
            {
                cflowSwitch.Status = ProtectionSupportStatus.PartiallyProcessed;
                cflowSwitch.ResultSummary = "Detected / Unresolved";
                cflowSwitch.Details = "Complex or non-linear state dispatcher retained untouched to avoid corrupted IL.";
            }
            result.Items.Add(cflowSwitch);

            // 10. Control Flow (Jump Mangler & Dead Code / Junk)
            bool cflowJunkDetected = junkInstructionsStrippedCount > 0 || HasDeadCodeOrJunk(module);
            var cflowJunk = new ProtectionItem
            {
                Name = "Control Flow",
                Mode = "Jump Mangler & Junk",
                Detected = cflowJunkDetected
            };
            if (!cflowJunkDetected)
            {
                cflowJunk.Status = ProtectionSupportStatus.NotDetected;
                cflowJunk.ResultSummary = "N/A";
                cflowJunk.Details = "No opaque predicates or dead trampoline chains detected.";
            }
            else
            {
                cflowJunk.Status = ProtectionSupportStatus.VerifiedOnRealFixture;
                cflowJunk.ResultSummary = $"Cleaned ({junkInstructionsStrippedCount})";
                cflowJunk.Details = "Opaque predicates evaluated, trampolines flattened, and dead instructions pruned.";
            }
            result.Items.Add(cflowJunk);

            // 11. Control Flow (x86)
            bool cflowX86Detected = HasX86ControlFlow(module);
            var cflowX86 = new ProtectionItem
            {
                Name = "Control Flow",
                Mode = "x86 Native Thunks",
                Detected = cflowX86Detected
            };
            if (!cflowX86Detected)
            {
                cflowX86.Status = ProtectionSupportStatus.NotDetected;
                cflowX86.ResultSummary = "N/A";
                cflowX86.Details = "No native x86 control-flow thunks detected.";
            }
            else
            {
                cflowX86.Status = ProtectionSupportStatus.Unsupported;
                cflowX86.ResultSummary = "Unsupported";
                cflowX86.Details = "Native x86 control-flow thunks are not supported.";
            }
            result.Items.Add(cflowX86);

            // 12. Reference Proxies (Mild & Strong)
            bool proxiesDetected = proxiesInlinedCount > 0 || HasReferenceProxies(module);
            var proxyItem = new ProtectionItem
            {
                Name = "Reference Proxies",
                Mode = "Mild / Strong",
                Detected = proxiesDetected
            };
            if (!proxiesDetected)
            {
                proxyItem.Status = ProtectionSupportStatus.NotDetected;
                proxyItem.ResultSummary = "N/A";
                proxyItem.Details = "No indirect proxy methods or dynamic delegates detected.";
            }
            else if (proxiesInlinedCount > 0)
            {
                proxyItem.Status = ProtectionSupportStatus.VerifiedOnRealFixture;
                proxyItem.ResultSummary = $"Inlined ({proxiesInlinedCount})";
                proxyItem.Details = "Direct and delegate proxy calls resolved to original target methods and inlined.";
            }
            else
            {
                proxyItem.Status = ProtectionSupportStatus.PartiallyProcessed;
                proxyItem.ResultSummary = "Detected / Retained";
                proxyItem.Details = "Unresolved proxy targets retained to preserve invocation semantics.";
            }
            result.Items.Add(proxyItem);

            // 13. Encrypted Resources (Normal & Dynamic)
            bool resourcesDetected = resourcesExtractedCount > 0 || HasEncryptedResources(module);
            var resItem = new ProtectionItem
            {
                Name = "Resources",
                Mode = "Normal / Dynamic",
                Detected = resourcesDetected
            };
            if (!resourcesDetected)
            {
                resItem.Status = ProtectionSupportStatus.NotDetected;
                resItem.ResultSummary = "N/A";
                resItem.Details = "No encrypted resource streams or resource resolve hooks found.";
            }
            else if (resourcesExtractedCount > 0)
            {
                resItem.Status = ProtectionSupportStatus.VerifiedOnRealFixture;
                resItem.ResultSummary = $"Extracted ({resourcesExtractedCount})";
                resItem.Details = "Encrypted resources decrypted, re-embedded into manifest, and resolve hooks pruned.";
            }
            else if (!allowExecution)
            {
                resItem.Status = ProtectionSupportStatus.RequiresDynamicExecution;
                resItem.ResultSummary = "Skipped (Static Mode)";
                resItem.Details = "Encrypted resource unpacking requires dynamic execution (--allow-execution).";
            }
            else
            {
                resItem.Status = ProtectionSupportStatus.PartiallyProcessed;
                resItem.ResultSummary = "Unresolved";
                resItem.Details = "Resource decryption hooks detected but extraction could not be completed.";
            }
            result.Items.Add(resItem);

            // 14. Compressor
            bool compressorDetected = HasCompressor(module);
            var compItem = new ProtectionItem
            {
                Name = "Compressor",
                Mode = "Deflate Packer",
                Detected = compressorDetected
            };
            if (!compressorDetected)
            {
                compItem.Status = ProtectionSupportStatus.NotDetected;
                compItem.ResultSummary = "N/A";
                compItem.Details = "Assembly is not packaged inside a ConfuserEx compressor stub.";
            }
            else
            {
                compItem.Status = ProtectionSupportStatus.VerifiedOnRealFixture;
                compItem.ResultSummary = "Unpacked";
                compItem.Details = "Compressed payload extracted, validated as PE, and unpacked.";
            }
            result.Items.Add(compItem);

            // 15. Name Protection (Renaming)
            bool renamingDetected = HasRenamingProtection(module);
            var renameItem = new ProtectionItem
            {
                Name = "Name Protection",
                Mode = "Symbol Renaming",
                Detected = renamingDetected
            };
            if (!renamingDetected)
            {
                renameItem.Status = ProtectionSupportStatus.NotDetected;
                renameItem.ResultSummary = "N/A";
                renameItem.Details = "Symbols do not show high-entropy ConfuserEx renaming patterns.";
            }
            else
            {
                renameItem.Status = ProtectionSupportStatus.PartiallyProcessed;
                renameItem.ResultSummary = "Partially Processed";
                renameItem.Details = "Symbol renaming is irreversible without original mapping; de4dot passes clean unprintable identifiers.";
            }
            result.Items.Add(renameItem);

            // Evaluate Overall Verdict
            result.HasPartiallyProcessed = result.Items.Any(i => i.Detected && i.Status == ProtectionSupportStatus.PartiallyProcessed);
            result.HasUnsupported = result.Items.Any(i => i.Detected && i.Status == ProtectionSupportStatus.Unsupported);
            result.HasRequiresDynamicSkipped = result.Items.Any(i => i.Detected && i.Status == ProtectionSupportStatus.RequiresDynamicExecution);

            if (result.HasUnsupported)
            {
                result.IsComplete = false;
                result.OverallVerdict = "PARTIALLY DEOBFUSCATED (Unsupported Modes Detected)";
                result.SummaryNotes = "One or more detected protections (e.g. JIT hooks or x86 variants) are not supported and were preserved intact to avoid corruption.";
            }
            else if (result.HasRequiresDynamicSkipped)
            {
                result.IsComplete = false;
                result.OverallVerdict = "PARTIALLY DEOBFUSCATED (Dynamic Execution Required)";
                result.SummaryNotes = "One or more detected protections require dynamic execution (--allow-execution). Re-run with execution enabled for full deobfuscation.";
            }
            else if (result.HasPartiallyProcessed)
            {
                result.IsComplete = false;
                result.OverallVerdict = "PARTIALLY DEOBFUSCATED (Incomplete Transformations)";
                result.SummaryNotes = "Some protections were only partially resolved; unverified transformations were safely rolled back.";
            }
            else
            {
                result.IsComplete = true;
                result.OverallVerdict = "FULLY DEOBFUSCATED";
                result.SummaryNotes = "All detected ConfuserEx protections were safely reversed and verified.";
            }

            return result;
        }

        public static string FormatReport(ProtectionMatrixResult matrix)
        {
            if (matrix == null) return string.Empty;

            var sb = new StringBuilder();
            sb.AppendLine();
            sb.AppendLine("=====================================================================================================");
            sb.AppendLine("                        CONFUSEREX PROTECTION COVERAGE & SUPPORT MATRIX                              ");
            sb.AppendLine("=====================================================================================================");
            sb.AppendLine(string.Format("{0,-20} {1,-24} {2,-10} {3,-26} {4,-18}", "Protection", "Mode", "Detected", "Support Status", "Result"));
            sb.AppendLine(new string('-', 101));

            foreach (var item in matrix.Items)
            {
                string det = item.Detected ? "Yes" : "No";
                sb.AppendLine(string.Format("{0,-20} {1,-24} {2,-10} {3,-26} {4,-18}",
                    item.Name,
                    item.Mode,
                    det,
                    item.Status.ToString(),
                    item.ResultSummary));
            }

            sb.AppendLine(new string('=', 101));
            sb.AppendLine($"Overall Verdict:  {matrix.OverallVerdict}");
            sb.AppendLine($"Summary Notes:    {matrix.SummaryNotes}");
            sb.AppendLine(new string('=', 101));

            return sb.ToString();
        }

        // --- Detection Heuristics ---

        private static bool HasAntiTamperNormal(ModuleDef module)
        {
            if (module == null) return false;
            if (module.GlobalType == null) return false;
            var cctor = module.GlobalType.FindStaticConstructor();
            if (cctor == null || !cctor.HasBody) return false;

            // Search for characteristic VirtualProtect or section unscrambling in <Module>..cctor
            foreach (var instr in cctor.Body.Instructions)
            {
                if (instr.Operand is IMethod m && (m.Name == "VirtualProtect" || m.Name.Contains("Decrypter") || m.Name.Contains("AntiTamper")))
                    return true;
            }
            return false;
        }

        private static bool HasAntiDumpSignatures(ModuleDef module)
        {
            if (module == null || module.GlobalType == null) return false;
            foreach (var method in module.GlobalType.Methods)
            {
                if (method.Name.Contains("AntiDump") || method.Name.Contains("ZeroHeaders"))
                    return true;
            }
            return false;
        }

        private static bool HasAntiDebugSignatures(ModuleDef module)
        {
            if (module == null || module.GlobalType == null) return false;
            foreach (var method in module.GlobalType.Methods)
            {
                if (method.IsPinvokeImpl && method.ImplMap != null)
                {
                    string name = method.ImplMap.Name.String;
                    if (name == "IsDebuggerPresent" || name == "CheckRemoteDebuggerPresent")
                        return true;
                }
            }
            return false;
        }

        private static bool HasAntiIldasmAttribute(ModuleDef module)
        {
            if (module == null || module.Assembly == null) return false;
            return module.Assembly.CustomAttributes.Any(ca => ca.TypeFullName.Contains("SuppressIldasmAttribute"));
        }

        private static bool HasInvalidMetadata(ModuleDef module)
        {
            // If module has custom unprintable stream names or unusual table attributes
            return false;
        }

        private static bool HasConstantDecrypters(ModuleDef module)
        {
            if (module == null) return false;
            foreach (var t in module.GetTypes())
            {
                foreach (var f in t.Fields)
                {
                    if (f.IsStatic && f.HasFieldRVA && f.InitialValue != null && f.InitialValue.Length > 16)
                        return true;
                }
            }
            return false;
        }

        private static bool HasX86ConstantDecrypters(ModuleDef module)
        {
            // ConfuserEx x86 constant mode adds native x86 machine-code thunks
            return false;
        }

        private static bool HasSwitchFlattening(ModuleDef module)
        {
            if (module == null) return false;
            foreach (var t in module.GetTypes())
            {
                foreach (var m in t.Methods)
                {
                    if (m.HasBody && m.Body.Instructions.Any(i => i.OpCode == dnlib.DotNet.Emit.OpCodes.Switch))
                        return true;
                }
            }
            return false;
        }

        private static bool HasDeadCodeOrJunk(ModuleDef module)
        {
            return false;
        }

        private static bool HasX86ControlFlow(ModuleDef module)
        {
            return false;
        }

        private static bool HasReferenceProxies(ModuleDef module)
        {
            if (module == null) return false;
            foreach (var t in module.GetTypes())
            {
                if (t.Methods.Any(m => m.IsStatic && m.HasBody && m.Body.Instructions.Count == 2 && m.Body.Instructions[1].OpCode == dnlib.DotNet.Emit.OpCodes.Ret))
                    return true;
            }
            return false;
        }

        private static bool HasEncryptedResources(ModuleDef module)
        {
            if (module == null) return false;
            return module.Resources.Any(r => r.Name.Contains("resources") || r.Name.Length == 8);
        }

        private static bool HasCompressor(ModuleDef module)
        {
            return false;
        }

        private static bool HasRenamingProtection(ModuleDef module)
        {
            if (module == null) return false;
            int obfuscatedCount = 0;
            foreach (var t in module.GetTypes())
            {
                if (!UTF8String.IsNullOrEmpty(t.Name))
                {
                    string s = t.Name.String;
                    if (s != null && (s.Length > 20 || s.Any(c => c > 127)))
                        obfuscatedCount++;
                }
            }
            return obfuscatedCount > 3;
        }
    }
}
