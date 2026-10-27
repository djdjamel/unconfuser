using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

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
        Unsupported,
        NotEvaluated
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
        public bool HasCodeProtectionsPartiallyProcessed => Items.Any(i => i.Detected && (i.Status == ProtectionSupportStatus.PartiallyProcessed || i.Status == ProtectionSupportStatus.Detected) && i.Name != "Name Protection");
        public bool HasUnsupported { get; set; }
        public bool HasRequiresDynamicSkipped { get; set; }
        public bool HasNotEvaluated { get; set; }
        public bool AllConstantsResolved { get; set; }
        public string OverallVerdict { get; set; }
        public string SummaryNotes { get; set; }
    }

    public static class ProtectionMatrix
    {
        public static bool DetermineAllConstantsResolved(
            bool isUnevaluated,
            bool constantsDetected,
            int decryptedCount,
            bool decrypterReportedAllResolved,
            bool allowExecution)
        {
            if (isUnevaluated) return false;
            if (!constantsDetected) return true;
            if (!allowExecution) return false;
            if (decryptedCount > 0 && decrypterReportedAllResolved) return true;
            return false;
        }

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
            int cleanerHooksStrippedCount,
            bool compressorUnpacked = false,
            IEnumerable<string> unevaluatedProtections = null,
            bool symbolsRenamed = false,
            bool antiIldasmStripped = false,
            bool antiDebugStripped = false,
            bool ilVerificationIndeterminate = false)
        {
            var result = new ProtectionMatrixResult();
            var unevaluatedSet = unevaluatedProtections != null
                ? new HashSet<string>(unevaluatedProtections, StringComparer.OrdinalIgnoreCase)
                : null;

            Func<string, string, bool> isUnevaluated = (name, mode) =>
            {
                if (unevaluatedSet == null) return false;
                return unevaluatedSet.Contains(name) ||
                       unevaluatedSet.Contains($"{name} ({mode})") ||
                       unevaluatedSet.Contains(mode);
            };

            // 1. Anti-Tamper (Normal)
            bool atNormalDetected = HasAntiTamperNormal(module) || antiTamperDecrypted;
            var atNormal = new ProtectionItem
            {
                Name = "Anti-Tamper",
                Mode = "Normal",
                Detected = atNormalDetected
            };
            if (isUnevaluated("Anti-Tamper", "Normal"))
            {
                atNormal.Detected = false;
                atNormal.Status = ProtectionSupportStatus.NotEvaluated;
                atNormal.ResultSummary = "Not Evaluated";
                atNormal.Details = "Anti-Tamper normal detection was not evaluated.";
            }
            else if (!atNormalDetected)
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
            if (isUnevaluated("Anti-Tamper", "JIT"))
            {
                atJit.Detected = false;
                atJit.Status = ProtectionSupportStatus.NotEvaluated;
                atJit.ResultSummary = "Not Evaluated";
                atJit.Details = "Anti-Tamper JIT mode detection was not evaluated.";
            }
            else if (!jitModeDetected)
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
            if (isUnevaluated("Anti-Dump", "PE/CLR Header Scrub"))
            {
                antiDump.Detected = false;
                antiDump.Status = ProtectionSupportStatus.NotEvaluated;
                antiDump.ResultSummary = "Not Evaluated";
                antiDump.Details = "Anti-Dump detection was not evaluated.";
            }
            else if (!antiDumpDetected)
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
            bool antiDebugDetected = antiDebugStripped || HasAntiDebugSignatures(module);
            var antiDebug = new ProtectionItem
            {
                Name = "Anti-Debug",
                Mode = "Managed Watchdog & Win32 P/Invoke",
                Detected = antiDebugDetected
            };
            if (isUnevaluated("Anti-Debug", "Managed Watchdog & Win32 P/Invoke") || isUnevaluated("Anti-Debug", "P/Invoke & API Checks"))
            {
                antiDebug.Detected = false;
                antiDebug.Status = ProtectionSupportStatus.NotEvaluated;
                antiDebug.ResultSummary = "Not Evaluated";
                antiDebug.Details = "Anti-Debug detection was not evaluated.";
            }
            else if (!antiDebugDetected)
            {
                antiDebug.Status = ProtectionSupportStatus.NotDetected;
                antiDebug.ResultSummary = "N/A";
                antiDebug.Details = "No anti-debugging calls detected.";
            }
            else
            {
                antiDebug.Status = (antiDebugStripped || cleanerHooksStrippedCount > 0) ? ProtectionSupportStatus.SupportedStatic : ProtectionSupportStatus.PartiallyProcessed;
                antiDebug.ResultSummary = (antiDebugStripped || cleanerHooksStrippedCount > 0) ? "Neutralized" : "Detected";
                antiDebug.Details = (antiDebugStripped || cleanerHooksStrippedCount > 0)
                    ? "Anti-debug managed watchdog thread, profiler checks, and P/Invokes stripped by CleanerKiller."
                    : "Anti-debug checks detected in module.";
            }
            result.Items.Add(antiDebug);

            // 5. Anti-ILDasm
            bool antiIldasmPresent = HasAntiIldasmAttribute(module);
            bool antiIldasmDetected = antiIldasmPresent || antiIldasmStripped;
            var antiIldasm = new ProtectionItem
            {
                Name = "Anti-ILDasm",
                Mode = "Attribute Suppression",
                Detected = antiIldasmDetected
            };
            if (isUnevaluated("Anti-ILDasm", "Attribute Suppression"))
            {
                antiIldasm.Detected = false;
                antiIldasm.Status = ProtectionSupportStatus.NotEvaluated;
                antiIldasm.ResultSummary = "Not Evaluated";
                antiIldasm.Details = "Anti-ILDasm suppression detection was not evaluated.";
            }
            else if (antiIldasmStripped && !antiIldasmPresent)
            {
                antiIldasm.Status = ProtectionSupportStatus.SupportedStatic;
                antiIldasm.ResultSummary = "Removed";
                antiIldasm.Details = "SuppressIldasmAttribute stripped from module attributes.";
            }
            else if (antiIldasmPresent)
            {
                antiIldasm.Status = ProtectionSupportStatus.Detected;
                antiIldasm.ResultSummary = "Detected";
                antiIldasm.Details = "SuppressIldasmAttribute is present on the module and was not stripped.";
            }
            else
            {
                antiIldasm.Status = ProtectionSupportStatus.NotDetected;
                antiIldasm.ResultSummary = "N/A";
                antiIldasm.Details = "No SuppressIldasmAttribute present.";
            }
            result.Items.Add(antiIldasm);

            // 6. Invalid Metadata
            bool? invalidMetadataDetected = HasInvalidMetadata(module);
            var invalidMeta = new ProtectionItem
            {
                Name = "Invalid Metadata",
                Mode = "Stream & Table Mangling",
                Detected = invalidMetadataDetected ?? false
            };
            if (isUnevaluated("Invalid Metadata", "Stream & Table Mangling") || !invalidMetadataDetected.HasValue)
            {
                invalidMeta.Detected = false;
                invalidMeta.Status = ProtectionSupportStatus.NotEvaluated;
                invalidMeta.ResultSummary = "Not Evaluated";
                invalidMeta.Details = "Invalid metadata detection not evaluated or stream table inaccessible.";
            }
            else if (!invalidMetadataDetected.Value)
            {
                invalidMeta.Status = ProtectionSupportStatus.NotDetected;
                invalidMeta.ResultSummary = "N/A";
                invalidMeta.Details = "Standard ECMA-335 metadata streams and tables verified intact.";
            }
            else
            {
                invalidMeta.Status = ProtectionSupportStatus.SupportedStatic;
                invalidMeta.ResultSummary = "Normalized";
                invalidMeta.Details = "Invalid metadata streams or mangled stream names detected and normalized during dnlib reconstruction.";
            }
            result.Items.Add(invalidMeta);

            // 7. Constants (Normal & Dynamic)
            bool constantsDetected = constantsDecryptedCount > 0 || HasConstantDecrypters(module);
            bool effectiveAllConstantsResolved = DetermineAllConstantsResolved(
                isUnevaluated("Constants", "Normal / Dynamic"),
                constantsDetected,
                constantsDecryptedCount,
                allConstantsResolved,
                allowExecution);

            var constItem = new ProtectionItem
            {
                Name = "Constants",
                Mode = "Normal / Dynamic",
                Detected = constantsDetected
            };
            if (isUnevaluated("Constants", "Normal / Dynamic"))
            {
                constItem.Detected = false;
                constItem.Status = ProtectionSupportStatus.NotEvaluated;
                constItem.ResultSummary = "Not Evaluated";
                constItem.Details = "Encrypted constant detection was not evaluated.";
            }
            else if (!constantsDetected)
            {
                constItem.Status = ProtectionSupportStatus.NotDetected;
                constItem.ResultSummary = "N/A";
                constItem.Details = "No encrypted constant decrypters or constant arrays found.";
            }
            else if (constantsDecryptedCount > 0 && effectiveAllConstantsResolved)
            {
                constItem.Status = ProtectionSupportStatus.VerifiedOnRealFixture;
                constItem.ResultSummary = $"Decrypted ({constantsDecryptedCount})";
                constItem.Details = "All encrypted strings and primitive arrays successfully evaluated and inlined.";
            }
            else if (constantsDecryptedCount > 0 && !effectiveAllConstantsResolved)
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
            result.AllConstantsResolved = effectiveAllConstantsResolved;
            result.Items.Add(constItem);

            // 8. Constants (x86)
            bool? constX86Detected = HasX86ConstantDecrypters(module);
            var constX86 = new ProtectionItem
            {
                Name = "Constants",
                Mode = "x86 Native",
                Detected = constX86Detected ?? false
            };
            if (isUnevaluated("Constants", "x86 Native") || !constX86Detected.HasValue)
            {
                constX86.Detected = false;
                constX86.Status = ProtectionSupportStatus.NotEvaluated;
                constX86.ResultSummary = "Not Evaluated";
                constX86.Details = "Native x86 constant decrypter detection not evaluated in current module representation.";
            }
            else if (constX86Detected.Value)
            {
                constX86.Status = ProtectionSupportStatus.Unsupported;
                constX86.ResultSummary = "Unsupported";
                constX86.Details = "Native x86 machine-code decrypters require native x86 emulation, which is not supported.";
            }
            else
            {
                constX86.Status = ProtectionSupportStatus.NotDetected;
                constX86.ResultSummary = "N/A";
                constX86.Details = "Pure IL assembly; no native x86 constant decrypter stubs present.";
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
            if (isUnevaluated("Control Flow", "Switch / State Machine"))
            {
                cflowSwitch.Detected = false;
                cflowSwitch.Status = ProtectionSupportStatus.NotEvaluated;
                cflowSwitch.ResultSummary = "Not Evaluated";
                cflowSwitch.Details = "Control Flow switch dispatcher detection was not evaluated.";
            }
            else if (!cflowSwitchDetected)
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
            if (isUnevaluated("Control Flow", "Jump Mangler & Junk"))
            {
                cflowJunk.Detected = false;
                cflowJunk.Status = ProtectionSupportStatus.NotEvaluated;
                cflowJunk.ResultSummary = "Not Evaluated";
                cflowJunk.Details = "Dead code and junk instruction detection was not evaluated.";
            }
            else if (!cflowJunkDetected)
            {
                cflowJunk.Status = ProtectionSupportStatus.NotDetected;
                cflowJunk.ResultSummary = "N/A";
                cflowJunk.Details = "No opaque predicates, dead trampoline chains, or junk stack pairs detected.";
            }
            else if (junkInstructionsStrippedCount > 0)
            {
                cflowJunk.Status = ProtectionSupportStatus.VerifiedOnRealFixture;
                cflowJunk.ResultSummary = $"Cleaned ({junkInstructionsStrippedCount})";
                cflowJunk.Details = "Opaque predicates evaluated, trampolines flattened, and dead instructions pruned.";
            }
            else
            {
                cflowJunk.Status = ProtectionSupportStatus.PartiallyProcessed;
                cflowJunk.ResultSummary = "Detected / Unresolved";
                cflowJunk.Details = "Dead code or junk instruction sequences detected but not fully pruned.";
            }
            result.Items.Add(cflowJunk);

            // 11. Control Flow (x86)
            bool? cflowX86Detected = HasX86ControlFlow(module);
            var cflowX86 = new ProtectionItem
            {
                Name = "Control Flow",
                Mode = "x86 Native Thunks",
                Detected = cflowX86Detected ?? false
            };
            if (isUnevaluated("Control Flow", "x86 Native Thunks") || !cflowX86Detected.HasValue)
            {
                cflowX86.Detected = false;
                cflowX86.Status = ProtectionSupportStatus.NotEvaluated;
                cflowX86.ResultSummary = "Not Evaluated";
                cflowX86.Details = "Native x86 control-flow thunk detection not evaluated in current module representation.";
            }
            else if (cflowX86Detected.Value)
            {
                cflowX86.Status = ProtectionSupportStatus.Unsupported;
                cflowX86.ResultSummary = "Unsupported";
                cflowX86.Details = "Native x86 control-flow thunks detected. Native x86 machine-code emulation is not supported.";
            }
            else
            {
                cflowX86.Status = ProtectionSupportStatus.NotDetected;
                cflowX86.ResultSummary = "N/A";
                cflowX86.Details = "Pure IL assembly; no native x86 control-flow thunks detected.";
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
            if (isUnevaluated("Reference Proxies", "Mild / Strong"))
            {
                proxyItem.Detected = false;
                proxyItem.Status = ProtectionSupportStatus.NotEvaluated;
                proxyItem.ResultSummary = "Not Evaluated";
                proxyItem.Details = "Reference proxy detection was not evaluated.";
            }
            else if (!proxiesDetected)
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
            if (isUnevaluated("Resources", "Normal / Dynamic"))
            {
                resItem.Detected = false;
                resItem.Status = ProtectionSupportStatus.NotEvaluated;
                resItem.ResultSummary = "Not Evaluated";
                resItem.Details = "Encrypted resource detection was not evaluated.";
            }
            else if (!resourcesDetected)
            {
                resItem.Status = ProtectionSupportStatus.NotDetected;
                resItem.ResultSummary = "N/A";
                resItem.Details = "No encrypted resource streams or resource resolve hooks found.";
            }
            else if (resourcesExtractedCount > 0)
            {
                bool hooksRemaining = HasEncryptedResources(module);
                if (!hooksRemaining)
                {
                    resItem.Status = ProtectionSupportStatus.VerifiedOnRealFixture;
                    resItem.ResultSummary = $"Extracted ({resourcesExtractedCount})";
                    resItem.Details = "Encrypted resources decrypted, re-embedded into manifest, and resolve hooks pruned.";
                }
                else
                {
                    resItem.Status = ProtectionSupportStatus.PartiallyProcessed;
                    resItem.ResultSummary = $"Extracted ({resourcesExtractedCount}) / Hook Retained";
                    resItem.Details = "Encrypted resources decrypted and re-embedded into manifest, but resource resolve hook was retained in <Module>.";
                }
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
            bool compressorDetected = compressorUnpacked || HasCompressor(module);
            var compItem = new ProtectionItem
            {
                Name = "Compressor",
                Mode = "Deflate Packer",
                Detected = compressorDetected
            };
            if (isUnevaluated("Compressor", "Deflate Packer"))
            {
                compItem.Detected = false;
                compItem.Status = ProtectionSupportStatus.NotEvaluated;
                compItem.ResultSummary = "Not Evaluated";
                compItem.Details = "Compressor stub detection was not evaluated.";
            }
            else if (!compressorDetected)
            {
                compItem.Status = ProtectionSupportStatus.NotDetected;
                compItem.ResultSummary = "N/A";
                compItem.Details = "Assembly is not packaged inside a ConfuserEx compressor stub.";
            }
            else if (compressorUnpacked)
            {
                compItem.Status = ProtectionSupportStatus.VerifiedOnRealFixture;
                compItem.ResultSummary = "Unpacked";
                compItem.Details = "Compressed payload extracted, validated as PE, and unpacked.";
            }
            else if (!allowExecution)
            {
                compItem.Status = ProtectionSupportStatus.RequiresDynamicExecution;
                compItem.ResultSummary = "Skipped (Static Mode)";
                compItem.Details = "Compressor stub detected; dynamic method-rewrite unpacking requires --allow-execution.";
            }
            else
            {
                compItem.Status = ProtectionSupportStatus.PartiallyProcessed;
                compItem.ResultSummary = "Detected / Unresolved";
                compItem.Details = "ConfuserEx Compressor stub detected, but payload could not be unpacked safely.";
            }
            result.Items.Add(compItem);

            // 15. Name Protection (Renaming)
            bool renamingRemains = HasRenamingProtection(module);
            bool renamingDetected = symbolsRenamed || renamingRemains;
            var renameItem = new ProtectionItem
            {
                Name = "Name Protection",
                Mode = "Symbol Renaming",
                Detected = renamingDetected
            };
            if (isUnevaluated("Name Protection", "Symbol Renaming"))
            {
                renameItem.Detected = false;
                renameItem.Status = ProtectionSupportStatus.NotEvaluated;
                renameItem.ResultSummary = "Not Evaluated";
                renameItem.Details = "Symbol renaming detection was not evaluated.";
            }
            else if (!renamingDetected)
            {
                renameItem.Status = ProtectionSupportStatus.NotDetected;
                renameItem.ResultSummary = "N/A";
                renameItem.Details = "Symbols do not show unprintable or high-entropy ConfuserEx renaming patterns.";
            }
            else if (symbolsRenamed && !renamingRemains)
            {
                renameItem.Status = ProtectionSupportStatus.VerifiedOnRealFixture;
                renameItem.ResultSummary = "Cleaned (Normalized)";
                renameItem.Details = "All unprintable and Unicode-mangled identifiers have been cleaned and normalized to valid C# symbols.";
            }
            else
            {
                renameItem.Status = ProtectionSupportStatus.PartiallyProcessed;
                renameItem.ResultSummary = "Partially Processed";
                renameItem.Details = "Symbol renaming detected; unprintable or mangled identifiers remain in internal/private scope.";
            }
            result.Items.Add(renameItem);

            // Evaluate Overall Verdict
            result.HasPartiallyProcessed = result.Items.Any(i => i.Detected && (i.Status == ProtectionSupportStatus.PartiallyProcessed || i.Status == ProtectionSupportStatus.Detected));
            result.HasUnsupported = result.Items.Any(i => i.Detected && i.Status == ProtectionSupportStatus.Unsupported);
            result.HasRequiresDynamicSkipped = result.Items.Any(i => i.Detected && i.Status == ProtectionSupportStatus.RequiresDynamicExecution);
            result.HasNotEvaluated = result.Items.Any(i => i.Status == ProtectionSupportStatus.NotEvaluated);

            if (result.HasUnsupported)
            {
                result.IsComplete = false;
                result.OverallVerdict = "PARTIALLY DEOBFUSCATED (Unsupported Modes Detected)";
                result.SummaryNotes = "One or more detected protections (e.g. JIT hooks or x86 variants) are not supported and were preserved intact to avoid corruption.";
                if (result.HasNotEvaluated)
                    result.SummaryNotes += " Additionally, one or more protections could not be conclusively evaluated.";
            }
            else if (result.HasRequiresDynamicSkipped)
            {
                result.IsComplete = false;
                result.OverallVerdict = "PARTIALLY DEOBFUSCATED (Dynamic Execution Required)";
                result.SummaryNotes = "One or more detected protections require dynamic execution (--allow-execution). Re-run with execution enabled for full deobfuscation.";
                if (result.HasNotEvaluated)
                    result.SummaryNotes += " Additionally, one or more protections could not be conclusively evaluated.";
            }
            else if (result.HasPartiallyProcessed)
            {
                result.IsComplete = false;
                result.OverallVerdict = "PARTIALLY DEOBFUSCATED (Incomplete Transformations)";
                result.SummaryNotes = "Some protections were only partially resolved; unverified transformations were safely rolled back.";
                if (result.HasNotEvaluated)
                    result.SummaryNotes += " Additionally, one or more protections could not be conclusively evaluated.";
            }
            else if (result.HasNotEvaluated)
            {
                result.IsComplete = false;
                result.OverallVerdict = "DEOBFUSCATION UNCONFIRMED (Unevaluated Protections)";
                result.SummaryNotes = "One or more protections could not be conclusively evaluated (unsupported detectors). Deobfuscation cannot be verified as complete.";
            }
            else if (ilVerificationIndeterminate)
            {
                result.IsComplete = true;
                result.OverallVerdict = "DEOBFUSCATION COMPLETED (INDETERMINATE IL VERIFICATION)";
                result.SummaryNotes = "All detected ConfuserEx protections were safely reversed, but external IL verification was indeterminate due to unresolved external assembly references. Runtime JIT verification required.";
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
                string det = item.Status == ProtectionSupportStatus.NotEvaluated ? "N/E" : (item.Detected ? "Yes" : "No");
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

        public static bool HasAntiTamperNormal(ModuleDef module)
        {
            if (module == null) return false;
            if (module.GlobalType == null) return false;

            // 1. Check if GlobalType has a P/Invoke to VirtualProtect in kernel32.dll
            foreach (var m in module.GlobalType.Methods)
            {
                if (m.IsPinvokeImpl && m.ImplMap != null)
                {
                    string pName = m.ImplMap.Name?.String;
                    if (string.Equals(pName, "VirtualProtect", StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }

            // 2. Check for characteristic VirtualProtect or section unscrambling in <Module>..cctor or called methods
            var cctor = module.GlobalType.FindStaticConstructor();
            if (cctor != null && cctor.HasBody)
            {
                foreach (var instr in cctor.Body.Instructions)
                {
                    if (instr.Operand is IMethod m)
                    {
                        if (m.Name.IndexOf("VirtualProtect", StringComparison.OrdinalIgnoreCase) >= 0 || m.Name.Contains("AntiTamper"))
                            return true;

                        var mDef = m.ResolveMethodDef();
                        if (mDef != null && mDef.HasBody)
                        {
                            foreach (var inner in mDef.Body.Instructions)
                            {
                                if (inner.Operand is IMethod innerM)
                                {
                                    if (innerM.Name.IndexOf("VirtualProtect", StringComparison.OrdinalIgnoreCase) >= 0)
                                        return true;

                                    var innerDef = innerM.ResolveMethodDef();
                                    if (innerDef != null && innerDef.IsPinvokeImpl && innerDef.ImplMap != null)
                                    {
                                        string pinvokeName = innerDef.ImplMap.Name?.String;
                                        if (string.Equals(pinvokeName, "VirtualProtect", StringComparison.OrdinalIgnoreCase))
                                            return true;
                                    }
                                }
                            }
                        }
                    }
                }
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
                    if (name == "IsDebuggerPresent" || name == "CheckRemoteDebuggerPresent" ||
                        name == "NtSetInformationThread" || name == "OutputDebugStringA" || name == "OutputDebugStringW")
                        return true;
                }

                if (method.HasBody && method.Body.Instructions != null)
                {
                    foreach (var ins in method.Body.Instructions)
                    {
                        if (ins.OpCode == OpCodes.Ldstr && ins.Operand is string s &&
                            s.IndexOf("ENABLE_PROFILING", StringComparison.OrdinalIgnoreCase) >= 0)
                            return true;

                        if (ins.Operand is IMethod called)
                        {
                            string fn = called.FullName;
                            if (fn.IndexOf("IsAttached", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                fn.IndexOf("IsLogging", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                fn.IndexOf("FailFast", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                fn.IndexOf("IsDebuggerPresent", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                fn.IndexOf("CheckRemoteDebuggerPresent", StringComparison.OrdinalIgnoreCase) >= 0)
                                return true;
                        }
                    }
                }
            }
            return false;
        }

        public static bool HasAntiIldasmAttribute(ModuleDef module)
        {
            if (module == null) return false;
            bool onAssembly = module.Assembly != null && module.Assembly.CustomAttributes.Any(ca => ca?.TypeFullName != null && ca.TypeFullName.IndexOf("SuppressIldasmAttribute", StringComparison.OrdinalIgnoreCase) >= 0);
            bool onModule = module.CustomAttributes.Any(ca => ca?.TypeFullName != null && ca.TypeFullName.IndexOf("SuppressIldasmAttribute", StringComparison.OrdinalIgnoreCase) >= 0);
            return onAssembly || onModule;
        }

        public static bool? HasInvalidMetadata(ModuleDef module)
        {
            if (module == null) return null;
            if (module is ModuleDefMD modMD && modMD.MetaData?.AllStreams != null)
            {
                foreach (var stream in modMD.MetaData.AllStreams)
                {
                    string sName = stream.Name;
                    if (sName == "#Schema") return true;
                    if (!string.IsNullOrEmpty(sName) && sName.Any(c => c < 32 || c > 126)) return true;
                }
                return false;
            }
            if (module is ModuleDefUser)
                return false;

            return null;
        }

        public static bool HasConstantDecrypters(ModuleDef module)
        {
            if (module == null || module.GlobalType == null) return false;
            foreach (var m in module.GlobalType.Methods)
            {
                if (!m.HasBody) continue;
                if (!m.IsStatic || !m.HasGenericParameters) continue;
                if (m.ReturnType.ElementType == ElementType.MVar &&
                    m.Parameters.Count == 1 &&
                    m.Parameters[0].Type.ElementType == ElementType.U4)
                {
                    return true;
                }
            }
            return false;
        }

        public static bool? HasX86ConstantDecrypters(ModuleDef module)
        {
            if (module == null) return null;
            return HasNativeMethods(module);
        }

        private static bool HasSwitchFlattening(ModuleDef module)
        {
            if (module == null) return false;
            foreach (var t in module.GetTypes())
            {
                foreach (var m in t.Methods)
                {
                    if (!m.HasBody) continue;
                    var instrs = m.Body.Instructions;
                    for (int i = 0; i < instrs.Count; i++)
                    {
                        if (instrs[i].OpCode == OpCodes.Switch)
                        {
                            int headerStart = Math.Max(0, i - 6);
                            bool hasArith = false;
                            for (int k = headerStart; k < i; k++)
                            {
                                var op = instrs[k].OpCode;
                                if (op == OpCodes.Xor || op == OpCodes.Rem || op == OpCodes.Rem_Un)
                                {
                                    hasArith = true;
                                    break;
                                }
                            }
                            if (!hasArith) continue;

                            // ConfuserEx switch flattening is a loop/state-machine dispatcher.
                            // There must be at least one backward branch targeting the header [headerStart..i].
                            for (int b = i + 1; b < instrs.Count; b++)
                            {
                                var target = instrs[b].Operand as Instruction;
                                if (target != null)
                                {
                                    int targetIdx = instrs.IndexOf(target);
                                    if (targetIdx >= headerStart && targetIdx <= i)
                                        return true;
                                }
                            }
                        }
                    }
                }
            }
            return false;
        }

        public static bool HasDeadCodeOrJunk(ModuleDef module)
        {
            if (module == null) return false;
            foreach (var t in module.GetTypes())
            {
                foreach (var m in t.Methods)
                {
                    if (!m.HasBody || m.Body.Instructions == null || m.Body.Instructions.Count < 2)
                        continue;

                    var instrs = m.Body.Instructions;
                    for (int i = 0; i < instrs.Count - 1; i++)
                    {
                        var first = instrs[i];
                        var second = instrs[i + 1];

                        if (second.OpCode == OpCodes.Pop && (first.IsLdcI4() || first.OpCode == OpCodes.Dup))
                            return true;

                        if ((first.OpCode == OpCodes.Br || first.OpCode == OpCodes.Br_S) && first.Operand == second)
                            return true;
                    }
                }
            }
            return false;
        }

        public static bool? HasX86ControlFlow(ModuleDef module)
        {
            if (module == null) return null;
            return HasNativeMethods(module);
        }

        private static bool HasNativeMethods(ModuleDef module)
        {
            if (module == null) return false;
            foreach (var t in module.GetTypes())
            {
                foreach (var m in t.Methods)
                {
                    if (m.IsNative || (m.ImplAttributes & MethodImplAttributes.CodeTypeMask) == MethodImplAttributes.Native)
                        return true;
                }
            }
            return false;
        }

        private static bool HasReferenceProxies(ModuleDef module)
        {
            if (module == null) return false;
            foreach (var t in module.GetTypes())
            {
                foreach (var m in t.Methods)
                {
                    if (ConfuserExTools.ProxyKiller.ProxyKillerImpl.TryAnalyzeClassicProxy(m, ignoreAccess: false, out _, out _))
                        return true;
                }
            }
            if (module.GlobalType != null)
            {
                foreach (var f in module.GlobalType.Fields)
                {
                    var ft = (f.FieldSig?.Type?.ToTypeDefOrRef() as TypeDef) ?? f.FieldSig?.Type?.ToTypeDefOrRef()?.ResolveTypeDef();
                    if (ft != null && ft.BaseType != null && ft.BaseType.FullName == "System.MulticastDelegate")
                        return true;
                }
            }
            return false;
        }

        private static bool HasEncryptedResources(ModuleDef module)
        {
            if (module == null) return false;
            if (module.GlobalType != null)
            {
                foreach (var m in module.GlobalType.Methods)
                {
                    if (!m.HasBody) continue;
                    foreach (var inst in m.Body.Instructions)
                    {
                        if (inst.Operand is IMethod target &&
                            (target.Name == "GetManifestResourceStream" || target.Name == "add_ResourceResolve"))
                        {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        public static bool HasCompressor(ModuleDef module)
        {
            if (module == null) return false;
            if (module is ModuleDefMD modMD && modMD.MetaData?.TablesStream?.FileTable != null)
            {
                for (uint rid = 1; rid <= modMD.MetaData.TablesStream.FileTable.Rows; rid++)
                {
                    var row = modMD.TablesStream.ReadFileRow(rid);
                    string name = modMD.StringsStream.ReadNoNull(row.Name);
                    if (string.Equals(name, "koi", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(name, "netmodule", StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            foreach (var res in module.Resources)
            {
                string rName = res.Name?.String;
                if (!string.IsNullOrEmpty(rName) &&
                    (rName.Equals("ConfuserEx.CompressedPayload", StringComparison.OrdinalIgnoreCase) ||
                     rName.StartsWith("Confuser.", StringComparison.OrdinalIgnoreCase) ||
                     rName.StartsWith("koi.", StringComparison.OrdinalIgnoreCase) ||
                     rName.Equals("koi", StringComparison.OrdinalIgnoreCase)))
                {
                    return true;
                }
            }
            return false;
        }

        public static bool HasRenamingProtection(ModuleDef module)
        {
            if (module == null) return false;
            int obfuscatedCount = 0;
            foreach (var t in module.GetTypes())
            {
                if (t.IsGlobalModuleType || (t.DeclaringType != null && t.DeclaringType.IsGlobalModuleType))
                    continue;
                if (!UTF8String.IsNullOrEmpty(t.Name))
                {
                    string s = t.Name.String;
                    if (s != null && IsConfuserExObfuscatedIdentifier(s))
                        obfuscatedCount++;
                }
                foreach (var m in t.Methods)
                {
                    if (!UTF8String.IsNullOrEmpty(m.Name) && !m.IsConstructor && IsConfuserExObfuscatedIdentifier(m.Name.String))
                        obfuscatedCount++;
                }
                foreach (var f in t.Fields)
                {
                    if (!UTF8String.IsNullOrEmpty(f.Name) && IsConfuserExObfuscatedIdentifier(f.Name.String))
                        obfuscatedCount++;
                }
                if (obfuscatedCount > 3) return true;
            }
            return obfuscatedCount > 3;
        }

        public static bool IsConfuserExObfuscatedIdentifier(string name)
        {
            if (string.IsNullOrEmpty(name)) return false;
            foreach (char c in name)
            {
                int code = (int)c;
                if (code >= 0x2000 && code <= 0x206F) return true;
                if (code >= 0xFE00 && code <= 0xFEFF) return true;
                if (char.IsControl(c) || char.GetUnicodeCategory(c) == System.Globalization.UnicodeCategory.Format) return true;
            }
            return false;
        }
    }
}
