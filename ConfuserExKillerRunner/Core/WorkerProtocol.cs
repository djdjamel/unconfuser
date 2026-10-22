using System;
using System.Globalization;
using ConfuserExKillerRunner.Killers;
using Tool;

namespace ConfuserExKillerRunner.Core
{
    /// <summary>
    /// Provides strongly typed, structured serialization and deserialization for IPC between
    /// ConfuserExKillerRunner and isolated worker processes using SimpleJson.
    /// </summary>
    public static class WorkerProtocol
    {
        public static void ParseAntiTamperMeta(string json, AntiTamperResult result)
        {
            if (result == null) throw new ArgumentNullException(nameof(result));
            if (string.IsNullOrWhiteSpace(json)) return;

            try
            {
                var root = JsonValue.Parse(json);
                if (!root.IsObject) return;

                string statusStr = root["Status"].AsString(null);
                if (!string.IsNullOrEmpty(statusStr) && Enum.TryParse<AntiTamperStatus>(statusStr, out var parsedStatus))
                    result.Status = parsedStatus;

                if (root.ContainsKey("Modified"))
                    result.Modified = root["Modified"].AsBool(result.Modified);

                string msg = root["Message"].AsString(null);
                if (msg != null)
                    result.Message = msg;

                var sections = root["DecryptedSections"];
                if (sections.IsArray)
                {
                    foreach (var item in sections.AsArray())
                    {
                        string secName = item.IsObject ? item["Section"].AsString(null) : item.AsString(null);
                        if (!string.IsNullOrEmpty(secName) && !result.DecryptedSections.Contains(secName))
                            result.DecryptedSections.Add(secName);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"[WorkerProtocol] Failed to parse AntiTamper metadata JSON: {ex.Message}");
            }
        }

        public static void ParseResourceMeta(string json, DynamicResourceResult result)
        {
            if (result == null) throw new ArgumentNullException(nameof(result));
            if (string.IsNullOrWhiteSpace(json)) return;

            try
            {
                var root = JsonValue.Parse(json);
                if (!root.IsObject) return;

                if (root.ContainsKey("Success"))
                    result.Success = root["Success"].AsBool(result.Success);

                if (root.ContainsKey("DecryptedCount"))
                    result.ExtractedCount = root["DecryptedCount"].AsInt(result.ExtractedCount);

                string msg = root["Message"].AsString(null);
                if (!string.IsNullOrEmpty(msg))
                    result.Message = msg;
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"[WorkerProtocol] Failed to parse resource metadata JSON: {ex.Message}");
            }
        }

        public static void ParseCompressorMeta(string json, DynamicCompressorResult result)
        {
            if (result == null) throw new ArgumentNullException(nameof(result));
            if (string.IsNullOrWhiteSpace(json)) return;

            try
            {
                var root = JsonValue.Parse(json);
                if (!root.IsObject) return;

                if (root.ContainsKey("Success"))
                    result.Success = root["Success"].AsBool(result.Success);

                string msg = root["Message"].AsString(null);
                if (!string.IsNullOrWhiteSpace(msg))
                    result.Message = msg;

                var epVal = root["EntryPointToken"];
                if (epVal.IsString)
                {
                    string epStr = epVal.AsString();
                    if (epStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                        epStr = epStr.Substring(2);
                    if (uint.TryParse(epStr, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out uint epToken))
                        result.RecoveredEntryPointToken = epToken;
                }
                else if (epVal.IsNumber)
                {
                    result.RecoveredEntryPointToken = (uint)epVal.AsLong(0);
                }
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"[WorkerProtocol] Failed to parse compressor metadata JSON: {ex.Message}");
            }
        }

        public static void ParseConstantsMeta(string json, out int decryptedCount, out bool allResolved, out string message)
        {
            decryptedCount = 0;
            allResolved = false;
            message = null;

            if (string.IsNullOrWhiteSpace(json)) return;

            try
            {
                var root = JsonValue.Parse(json);
                if (!root.IsObject) return;

                if (root.ContainsKey("DecryptedCount"))
                    decryptedCount = root["DecryptedCount"].AsInt(0);

                if (root.ContainsKey("AllResolved"))
                    allResolved = root["AllResolved"].AsBool(false);

                string msg = root["Message"].AsString(null);
                if (!string.IsNullOrWhiteSpace(msg))
                    message = msg;
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"[WorkerProtocol] Failed to parse constants metadata JSON: {ex.Message}");
            }
        }

        public static void ParseFieldRvaMeta(string json, out int restoredCount, out string message)
        {
            restoredCount = 0;
            message = null;

            if (string.IsNullOrWhiteSpace(json)) return;

            try
            {
                var root = JsonValue.Parse(json);
                if (!root.IsObject) return;

                if (root.ContainsKey("RestoredCount"))
                    restoredCount = root["RestoredCount"].AsInt(0);

                string msg = root["Message"].AsString(null);
                if (!string.IsNullOrWhiteSpace(msg))
                    message = msg;
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"[WorkerProtocol] Failed to parse FieldRva metadata JSON: {ex.Message}");
            }
        }
    }
}
