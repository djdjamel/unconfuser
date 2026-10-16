using System;

namespace Tool
{
    public static class Logger
    {
        public static void Initialize(bool verbose) { }
        public static void Flush() { }
        public static void LogInfo(string message = "") => Console.WriteLine("[INFO] " + message);
        public static void LogWarning(string message) => Console.WriteLine("[WARN] " + message);
        public static void LogError(string message) => Console.WriteLine("[ERROR] " + message);
        public static void LogDebugInfo(string message) => Console.WriteLine("[DEBUG] " + message);
        public static void LogException(Exception ex) => Console.WriteLine("[EXCEPTION] " + ex.Message);
    }
}
