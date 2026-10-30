using System;
using System.IO;

namespace ConfuserExKillerRunner.Tests
{
    public static class TestPathHelper
    {
        private static string _cachedRepoRoot;

        public static string GetRepositoryRoot()
        {
            if (_cachedRepoRoot != null && Directory.Exists(_cachedRepoRoot))
                return _cachedRepoRoot;

            // Strategy 1: Walk up from AppDomain.CurrentDomain.BaseDirectory
            string current = AppDomain.CurrentDomain.BaseDirectory;
            while (!string.IsNullOrEmpty(current))
            {
                if (File.Exists(Path.Combine(current, "unconfuser.sln")) ||
                    Directory.Exists(Path.Combine(current, ".git")))
                {
                    _cachedRepoRoot = Path.GetFullPath(current);
                    return _cachedRepoRoot;
                }
                var parent = Directory.GetParent(current);
                if (parent == null) break;
                current = parent.FullName;
            }

            // Strategy 2: Walk up from Directory.GetCurrentDirectory()
            current = Directory.GetCurrentDirectory();
            while (!string.IsNullOrEmpty(current))
            {
                if (File.Exists(Path.Combine(current, "unconfuser.sln")) ||
                    Directory.Exists(Path.Combine(current, ".git")))
                {
                    _cachedRepoRoot = Path.GetFullPath(current);
                    return _cachedRepoRoot;
                }
                var parent = Directory.GetParent(current);
                if (parent == null) break;
                current = parent.FullName;
            }

            // Strategy 3: Standard 4-level parent fallback
            _cachedRepoRoot = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", ".."));
            return _cachedRepoRoot;
        }

        public static string GetBenignSampleExe()
        {
            string root = GetRepositoryRoot();
            var candidates = new[]
            {
                Path.Combine(root, "benchmarks", "BenignSample", "bin", "Release", "net48", "BenignSample.exe"),
                Path.Combine(root, "benchmarks", "BenignSample", "bin", "Debug", "net48", "BenignSample.exe"),
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "BenignSample.exe")
            };

            foreach (var cand in candidates)
            {
                if (File.Exists(cand))
                    return Path.GetFullPath(cand);
            }

            throw new FileNotFoundException("BenignSample.exe could not be located in repository or output directories.");
        }
    }
}
