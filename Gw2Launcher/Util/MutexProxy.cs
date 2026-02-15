using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

namespace Gw2Launcher.Util
{
    /// <summary>
    /// Deploys a version.dll proxy next to the GW2 executable that hooks
    /// CreateMutex to prevent the single-instance check. This replaces the
    /// previous NtQuerySystemInformation + DuplicateHandle mutex killing approach.
    /// On Windows the proxy is loaded automatically via DLL search order; on
    /// Wine/Proton, WINEDLLOVERRIDES is set to prefer the local DLL over the builtin.
    /// </summary>
    static class MutexProxy
    {
        private const string PROXY_DLL_NAME = "version.dll";
        private const string RESOURCE_NAME = "Gw2Launcher.Resources.version_proxy.dll";
    /// On Wine/Proton, also sets WINEDLLOVERRIDES so the proxy is loaded.

        /// <summary>
        /// Ensures the version.dll proxy is deployed next to the GW2 executable.
        /// Call this before launching GW2 in multi-instance mode.
        /// </summary>
        /// <param name="gw2ExePath">Full path to Gw2-64.exe or Gw2.exe</param>
        /// <returns>True if the proxy is in place</returns>
        public static bool EnsureProxyDeployed(string gw2ExePath)
        {
            try
            {
                var dir = Path.GetDirectoryName(gw2ExePath);
                var target = Path.Combine(dir, PROXY_DLL_NAME);

                if (File.Exists(target))
                    return true;

                using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(RESOURCE_NAME))
                {
                    if (stream == null)
                    {
                        Logging.Log(new Exception("Embedded version_proxy.dll resource not found"));
                        return false;
                    }

                    using (var fs = File.Create(target))
                    {
                        stream.CopyTo(fs);
                    }
                }

                Logging.Log("Deployed mutex proxy: " + target);
                return true;
            }
            catch (Exception e)
            {
                Logging.Log(e);
                return false;
            }
        }

        /// <summary>
        /// Adds WINEDLLOVERRIDES to the process environment variables so Wine
        /// loads our native version.dll instead of its builtin.
        /// </summary>
        public static void SetEnvironment(Dictionary<string, string> variables)
        {
            const string key = "WINEDLLOVERRIDES";
            string existing;

            if (variables.TryGetValue(key, out existing) && !string.IsNullOrEmpty(existing))
            {
                // Append to existing overrides if version isn't already there
                if (existing.IndexOf("version=", StringComparison.OrdinalIgnoreCase) < 0)
                    variables[key] = "version=n,b;" + existing;
            }
            else
            {
                // Check the process-level env var (set by Lutris, etc.)
                var envValue = Environment.GetEnvironmentVariable(key);
                if (!string.IsNullOrEmpty(envValue))
                {
                    if (envValue.IndexOf("version=", StringComparison.OrdinalIgnoreCase) < 0)
                        variables[key] = "version=n,b;" + envValue;
                }
                else
                {
                    variables[key] = "version=n,b";
                }
            }
        }
    }
}
