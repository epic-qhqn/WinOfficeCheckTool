using System;
using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Text.RegularExpressions;

namespace WinCheckTool
{
    [SupportedOSPlatform("windows")]
    public class Module_BIOS_Extractor : ICheckModule
    {
        public string ModuleName => LanguageManager.GetString("MOD_BIOS");

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint GetSystemFirmwareTable(uint firmwareTableProviderSignature, uint firmwareTableID, IntPtr firmwareTableBuffer, uint bufferSize);

        public CheckResult Execute()
        {
            try
            {
                // Step 1: Extract hardware-embedded OEM Key (MSDM table).
                string oemKey = GetBiosKeyViaPInvoke();

                if (string.IsNullOrEmpty(oemKey))
                {
                    oemKey = GetBiosKeyViaWmi();
                }

                if (string.IsNullOrEmpty(oemKey))
                {
                    return new CheckResult { Status = CheckStatus.Clean, Message = LanguageManager.GetString("BIOS_NO_KEY") };
                }

                // Step 2: Extract currently Active Windows License Partial Key.
                string activePartialKey = GetActiveWindowsPartialKey();

                // Step 3: Correlate hardware original intent vs system current reality.
                if (!string.IsNullOrEmpty(activePartialKey))
                {
                    // If the embedded OEM key ends with the active partial product key, the license is genuinely matched.
                    if (oemKey.EndsWith(activePartialKey, StringComparison.OrdinalIgnoreCase))
                    {
                        return new CheckResult { Status = CheckStatus.Clean, Message = $"{LanguageManager.GetString("BIOS_KEY_MATCH")} [[ [{oemKey}] ]]" };
                    }
                    else
                    {
                        // Highly forensic indicator: The machine has an OEM key, but a completely different key is forcing activation.
                        return new CheckResult { Status = CheckStatus.Warning, Message = string.Format(LanguageManager.GetString("BIOS_KEY_MISMATCH"), activePartialKey) + $" [[ [{oemKey}] ]]" };
                    }
                }

                // Fallback: If system is not activated at all, but an OEM key exists in the hardware.
                return new CheckResult { Status = CheckStatus.Clean, Message = $"{LanguageManager.GetString("BIOS_KEY_FOUND")} [[ [{oemKey}] ]]" };
            }
            catch (Exception ex)
            {
                return new CheckResult { Status = CheckStatus.Error, Message = LanguageManager.GetString("BIOS_ERROR") + ex.Message };
            }
        }

        private static string GetBiosKeyViaPInvoke()
        {
            // Decodes Windows ACPI MSDM memory table via direct system calls.
            uint acpi = (((uint)'I' << 24) | ((uint)'P' << 16) | ((uint)'C' << 8) | 'A');
            uint msdm = (((uint)'M' << 24) | ((uint)'D' << 16) | ((uint)'S' << 8) | 'M');

            uint size = GetSystemFirmwareTable(acpi, msdm, IntPtr.Zero, 0);
            if (size == 0) return null;

            IntPtr buffer = Marshal.AllocHGlobal((int)size);
            try
            {
                GetSystemFirmwareTable(acpi, msdm, buffer, size);
                byte[] bytes = new byte[size];
                Marshal.Copy(buffer, bytes, 0, (int)size);

                Match match = Regex.Match(Encoding.ASCII.GetString(bytes), @"[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}");
                if (match.Success) return match.Value;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer); 
            }
            return null;
        }

        private static string GetBiosKeyViaWmi()
        {
            // Fallback strategy utilizing standard Windows Management Instrumentation.
            try 
            {
                string query = "SELECT OA3xOriginalProductKey FROM SoftwareLicensingService";
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(query))
                using (ManagementObjectCollection objCollection = searcher.Get())
                {
                    foreach (ManagementObject obj in objCollection)
                    {
                        object key = obj["OA3xOriginalProductKey"];
                        if (key != null && !string.IsNullOrEmpty(key.ToString())) return key.ToString();
                    }
                }
            } 
            catch { } 
            return null;
        }

        private static string GetActiveWindowsPartialKey()
        {
            // Queries WMI strictly for the currently ACTIVE Windows product key suffix (Last 5 characters).
            try
            {
                string query = "SELECT PartialProductKey FROM SoftwareLicensingProduct WHERE ApplicationId = '55c92734-d682-4d71-983e-d6ec3f16059f' AND LicenseStatus = 1 AND PartialProductKey IS NOT NULL";
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(query))
                using (ManagementObjectCollection objCollection = searcher.Get())
                {
                    foreach (ManagementObject obj in objCollection)
                    {
                        string partialKey = obj["PartialProductKey"]?.ToString();
                        if (!string.IsNullOrEmpty(partialKey)) return partialKey.Trim();
                    }
                }
            }
            catch { }
            return null;
        }
    }
}