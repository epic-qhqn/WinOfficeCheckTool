using System;
using System.Collections;
using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

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
                // Generates a hardware fingerprint (Hardware ID) using SHA256 for advanced tracing.
                string hwidHash = GenerateHardwareID();

                // Step 1: Extract hardware-embedded OEM Key (MSDM table).
                string oemKey = GetBiosKeyViaPInvoke();

                if (string.IsNullOrEmpty(oemKey))
                {
                    oemKey = GetBiosKeyViaWmi();
                }

                // Extracts DigitalProductId directly from Registry as a fallback parallel to WMI.
                string decodedRegistryKey = DecodeRegistryProductKey();

                // Step 2: Extract currently Active Windows License Partial Key via WMI.
                string activePartialKey = GetActiveWindowsPartialKey();

                // Unifies validation string.
                if (string.IsNullOrEmpty(activePartialKey) && !string.IsNullOrEmpty(decodedRegistryKey))
                {
                    // Fallback to Registry tail if WMI SPP is completely broken.
                    activePartialKey = decodedRegistryKey.Substring(Math.Max(0, decodedRegistryKey.Length - 5));
                }

                // Step 3: Check for MAS HWID Generic Keys (Suspicious if used without BIOS Key).
                string[] genericMASKeys = { "3V66T", "PKCKT", "2YV77", "8HVX7", "WXCHW", "6F4BT", "2YT43", "KHJW4", "VCFB2", "MDWWJ" };
                bool usesGenericKey = false;
                
                if (!string.IsNullOrEmpty(activePartialKey))
                {
                    foreach (string gk in genericMASKeys)
                    {
                        if (activePartialKey.Equals(gk, StringComparison.OrdinalIgnoreCase))
                        {
                            usesGenericKey = true;
                            break;
                        }
                    }
                }

                if (string.IsNullOrEmpty(oemKey))
                {
                    if (usesGenericKey)
                    {
                        // Highly likely HWID Digital License applied to a non-OEM machine illegally.
                        return new CheckResult { Status = CheckStatus.Warning, Message = LanguageManager.GetString("BIOS_HWID_MAS") + $" [[({activePartialKey})]] (HWID: {hwidHash})" };
                    }
                    return new CheckResult { Status = CheckStatus.Clean, Message = LanguageManager.GetString("BIOS_NO_KEY") + (string.IsNullOrEmpty(decodedRegistryKey) ? "" : $"\n  -> {LanguageManager.GetString("BIOS_REG_KEY")} [[{decodedRegistryKey}]]") };
                }

                // Step 4: Correlate hardware original intent vs system current reality.
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

        private static string DecodeRegistryProductKey()
        {
            // Direct Base24 decoding of DigitalProductId to bypass WMI corruption.
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    if (key != null)
                    {
                        byte[] digitalProductId = key.GetValue("DigitalProductId") as byte[];
                        if (digitalProductId != null && digitalProductId.Length >= 67)
                        {
                            const int keyOffset = 52;
                            byte isWin8 = (byte)((digitalProductId[66] / 6) & 1);
                            digitalProductId[66] = (byte)((digitalProductId[66] & 0xf7) | ((isWin8 & 2) * 4));

                            const string chars = "BCDFGHJKMPQRTVWXY2346789";
                            int last = 0;
                            string decodedKey = string.Empty;

                            for (int i = 24; i >= 0; i--)
                            {
                                int current = 0;
                                for (int j = 14; j >= 0; j--)
                                {
                                    current = (current * 256) ^ digitalProductId[j + keyOffset];
                                    digitalProductId[j + keyOffset] = (byte)(current / 24);
                                    current %= 24;
                                }
                                decodedKey = chars[current] + decodedKey;
                                last = current;
                            }

                            if (isWin8 == 1)
                            {
                                string part1 = decodedKey.Substring(1, last);
                                string part2 = decodedKey.Substring(last + 1, decodedKey.Length - (last + 1));
                                decodedKey = part1 + "N" + part2;
                            }

                            // Format xxxxx-xxxxx-xxxxx-xxxxx-xxxxx
                            return Regex.Replace(decodedKey, ".{5}", "$0-").TrimEnd('-');
                        }
                    }
                }
            }
            catch { }
            return null;
        }

        private static string GenerateHardwareID()
        {
            // Creates a cryptographic hash of the Motherboard + Processor IDs for tracing HWID Spoofing anomalies.
            try
            {
                string hardwareRaw = "";
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BaseBoard"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        hardwareRaw += obj["SerialNumber"]?.ToString();
                        break;
                    }
                }
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT ProcessorId FROM Win32_Processor"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        hardwareRaw += obj["ProcessorId"]?.ToString();
                        break;
                    }
                }

                if (!string.IsNullOrEmpty(hardwareRaw))
                {
                    using (SHA256 sha256Hash = SHA256.Create())
                    {
                        byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(hardwareRaw));
                        StringBuilder builder = new StringBuilder();
                        for (int i = 0; i < 8; i++) // Returns a 16-character short hash.
                        {
                            builder.Append(bytes[i].ToString("x2"));
                        }
                        return builder.ToString();
                    }
                }
            }
            catch { }
            return "UNKNOWN-HWID";
        }
    }
}