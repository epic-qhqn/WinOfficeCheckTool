using System;
using System.Management;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace WinCheckTool
{
    [SupportedOSPlatform("windows")]
    public class Module_Office_Inspector : ICheckModule
    {
        public string ModuleName => LanguageManager.GetString("MOD_OFFICE");

        public CheckResult Execute()
        {
            try
            {
                CheckResult wmiResult = CheckOfficeWMI();

                // Ohook injection takes absolute priority over standard WMI statuses.
                CheckResult ohookResult = CheckOhookBypass();
                if (ohookResult.Status == CheckStatus.Danger)
                {
                    return ohookResult; 
                }

                return wmiResult;
            }
            catch (Exception ex)
            {
                return new CheckResult { Status = CheckStatus.Error, Message = LanguageManager.GetString("OFFICE_ERROR") + ex.Message };
            }
        }

        private CheckResult CheckOfficeWMI()
        {
            // Targets Office Application ID for KMS/Channel evaluation.
            string queryString = "SELECT Name, LicenseStatus, KeyManagementServiceMachine, PartialProductKey, ApplicationId FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL";
            
            System.Management.EnumerationOptions options = new System.Management.EnumerationOptions { ReturnImmediately = true, Timeout = TimeSpan.FromSeconds(10) };
            ManagementScope scope = new ManagementScope(@"\\localhost\root\cimv2");
            ObjectQuery query = new ObjectQuery(queryString);

            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query, options))
                using (ManagementObjectCollection objCollection = searcher.Get())
                {
                    CheckResult worstResult = new CheckResult { Status = CheckStatus.Warning, Message = LanguageManager.GetString("OFFICE_NOT_FOUND") };

                    foreach (ManagementObject obj in objCollection)
                    {
                        string appId = obj["ApplicationId"]?.ToString();
                        if (string.IsNullOrEmpty(appId) || appId.ToLower() != "0ff1ce15-a989-479d-af46-f275c6370663")
                            continue;

                        uint status = 0;
                        if (obj["LicenseStatus"] != null) uint.TryParse(obj["LicenseStatus"].ToString(), out status);

                        if (status == 1) 
                        {
                            string bestChannel = obj["Name"]?.ToString() ?? "";
                            string kmsServer = obj["KeyManagementServiceMachine"]?.ToString() ?? "";
                            
                            if (!string.IsNullOrEmpty(kmsServer))
                            {
                                if (IsSuspiciousKMS(kmsServer)) 
                                {
                                    worstResult = new CheckResult { Status = CheckStatus.Danger, Message = LanguageManager.GetString("OFFICE_KMS_DETECTED") + $" [[{kmsServer}]]" };
                                    break; 
                                }
                                else if (worstResult.Status != CheckStatus.Danger)
                                {
                                    worstResult = new CheckResult { Status = CheckStatus.Warning, Message = LanguageManager.GetString("OFFICE_KMS_LEGAL") + $" [[{kmsServer}]]" };
                                }
                            }
                            else
                            {
                                if (worstResult.Status == CheckStatus.Warning && worstResult.Message == LanguageManager.GetString("OFFICE_NOT_FOUND"))
                                {
                                    string cleanChannel = bestChannel.Contains(",") ? bestChannel.Split(',')[1].Trim() : bestChannel;
                                    worstResult = new CheckResult { Status = CheckStatus.Clean, Message = LanguageManager.GetString("OFFICE_CLEAN") + $" [[({cleanChannel})]]" };
                                }
                            }
                        }
                    }

                    return worstResult;
                }
            }
            catch
            {
                return new CheckResult { Status = CheckStatus.Error, Message = "SPP WMI Query Failed." };
            }
        }

        private CheckResult CheckOhookBypass()
        {
            // Scans registry architecture for the explicit presence of Ohook logic routing hooks.
            string[] ohookPaths = {
                @"SOFTWARE\Ohook",
                @"SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Ohook",
                @"SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Classes\AppId\OtkApp"
            };

            foreach (string path in ohookPaths)
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(path))
                {
                    if (key != null)
                    {
                        return new CheckResult { Status = CheckStatus.Danger, Message = LanguageManager.GetString("HEUR_OHOOK") };
                    }
                }
            }
            return new CheckResult { Status = CheckStatus.Clean, Message = "" }; 
        }

        private bool IsSuspiciousKMS(string kmsServer)
        {
            if (string.IsNullOrEmpty(kmsServer)) return false;
            string lower = kmsServer.ToLower().Trim();

            string[] badWords = { "127.0.0.1", "0.0.0.0", "::1", "localhost", "kms", "loli", "msguides", "massgrave", "03k", "v0v", "lzzy", "rg-adguard", "kmsauto", "ratiborus" };
            foreach (string word in badWords)
            {
                if (lower.Contains(word)) return true;
            }

            var match = Regex.Match(lower, @"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b");
            if (match.Success)
            {
                string ipStr = match.Groups[1].Value;
                string[] parts = ipStr.Split('.');
                if (parts.Length == 4 && int.TryParse(parts[0], out int p1) && int.TryParse(parts[1], out int p2))
                {
                    bool isPrivate = (p1 == 10) || (p1 == 172 && p2 >= 16 && p2 <= 31) || (p1 == 192 && p2 == 168);
                    if (!isPrivate) return true; 
                }
            }
            return false;
        }
    }
}