using System;
using System.Management;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;

namespace WinCheckTool
{
    [SupportedOSPlatform("windows")]
    public class Module_WMI_Inspector : ICheckModule
    {
        public string ModuleName => LanguageManager.GetString("MOD_WMI");

        public CheckResult Execute()
        {
            try
            {
                System.Management.EnumerationOptions options = new System.Management.EnumerationOptions 
                { 
                    ReturnImmediately = true, 
                    Timeout = TimeSpan.FromSeconds(10) 
                };

                // Targets Windows Licensing Application ID.
                string queryString = "SELECT Name, Description, LicenseStatus, KeyManagementServiceMachine, ApplicationId FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL";
                ManagementScope scope = new ManagementScope(@"\\localhost\root\cimv2");
                ObjectQuery query = new ObjectQuery(queryString);
                
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query, options))
                using (ManagementObjectCollection objCollection = searcher.Get())
                {
                    CheckResult worstResult = new CheckResult { Status = CheckStatus.Warning, Message = LanguageManager.GetString("WMI_NOT_ACTIVATED") };

                    foreach (ManagementObject obj in objCollection)
                    {
                        string appId = obj["ApplicationId"]?.ToString();
                        if (string.IsNullOrEmpty(appId) || appId.ToLower() != "55c92734-d682-4d71-983e-d6ec3f16059f") 
                            continue;

                        uint status = 0;
                        if (obj["LicenseStatus"] != null) uint.TryParse(obj["LicenseStatus"].ToString(), out status);

                        if (status == 1) // Actively licensed iteration.
                        {
                            string channelName = Convert.ToString(obj["Name"]);
                            string channelDesc = Convert.ToString(obj["Description"]);
                            string kmsServer = Convert.ToString(obj["KeyManagementServiceMachine"]);

                            string nameLower = channelName.ToLower();
                            string descLower = channelDesc.ToLower();
                            
                            // Cross-checking logical channels: IoT/Enterprise should generally not be "Retail/OEM:NONSLP".
                            bool isEnterpriseOrIoT = nameLower.Contains("enterprise") || nameLower.Contains("ltsc") || nameLower.Contains("iot") || nameLower.Contains("server");
                            bool isHwidSpoofedChannel = descLower.Contains("retail") || descLower.Contains("oem:nonslp");
                            
                            if (isEnterpriseOrIoT && isHwidSpoofedChannel)
                            {
                                worstResult = new CheckResult { Status = CheckStatus.Danger, Message = LanguageManager.GetString("WMI_HWID_ANOMALY") + $" [[({channelName} | {channelDesc})]]" };
                                break; 
                            }
                            else if (!string.IsNullOrEmpty(kmsServer))
                            {
                                if (IsSuspiciousKMS(kmsServer))
                                {
                                    worstResult = new CheckResult { Status = CheckStatus.Danger, Message = LanguageManager.GetString("WMI_KMS_DETECTED") + $" [[{kmsServer}]]" };
                                    break; 
                                }
                                else if (worstResult.Status != CheckStatus.Danger)
                                {
                                    worstResult = new CheckResult { Status = CheckStatus.Warning, Message = LanguageManager.GetString("WMI_KMS_LEGAL") + $" [[{kmsServer}]]" };
                                }
                            }
                            else
                            {
                                if (worstResult.Status == CheckStatus.Warning && worstResult.Message == LanguageManager.GetString("WMI_NOT_ACTIVATED"))
                                {
                                    string cleanChannel = channelName.Contains(",") ? channelName.Split(',')[1].Trim() : channelName;
                                    worstResult = new CheckResult { Status = CheckStatus.Clean, Message = LanguageManager.GetString("WMI_CLEAN") + $" [[({cleanChannel})]]" };
                                }
                            }
                        }
                    }

                    return worstResult;
                }
            }
            catch (Exception ex)
            {
                return new CheckResult { Status = CheckStatus.Error, Message = LanguageManager.GetString("WMI_ERROR") + ex.Message };
            }
        }

        private bool IsSuspiciousKMS(string kmsServer)
        {
            if (string.IsNullOrEmpty(kmsServer)) return false;
            string lower = kmsServer.ToLower().Trim();

            // Explicit blacklist database of known public KMS emulators.
            string[] badWords = { "127.0.0.1", "0.0.0.0", "::1", "localhost", "kms", "loli", "msguides", "massgrave", "03k", "v0v", "lzzy", "rg-adguard", "kmsauto", "ratiborus" };
            foreach (string word in badWords)
            {
                if (lower.Contains(word)) return true;
            }

            // Validates against public IP addresses. Local subnets (10.x, 192.168.x) are excluded from flagging to respect corporate VPNs.
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