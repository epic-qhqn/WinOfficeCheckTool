using System;
using System.IO;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace WinCheckTool
{
    [SupportedOSPlatform("windows")]
    public class Module_Heuristics : ICheckModule
    {
        public string ModuleName => LanguageManager.GetString("MOD_HEURISTIC");

        public CheckResult Execute()
        {
            try
            {
                // Scans Image File Execution Options for process redirection (debugger manipulation).
                string[] suspiciousProcesses = { "sppsvc.exe", "osppsvc.exe" };
                string ifeoPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

                using (RegistryKey ifeoKey = Registry.LocalMachine.OpenSubKey(ifeoPath))
                {
                    if (ifeoKey != null)
                    {
                        foreach (string process in suspiciousProcesses)
                        {
                            using (RegistryKey processKey = ifeoKey.OpenSubKey(process))
                            {
                                if (processKey != null)
                                {
                                    if (processKey.GetValue("Debugger") != null || processKey.GetValue("FilterFullPath") != null)
                                    {
                                        return new CheckResult { Status = CheckStatus.Danger, Message = LanguageManager.GetString("HEUR_OHOOK") + $" [[ [{process}] ]]" };
                                    }
                                }
                            }
                        }
                    }
                }

                // Detects suppression of Genuine Ticket generation (Common MAS parameter).
                string sppPath = @"SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform";
                using (RegistryKey sppKey = Registry.LocalMachine.OpenSubKey(sppPath))
                {
                    if (sppKey != null)
                    {
                        object noGenTicket = sppKey.GetValue("NoGenTicket");
                        if (noGenTicket != null && int.TryParse(noGenTicket.ToString(), out int nVal) && nVal == 1)
                        {
                            return new CheckResult { Status = CheckStatus.Danger, Message = LanguageManager.GetString("HEUR_NOGENTICKET") };
                        }
                    }
                }

                // Detects frozen trial period counters.
                string rootSppPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform";
                using (RegistryKey rootSppKey = Registry.LocalMachine.OpenSubKey(rootSppPath))
                {
                    if (rootSppKey != null)
                    {
                        object skipRearm = rootSppKey.GetValue("SkipRearm");
                        if (skipRearm != null && int.TryParse(skipRearm.ToString(), out int sVal) && sVal == 1)
                        {
                            return new CheckResult { Status = CheckStatus.Danger, Message = LanguageManager.GetString("HEUR_SKIPREARM") };
                        }
                    }
                }

                // Inspects network validation blocks within the internal Hosts routing table.
                string hostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
                if (File.Exists(hostsPath))
                {
                    string hostsContent = File.ReadAllText(hostsPath).ToLower();
                    if (hostsContent.Contains("validation.sls.microsoft.com") || hostsContent.Contains("activation.sls.microsoft.com"))
                    {
                        return new CheckResult { Status = CheckStatus.Danger, Message = LanguageManager.GetString("HEUR_HOSTS") };
                    }
                }

                return new CheckResult { Status = CheckStatus.Clean, Message = LanguageManager.GetString("HEUR_CLEAN") };
            }
            catch (UnauthorizedAccessException)
            {
                return new CheckResult { Status = CheckStatus.Warning, Message = LanguageManager.GetString("HEUR_ERROR") + "Access Denied." };
            }
            catch (Exception ex)
            {
                return new CheckResult { Status = CheckStatus.Error, Message = LanguageManager.GetString("HEUR_ERROR") + ex.Message };
            }
        }
    }
}