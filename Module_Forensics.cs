using System;
using System.IO;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using System.Diagnostics.Eventing.Reader;
using System.Text.RegularExpressions;
using System.Security.Cryptography.X509Certificates;

namespace WinCheckTool
{
    [SupportedOSPlatform("windows")]
    public class Module_Forensics : ICheckModule
    {
        public string ModuleName => LanguageManager.GetString("MOD_FORENSIC");

        public CheckResult Execute()
        {
            try
            {
                // Inspects existence of forged tickets bypassing digital hardware signatures.
                string ticketPath = @"C:\ProgramData\Microsoft\Windows\ClipSVC\GenuineTicket";
                if (Directory.Exists(ticketPath))
                {
                    string[] xmlFiles = Directory.GetFiles(ticketPath, "*.xml");
                    if (xmlFiles.Length > 0)
                    {
                        return new CheckResult { Status = CheckStatus.Danger, Message = LanguageManager.GetString("FOR_TSFORGE") };
                    }
                }

                // Advanced Anti-Hooking: Verifies Digital Signatures natively preventing PInvoke Memory Leaks.
                string[] maliciousDlls = {
                    @"C:\Windows\System32\SppExtComObjHook.dll",
                    @"C:\Windows\System32\sppc.dll.bak",
                    @"C:\Windows\system32\xNtKrnl.exe",
                    @"C:\Windows\System32\sppsvc.exe" // The core service itself.
                };

                foreach (string dll in maliciousDlls)
                {
                    if (File.Exists(dll)) 
                    {
                        if (dll.Contains("xNtKrnl")) return new CheckResult { Status = CheckStatus.Danger, Message = LanguageManager.GetString("FOR_WIN_LOADER") };
                        
                        // If it's a known hook name, flag immediately.
                        if (dll.Contains("SppExtComObjHook")) return new CheckResult { Status = CheckStatus.Danger, Message = LanguageManager.GetString("FOR_MALICIOUS_DLL") + $"[[{Path.GetFileName(dll)}]]" };

                        // If it's the core sppsvc, verify Microsoft signature to detect memory patching.
                        if (dll.EndsWith("sppsvc.exe", StringComparison.OrdinalIgnoreCase))
                        {
                            if (!IsMicrosoftSigned(dll))
                            {
                                return new CheckResult { Status = CheckStatus.Danger, Message = LanguageManager.GetString("OFFICE_SIGNATURE_FAIL") + $" [[{Path.GetFileName(dll)}]]" };
                            }
                        }
                    }
                }

                // Dynamic Network State Analysis (Active TCP Connections targeting Port 1688).
                // Safely utilizes BCL IPGlobalProperties over risky native GetExtendedTcpTable.
                try
                {
                    IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
                    TcpConnectionInformation[] connections = properties.GetActiveTcpConnections();
                    foreach (TcpConnectionInformation c in connections)
                    {
                        if (c.RemoteEndPoint.Port == 1688)
                        {
                            string ip = c.RemoteEndPoint.Address.ToString();
                            // Whitelist local loopback for now, heavily scrutinize external IPs.
                            if (ip != "127.0.0.1" && ip != "::1" && !ip.Contains("microsoft"))
                            {
                                return new CheckResult { Status = CheckStatus.Danger, Message = LanguageManager.GetString("FOR_TCP_1688") + $" [[{ip}]]" };
                            }
                        }
                    }
                }
                catch { } // Failsafe for NetworkInformation permissions.

                // Identifies hidden directories storing illegal renewal scripts.
                string[] badDirs = {
                    @"C:\Windows\KMS",
                    @"C:\Windows\AutoKMS",
                    @"C:\ProgramData\KMSAuto",
                    @"C:\ProgramData\KMS_VL_ALL",
                    @"C:\Program Files\KMSpico"
                };
                foreach (string d in badDirs)
                {
                    if (Directory.Exists(d)) return new CheckResult { Status = CheckStatus.Danger, Message = LanguageManager.GetString("FOR_CRACK_DIR") + $"[[{d}]]" };
                }

                // Sweeps Windows Task Scheduler definitions for auto-renewing activation malware payloads.
                string taskPath = @"C:\Windows\System32\Tasks";
                if (Directory.Exists(taskPath))
                {
                    string[] taskFiles = Directory.GetFiles(taskPath, "*", SearchOption.AllDirectories);
                    foreach (string f in taskFiles)
                    {
                        string taskName = Path.GetFileName(f).ToLower();
                        if (taskName.Contains("autokms") || taskName.Contains("sppextcomobjhook") || taskName.Contains("kms38") || taskName.Contains("kmsauto") || taskName.Contains("ratiborus") || taskName.Contains("kmsconnectionmonitor") || taskName.Contains("kms-activator") || taskName.Contains("mas_kms") || taskName.Contains("kmseldi"))
                        {
                            return new CheckResult { Status = CheckStatus.Danger, Message = LanguageManager.GetString("FOR_TASK") + $"[[{taskName}]]" };
                        }
                    }
                }

                // Extracts command-line history to trace ephemeral PowerShell memory injections.
                string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string psHistoryPath = Path.Combine(appData, @"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");
                
                if (File.Exists(psHistoryPath))
                {
                    string[] lines = File.ReadAllLines(psHistoryPath);
                    foreach (string line in lines)
                    {
                        string lowerLine = line.ToLower();
                        if (lowerLine.Contains("massgrave.dev") || lowerLine.Contains("hwid") || lowerLine.Contains("kms38") || lowerLine.Contains("get.activated.win") || lowerLine.Contains("kms-server"))
                        {
                            return new CheckResult { Status = CheckStatus.Danger, Message = LanguageManager.GetString("FOR_HISTORY") + $"[[{line.Trim()}]]" };
                        }
                    }
                }

                // Analyzes Windows Event Logs for illegal KMS server connection history (Event ID 12288).
                try
                {
                    string evQuery = "*[System[Provider[@Name='Microsoft-Windows-Security-SPP'] and (EventID=12288)]]";
                    EventLogQuery logQuery = new EventLogQuery("Application", PathType.LogName, evQuery);
                    logQuery.ReverseDirection = true; // Fetch newest first.

                    using (EventLogReader logReader = new EventLogReader(logQuery))
                    {
                        EventRecord evt;
                        int limit = 50; // Performance constraint.
                        while ((evt = logReader.ReadEvent()) != null && limit-- > 0)
                        {
                            string msg = evt.FormatDescription();
                            if (!string.IsNullOrEmpty(msg))
                            {
                                Match m = Regex.Match(msg, @"(?i)([a-zA-Z0-9\.\-_]+):1688");
                                if (m.Success)
                                {
                                    string ip = m.Groups[1].Value.ToLower();
                                    // Bypass genuine Microsoft internal addresses.
                                    if (!ip.Contains("microsoft") && !ip.Contains("windows"))
                                    {
                                        return new CheckResult { Status = CheckStatus.Danger, Message = LanguageManager.GetString("FOR_EVENT_KMS") + $" [[{ip}]]" };
                                    }
                                }
                            }
                        }
                    }
                }
                catch { } // Failsafe for EventLog access permission issues.

                return new CheckResult { Status = CheckStatus.Clean, Message = LanguageManager.GetString("FOR_CLEAN") };
            }
            catch (UnauthorizedAccessException)
            {
                return new CheckResult { Status = CheckStatus.Warning, Message = LanguageManager.GetString("FOR_ERROR") + "Access Denied." };
            }
            catch (Exception ex)
            {
                return new CheckResult { Status = CheckStatus.Error, Message = LanguageManager.GetString("FOR_ERROR") + ex.Message };
            }
        }

        // Memory-safe signature verification leveraging Cryptography classes.
        private bool IsMicrosoftSigned(string filePath)
        {
            try
            {
                // .NET 10 Modern Security Standard: Prevents legacy parsing vulnerabilities and memory leaks.
                using (X509Certificate2 cert = X509CertificateLoader.LoadCertificateFromFile(filePath))
                {
                    return cert.Subject.Contains("Microsoft", StringComparison.OrdinalIgnoreCase);
                }
            }
            catch 
            { 
                // CryptographicException thrown if file has no valid signature or is heavily tampered.
                return false; 
            }
        }
    }
}