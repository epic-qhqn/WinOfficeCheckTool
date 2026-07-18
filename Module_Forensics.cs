using System;
using System.IO;
using System.Runtime.Versioning;

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

                // Validates integrity of internal library files protecting against DLL injection.
                string[] maliciousDlls = {
                    @"C:\Windows\System32\SppExtComObjHook.dll",
                    @"C:\Windows\System32\sppc.dll.bak",
                    @"C:\Program Files\Microsoft Office\root\vfs\System\sppc.dll",
                    @"C:\Program Files (x86)\Microsoft Office\root\vfs\System\sppc.dll",
                    @"C:\Windows\system32\xNtKrnl.exe" 
                };
                foreach (string dll in maliciousDlls)
                {
                    if (File.Exists(dll)) 
                    {
                        if (dll.Contains("xNtKrnl")) return new CheckResult { Status = CheckStatus.Danger, Message = LanguageManager.GetString("FOR_WIN_LOADER") };
                        return new CheckResult { Status = CheckStatus.Danger, Message = LanguageManager.GetString("FOR_MALICIOUS_DLL") + $"[[{Path.GetFileName(dll)}]]" };
                    }
                }

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
                        if (taskName.Contains("autokms") || taskName.Contains("sppextcomobjhook") || taskName.Contains("kms38") || taskName.Contains("kmsauto") || taskName.Contains("ratiborus"))
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
    }
}