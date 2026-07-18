using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Runtime.Versioning;
using System.Management;
using Microsoft.Win32;

namespace WinCheckTool
{
    [SupportedOSPlatform("windows")]
    class Program
    {
        static void Main(string[] args)
        {
            // Enforce UTF-8 encoding for cross-platform terminal rendering.
            Console.OutputEncoding = Encoding.UTF8;
            Console.Title = "WinOfficeCheckTool - kishikuun";
            
            // UI Enhancement: Language selection prompt.
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("Select language / Chọn ngôn ngữ (");
            Console.ForegroundColor = ConsoleColor.Red; 
            Console.Write("V = Tiếng Việt");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" / ");
            Console.ForegroundColor = ConsoleColor.Blue; 
            Console.Write("E = English");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("): ");
            Console.ResetColor();

            var keyInfo = Console.ReadKey(true);
            if (keyInfo.Key == ConsoleKey.E)
            {
                LanguageManager.IsVietnamese = false;
            }
            Console.Clear();

            PrintHeader(LanguageManager.GetString("APP_TITLE"));
            Console.WriteLine(); 
            
            // Render User-Friendly System Information to Console with Uniform Coloring.
            string osFriendly = GetFriendlyOS();
            string cpuFriendly = GetFriendlyCPU();
            
            // Timezone formatting (UTCzzz) for global compatibility.
            string scanTime = DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss (UTCzzz)");

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(LanguageManager.GetString("REPORT_SYS_INFO"));
            
            PrintSysInfoLine(LanguageManager.GetString("REPORT_PC_NAME"), Environment.MachineName);
            PrintSysInfoLine(LanguageManager.GetString("REPORT_OS"), osFriendly);
            PrintSysInfoLine(LanguageManager.GetString("REPORT_CPU"), cpuFriendly);
            PrintSysInfoLine(LanguageManager.GetString("REPORT_USER"), Environment.UserName);
            PrintSysInfoLine(LanguageManager.GetString("REPORT_TIME"), scanTime);
            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"[*] {LanguageManager.GetString("STARTING")}\n");
            Thread.Sleep(800); 

            // Dependency injection of security analysis modules.
            List<ICheckModule> modules = new List<ICheckModule>
            {
                new Module_WMI_Inspector(),
                new Module_Office_Inspector(),
                new Module_BIOS_Extractor(),
                new Module_Heuristics(),
                new Module_Forensics()
            };
            
            int dangerCount = 0; 
            int warningCount = 0;
            List<string> dangerFindings = new List<string>();
            StringBuilder reportBuilder = new StringBuilder();

            // Execute scanning sequence synchronously with fault tolerance.
            foreach (var module in modules)
            {
                CheckResult result;
                try
                {
                    result = module.Execute();
                }
                catch (Exception ex)
                {
                    // Failsafe execution: Prevents an entire program crash if a single WMI/COM node fails.
                    result = new CheckResult { Status = CheckStatus.Error, Message = "CRASH: " + ex.Message };
                }

                string prefix = $"  {module.ModuleName}".PadRight(30) + ": ";
                string symbol = "";
                ConsoleColor hlColor = ConsoleColor.White;

                // Color coding hierarchy mapped to severity statuses.
                switch (result.Status)
                {
                    case CheckStatus.Clean:   symbol = "[+] "; hlColor = ConsoleColor.Green; break;
                    case CheckStatus.Warning: symbol = "[!] "; hlColor = ConsoleColor.Yellow; break;
                    case CheckStatus.Danger:  symbol = "[-] "; hlColor = ConsoleColor.Red; break;
                    case CheckStatus.Error:   symbol = "[?] "; hlColor = ConsoleColor.DarkGray; break; // System exception state
                }
                
                // Print UI strictly highlighting keywords wrapped in [[ ]].
                Console.ForegroundColor = hlColor;
                Console.Write(symbol);
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.Write(prefix);
                WriteColoredMessage(result.Message, ConsoleColor.Gray, hlColor); 
                
                // Filter markup strings for clean TXT generation.
                string cleanMessage = result.Message.Replace("[[", "").Replace("]]", "");
                reportBuilder.AppendLine(symbol + prefix + cleanMessage); 
                
                if (result.Status == CheckStatus.Danger) 
                {
                    dangerCount++;
                    // Precision padding for the Conclusion UI.
                    string alignedPrefix = $"[{module.ModuleName}]".PadRight(28);
                    dangerFindings.Add($"{alignedPrefix}: {result.Message}"); 
                }
                else if (result.Status == CheckStatus.Warning) 
                {
                    warningCount++;
                }
                
                Thread.Sleep(400); 
            }

            // Synthesize Final Dynamic Assessment Conclusion based on collected telemetry.
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(LanguageManager.GetString("HEADER_CONCLUSION"));
            
            List<string> conclusionLines = new List<string>();

            // Highest severity: Cracks found. Overrides warnings.
            if (dangerCount > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                WriteColoredMessage(LanguageManager.GetString("CONCLUSION_DANGER_HEADER"), ConsoleColor.Red, ConsoleColor.Red);
                conclusionLines.Add(LanguageManager.GetString("CONCLUSION_DANGER_HEADER").Replace("[[", "").Replace("]]", ""));

                foreach(string finding in dangerFindings)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write("   - ");
                    WriteColoredMessage(finding, ConsoleColor.Gray, ConsoleColor.Red);
                    conclusionLines.Add($"   - {finding.Replace("[[", "").Replace("]]", "")}");
                }
                
                Console.WriteLine();
                conclusionLines.Add(""); 
                
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("   -> ");
                WriteColoredMessage(LanguageManager.GetString("CONCLUSION_DETAIL"), ConsoleColor.Gray, ConsoleColor.Red);
                conclusionLines.Add($"   -> {LanguageManager.GetString("CONCLUSION_DETAIL").Replace("[[", "").Replace("]]", "")}");
            }
            // Moderate severity: No cracks, but anomalies detected (e.g. Mismatched OEM key or unactivated).
            else if (warningCount > 0)
            {
                WriteColoredMessage(LanguageManager.GetString("WARN_SUSPICIOUS"), ConsoleColor.Yellow, ConsoleColor.Yellow);
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine(LanguageManager.GetString("WARN_SUSPICIOUS_DETAIL"));
                
                conclusionLines.Add(LanguageManager.GetString("WARN_SUSPICIOUS").Replace("[[", "").Replace("]]", ""));
                conclusionLines.Add(LanguageManager.GetString("WARN_SUSPICIOUS_DETAIL"));
            }
            // Pristine state.
            else
            {
                WriteColoredMessage(LanguageManager.GetString("SAFE_SYS"), ConsoleColor.Green, ConsoleColor.Green);
                conclusionLines.Add(LanguageManager.GetString("SAFE_SYS").Replace("[[", "").Replace("]]", ""));
            }
            Console.ResetColor();

            // UI Enhancement: Colored Export Prompt.
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(LanguageManager.IsVietnamese ? "Nhấn " : "Press ");
            Console.ForegroundColor = ConsoleColor.Magenta; 
            Console.Write("'Y'");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(LanguageManager.IsVietnamese ? " để xuất Report ra " : " to export report to ");
            Console.ForegroundColor = ConsoleColor.Magenta; 
            Console.Write(LanguageManager.IsVietnamese ? "file .TXT" : "file .TXT");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(LanguageManager.IsVietnamese ? ", hoặc phím bất kỳ để thoát... " : ", or any other key to exit... ");
            Console.ResetColor();

            var exportKey = Console.ReadKey(true);
            if (exportKey.Key == ConsoleKey.Y)
            {
                ExportReport(reportBuilder.ToString(), conclusionLines, osFriendly, cpuFriendly, scanTime);
            }
        }

        static void PrintHeader(string title)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(new string('=', 95));
            Console.WriteLine(title.PadLeft((95 + title.Length) / 2));
            Console.WriteLine(new string('=', 95));
            
            // Clean separator for transition to SYSTEM INFORMATION.
            Console.WriteLine(LanguageManager.GetString("HEADER_ANALYSIS"));
            Console.ResetColor();
        }

        // Helper Method to manage uniform coloring of the System Information block.
        static void PrintSysInfoLine(string label, string value)
        {
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.Write(label);
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(value);
        }

        // Core UI Engine: Parses text dynamically and highlights target strings wrapped in [[ ]].
        static void WriteColoredMessage(string text, ConsoleColor baseColor, ConsoleColor highlightColor)
        {
            string[] parts = text.Split(new string[] { "[[" }, StringSplitOptions.None);
            for (int i = 0; i < parts.Length; i++)
            {
                if (i == 0)
                {
                    Console.ForegroundColor = baseColor;
                    Console.Write(parts[i]);
                }
                else
                {
                    string[] subParts = parts[i].Split(new string[] { "]]" }, StringSplitOptions.None);
                    Console.ForegroundColor = highlightColor;
                    Console.Write(subParts[0]); // Extracted keyword to highlight.
                    
                    if (subParts.Length > 1)
                    {
                        Console.ForegroundColor = baseColor;
                        Console.Write(subParts[1]); // Remaining baseline text.
                    }
                }
            }
            Console.WriteLine();
        }

        static void ExportReport(string scanDetails, List<string> conclusionLines, string osInfo, string cpuInfo, string scanTime)
        {
            Console.WriteLine(); // Visual padding before export result.
            try
            {
                string machineName = Environment.MachineName;
                string fileName = $"{machineName}_checkwinoffice.txt";
                string currentDir = AppDomain.CurrentDomain.BaseDirectory;
                string fullPath = Path.Combine(currentDir, fileName);

                using (StreamWriter writer = new StreamWriter(fullPath, false, Encoding.UTF8))
                {
                    writer.WriteLine(new string('=', 95));
                    writer.WriteLine(LanguageManager.GetString("APP_TITLE").PadLeft((95 + LanguageManager.GetString("APP_TITLE").Length) / 2));
                    writer.WriteLine(new string('=', 95));
                    
                    writer.WriteLine(LanguageManager.GetString("HEADER_ANALYSIS"));
                    
                    writer.WriteLine("\n" + LanguageManager.GetString("REPORT_SYS_INFO"));
                    writer.WriteLine(LanguageManager.GetString("REPORT_PC_NAME") + machineName);
                    writer.WriteLine(LanguageManager.GetString("REPORT_OS") + osInfo);
                    writer.WriteLine(LanguageManager.GetString("REPORT_CPU") + cpuInfo);
                    writer.WriteLine(LanguageManager.GetString("REPORT_USER") + Environment.UserName);
                    writer.WriteLine(LanguageManager.GetString("REPORT_TIME") + scanTime);
                    
                    writer.WriteLine("\n" + new string('-', 95));
                    writer.WriteLine(LanguageManager.GetString("REPORT_DETAILS"));
                    writer.Write(scanDetails); 
                    
                    writer.WriteLine(new string('-', 95));
                    writer.WriteLine(LanguageManager.GetString("HEADER_CONCLUSION"));
                    foreach(var line in conclusionLines)
                    {
                        writer.WriteLine(line);
                    }
                    writer.WriteLine(new string('=', 95));
                }

                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write($"[+] {LanguageManager.GetString("EXPORT_SUCCESS")}");
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine(fullPath);
                
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("...");
                Console.WriteLine(LanguageManager.GetString("EXIT_AUTO"));
                Thread.Sleep(5000); 
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(LanguageManager.GetString("EXPORT_FAIL") + ex.Message);
                Thread.Sleep(5000); 
            }
            
            Console.ResetColor();
        }

        // Extracts WMI OS Caption reliably, bypassing the persistent Windows 11 registry string bug.
        public static string GetFriendlyOS()
        {
            string osName = "";
            string osVersion = "";
            
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Caption FROM Win32_OperatingSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        osName = obj["Caption"]?.ToString();
                        break;
                    }
                }
            }
            catch { }

            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    if (key != null)
                    {
                        if (string.IsNullOrEmpty(osName)) 
                        {
                            osName = key.GetValue("ProductName")?.ToString();
                        }
                        
                        osVersion = key.GetValue("DisplayVersion")?.ToString();
                        if (string.IsNullOrEmpty(osVersion))
                        {
                            osVersion = key.GetValue("ReleaseId")?.ToString();
                        }

                        // Build verification fallback to correct false "Windows 10" registry readouts.
                        if (!string.IsNullOrEmpty(osName) && osName.StartsWith("Windows 10"))
                        {
                            object buildObj = key.GetValue("CurrentBuild");
                            if (buildObj != null && int.TryParse(buildObj.ToString(), out int build) && build >= 22000)
                            {
                                osName = osName.Replace("Windows 10", "Windows 11");
                            }
                        }
                    }
                }
            }
            catch { }

            if (!string.IsNullOrEmpty(osName))
            {
                osName = osName.Replace("Microsoft ", "").Trim(); 
                return string.IsNullOrEmpty(osVersion) ? osName : $"{osName} (Version {osVersion})";
            }

            return Environment.OSVersion.ToString();
        }

        public static string GetFriendlyCPU()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0"))
                {
                    if (key != null)
                    {
                        string cpuName = key.GetValue("ProcessorNameString")?.ToString();
                        if (!string.IsNullOrEmpty(cpuName)) return cpuName.Trim();
                    }
                }
            }
            catch { }
            return Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER");
        }
    }
}