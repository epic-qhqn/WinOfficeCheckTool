using System.Collections.Generic;

namespace WinCheckTool
{
    public static class LanguageManager
    {
        public static bool IsVietnamese = true;

        // Localization Dictionary - Vietnamese Payload
        private static readonly Dictionary<string, string> ViDict = new Dictionary<string, string>
        {
            { "APP_TITLE", "WIN/OFFICE LICENSE FORENSICS TOOL" },
            
            { "STARTING", "Đang nạp các module phân tích hệ thống (Deep System Scan)..." },
            
            { "HEADER_ANALYSIS", "[FORENSIC ANALYSIS - CRACK TRACES]" },
            { "HEADER_CONCLUSION", "[SYSTEM FORENSIC CONCLUSION]" },
            
            { "CONCLUSION_DANGER_HEADER", "=> [[CẢNH BÁO:]] PHÁT HIỆN HỆ THỐNG SỬ DỤNG CÔNG CỤ BẺ KHÓA (CRACKS DETECTED):" },
            { "CONCLUSION_DETAIL", "Hệ thống [[KHÔNG AN TOÀN]]. Các cơ chế cấp phép lõi đã bị can thiệp trái phép." },
            { "WARN_SUSPICIOUS", "=> [[LƯU Ý:]] HỆ THỐNG CÓ DẤU HIỆU BẤT THƯỜNG (HOẶC BẢN QUYỀN LỆCH)." },
            { "WARN_SUSPICIOUS_DETAIL", "   Vui lòng kiểm tra lại các mục hiển thị cảnh báo [!] màu vàng phía trên." },
            { "SAFE_SYS", "=> [[AN TOÀN TỐI ĐA:]] Không phát hiện bất kỳ dấu vết bẻ khóa nào. Hệ thống nguyên bản." },
            
            { "EXPORT_SUCCESS", "Đã xuất Report thành công tại: " },
            { "EXPORT_FAIL", "\n[-] Lỗi I/O khi xuất file: " },
            { "EXIT_AUTO", "Tự động thoát sau 5 giây..." },
            
            { "REPORT_SYS_INFO", "SYSTEM INFORMATION:" },
            { "REPORT_PC_NAME", "- PC Name      : " },
            { "REPORT_OS", "- OS Version   : " },
            { "REPORT_CPU", "- Processor    : " },
            { "REPORT_USER", "- Current User : " },
            { "REPORT_TIME", "- Scan Time    : " },
            { "REPORT_DETAILS", "DETAILED SCAN RESULTS:" },
            
            { "MOD_WMI", "WMI & SPP Status" },
            { "WMI_NOT_ACTIVATED", "Hệ thống [[chưa Activate]] (No active license)." },
            { "WMI_KMS_DETECTED", "[[PHÁT HIỆN:]] Máy chủ [[KMS lậu]] (Unauthorized KMS Host):" },
            { "WMI_KMS_LEGAL", "Sử dụng [[KMS Doanh nghiệp hợp lệ]] (Volume License):" },
            { "WMI_HWID_ANOMALY", "[[PHÁT HIỆN:]] Kênh cấp phép (Channel) bất thường - Dấu hiệu [[HWID Spoofing/MAS]]:" },
            { "WMI_CLEAN", "[[Bản quyền chuẩn]] (Retail/OEM/Volume). Không có dấu vết KMS lậu." },
            { "WMI_ERROR", "Lỗi truy vấn WMI Exception: " },
            
            { "MOD_OFFICE", "Office & SPP Status" },
            { "OFFICE_NOT_FOUND", "Không tìm thấy Office License hoặc [[chưa Activate]]." },
            { "OFFICE_KMS_DETECTED", "[[PHÁT HIỆN:]] Máy chủ [[KMS lậu]] (Unauthorized KMS Host):" },
            { "OFFICE_KMS_LEGAL", "Sử dụng [[KMS Doanh nghiệp hợp lệ]] (Volume License):" },
            { "OFFICE_CLEAN", "[[Bản quyền chuẩn]]. Không có dấu vết KMS lậu." },
            { "OFFICE_ERROR", "Lỗi truy vấn Office (Chưa cài đặt hoặc hỏng WMI): " },

            { "MOD_BIOS", "BIOS / ACPI OEM Key" },
            { "BIOS_NO_KEY", "[[Không có OEM Key]] nhúng trong BIOS (Máy ráp/Không có license gốc)." },
            { "BIOS_KEY_FOUND", "[[Phát hiện OEM Key]] nhúng trong phần cứng (BIOS/UEFI):" },
            { "BIOS_KEY_MATCH", "[[Khớp bản quyền]]: OEM Key gốc ĐANG ĐƯỢC SỬ DỤNG trên hệ thống:" },
            { "BIOS_KEY_MISMATCH", "[[Lệch bản quyền]]: Có OEM Key gốc nhưng Windows đang dùng Key khác (đuôi {0}):" },
            { "BIOS_ERROR", "Lỗi trích xuất bảng ACPI: " },
            
            { "MOD_HEURISTIC", "Registry & Heuristics" },
            { "HEUR_CLEAN", "[[Registry sạch]]. Không phát hiện Hooking hoặc chặn xác thực bản quyền." },
            { "HEUR_OHOOK", "[[PHÁT HIỆN:]] Mã độc Hook ([[Ohook/IFEO]]) đánh chặn xác thực bản quyền Office." },
            { "HEUR_NOGENTICKET", "[[PHÁT HIỆN:]] Khóa [['NoGenTicket']] chặn Telemetry (Phổ biến khi dùng MAS/HWID)." },
            { "HEUR_SKIPREARM", "[[PHÁT HIỆN:]] Khóa [['SkipRearm']] đóng băng Trial Timer." },
            { "HEUR_HOSTS", "[[PHÁT HIỆN:]] File [[Hosts]] chặn kết nối đến Microsoft Activation Servers." },
            { "HEUR_ERROR", "Lỗi truy cập Registry: " },
            
            { "MOD_FORENSIC", "System Forensics & Tasks" },
            { "FOR_CRACK_DIR", "[[PHÁT HIỆN:]] Thư mục chứa công cụ [[Crack lậu]]: " },
            { "FOR_TASK", "[[PHÁT HIỆN:]] Tác vụ gia hạn [[Crack ẩn]] (Task Scheduler): " },
            { "FOR_HISTORY", "[[PHÁT HIỆN:]] Lịch sử Console chạy [[Script lậu]] trực tuyến (MAS/HWID): " },
            { "FOR_TSFORGE", "[[PHÁT HIỆN:]] File GenuineTicket [[giả mạo]] (TSForge / Offline Bypass)." },
            { "FOR_MALICIOUS_DLL", "[[PHÁT HIỆN:]] Thư viện SPP [[bị giả mạo]] (Malicious DLL): " },
            { "FOR_WIN_LOADER", "[[PHÁT HIỆN:]] Dấu vết can thiệp Bootloader ([[Win 7 Daz Loader]])." },
            { "FOR_CLEAN", "[[Hệ thống sạch]]. Không phát hiện Task ẩn, thư mục Crack hay Console History." },
            { "FOR_ERROR", "Lỗi truy xuất Forensics: " }
        };

        // Localization Dictionary - English Payload
        private static readonly Dictionary<string, string> EnDict = new Dictionary<string, string>
        {
            { "APP_TITLE", "WIN/OFFICE LICENSE FORENSICS TOOL" },
            
            { "STARTING", "Loading deep system analysis modules..." },
            
            { "HEADER_ANALYSIS", "[FORENSIC ANALYSIS - CRACK TRACES]" },
            { "HEADER_CONCLUSION", "[SYSTEM FORENSIC CONCLUSION]" },
            
            { "CONCLUSION_DANGER_HEADER", "=> [[WARNING:]] THE FOLLOWING LICENSE CRACKS WERE DETECTED:" },
            { "CONCLUSION_DETAIL", "System integrity is [[COMPROMISED]]. Core licensing mechanisms have been tampered with." },
            { "WARN_SUSPICIOUS", "=> [[NOTICE:]] SUSPICIOUS ACTIVITY OR MISMATCHED ACTIVATION." },
            { "WARN_SUSPICIOUS_DETAIL", "   Please review the yellow warning items above." },
            { "SAFE_SYS", "=> [[MAXIMUM SAFETY:]] No crack traces detected. System is pristine." },
            
            { "EXPORT_SUCCESS", "Report exported successfully to: " },
            { "EXPORT_FAIL", "\n[-] Error exporting file: " },
            { "EXIT_AUTO", "Auto-exiting in 5 seconds..." },
            
            { "REPORT_SYS_INFO", "SYSTEM INFORMATION:" },
            { "REPORT_PC_NAME", "- PC Name      : " },
            { "REPORT_OS", "- OS Version   : " },
            { "REPORT_CPU", "- Processor    : " },
            { "REPORT_USER", "- Current User : " },
            { "REPORT_TIME", "- Scan Time    : " },
            { "REPORT_DETAILS", "DETAILED SCAN RESULTS:" },

            { "MOD_WMI", "WMI & SPP Status" },
            { "WMI_NOT_ACTIVATED", "System is [[not activated]]." },
            { "WMI_KMS_DETECTED", "[[DETECTED:]] Unauthorized [[KMS server]]:" },
            { "WMI_KMS_LEGAL", "[[Valid Enterprise]] Volume License KMS in use:" },
            { "WMI_HWID_ANOMALY", "[[DETECTED:]] Anomalous License Channel ([[HWID Spoofing/MAS]] signature):" },
            { "WMI_CLEAN", "[[Genuine License]] (Retail/OEM/Volume). No illegal KMS traces." },
            { "WMI_ERROR", "WMI Query Error: " },
            
            { "MOD_OFFICE", "Office & SPP Status" },
            { "OFFICE_NOT_FOUND", "Office license not found or [[not activated]]." },
            { "OFFICE_KMS_DETECTED", "[[DETECTED:]] Unauthorized [[KMS server]]:" },
            { "OFFICE_KMS_LEGAL", "[[Valid Enterprise]] Volume License KMS in use:" },
            { "OFFICE_CLEAN", "[[Genuine License]]. No illegal KMS traces." },
            { "OFFICE_ERROR", "Office Query Error (Not installed or WMI broken): " },

            { "MOD_BIOS", "BIOS / ACPI OEM Key" },
            { "BIOS_NO_KEY", "[[No OEM Key]] embedded in BIOS (Custom PC / No original license)." },
            { "BIOS_KEY_FOUND", "[[Original OEM Key]] detected in hardware (BIOS/UEFI):" },
            { "BIOS_KEY_MATCH", "[[License Match]]: Embedded OEM Key is CURRENTLY IN USE:" },
            { "BIOS_KEY_MISMATCH", "[[License Mismatch]]: OEM Key found but Windows uses a different key (ending in {0}):" },
            { "BIOS_ERROR", "Error decoding ACPI table: " },
            
            { "MOD_HEURISTIC", "Registry & Logic Heuristics" },
            { "HEUR_CLEAN", "[[Registry clean]]. No Hook injection or license blocking detected." },
            { "HEUR_OHOOK", "[[DETECTED:]] Hook injection ([[Ohook/IFEO]]) redirecting Office license validation." },
            { "HEUR_NOGENTICKET", "[[DETECTED:]] [['NoGenTicket']] policy blocking authentication data (MAS/HWID)." },
            { "HEUR_SKIPREARM", "[[DETECTED:]] [['SkipRearm']] registry freezing trial period." },
            { "HEUR_HOSTS", "[[DETECTED:]] [[Hosts file]] blocking MS activation servers." },
            { "HEUR_ERROR", "Error scanning Registry: " },
            
            { "MOD_FORENSIC", "System Forensics & Tasks" },
            { "FOR_CRACK_DIR", "[[DETECTED:]] Illegal [[crack tool]] directory: " },
            { "FOR_TASK", "[[DETECTED:]] Malicious renewal [[task]] (Task Scheduler): " },
            { "FOR_HISTORY", "[[DETECTED:]] Console command history for [[script activation]] (MAS/HWID): " },
            { "FOR_TSFORGE", "[[DETECTED:]] Forged offline GenuineTicket ([[TSForge]] / Offline Bypass)." },
            { "FOR_MALICIOUS_DLL", "[[DETECTED:]] Forged system library ([[Malicious DLL]]): " },
            { "FOR_WIN_LOADER", "[[DETECTED:]] Bootloader crack traces ([[Win 7 Daz Loader]])." },
            { "FOR_CLEAN", "[[System clean]]. No hidden tasks, crack directories, or console history." },
            { "FOR_ERROR", "Error scanning Forensics: " }
        };

        public static string GetString(string key)
        {
            var dict = IsVietnamese ? ViDict : EnDict;
            return dict.ContainsKey(key) ? dict[key] : key; 
        }
    }
}