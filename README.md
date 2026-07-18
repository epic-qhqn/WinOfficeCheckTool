<div align="center">
  <h1>🛡️ WinOfficeCheckTool</h1>
  <p><b>Advanced Forensic Analysis for Windows & Office Licensing.</b></p>
  <p><i>Công cụ kiểm tra, rà soát và bóc tách dấu vết bản quyền Windows/Office chuyên sâu.</i></p>
  
  ![C#](https://img.shields.io/badge/C%23-239120?style=for-the-badge&logo=c-sharp&logoColor=white)
  ![.NET 10](https://img.shields.io/badge/.NET_10-512BD4?style=for-the-badge&logo=dotnet&logoColor=white)
  ![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)

  [English](#english) • [Tiếng Việt](#tiếng-việt)
</div>

---

<h2 id="english">🇬🇧 English</h2>

A deep-system forensic CLI utility designed to analyze the integrity of Windows and Microsoft Office licensing mechanisms. It detects sophisticated spoofing methods, malicious KMS servers, and hidden registry bypasses that standard diagnostic tools miss.

### 🧰 Inspection Modules
| Module | Target | Description |
| :--- | :---: | :--- |
| **WMI & SPP Status** | Windows | Cross-validates Software Protection Platform channels. |
| **Office & SPP Status** | Office | Scans for valid Office unified AppIDs and KMS hosts. |
| **BIOS/ACPI Extractor** | Hardware | Extracts embedded MSDM tables and verifies OEM key matching. |
| **Registry Heuristics** | System | Detects Ohook, IFEO debugging, NoGenTicket, and SkipRearm. |
| **System Forensics** | File System | Sweeps for GenuineTicket spoofing, Scheduled Tasks, and PS History. |

### ✨ Core Features
* Performs **Exhaustive WMI Search** to ensure hidden malicious digital tickets (e.g., MAS HWID) are not masked by standard unactivated or trial keys in the WMI repository.
* Correlates hardware-embedded **OEM keys** with the currently active Windows partial product key to detect "overwritten" or spoofed activations on factory-licensed machines.
* Actively parses PowerShell `ConsoleHost_history.txt` and Windows Task Scheduler to find ephemeral crack executions and auto-renewal payloads (e.g., AutoKMS, KMS38).
* Self-contained, single-file executable architecture requiring **zero .NET SDK installation** on the target machine.

### 💻 Technical Details
* Utilizes a highly optimized custom Console UI engine that parses inline markup (`[[ ]]`) to highlight specific forensic keywords without oversaturating the terminal with colors.
* Prevents generic COM initialization exceptions (`WmiNetUtilsHelper`) by forcing native C++ libraries to extract into RAM during standalone execution.
* WMI queries are wrapped in strict `EnumerationOptions` with timeouts, guaranteeing the application never deadlocks on severely corrupted OS repositories (typical in legacy Win 7/8.1 machines).

### 🚀 Setup & Execution
1. Clone the repository and navigate to the directory in your terminal.
2. Configure and build the self-contained executable using the **.NET 10 SDK**: Run `dotnet clean` followed by `dotnet publish -c Release`.
3. Locate the compiled executable inside `bin\Release\net10.0-windows\win-x64\publish\`.
4. Run **Checkwin.exe** as Administrator on any target machine (no installation required).
5. Follow the on-screen prompts to export a detailed `.TXT` forensic report.

---

<h2 id="tiếng-việt">🇻🇳 Tiếng Việt</h2>

Công cụ dòng lệnh (CLI) phân tích pháp y hệ thống, được thiết kế để kiểm tra tính toàn vẹn của bản quyền Windows và Microsoft Office. Phần mềm có khả năng bóc tách các thủ thuật giả mạo tinh vi, máy chủ KMS lậu và các bypass can thiệp Registry mà các công cụ thông thường thường bỏ sót.

### 🧰 Cấu Trúc Module
| Module | Mục tiêu | Ghi chú |
| :--- | :---: | :--- |
| **WMI & SPP Status** | Windows | Rà soát chéo các kênh cấp phép của Software Protection Platform. |
| **Office & SPP Status** | Office | Quét AppID đồng nhất của Office và kiểm tra máy chủ KMS. |
| **BIOS/ACPI Extractor** | Hardware | Trích xuất bảng MSDM và đối chiếu tính trùng khớp của OEM Key. |
| **Registry Heuristics** | System | Phát hiện Ohook, IFEO, NoGenTicket, và chặn đếm ngược SkipRearm. |
| **System Forensics** | File System | Quét GenuineTicket giả, Tác vụ ẩn (Task), và Lịch sử PowerShell. |

### ✨ Tính Năng
* Thực thi **Thuật toán rà soát WMI toàn diện (Exhaustive Search)** để đảm bảo các thẻ bản quyền lậu (như MAS HWID) không bị che giấu bởi các key rác hoặc key dùng thử trong hệ thống.
* Đối chiếu trực tiếp **OEM Key** nhúng trong phần cứng với 5 số đuôi của Key đang kích hoạt nhằm phát hiện các máy có sẵn bản quyền gốc nhưng bị thợ cài đè bản lậu.
* Chủ động trích xuất `ConsoleHost_history.txt` của PowerShell và Windows Task Scheduler để tóm gọn các lệnh bẻ khóa chạy một lần hoặc các tác vụ gia hạn ngầm (AutoKMS, KMS38).
* Kiến trúc phần mềm độc lập (Self-contained Single-file), có thể chạy trực tiếp trên mọi máy tính mà **không cần cài đặt .NET SDK**.

### 💻 Chi Tiết Kỹ Thuật
* Sử dụng Engine UI Console tự phát triển có khả năng dịch cú pháp thẻ (`[[ ]]`) để đánh dấu màu sắc (highlight) các từ khóa pháp y quan trọng, giúp giao diện trực quan và không bị lóa mắt.
* Ngăn chặn triệt để lỗi khởi tạo thư viện COM (`WmiNetUtilsHelper`) bằng cách ép giải nén các thư viện C++ lõi vào RAM khi chạy dạng file đơn.
* Các luồng truy vấn WMI được bọc bởi `EnumerationOptions` kèm cơ chế Timeout, đảm bảo công cụ không bao giờ bị treo cứng ngay cả khi chạy trên các hệ điều hành bị hỏng Registry nặng (phổ biến ở Win 7/8.1 cũ).

### 🚀 Hướng Dẫn Cài Đặt & Sử Dụng
1. Clone mã nguồn và mở Terminal tại thư mục dự án.
2. Tiến hành dọn dẹp và đóng gói phần mềm bằng **.NET 10 SDK**: Gõ lệnh `dotnet clean` sau đó `dotnet publish -c Release`.
3. Lấy file thực thi duy nhất tại đường dẫn `bin\Release\net10.0-windows\win-x64\publish\`.
4. Copy và chạy **Checkwin.exe** dưới quyền Quản trị viên (Run as Administrator) trên bất kỳ máy nào mà không cần cài đặt thêm phần mềm bổ trợ.
5. Làm theo hướng dẫn trên màn hình để xuất báo cáo chi tiết ra file `.TXT`.
