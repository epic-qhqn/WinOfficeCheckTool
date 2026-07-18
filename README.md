<div align="center">
  <h1>🛡️ WinOfficeCheckTool</h1>
  <p><b>Check Tool for Windows & Office Licensing.</b></p>
  <p><i>Công cụ kiểm tra và rà soát dấu vết bản quyền Windows/Office.</i></p>
  
  ![C#](https://img.shields.io/badge/C%23-239120?style=for-the-badge&logo=c-sharp&logoColor=white)
  ![.NET 10](https://img.shields.io/badge/.NET_10-512BD4?style=for-the-badge&logo=dotnet&logoColor=white)
  ![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)

  [English](#english) • [Tiếng Việt](#tiếng-việt)
</div>

---

<h2 id="english">🇬🇧 English</h2>

A CLI utility designed to check the status of Windows and Microsoft Office licensing mechanisms. It helps detect spoofing methods, unauthorized KMS servers, and Registry bypasses.

### 🧰 Inspection Modules
| Module | Target | Description |
| :--- | :---: | :--- |
| **WMI & SPP Status** | Windows | Cross-validates Software Protection Platform channels. |
| **Office & SPP Status** | Office | Scans for valid Office AppIDs and KMS hosts. |
| **BIOS/ACPI Extractor** | Hardware | Extracts embedded MSDM tables and checks OEM key matching. |
| **Registry Checks** | System | Detects Ohook, IFEO, NoGenTicket, and SkipRearm. |
| **File System** | Files | Checks for GenuineTicket spoofing, Scheduled Tasks, and PS History. |

### ✨ Core Features
* Performs a **WMI Search** to identify digital tickets (e.g., MAS HWID) that might be masked by standard unactivated or trial keys.
* Compares hardware-embedded **OEM keys** with the currently active Windows partial product key to check for mismatched activations.
* Reads PowerShell `ConsoleHost_history.txt` and Windows Task Scheduler to find crack scripts and auto-renewal tasks (e.g., AutoKMS, KMS38).
* Self-contained, single-file executable architecture requiring **zero .NET SDK installation** on the target machine.

### 💻 Technical Details
* Uses a custom Console UI engine that parses inline markup (`[[ ]]`) to highlight specific keywords.
* Prevents COM initialization exceptions (`WmiNetUtilsHelper`) by forcing native C++ libraries to extract into RAM during standalone execution.
* WMI queries are wrapped in `EnumerationOptions` with timeouts, preventing the application from freezing on corrupted OS repositories.

### 🚀 Setup & Execution
1. Clone the repository and navigate to the directory in your terminal.
2. Configure and build the self-contained executable using the **.NET 10 SDK**: Run `dotnet clean` followed by `dotnet publish -c Release`.
3. Locate the compiled executable inside `bin\Release\net10.0-windows\win-x64\publish\`.
4. Run **WinOfficeCheckTool.exe** as Administrator on any target machine (no installation required).
5. Follow the on-screen prompts to export a `.TXT` report.

---

<h2 id="tiếng-việt">🇻🇳 Tiếng Việt</h2>

Công cụ dòng lệnh (CLI) được thiết kế để kiểm tra trạng thái bản quyền Windows và Microsoft Office. Phần mềm hỗ trợ phát hiện các công cụ giả mạo, KMS lậu và các bypass can thiệp Registry.

### 🧰 Cấu Trúc Module
| Module | Mục tiêu | Ghi chú |
| :--- | :---: | :--- |
| **WMI & SPP Status** | Windows | Rà soát chéo các kênh cấp phép của Software Protection Platform. |
| **Office & SPP Status** | Office | Quét AppID của Office và kiểm tra máy chủ KMS. |
| **BIOS/ACPI Extractor** | Hardware | Trích xuất bảng MSDM và đối chiếu tính trùng khớp của OEM Key. |
| **Registry Checks** | System | Phát hiện Ohook, IFEO, NoGenTicket, và chặn đếm ngược SkipRearm. |
| **File System** | Files | Quét GenuineTicket giả, Tác vụ ẩn (Task), và Lịch sử PowerShell. |

### ✨ Tính Năng
* Thực hiện **rà soát WMI** để tìm kiếm các thẻ bản quyền (như MAS HWID) có thể bị che giấu bởi các key rác hoặc key dùng thử trong hệ thống.
* Đối chiếu trực tiếp **OEM Key** nhúng trong phần cứng với 5 số đuôi của Key đang kích hoạt để kiểm tra tình trạng lệch bản quyền.
* Đọc file `ConsoleHost_history.txt` của PowerShell và Windows Task Scheduler để tìm các lệnh bẻ khóa hoặc các task gia hạn ngầm (AutoKMS, KMS38).
* Kiến trúc phần mềm độc lập (Self-contained Single-file), có thể chạy trực tiếp trên máy tính mà **không cần cài đặt .NET SDK**.

### 💻 Chi Tiết Kỹ Thuật
* Sử dụng Engine UI Console tự viết có khả năng dịch cú pháp thẻ (`[[ ]]`) để highlight các từ khóa quan trọng.
* Tránh lỗi khởi tạo thư viện COM (`WmiNetUtilsHelper`) bằng cách ép giải nén các thư viện C++ lõi vào RAM khi chạy dạng file đơn.
* Các truy vấn WMI được bọc bởi `EnumerationOptions` kèm cơ chế Timeout, hạn chế tình trạng treo tool khi chạy trên các hệ điều hành bị lỗi WMI.

### 🚀 Hướng Dẫn Cài Đặt & Sử Dụng
1. Clone mã nguồn và mở Terminal tại thư mục dự án.
2. Tiến hành dọn dẹp và đóng gói phần mềm bằng **.NET 10 SDK**: Gõ lệnh `dotnet clean` sau đó `dotnet publish -c Release`.
3. Lấy file thực thi duy nhất tại đường dẫn `bin\Release\net10.0-windows\win-x64\publish\`.
4. Copy và chạy **WinOfficeCheckTool.exe** dưới quyền Quản trị viên (Run as Administrator) trên bất kỳ máy nào mà không cần cài đặt thêm phần mềm bổ trợ.
5. Làm theo hướng dẫn trên màn hình để xuất báo cáo ra file `.TXT`.
