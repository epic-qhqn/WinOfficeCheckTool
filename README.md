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

A CLI utility designed to check the status of Windows and Microsoft Office licensing mechanisms. It helps detect spoofing methods, unauthorized KMS servers, Registry bypasses, and performs deep system forensics.

### 🧰 Inspection Modules
| Module | Target | Description |
| :--- | :---: | :--- |
| **WMI & SPP Status** | Windows | Cross-validates Software Protection Platform channels. |
| **Office & SPP Status** | Office | Scans for valid Office AppIDs and malicious Ohook payloads. |
| **BIOS/ACPI Extractor** | Hardware | Extracts embedded MSDM tables and decodes Base24 keys from the Registry. |
| **Registry Checks** | System | Detects IFEO, NoGenTicket, and SkipRearm modifications. |
| **Forensics & Network** | System | Checks for GenuineTicket spoofing, TCP connections, and Digital Signatures. |

### ✨ Core Features
* Performs a **WMI Search** to identify digital tickets (e.g., MAS HWID) that might be masked by standard unactivated or trial keys.
* Compares hardware-embedded **OEM keys** with the currently active Windows partial product key, and natively decodes the fallback **DigitalProductId** directly from the System Registry using a custom Base24 algorithm.
* Verifies the **Digital Signature** of core system libraries using the modern .NET 10 `X509CertificateLoader` to catch memory patching and forged binaries.
* Scans active **TCP** network connections in real-time to intercept unauthorized local or public KMS emulators communicating on port 1688.
* Reads PowerShell `ConsoleHost_history.txt` and Windows Task Scheduler to find crack scripts and auto-renewal tasks (e.g., AutoKMS, KMS38).
* Self-contained, single-file executable architecture requiring **zero .NET SDK installation** on the target machine.

### 💻 Technical Details
* Uses a custom Console UI engine that parses inline markup (`[[ ]]`) to dynamically highlight forensic keywords.
* Completely eliminates native C++ **PInvoke** calls for network scanning to prevent **Memory Leaks**. All heavy forensic tasks are securely handled by the .NET Base Class Library and automatically cleaned by the Garbage Collector.
* Prevents COM initialization exceptions (`WmiNetUtilsHelper`) by forcing native C++ libraries to extract into RAM during standalone execution.
* Automatically resolves the Single-File extraction `%TEMP%` pathing issue by locking the output `.TXT` report explicitly to the host executable's directory.

### 🚀 Setup & Execution
1. Clone the repository and navigate to the directory in your terminal.
2. Configure and build the self-contained executable using the **.NET 10 SDK**: Run `dotnet clean` followed by `dotnet publish -c Release`.
3. Locate the compiled executable inside `bin\Release\net10.0-windows\win-x64\publish\`.
4. Run **WinOfficeCheckTool.exe** as Administrator on any target machine (no installation required).
5. Follow the on-screen prompts to export a `.TXT` report.

---

<h2 id="tiếng-việt">🇻🇳 Tiếng Việt</h2>

Công cụ dòng lệnh (CLI) được thiết kế để kiểm tra trạng thái bản quyền Windows và Microsoft Office. Phần mềm hỗ trợ phát hiện các công cụ giả mạo, KMS lậu, các bypass can thiệp Registry và thực hiện pháp y hệ thống chuyên sâu.

### 🧰 Cấu Trúc Module
| Module | Mục tiêu | Ghi chú |
| :--- | :---: | :--- |
| **WMI & SPP Status** | Windows | Rà soát chéo các kênh cấp phép của Software Protection Platform. |
| **Office & SPP Status** | Office | Quét AppID của Office và kiểm tra các payload độc hại như Ohook. |
| **BIOS/ACPI Extractor** | Hardware | Trích xuất bảng MSDM và giải mã Base24 trực tiếp từ Registry. |
| **Registry Checks** | System | Phát hiện IFEO, NoGenTicket, và chặn đếm ngược SkipRearm. |
| **Forensics & Network** | System | Quét GenuineTicket giả, kết nối TCP mạng, và kiểm duyệt Digital Signature. |

### ✨ Tính Năng
* Thực hiện **rà soát WMI** để tìm kiếm các thẻ bản quyền (như MAS HWID) có thể bị che giấu bởi các key rác hoặc key dùng thử trong hệ thống.
* Đối chiếu trực tiếp **OEM Key** nhúng trong phần cứng với 5 số đuôi của Key đang kích hoạt, đồng thời tự động giải mã thuật toán **Base24** để trích xuất Key dự phòng ẩn sâu bên trong Registry.
* Xác thực **Digital Signature** của các file hệ thống lõi thông qua API bảo mật mới nhất của **.NET 10** nhằm tóm gọn các hình thức tiêm mã độc vào bộ nhớ.
* Quét các luồng mạng **TCP** theo thời gian thực để chặn đứng các máy chủ KMS lậu đang lén lút giao tiếp qua cổng 1688.
* Đọc file `ConsoleHost_history.txt` của PowerShell và Windows Task Scheduler để tìm các lệnh bẻ khóa hoặc các task gia hạn ngầm (AutoKMS, KMS38).
* Kiến trúc phần mềm độc lập (Self-contained Single-file), có thể chạy trực tiếp trên máy tính mà **không cần cài đặt .NET SDK**.

### 💻 Chi Tiết Kỹ Thuật
* Sử dụng Engine UI Console tự viết có khả năng dịch cú pháp thẻ (`[[ ]]`) để highlight các từ khóa quan trọng.
* Loại bỏ hoàn toàn các hàm **PInvoke** gọi API thô của C++ để triệt tiêu rủi ro **Memory Leak**. Toàn bộ tác vụ quét mạng lưới được xử lý an toàn bởi Base Class Library và dọn dẹp tức thời nhờ **Garbage Collector**.
* Tránh lỗi khởi tạo thư viện COM (`WmiNetUtilsHelper`) bằng cách ép giải nén các thư viện C++ lõi vào RAM khi chạy dạng file đơn.
* Xử lý triệt để bài toán bung file tạm **%TEMP%** của môi trường Single-File, đảm bảo báo cáo `.TXT` luôn được trút ra an toàn ngay tại thư mục chứa file thực thi gốc.

### 🚀 Hướng Dẫn Cài Đặt & Sử Dụng
1. Clone mã nguồn và mở Terminal tại thư mục dự án.
2. Tiến hành dọn dẹp và đóng gói phần mềm bằng **.NET 10 SDK**: Gõ lệnh `dotnet clean` sau đó `dotnet publish -c Release`.
3. Lấy file thực thi duy nhất tại đường dẫn `bin\Release\net10.0-windows\win-x64\publish\`.
4. Copy và chạy **WinOfficeCheckTool.exe** dưới quyền Quản trị viên (Run as Administrator) trên bất kỳ máy nào mà không cần cài đặt thêm phần mềm bổ trợ.
5. Làm theo hướng dẫn trên màn hình để xuất báo cáo ra file `.TXT`.
