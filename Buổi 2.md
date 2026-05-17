Các loại log chính gửi về SIEM.
### 1. Network Logs
Cung cấp tầm nhìn toàn cảnh về luồng dữ liệu ra/vào hạ tầng, đóng vai trò là chốt chặn đầu tiên để phát hiện xâm nhập từ bên ngoài và hành vi tuồn dữ liệu từ bên trong.
- **Firewall Logs:**  
    Giám sát kiểm soát truy cập (allow/deny). Dùng để phát hiện sớm các chiến dịch dò quét cổng (Port scan), hoặc cảnh báo khi một thiết bị nội bộ lén lút kết nối ra máy chủ điều khiển của tin tặc (C2 Server).
- **NIDS/NIPS Logs (Suricata, Snort, etc.):**  
    Phân tích sâu vào nội dung gói tin (payload). Giúp SOC nhận diện và cảnh báo chính xác các kỹ thuật tấn công khai thác lỗ hổng trước khi gói tin chạm tới máy chủ.
- **Proxy Logs:**  
    Kiểm soát luồng truy cập Internet nội bộ.
- **VPN Logs:**  
    Giám sát cánh cửa truy cập từ xa.
- **DHCP Logs:**  
    Cấp phát IP, địa chỉ MAC, hostname. Hỗ trợ truy vết và ánh xạ thiết bị khi điều tra.
### 2. Endpoint / OS Logs
Giám sát hành vi của User và Tiến trình bên trong máy chủ.
- **Windows Event Logs:**
    - **Security Log (quan trọng nhất):** Có vai trò sống còn trong giám sát xác thực (Event 4624/4625), giúp phát hiện Brute Force, Pass-the-Hash, mạo danh tài khoản, hoặc hành vi lén lút tạo user quản trị (Event 4720).
    - **System Log:** Lỗi driver, khởi động lại hệ thống, lỗi dịch vụ.
    - **Application Log:** Lỗi ứng dụng chạy trên máy chủ.  
    - Setup log: log cài đặt
    - Foward event: log từ máy khác gửi về
        _cài thêm **Sysmon** để ghi chi tiết tiến trình, kết nối mạng, thay đổi registry.
    -> eventvwr: xem log
- **Linux Syslog:**
    - **auth.log / secure:** Vai trò là người gác cổng, ghi nhận mọi lượt đăng nhập SSH và việc sử dụng quyền `sudo`, giúp phát hiện kẻ tấn công đang nỗ lực chiếm quyền Root.
    - **syslog / messages:** Thông tin kernel, dịch vụ, khởi động.  
        cài thêm **auditd** để giám sát chi tiết các lời gọi hệ thống, thay đổi file cấu hình.
        
4. Application & Service Logs
- **Web Server Logs (IIS, Apache, Nginx):**
    - **access.log:** ghi lại **từng yêu cầu (HTTP request)** mà bất kỳ ai hoặc bất kỳ công cụ nào gửi đến máy chủ Web, bất kể yêu cầu đó thành công hay thất bại.
    
    - **error.log:** ghi lại những **lỗi thực thi nội bộ, sự cố ứng dụng, hoặc các hành vi bị từ chối** bởi máy chủ (như bị Web Application Firewall chặn).
        
- **Database Logs (MySQL, MSSQL):** Ghi lại câu lệnh truy vấn (Query execution) và các lỗi đăng nhập. Giúp xác nhận hacker đã đánh cắp bảng dữ liệu (Table) nào thành công.
- **Email Logs (Exchange, SMTP):** Theo dõi thông tin người gửi, người nhận, tên file đính kèm. Là dấu vết đầu tiên để phát hiện Phishing email hoặc Email giả mạo (Spoofing). xxx
- **Application Audit Logs:** Log do chính phần mềm nghiệp vụ sinh ra (Ví dụ: Admin tự ý cấp quyền, export dữ liệu khách hàng) để phòng chống rủi ro nội bộ (Inside
---
modsecurity
core ruleset: owasp 
### 5. Cloud & SaaS Logs
Tập trung vào phân quyền truy cập và môi trường hạ tầng hiện đại.
- Cloud Audit (AWS CloudTrail / Azure Activity / GCP Audit):** Theo dõi các lệnh gọi API lên hệ thống đám mây (Tạo/xóa máy ảo, thay đổi quyền IAM, truy cập S3 bucket).
- **Active Directory / LDAP (Identity):** Trái tim của hệ thống Windows. Ghi nhận tạo tài khoản, đổi Group Policy (GPO), request vé Kerberos. Phát hiện tấn công Kerberoasting hoặc Golden Ticket.
- **MFA / SSO Logs (Okta, Azure AD, Microsoft 365):** Ghi nhận quá trình cấp token đăng nhập và xác thực đa yếu tố. Phát hiện kỹ thuật tấn công làm phiền (MFA fatigue bombing) hoặc chiếm quyền tài khoản (Account takeover).
----
CHI TIẾT OS LOG
## 1. Nhật ký trên Linux Server
Trên Linux, log chủ yếu tồn tại dưới dạng **tệp văn bản (plain text)** nằm tập trung trong thư mục `/var/log/`.
### Các loại log quan trọng nhất:
- **`auth.log` (hoặc `secure` trên RHEL/CentOS):**
    - **Nội dung:** Vai trò là "người gác cổng", ghi nhận mọi lượt đăng nhập SSH (thành công/thất bại), việc sử dụng quyền `sudo`, và thay đổi tài khoản.
    - **Cấu trúc:** `Timestamp | Hostname | Service[PID] | Message` (Ví dụ: `Apr 1 10:00:01 kali sudo: pam_unix(sudo:session): session opened for user root`).
- **`syslog` (hoặc `messages`):**
    - **Nội dung:** Nhật ký chung của hệ thống, bao gồm thông tin từ Kernel, các dịch vụ khởi động và lỗi phần cứng.
    - **Cấu trúc:** Tương tự `auth.log`, ghi lại các sự kiện từ mức độ `info` đến `critical`.
- **`audit/audit.log` (Khi cài thêm `auditd`):**
    - **Nội dung:** Giám sát chi tiết các lời gọi hệ thống (syscall), theo dõi lệnh người dùng gõ trên terminal và thay đổi các file cấu hình.
    - **Cấu trúc:** Gồm nhiều trường phức tạp như `type=SYSCALL`, `msg=audit(...)`, `exe="/usr/bin/curl"`, `key="command_monitor"`.
## 2. Nhật ký trên Windows Server
Khác với Linux, Windows không lưu log thành file text thông thường mà lưu dưới dạng **Binary (.evtx)** và quản lý tập trung qua công cụ **Event Viewer**.
### Các kênh log chính (Windows Event Logs):
- **Security Log (Quan trọng nhất):**
    - **Nội dung:** Có vai trò sống còn trong giám sát xác thực, phát hiện Brute Force hoặc hành vi tạo user quản trị lén lút.
    - **Các Event ID trọng tâm:** 4624 (Logon thành công), 4625 (Logon thất bại), 4720 (Tạo tài khoản người dùng).
- **System Log:**
    - **Nội dung:** Ghi lại lỗi driver, khởi động lại hệ thống, lỗi dịch vụ và các sự kiện do Windows System sinh ra.
- **Application Log:**
    - **Nội dung:** Ghi lại các sự kiện lỗi hoặc thông tin từ các ứng dụng chạy trực tiếp trên máy chủ.
### Cấu trúc của một Windows Event:
Một bản ghi Event Log của Windows luôn bao gồm các trường chuẩn hóa sau:
- **Log Name:** Kênh log (Security, System...).
- **Source:** Ứng dụng hoặc thành phần sinh ra log.
- **Event ID:** Mã định danh duy nhất cho loại sự kiện đó.
- **Level:** Mức độ (Information, Warning, Error, Critical).
- **User:** Tài khoản thực hiện hành động.
- **Computer:** Tên máy tính phát sinh sự kiện.
## 3. So sánh

| **Đặc điểm**       | **Linux (Kali/Ubuntu)**             | **Windows**                                          |
| ------------------ | ----------------------------------- | ---------------------------------------------------- |
| **Định dạng gốc**  | Text file (`.log`)                  | Binary file (`.evtx`)                                |
| **Quản lý**        | Thư mục `/var/log/`                 | Event Viewer                                         |
| **Cách Wazuh đọc** | Đọc trực tiếp dòng cuối của file.   | Truy vấn qua Windows API (Event Channel).            |
| **Công cụ bổ trợ** | **Auditd:** Giám sát lệnh thực thi. | **Sysmon:** Ghi chi tiết tiến trình và kết nối mạng. |

----
## Security alert
**Security Alert không phải là một loại log thô (raw log) riêng biệt**, mà nó là **kết quả của quá trình phân tích** từ các loại log mà chúng ta đã xét.
là một "thông báo báo động" được sinh ra khi các hệ thống bảo mật (Wazuh, Firewall, IDS) phát hiện thấy một bản ghi log có dấu hiệu nguy hiểm.

**1. Alert từ Endpoint Security Logs (Wazuh Agent)**
- **Nguồn:** Từ các module như FIM (File Integrity), Vulnerability Detector, Rootcheck.
- **Cơ chế:** Khi Agent thấy một file hệ thống bị sửa đổi (FIM), nó không chỉ ghi log mà còn đẩy về Manager một **Security Alert** mức độ cao (ví dụ Level 10).
- **Đặc điểm:** Alert này cho bạn biết trực tiếp: _"Có lỗ hổng nghiêm trọng"_ hoặc _"Phát hiện dấu vết Rootkit"_.
**2. Alert từ Network Logs (NIDS/NIPS): **
Các thiết bị mạng như Suricata hoặc Firewall trên pfSense cũng sinh ra Alert.
- **Nguồn:** Từ Suricata (NIDS) hoặc logs từ Firewall.
- **Cơ chế:** Khi Suricata soi vào nội dung gói tin và thấy chuỗi `' OR 1=1 --`, nó sẽ đối chiếu với bộ chữ ký (signature) và tạo ra một **Security Alert** gửi về Wazuh.
- **Đặc điểm:** Alert này báo động: _"Phát hiện tấn công SQL Injection từ IP bên ngoài"_.
**3. Alert từ quá trình Correlation (Đối soát log)**
Đây là loại Alert "thông minh" nhất, do **Wazuh Manager** tạo ra sau khi nhận được các OS Logs bình thường.
- **Nguồn:** Từ các OS Logs như Windows Event Logs hoặc Linux `auth.log`.
- **Cơ chế:** Bản thân một dòng log "Login fail" trong `auth.log` chỉ là một **OS Log** bình thường. Nhưng khi Manager thấy 100 dòng như vậy trong 1 phút, nó sẽ kích hoạt Rule và tạo ra một **Security Alert** với tiêu đề: _"Brute Force attack detected"_.
----
### 1. Giới hạn của Security Alert (Tầng Phòng ngự)
Security Alert (từ Firewall, IDS/IPS) giống như một cái máy quét ở cổng bảo vệ.
- **Cơ chế:** Nó chỉ báo động khi thấy "dấu hiệu" nghi vấn (Signature).
- **Điểm yếu:** Nếu hacker dùng kỹ thuật mã hóa (Encoding), dùng kỹ thuật phân mảnh gói tin hoặc tìm ra một lỗ hổng mới (Zero-day) mà Firewall chưa có luật chặn, nó sẽ để kẻ tấn công đi qua mà không hề rung chuông.
- **Thông tin:** Ngay cả khi nó báo động, nó thường chỉ cho biết: _"IP A tấn công SQLi vào IP B"_. Nó không cho bạn biết sau cú SQLi đó, hacker đã thực sự lấy được dữ liệu gì hay chỉ nhận về một trang lỗi 404.
### 2. Sức mạnh của Access Log / App Log (Tầng Sự thật)
Đây là "hộp đen" của máy bay, ghi lại mọi biến cố xảy ra bên trong buồng lái (Service).
- **Tính khách quan:** Dù hacker có bypass được Firewall tinh vi đến đâu, chúng vẫn phải gửi một yêu cầu HTTP đến Apache để lấy dữ liệu. Yêu cầu đó **bắt buộc** phải được Apache ghi lại trong `access.log`.
- **Truy vết Root Cause:** * Qua `access.log`, bạn thấy chính xác URL độc hại đã "lọt lưới".
    - Qua `error.log`, bạn thấy mã lỗi 500 hoặc thông báo lỗi Database, xác nhận lỗ hổng nằm ở file code nào (ví dụ: `shop.php` dòng 45).
- **Bằng chứng:** Đây là nguồn tin cậy nhất để trả lời câu hỏi: _"Hacker đã vào bằng con đường nào và chúng đã lấy đi những gì?"_.
---
wazuh agent và modsecurity
- wazuh agent gửi toàn bộ access.log (0 biết có tấn công) -> mana -> decode, rule -> alert
- modsecurity -> nhận diện tấn công -> chặn (error.log) ->mana -> decode, rule (chỉ khác là soi vào rule cho mod) -> alert
suricata:
- Suricata đóng vai trò như một bộ cảm biến (Sensor) ghi lại **mọi hoạt động giao thức** (HTTP, DNS, TLS, SSH) và thông tin tệp tin (`fileinfo`), bất kể nó có độc hại hay không.
- Chỉ khi gói tin khớp với một **Signature** (chữ ký) trong các file `.rules` (như `emerging-sql.rules`), Suricata mới tạo ra một bản ghi có `event_type: alert`.
### Bảng so sánh mức độ 

| **Đặc điểm**        | **Suricata (IDS Mạng)**                               | **ModSecurity (WAF Host)**                           |
| ------------------- | ----------------------------------------------------- | ---------------------------------------------------- |
| **Mức độ cụ thể**   | **Rất cụ thể:** Biết là Nmap.                         | **Chung chung:** Biết là hành vi bất thường/thăm dò. |
| **Phân loại MITRE** | Thường không gắn sẵn (Wazuh tự gắn).                  | Gắn nhãn **T1083 (Discovery)**.                      |
| **Ưu điểm**         | Giúp SOC biết chính xác hacker đang dùng "vũ khí" gì. | Giúp chặn được cả những "vũ khí" mới chưa có tên.    |
