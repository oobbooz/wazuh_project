```
[Attacker ngoài Internet]
        ↓
   (1) em0 - WAN (pfSense)
        ↓
   (2) Firewall rules (pfSense kiểm tra)
        ↓
   (3) Suricata (IDS/IPS inspect traffic)
        ↓
   (4) NAT / Port Forward (nếu có)
        ↓
   (5) em1 - LAN
        ↓
[Máy trong mạng nội bộ (victim)]
```
- **em0 (WAN)**: thấy request gốc → alert 
- **em1 (LAN)**: thấy request sau NAT → alert lại
## 1. Giai đoạn 1: Recon (Trinh sát hệ thống)
```
nmap -sS -A 192.168.10.133
```
- trên suricata (pfsense), nhận được các alert.
![[Pasted image 20260415222710.png]]
#### Kết quả recon
┌──(kali㉿kali)-[~]
└─$ ==nmap -A -T4 192.168.10.133==                               
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-21 12:36 EDT
Nmap scan report for 192.168.10.133
Host is up (0.0031s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE  SERVICE VERSION
==22/tcp  open   ssh==     OpenSSH 8.9p1 Ubuntu 3ubuntu0.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 d0:9a:82:d7:5e:cc:7d:f5:5d:3e:0f:72:75:0f:66:4d (ECDSA)
|_  256 bd:3d:d4:64:3a:5a:ff:16:af:20:c5:13:e7:cf:9f:dd (ED25519)
==80/tcp  open   http==    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: 403 Forbidden
443/tcp closed https
MAC Address: 00:0C:29:DF:61:BC (VMware)
Device type: general purpose|firewall
Running (JUST GUESSING): Linux 4.X|2.6.X|5.X|3.X (94%), IPFire 2.X (88%)
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:2.6.32 cpe:/o:ipfire:ipfire:2.27 cpe:/o:linux:linux_kernel:5.15 cpe:/o:linux:linux_kernel:6.1 cpe:/o:linux:linux_kernel:3.10
Aggressive OS guesses: Linux 4.19 - 5.15 (94%), Linux 2.6.32 (89%), Linux 4.0 - 4.4 (89%), Linux 4.15 (89%), IPFire 2.27 (Linux 5.15 - 6.1) (88%), Linux 5.4 (88%), Linux 2.6.32 or 3.10 (87%), Linux 2.6.32 - 2.6.35 (86%), Linux 2.6.32 - 2.6.39 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   3.09 ms 192.168.10.133         

=> Tổng kết Giai đoạn 1 cho Hacker
Hacker đã có đủ thông tin để lập kế hoạch:
1. Bỏ qua tấn công hệ điều hành chung vì bị nhiễu.
2. **Mục tiêu số 1:** Brute force SSH ở cổng 22.
3. **Mục tiêu số 2:** Tìm cách Bypass (qua mặt) bộ quy tắc WAF ở cổng 80 để khai thác ứng dụng Web.
#### A. Log trên suricata

| **Trường Dữ Liệu (Field)**                                  | **Giá Trị (Value)**              | **Giải thích Chuyên sâu (Deep Dive Analysis)**                                                                                               |
| ----------------------------------------------------------- | -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| **Nhóm: Metadata Hệ thống Wazuh (System Index & Identity)** |                                  |                                                                                                                                              |
| `_index`                                                    | wazuh-alerts-4.x-2026.04.15      | Chỉ mục (Index) trên cơ sở dữ liệu Elasticsearch/OpenSearch lưu trữ bản log này. Giúp hệ thống tối ưu hóa việc tìm kiếm theo ngày.           |
| `id`                                                        | 1776268922.540741                | Mã định danh duy nhất (Unique ID) mà Wazuh tự động tạo ra cho riêng sự kiện này để không bị trùng lặp.                                       |
| `input.type`                                                | log                              | Kiểu dữ liệu đầu vào. Xác nhận đây là một tệp nhật ký (log) chứ không phải là cấu hình hay cảnh báo từ API.                                  |
| `timestamp`                                                 | Apr 15, 2026 @ 23:02:02.404      | Thời điểm **Wazuh Manager tiếp nhận và ghi nhận** bản log này vào cơ sở dữ liệu.                                                             |
| **Nhóm: Nguồn cung cấp Log (Agent & Location)**             |                                  |                                                                                                                                              |
| `agent.id`                                                  | 000                              | ID của Agent báo cáo. `000` thường ám chỉ chính Wazuh Manager hoặc thiết bị đẩy log dạng Syslog trực tiếp về Manager (agentless).            |
| `agent.name`                                                | bo-wazuh                         | Tên của Agent/Manager xử lý log này.                                                                                                         |
| `manager.name`                                              | bo-wazuh                         | Tên của máy chủ Wazuh Manager quản lý luồng dữ liệu này.                                                                                     |
| `location`                                                  | 192.168.20.128                   | Nơi xuất phát của log. Ở đây là IP của máy pfSense (tường lửa) đã gửi log Suricata qua giao thức Syslog/Forwarder về cho Wazuh.              |
| `decoder.name`                                              | suricata-raw-fix                 | Tên bộ giải mã (Decoder) của Wazuh dùng để đọc và bóc tách định dạng JSON thô (raw) do Suricata gửi đến.                                     |
| **Nhóm: Chi tiết Gói tin Mạng (Network Traffic Context)**   |                                  |                                                                                                                                              |
| `data.src_ip`                                               | ==192.168.10.147==               | IP của kẻ tấn công (Máy Kali Linux) chưa qua NAT.                                                                                            |
| `data.src_port`                                             | 50491                            | Cổng nguồn ngẫu nhiên (Ephemeral port) máy Kali mở ra để gửi gói tin đi.                                                                     |
| `data.dest_ip`                                              | 192.168.20.150                   | IP đích của máy chủ Web (Nạn nhân).                                                                                                          |
| `data.dest_port`                                            | 443                              | Cổng đích đang bị quét (Dịch vụ HTTPS).                                                                                                      |
| `data.proto`                                                | TCP                              | Giao thức tầng 4 được sử dụng (Transmission Control Protocol).                                                                               |
| `data.direction`                                            | to_server                        | Hướng luồng dữ liệu: Đang đi từ máy khách (Client) hướng vào máy chủ (Server).                                                               |
| `data.in_iface`                                             | ==em0==                          | Thẻ mạng thực tế trên pfSense bắt được gói tin này (Cổng WAN - Giao diện tiếp xúc Internet).                                                 |
| `data.pkt_src`                                              | wire/pcap                        | Phương thức Suricata dùng để tóm gói tin. `wire/pcap` nghĩa là bắt trực tiếp tín hiệu trên đường dây mạng (card mạng vật lý/ảo).             |
| `data.flow_id`                                              | 440606615140713.000000           | Mã số luồng dữ liệu do Suricata sinh ra. Rất hữu ích để truy vết các gói tin tiếp theo thuộc cùng một phiên kết nối.                         |
| `data.timestamp`                                            | Apr 15, 2026 @ 23:02:01.889      | Thời điểm **Suricata phát hiện** sự kiện trên card mạng. _(Chú ý: Nhanh hơn `timestamp` của Wazuh khoảng nửa giây do thời gian truyền log)._ |
| **Nhóm: Cảnh báo từ Lõi Suricata (Suricata Alert Engine)**  |                                  |                                                                                                                                              |
| `data.event_type`                                           | alert                            | Loại sự kiện: Cảnh báo an ninh (Khác với các event thống kê `stats` hay log http `http` thông thường).                                       |
| `data.alert.signature`                                      | ==ET SCAN NMAP -sS window 1024== | Tên cảnh báo (Chữ ký): Phát hiện Nmap thực hiện kỹ thuật TCP SYN Stealth Scan nhờ đặc điểm TCP Window = 1024.                                |
| `data.alert.signature_id`                                   | 2009582                          | Mã SID (Signature ID) duy nhất của bộ luật này trong hệ thống cơ sở dữ liệu Emerging Threats (                                               |
#### B. Error.log

| **Nhóm thông tin**        | **Trường dữ liệu (Field)** | **Giá trị thực tế**              | **Ý nghĩa & Giải thích chi tiết**                                                                |
| ------------------------- | -------------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------ |
| **Hệ thống SIEM**         | `_index`                   | `wazuh-alerts-4.x-2026.04.14`    | Log được lưu trữ trong chỉ mục ngày 14/04/2026.                                                  |
|                           | `id`                       | `1776179422.3965238`             | Mã định danh duy nhất của cảnh báo này trên Wazuh.                                               |
|                           | `timestamp`                | `Apr 14, 2026 @ 22:10:22.990`    | Thời điểm log được hiển thị trên bảng điều khiển Wazuh.                                          |
| **Thông tin Agent**       | `agent.id`                 | `003`                            | ID của máy Agent đang chạy trên Web Server.                                                      |
|                           | `agent.ip`                 | `192.168.20.150`                 | Địa chỉ IP của máy chủ mục tiêu (Ubuntu/Apache).                                                 |
|                           | `agent.name`               | `Client-linux`                   | Tên của máy Agent cài trên Web Server.                                                           |
| **Nguồn phát Log**        | `location`                 | ==`/var/log/apache2/error.log`== | Log này được trích xuất từ tệp nhật ký lỗi của Apache.                                           |
|                           | `input.type`               | `log`                            | Dữ liệu được nạp vào dưới dạng tệp văn bản thô.                                                  |
| **Chi tiết kỹ thuật**     | `data.id`                  | `ModSecurity`                    | Xác nhận nguồn gốc bản tin này do ModSecurity tạo ra.                                            |
|                           | `data.srcip`               | `192.168.20.129`                 | **Kẻ tấn công:** Địa chỉ IP của máy phát động cuộc quét.                                         |
|                           | `decoder.name`             | `apache-errorlog`                | Bộ giải mã được dùng để bóc tách thông tin từ Apache Error Log.                                  |
| **Nội dung thô**          | **`full_log`**             | (Chứa nội dung chặn 403)         | **Quan trọng:** Ghi lại lý do chặn là do điểm độc hại vượt ngưỡng (Score: 8), tại đường dẫn `/`. |
| **Luật (Rule)**           | `rule.id`                  | `30411`                          | Mã luật của Wazuh dành cho hành vi "ModSecurity từ chối truy vấn".                               |
|                           | `rule.level`               | `7`                              | Mức độ cảnh báo: Khá cao (trên thang 15).                                                        |
|                           | `rule.description`         | `ModSecurity: Rejected a query`  | Mô tả ngắn: ModSecurity đã từ chối một yêu cầu truy cập.                                         |
|                           | `rule.firedtimes`          | `30`                             | Hành vi này đã lặp lại 30 lần từ cùng một nguồn.                                                 |
| **Phân loại chiến thuật** | `rule.mitre.id`            | `T1083`                          | Mã kỹ thuật theo ma trận MITRE: Tìm kiếm file và thư mục.                                        |
|                           | `rule.mitre.tactic`        | `Discovery`                      | Chiến thuật: Thăm dò/Khám phá hệ thống                                                           |
#### C. access.log

| **Nhóm thông tin**      | **Trường dữ liệu (Field)** | **Giá trị thực tế**               | **Ý nghĩa & Giải thích chi tiết**                                                             |
| ----------------------- | -------------------------- | --------------------------------- | --------------------------------------------------------------------------------------------- |
| **Hệ thống SIEM**       | `_index`                   | `wazuh-alerts-4.x-2026.04.14`     | Chỉ mục lưu trữ log theo ngày của Wazuh.                                                      |
|                         | `id`                       | `1776179422.3949122`              | Mã định danh duy nhất cho sự kiện này trong cơ sở dữ liệu.                                    |
|                         | `timestamp`                | `Apr 14, 2026 @ 22:10:22.812`     | Thời điểm log xuất hiện trên Dashboard của Wazuh.                                             |
| **Thông tin Agent**     | `agent.id`                 | `003`                             | ID định danh máy trạm (Ubuntu Web Server).                                                    |
|                         | `agent.ip`                 | `192.168.20.150`                  | IP nội bộ của máy chủ nạn nhân.                                                               |
|                         | `agent.name`               | `Client-linux`                    | Tên của Agent được đặt trên máy Ubuntu.                                                       |
| **Dữ liệu Truy cập**    | **`data.protocol`**        | **OPTIONS**                       | **Hành vi:** Nmap dùng lệnh này để hỏi Server hỗ trợ những tính năng nào (GET, POST, PUT...). |
|                         | `data.url`                 | `/`                               | Mục tiêu rà quét là thư mục gốc (trang chủ).                                                  |
|                         | **`data.id`**              | **403**                           | **Kết quả:** Mã lỗi HTTP Forbidden. Yêu cầu bị từ chối.                                       |
|                         | `data.srcip`               | `192.168.20.129`                  | **Kẻ tấn công:** IP của máy Kali Linux.                                                       |
| **Thông tin Gốc**       | `full_log`                 | `... Nmap Scripting Engine ...`   | Dòng log thô từ Apache, xác nhận công cụ tấn công là **Nmap**.                                |
|                         | `location`                 | ==`/var/log/apache2/access.log`== | Đường dẫn tệp tin nhật ký mà Agent đã đọc.                                                    |
| **Phân tích của Wazuh** | `decoder.name`             | `web-accesslog`                   | Bộ giải mã chuyên dùng cho nhật ký truy cập web.                                              |
|                         | `rule.id`                  | `31101`                           | ID luật của Wazuh dành cho các lỗi Web nhóm 400.                                              |
|                         | `rule.level`               | `5`                               | Mức độ cảnh báo: Trung bình (Màu vàng trên Dashboard).                                        |
|                         | `rule.description`         | `Web server 400 error code.`      | Mô tả: Máy chủ web trả về mã lỗi nhóm 400.                                                    |
|                         | `rule.firedtimes`          | `27`                              | **Tần suất:** Hành vi này đã lặp lại **27 lần** liên tục.                                     |
| **Tiêu chuẩn Tuân thủ** | `rule.pci_dss`             | `6.5, 11.4`                       | Vi phạm tiêu chuẩn an toàn thanh toán thẻ (Bảo vệ ứng dụng).                                  |
|                         | `rule.nist_800_53`         | `SA.11, SI.4`                     | Vi phạm tiêu chuẩn bảo mật của chính phủ Mỹ.                                                  |
|                         | `rule.gdpr`                | `IV_35.7.d`                       | Liên quan đến quy định bảo vệ dữ liệu châu Âu.                                                |
|                         | `rule.tsc`                 | `CC6.6, CC7.1...`                 | Các tiêu chuẩn kiểm soát an ninh Trust Services.                                              |
- **Log từ `error.log` (trước đó):** Giải thích **Cơ chế** (ModSecurity đã soi và chặn vì điểm độc hại cao).
- **Log từ `access.log` (bản này):** Giải thích **Kết quả** (Web Server đã thực thi lệnh chặn và ghi lại dấu vết truy cập).

| *Loại Log**                 | **Nguồn (Source)**              | **Đặc điểm (Characteristics)**                                                                                                          | **Ý nghĩa (Significance)**                                                                                                                           |
| --------------------------- | ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Suricata (NIDS)**         | Cổng mạng (WAN/LAN)             | Phân tích gói tin ở tầng mạng, dựa trên "chữ ký" (signatures) để nhận diện hành vi quét port, DoS, exploit hệ thống.                    | Cảnh báo **từ xa**. Phát hiện sớm kẻ tấn công đang "lảng vảng" thăm dò trước khi chúng đụng vào Web Server.                                          |
| **ModSecurity (WAF)**       | Tầng ứng dụng (Web Server)      | Thanh tra dữ liệu HTTP(S). Chặn SQL Injection, XSS, Path Traversal, các header bất thường. Thường ghi vào `error.log` hoặc `audit.log`. | Cảnh báo **tấn công Web**. Phát hiện ý đồ khai thác logic ứng dụng. Là lớp bảo vệ cuối cùng trước khi mã độc chạm tới database/server.               |
| **Access.log (Web Server)** | Lưu lượng truy cập (Web Server) | Ghi lại toàn bộ lịch sử các yêu cầu HTTP. Gồm: IP nguồn, URL, User-Agent, mã trạng thái (200, 404, 403), thời gian.                     | **Dấu vết hành vi**. Dùng để dựng lại toàn bộ lộ trình (timeline) của kẻ tấn công: chúng đã truy cập file nào, vào lúc nào, có thành công hay không. |

---
## Giai đoạn 2: Credential access (brute force)
![[Pasted image 20260422010630.png]]

### Suricata Network Alert

| **Nhóm thông tin**                      | **Trường (Field)**      | **Giá trị ghi nhận**         | **Giải thích ngắn gọn (Ý nghĩa)**                                                                                                                    |
| --------------------------------------- | ----------------------- | ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Nguồn phát báo cáo**                  | `agent.name`            | `bo-wazuh`                   | Log này không được gửi trực tiếp từ máy nạn nhân, mà do chính máy chủ Wazuh (`bo-wazuh`) tiếp nhận thông qua Syslog.                                 |
|                                         | `location`              | `192.168.20.128`             | **Nơi đặt cảm biến:** Đây chính là địa chỉ IP LAN của tường lửa pfSense mà chúng ta đã vất vả sửa lúc trước! pfSense đang gửi log Suricata về Wazuh. |
| **Thông tin Luồng mạng (Network Flow)** | `data.in_iface`         | `em0`                        | Gói tin độc hại đi vào từ cổng mạng WAN (`em0`) của pfSense.                                                                                         |
|                                         | `data.src_ip` / `port`  | `192.168.10.147` / `49018`   | IP của kẻ tấn công (Kali) và cổng xuất phát ngẫu nhiên.                                                                                              |
|                                         | `data.dest_ip` / `port` | `192.168.10.133` / `22`      | **Mục tiêu mạng:** Kẻ tấn công đang nhắm thẳng vào IP WAN và cổng SSH của tường lửa (sau đó mới bị NAT vào trong).                                   |
| **Chi tiết Cảnh báo NIDS**              | `data.alert.signature`  | `ET SCAN Potential SSH Scan` | **Nhận diện dấu hiệu:** Bộ luật Emerging Threats (ET) của Suricata nhận ra hành vi kết nối liên tục mang tính chất dò quét/Brute-force SSH.          |
|                                         | `data.alert.action`     | `allowed`                    | **Hành động của tường lửa:** Gói tin VẪN ĐƯỢC CHO QUA. (Suricata đang chạy ở chế độ IDS - Chỉ cảnh báo chứ chưa chặn).                               |
|                                         | `data.alert.severity`   | `2`                          | Mức độ nguy hiểm do Suricata đánh giá (Thường 1 là cao nhất, 3 là thấp nhất).                                                                        |
| **Luật Wazuh (Wazuh Rule)**             | `rule.level`            | `3`                          | Mức độ cảnh báo trên Wazuh. (Wazuh để mức 3 vì coi đây mới chỉ là rà quét mạng bên ngoài, chưa có hậu quả bên trong).                                |
|                                         | `rule.id` / `groups`    | `86601` / `suricata`         | Rule Wazuh dùng để dịch lại các alert từ Suricata.                                                                                                   |
|                                         | `decoder.name`          | `suricata-raw-fix`           | Wazuh đã dùng bộ giải mã dành riêng cho Suricata để bóc tách đoạn log JSON này.                                                                      |

-----
## Giai đoạn 3: Leo thang đặc quyền (Privilege Escalation)
![[Ảnh chụp màn hình 2026-04-22 010725.png]]
### Cảnh báo level 12 (wazuh mana)

| **Tactic (Chiến thuật)** | **Technique (Kỹ thuật)**  | **Mã ID**                                                 | **Tuân thủ (Compliance)**                                                                                                                                                             |
| ------------------------ | ------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Reconnaissance**       | Active Scanning           | **T1595**                                                 | NIST SP 800-53 (AU.14)                                                                                                                                                                |
| **Credential Access**    | Brute Force               | **T1110**                                                 | PCI DSS (10.2.4, 10.2.5)                                                                                                                                                              |
| **Credential Access**    | Password Guessing         | **T1110.001**                                             | GDPR (IV_35.7.d)                                                                                                                                                                      |
| **Lateral Movement**     | Remote Services: SSH      | **T1021.004**                                             | HIPAA (164.312.b)                                                                                                                                                                     |
| **Nhóm thông tin**       | **Trường (Field)**        | **Giá trị ghi nhận**                                      | **Giải thích ngắn gọn (Ý nghĩa)**                                                                                                                                                     |
| **Nguồn phát sinh**      | `agent.name` / `ip`       | `Client-linux` / `192.168.20.150`                         | Máy chủ Ubuntu nội bộ đang bị tấn công.                                                                                                                                               |
|                          | `predecoder.program_name` | `sshd`                                                    | Dịch vụ SSH Daemon trên máy Ubuntu đang xử lý kết nối.                                                                                                                                |
| **Chi tiết Kết nối**     | `data.srcip`              | `192.168.10.147`                                          | **IP của Kẻ tấn công (Máy Kali).** Lưu ý: Mặc dù đi qua pfSense NAT, nhưng nếu cấu hình đúng, IP nguồn thực sự của Kali vẫn được giữ nguyên để Ubuntu ghi nhận.                       |
|                          | `data.dstuser`            | `bo`                                                      | Tài khoản nạn nhân đã bị bẻ khóa mật khẩu.                                                                                                                                            |
| **Luật cảnh báo (Rule)** | `rule.level`              | `12`                                                      | **Cấp độ RẤT CAO:** 12 (Thang 15). Cấp độ này cực kỳ khẩn cấp, thường được cấu hình để gửi SMS/Call hoặc tự động kích hoạt kịch bản chặn IP (Active Response).                        |
|                          | `rule.id`                 | `40112`                                                   | Mã luật tương quan khét tiếng của Wazuh.                                                                                                                                              |
|                          | `rule.description`        | `Multiple authentication failures followed by a success.` | **Điểm mấu chốt:** Wazuh phát hiện có rất nhiều lần đăng nhập sai (thất bại), NHƯNG ngay sau đó lại có 1 lần đăng nhập THÀNH CÔNG. Đây là định nghĩa chuẩn giáo khoa của Brute-force! |
| **Threat Intel (MITRE)** | `rule.mitre.tactic`       | `Initial Access`, `Credential Access`, v.v.               | **Chiến thuật:** Giành quyền truy cập ban đầu và đánh cắp thông tin xác thực.                                                                                                         |
|                          | `rule.mitre.technique`    | `Brute Force` (T1110) & `Valid Accounts` (T1078)          | **Kỹ thuật:** Hacker đã dùng công cụ bẻ khóa (Hydra) để lấy được một tài khoản hợp lệ.                                                                                                |
| **Log gốc (Raw Data)**   | `full_log`                | `... Accepted password for bo from 192.168.10.147...`     | Câu log gốc từ hệ điều hành báo cáo rằng mật khẩu đã được chấp nhận.                                                                                                                  |
```
{
  "_index": "wazuh-alerts-4.x-2026.04.21",
  "_id": "1RkqsZ0BUqOhSIGEpUZv",
  "_version": 1,
  "_score": null,
  "_source": {
    "predecoder": {
      "hostname": "Client-linux",
      "program_name": "sshd",
      "timestamp": "Apr 21 17:50:46"
    },
    "input": {
      "type": "log"
    },
    "agent": {
      "ip": "192.168.20.150",
      "name": "Client-linux",
      "id": "003"
    },
    "manager": {
      "name": "bo-wazuh"
    },
    "data": {
      "srcip": "192.168.10.147",
      "dstuser": "bo",
      "srcport": "54386"
    },
    "rule": {
      "mail": true,
      "level": 12,
      "pci_dss": [
        "10.2.4",
        "10.2.5",
        "11.4"
      ],
      "hipaa": [
        "164.312.b"
      ],
      "tsc": [
        "CC6.1",
        "CC6.8",
        "CC7.2",
        "CC7.3"
      ],
      "description": "Multiple authentication failures followed by a success.",
      "groups": [
        "syslog",
        "attacks"
      ],
      "nist_800_53": [
        "AU.14",
        "AC.7",
        "SI.4"
      ],
      "frequency": 2,
      "gdpr": [
        "IV_35.7.d",
        "IV_32.2"
      ],
      "firedtimes": 2,
      "mitre": {
        "technique": [
          "Valid Accounts",
          "Brute Force"
        ],
        "id": [
          "T1078",
          "T1110"
        ],
        "tactic": [
          "Defense Evasion",
          "Persistence",
          "Privilege Escalation",
          "Initial Access",
          "Credential Access"
        ]
      },
      "id": "40112",
      "gpg13": [
        "7.1",
        "7.8"
      ]
    },
    "location": "journald",
    "decoder": {
      "parent": "sshd",
      "name": "sshd"
    },
    "id": "1776793847.7796238",
    "full_log": "Apr 21 17:50:46 Client-linux sshd[7387]: Accepted password for bo from 192.168.10.147 port 54386 ssh2",
    "timestamp": "2026-04-21T13:50:47.603-0400"
  },
  "fields": {
    "timestamp": [
      "2026-04-21T17:50:47.603Z"
    ]
  },
  "sort": [
    1776793847603
  ]
}
```

----
## Giai đoạn 4: Persistence
![[Pasted image 20260422010838.png]]

| **Nhóm thông tin**                    | **Trường (Field)**                             | **Giá trị ghi nhận**                | **Giải thích ngắn gọn (Ý nghĩa)**                                                                                         |
| ------------------------------------- | ---------------------------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| **Elasticsearch Meta**                | `_index`                                       | `wazuh-alerts-4.x-2026.04.21`       | Nơi lưu trữ log trên cơ sở dữ liệu (được đánh index theo ngày).                                                           |
|                                       | `_id`                                          | `3BkvsZ0BUqOhSIGEEkZe`              | Mã định danh duy nhất của sự kiện này trong cơ sở dữ liệu.                                                                |
| **Nguồn phát sinh (Agent & Manager)** | `agent.name` / `ip`                            | `Client-linux` / `192.168.20.150`   | Tên và IP của máy bị tác động (Mục tiêu Ubuntu vừa bị khai thác).                                                         |
|                                       | `manager.name`                                 | `bo-wazuh`                          | Tên của máy chủ Wazuh Manager tiếp nhận cảnh báo này.                                                                     |
| **Dữ liệu phân tích (Data)**          | `predecoder.program_name`                      | `useradd`                           | Tiến trình hệ thống (binary) đã tạo ra log này.                                                                           |
|                                       | `data.dstuser`                                 | `sysupdate`                         | **Tên tài khoản mới được tạo.** Đây chính là tài khoản ẩn danh bạn đã cấy vào.                                            |
|                                       | `data.uid` / `data.gid`                        | `1001` / `1001`                     | Mã định danh người dùng và nhóm của tài khoản mới (User ID/Group ID).                                                     |
|                                       | `data.shell` / `home`                          | `/bin/bash` / `/home/sysupdate`     | Loại shell được cấp phép và thư mục làm việc của tài khoản giả mạo này.                                                   |
| **Luật cảnh báo (Rule)**              | `rule.level`                                   | `8`                                 | **Cấp độ nghiêm trọng:** 8 (Trên thang 15). Cấp độ này đủ cao để kích hoạt gửi email hoặc cảnh báo đẩy cho quản trị viên. |
|                                       | `rule.id`                                      | `5902`                              | Mã luật (Rule ID) của Wazuh dành riêng cho sự kiện "Tạo user mới".                                                        |
|                                       | `rule.description`                             | `New user added to the system.`     | Mô tả bằng con người hiểu được: Phát hiện một user mới được thêm vào hệ thống.                                            |
| **Threat Intel (MITRE)**              | `rule.mitre.tactic`                            | `Persistence`                       | **Chiến thuật:** Kẻ tấn công muốn "Nằm vùng" (Duy trì quyền truy cập) sau khi xâm nhập.                                   |
|                                       | `rule.mitre.technique`                         | `Create Account`                    | **Kỹ thuật:** Tạo tài khoản cục bộ (Local Account).                                                                       |
|                                       | `rule.mitre.id`                                | `T1136`                             | Mã kỹ thuật tương ứng trên khung chuẩn MITRE ATT&CK toàn cầu.                                                             |
| **Tiêu chuẩn bảo mật (Compliance)**   | `rule.pci_dss`, `hipaa`, `gdpr`, `nist_800_53` | Các mã chuẩn (VD: `AU.14`, `CC6.8`) | Ánh xạ sự kiện này với các vi phạm chuẩn bảo mật quốc tế (Giúp làm báo cáo kiểm toán bảo mật).                            |

---
## Giai đoạn 5: Web Exploitation
Gobuster để tìm ra thư mục ẩn
![[Pasted image 20260422012031.png]]
![[Pasted image 20260422012642.png]]
Chỉnh sửa file
![[Pasted image 20260422013513.png]]

| **Nhóm**              | **Trường (Field)**           | **Giá trị thực tế**                                    | **Giải thích ý nghĩa**                                                |
| --------------------- | ---------------------------- | ------------------------------------------------------ | --------------------------------------------------------------------- |
| **Đối tượng**         | `syscheck.path`              | `/var/www/html/<br><br>admin_panel<br><br>/index.html` | Đường dẫn tệp tin đã bị thay đổi nội dung.                            |
| **Sự kiện**           | `syscheck.event`             | `modified`                                             | Trạng thái tệp: Đã bị sửa đổi.                                        |
| **Người thực hiện**   | `syscheck.uname_after`       | `root`                                                 | Tài khoản sở hữu phiên làm việc đã thực hiện sửa file.                |
| **Dung lượng**        | `syscheck.size_before/after` | `46` -> `87` bytes                                     | Dung lượng file tăng (chứng tỏ nội dung mới đã được chèn vào).        |
| **Hệ thống**          | `agent.name`                 | `Client-linux`                                         | Tên máy chủ nơi xảy ra sự cố.                                         |
| **Luật cảnh báo**     | `rule.id`                    | `550`                                                  | Mã luật tiêu chuẩn của Wazuh cho sự thay đổi tính toàn vẹn file.      |
| **Độ nghiêm trọng**   | `rule.level`                 | `7`                                                    | Cấp độ cảnh báo (Cần chú ý điều tra).                                 |
| **Kỹ thuật tấn công** | `rule.mitre.id`              | `T1565.001`                                            | **Stored Data Manipulation**: Kẻ tấn công sửa đổi dữ liệu đã lưu trữ. |
| **Chiến thuật**       | `rule.mitre.tactic`          | `Impact`                                               | Mục tiêu của kẻ tấn công là gây tác động lên hệ thống.                |
| **Dấu vân tay**       | `md5`, `sha1`, `sha256`      | Thay đổi toàn bộ                                       | Mã băm cũ khác mã băm mới, xác nhận dữ liệu đã bị can thiệp.          |

---
### SQL Injection với SSQLMap

```
sqlmap -u "http://192.168.20.150/shop.php?id=1" --batch --dbs
```

![[Pasted image 20260415234018.png]]


---
## TỔNG KẾT TOÀN DIỆN CHUỖI TẤN CÔNG (MASTER KILL CHAIN)
Đây là bảng **"Master Attack Chain"** toàn diện nhất, tích hợp cả Web Attack (với WAF) và các giai đoạn xâm nhập hệ thống mà bạn đã thực hiện. Đây chính là khung xương chuẩn mực cho một báo cáo đánh giá bảo mật (Pentest Report) hoặc một playbook phân tích sự cố (Incident Response) cho hệ thống SOC của bạn.

### Bảng Hệ Thống Hóa Attack Chain Toàn Diện (MITRE ATT&CK Mapping)

|**Giai đoạn**|**Hành động Hacker**|**Nguồn Log / Công cụ**|**Correlation / Hiện tượng**|**MITRE ID**|**Mô tả MITRE**|
|---|---|---|---|---|---|
|**Recon**|Nmap / Gobuster|Suricata (IDS)|Phát hiện quét port/directory|**T1595**|Active Scanning|
|**Web Attack**|SQL Injection (SQLMap/Curl)|ModSecurity (WAF)|**Payload bị chặn (403 Forbidden)**|**T1190**|Exploit Public-Facing App|
|**Initial Access**|Brute force SSH|Wazuh (sshd)|Đăng nhập sai nhiều lần -> Đúng|**T1110.001**|Password Guessing|
|**Privilege Escalation**|`sudo -i`|Wazuh (auditd)|Đăng nhập -> Thực thi Sudo root|**T1548.003**|Abuse Elevation (Sudo)|
|**Persistence**|`useradd sysupdate`|Wazuh (System)|User mới + Gán quyền sudo|**T1136.001**|Create Local Account|
|**Impact**|Sửa `index.html`|Wazuh (FIM)|Hash file thay đổi (Realtime)|**T1565.001**|Stored Data Manipulation|

