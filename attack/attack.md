
# Rule trên suricata để match cho log từ pfsense
-> có thể thấy level max=3
<group name="ids,suricata,">

    <!--
    {"timestamp":"2016-05-02T17:46:48.515262+0000","flow_id":1234,"in_iface":"eth0","event_type":"alert","src_ip":"16.10.10.10","src_port":5555,"dest_ip":"16.10.10.11","dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2019236,"rev":3,"signature":"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP Version Number","category":"Attempted Administrator Privilege Gain","severity":1},"payload":"abcde","payload_printable":"hi test","stream":0,"host":"suricata.com"}
    -->
    <rule id="86600" level="0">
        <decoded_as>json</decoded_as>
        <field name="timestamp">\.+</field>
        <field name="event_type">\.+</field>
        <description>Suricata messages.</description>
        <options>no_full_log</options>
    </rule>

    <rule id="86601" level="3">
        <if_sid>86600</if_sid>
        <field name="event_type">^alert$</field>
        <description>Suricata: Alert - $(alert.signature)</description>
        <options>no_full_log</options>
    </rule>

    <rule id="86602" level="0">
        <if_sid>86600</if_sid>
        <field name="event_type">^http$</field>
        <description>Suricata: HTTP.</description>
        <options>no_full_log</options>
    </rule>

    <rule id="86603" level="0">
        <if_sid>86600</if_sid>
        <field name="event_type">^dns$</field>
        <description>Suricata: DNS.</description>
        <options>no_full_log</options>
    </rule>

    <rule id="86604" level="0">
        <if_sid>86600</if_sid>
        <field name="event_type">^tls$</field>
        <description>Suricata: TLS.</description>
        <options>no_full_log</options>
    </rule>

</group>`

----
# Từ máy kali (.10.147) tấn công ubuntu (20.150)
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
1   3.09 ms 192.168.10.133         `

----
# Alert trên suricata
pfsensepfsense

| **Nhóm Trường**          | **Tên Trường (Field)**    | **Giá trị thực tế**                             | **Ý nghĩa & Giải thích chi tiết**                                       |
| ------------------------ | ------------------------- | ----------------------------------------------- | ----------------------------------------------------------------------- |
| **Hệ thống SIEM**        | `_index`                  | `wazuh-alerts-4.x-2026.04.14`                   | Chỉ mục lưu trữ trong cơ sở dữ liệu của Wazuh theo ngày 14/04/2026.     |
|                          | `id`                      | `1776174912.3833442`                            | Mã định danh duy nhất của sự kiện này trong hệ thống Wazuh.             |
|                          | `input.type`              | `log`                                           | Hình thức nạp dữ liệu vào là dạng tệp nhật ký (log).                    |
|                          | `timestamp`               | `Apr 14, 2026 @ 20:55:12.080`                   | Thời điểm log này được Wazuh ghi nhận vào hệ thống.                     |
| **Thông tin Agent**      | `agent.id`                | `000`                                           | ID của Wazuh Manager (000 là mặc định cho máy chủ quản lý).             |
|                          | `agent.name`              | `bo-wazuh`                                      | Tên của Manager đang xử lý dữ liệu.                                     |
|                          | `manager.name`            | `bo-wazuh`                                      | Tên máy chủ quản lý chịu trách nhiệm phân tích log.                     |
| **Nguồn phát Log**       | `location`                | `192.168.20.128`                                | **Địa chỉ IP của pfSense:** Đây là nơi Suricata phát hiện ra sự cố.     |
|                          | `data.in_iface`           | `em1`                                           | Tên giao tiếp mạng (Interface) trên pfSense đã hứng gói tin này.        |
|                          | `data.pkt_src`            | `wire/pcap`                                     | Nguồn gốc dữ liệu là từ việc bắt gói tin trực tiếp trên đường truyền.   |
| **Chi tiết Cảnh báo**    | `data.event_type`         | `alert`                                         | Loại sự kiện được Suricata định nghĩa là "Cảnh báo".                    |
|                          | `data.alert.signature`    | ==`ET SCAN Possible Nmap User-Agent Observed`== | **Chữ ký tấn công:** Phát hiện chuỗi Nmap trong User-Agent của HTTP.    |
|                          | `data.alert.signature_id` | `2024364`                                       | Mã ID định danh luật của Emerging Threats (ET) dành cho Nmap.           |
|                          | `data.alert.category`     | `Web Application Attack`                        | Phân loại mục tiêu tấn công là ứng dụng Web.                            |
|                          | ==`data.alert.severity`== | ==1==                                           | Mức độ nghiêm trọng theo thang Suricata (1 là cảnh báo thăm dò).        |
|                          | `data.alert.action`       | ==`allowed`==                                   | Trạng thái: IDS chỉ theo dõi, không chặn (Allow).                       |
|                          | `data.alert.gid`          | `1`                                             | Group ID của bộ luật Suricata.                                          |
|                          | `data.alert.rev`          | `5`                                             | Phiên bản cập nhật thứ 5 của bộ luật này.                               |
| **Dữ liệu Tầng mạng**    | `data.src_ip`             | ==`192.168.20.129`==                            | **Kẻ tấn công:** IP nguồn thực hiện hành vi.                            |
|                          | `data.src_port`           | `43804`                                         | Cổng nguồn máy tấn công sử dụng.                                        |
|                          | `data.dest_ip`            | ==`192.168.20.150`==                            | **Nạn nhân:** IP máy mục tiêu bị quét.                                  |
|                          | `data.dest_port`          | `80`                                            | Cổng đích (Dịch vụ Web).                                                |
|                          | `data.proto`              | `TCP`                                           | Giao thức truyền tải tầng 4.                                            |
|                          | `data.app_proto`          | `http`                                          | Giao thức ứng dụng tầng 7.                                              |
|                          | `data.direction`          | `to_server`                                     | Hướng đi của gói tin: Từ máy tấn công đến máy chủ.                      |
| **Dữ liệu Luồng (Flow)** | `data.flow_id`            | `2202000435364715.000000`                       | ID dùng để nhóm tất cả các gói tin thuộc cùng một phiên kết nối này.    |
|                          | `data.tx_id`              | `0`                                             | ID giao dịch (Transaction ID) trong luồng dữ liệu HTTP.                 |
|                          | `data.timestamp`          | `20:55:11.631`                                  | Thời điểm thực tế gói tin đi qua Suricata (trước khi về Wazuh).         |
| **Luật của Wazuh**       | `rule.id`                 | `86601`                                         | ID luật nội bộ của Wazuh để xử lý các log dạng Suricata JSON.           |
|                          | `rule.level`              | ==`3`==                                         | Mức độ cảnh báo hiển thị trên Dashboard (Thấp).                         |
|                          | `rule.description`        | `Suricata: Alert - ET SCAN Possible...`         | Mô tả ngắn gọn về sự cố cho người quản trị.                             |
|                          | `rule.firedtimes`         | `156`                                           | Số lần sự cố này đã lặp lại trong quá khứ.                              |
|                          | `rule.groups`             | ==`ids, suricata`==                             | Nhóm luật liên quan đến hệ thống IDS và Suricata.                       |
|                          | `rule.mail`               | `false`                                         | Cấu hình không gửi email thông báo cho sự kiện mức độ thấp này.         |
| **Giải mã**              | `decoder.name`            | `suricata-raw-fix`                              | Tên bộ giải mã Wazuh sử dụng để tách các trường trên từ chuỗi JSON thô. |
- ***Trễ thời gian (Latency):** Giữa `data.timestamp` (20:55:11.631) và `timestamp` của Wazuh (20:55:12.080) có độ trễ khoảng **0.449 giây**. Đây là thời gian pfSense đóng gói log và gửi qua mạng về Wazuh.*
-  ****`data.flow_id` (ID Luồng): "Cả một cuộc gọi điện thoại"***
Hãy tưởng tượng bạn gọi điện cho một người bạn. Từ lúc nhấc máy, nói chuyện 10 phút cho đến lúc cúp máy, toàn bộ quá trình đó được coi là **một Luồng (Flow)**.

- **Định nghĩa:** `flow_id` là một con số duy nhất mà Suricata gán cho tất cả các gói tin đi qua lại giữa **IP nguồn:Cổng nguồn** và **IP đích:Cổng đích**.
- **Tại sao cần nó?** Một cuộc tấn công Nmap có thể gửi hàng nghìn gói tin. Nếu không có `flow_id`, các dòng log sẽ rời rạc. Nhờ có ID này, nhân viên SOC có thể lọc ra và thấy toàn bộ "lịch sử cuộc trò chuyện" từ lúc bắt đầu đến lúc kết thúc.

- **`data.tx_id` (Transaction ID): "Một câu hỏi và một câu trả lời"**
Trong một cuộc điện thoại kéo dài 10 phút (Flow), bạn có thể hỏi nhiều câu khác nhau:

- Câu 1: "Bạn khỏe không?" -> Trả lời: "Tôi khỏe." (**Giao dịch 0**)
- Câu 2: "Mấy giờ rồi?" -> Trả lời: "8 giờ tối." (**Giao dịch 1**)
Trong log của bạn, `tx_id: 0` có nghĩa đây là **cặp yêu cầu/phản hồi đầu tiên** bên trong kết nối TCP đó.
- **Định nghĩa:** Trong giao thức HTTP, mỗi khi máy khách gửi 1 yêu cầu (GET/POST) và máy chủ phản hồi lại, đó là một **Giao dịch (Transaction)**.
- **Tại sao cần nó?** Một kết nối mạng (Flow) có thể duy trì rất lâu và thực hiện nhiều hành động. `tx_id` giúp bạn chỉ đích danh gói tin nào trong luồng đó đã gây ra cảnh báo.

----
### Bảng Phân Tích Chi Tiết Log Wazuh (ModSecurity)
#### A. Error.log

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
#### B. access.log

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
---
Vậy khi tấn công 1 máy, cơ bản sẽ nhận được 3 loại log/alert + hiển thị trên dashboard
### Bộ Ba Log Cho Một Cuộc Tấn Công

| **Thứ tự** | **Loại Log**                | **Nguồn gốc (Location)**                         | **Vai trò trong điều tra**                                              |
| ---------- | --------------------------- | ------------------------------------------------ | ----------------------------------------------------------------------- |
| **1**      | **Suricata Log**            | Từ pfSense (`.128`) gửi về qua Syslog            | **Cảnh báo sớm:** Phát hiện công cụ và hành vi ở tầng mạng.             |
| **2**      | **ModSecurity (Error Log)** | Từ `/var/log/apache2/error.log` trên máy `.150`  | **Lý do chặn:** Giải thích chi tiết tại sao yêu cầu bị từ chối.         |
| **3**      | **Apache Access Log**       | Từ `/var/log/apache2/access.log` trên máy `.150` | **Kết quả cuối cùng:** Xác nhận cuộc tấn công đã bị đẩy lùi thành công. |

----
# Một số tấn công khác
## 1. SQL

```
curl "http://192.168.20.150/shop.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users"
```

- 3 log nhận được
### a) Log từ suricata

*1 phần*

| `data.event_type`         | alert                                                      | Phân loại sự kiện: Đây là một cảnh báo an ninh.                       |
| ------------------------- | ---------------------------------------------------------- | --------------------------------------------------------------------- |
| `data.alert.signature`    | ==ET WEB_SERVER SELECT USER SQL Injection Attempt in URI== | Tên nhận dạng của cuộc tấn công (Cố gắng SQLi bằng SELECT USER).      |
| `data.alert.signature_id` | 2010963                                                    | Mã định danh (SID) của luật Emerging Threats.                         |
| `data.alert.category`     | ==Web Application Attack==                                 | Nhóm phân loại hành vi tấn công (Tấn công ứng dụng Web).              |
| `data.alert.severity`     | 1                                                          | Mức độ nghiêm trọng do bộ luật ET đánh giá (1 là mức cao nhất).       |
| `data.alert.action`       | allowed                                                    | Suricata phát hiện nhưng cho phép đi qua (do đang chạy ở chế độ IDS). |
| `data.alert.gid`          | 1                                                          | Group ID (ID nhóm) của hệ thống tạo ra luật.                          |
| `data.alert.rev`          | 7                                                          | Số lần cập nhật (Revision) của luật này.                              |

### b) Log từ modsecurity (error.log)
fulllog
`
[Wed Apr 15 18:07:15.320106 2026] [:error] [pid 1365:tid 128112856884800] [client 192.168.20.129:59290] [client 192.168.20.129] ModSecurity: Access denied with code 403 ==(phase 2)==. Operator GE matched 5 at TX:anomaly_score. [file "/usr/share/modsecurity-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "94"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 23)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.3.9"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "192.168.20.150"] [uri "/shop.php"] [unique_id "ad9xY76vn7BFoCBrAIRiZwAAAAA"]
`
Các phase:

ModSecurity không phân tích toàn bộ gói tin cùng một lúc. Nó chia quá trình xử lý HTTP thành **5 Phase (Giai đoạn)** để tối ưu hiệu năng. Nếu phát hiện mã độc ở Phase nào, nó sẽ chặn ngay lập tức mà không cần phân tích các Phase tiếp theo.

1. **Phase 1: Request Headers (Tiêu đề yêu cầu):** Phân tích các thông tin ban đầu như URI, User-Agent, Host... (Nếu bạn dùng payload Shellshock nhét vào User-Agent, nó sẽ bị tóm ở Phase 1).
2. **Phase 2: Request Body (Nội dung yêu cầu) -  _Log nổ ở đây_:** Phân tích phần thân của dữ liệu gửi lên, ví dụ như các tham số POST, form data, hoặc các chuỗi query trên URL. Việc log của bạn ghi nhận `(phase 2)` chứng tỏ payload SQL Injection đã được ModSecurity bóc tách và phân tích xong từ các tham số bạn gửi vào `shop.php`.
3. **Phase 3: Response Headers (Tiêu đề phản hồi):** Phân tích dữ liệu trước khi gửi trả về cho Client.
4. **Phase 4: Response Body (Nội dung phản hồi):** Phân tích nội dung trang web trả về. (Thường dùng để phát hiện Data Leakage - rò rỉ dữ liệu như lộ mã thẻ tín dụng, lộ nội dung file `/etc/passwd` ra ngoài màn hình).
5. **Phase 5: Logging (Ghi log):** Giai đoạn cuối cùng dùng để ghi nhận sự kiện ra file log (như dòng log bạn đang xem).

### c) Log từ access.log

| `rule.id`           | 31103                                 | ID của luật trên Wazuh chuyên bắt các mẫu tấn công SQL Injection trong URL.                                                    |
| ------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `rule.level`        | 7                                     | Mức độ cảnh báo (Khá cao - Tương đương với mức cảnh báo của ModSecurity).                                                      |
| `rule.description`  | ==SQL injection attempt.==            | Wazuh gắn nhãn trực diện: "Nỗ lực tấn công tiêm nhiễm SQL".                                                                    |
| `rule.groups`       | web, accesslog, attack, sql_injection | Các thẻ (tags) phân loại hành vi trên hệ thống.                                                                                |
| `rule.mitre.id`     | T1190                                 | Mã MITRE ATT&CK: Kỹ thuật khai thác ứng dụng trực diện web.                                                                    |
| `rule.mitre.tactic` | Initial Access                        | Chiến thuật: "Giành quyền truy cập ban đầu" (Khác với chiến thuật Discovery ở log ModSecurity).                                |
| `rule.pci_dss`      | 6.5, 11.4, 6.5.1                      | Log này phục vụ cho việc kiểm toán tuân thủ bảo mật thẻ thanh toán quốc tế (PCI-DSS), chứng minh hệ thống có giám sát lỗ hổng. |
| `rule.gdpr`         | IV_35.7.d                             | Phục vụ tuân thủ quy định bảo vệ dữ liệu chung của châu Âu (GDPR).                                                             |
### So sánh 

| **Trường thông tin (Field Focus)**  | **🛡️ Suricata (Network IDS)** | **🧱 ModSecurity (WAF)**              | **📝 Apache (Access Log)**                        |
| ----------------------------------- | ------------------------------ | ------------------------------------- | ------------------------------------------------- |
| **Nguồn log (`agent.name`)**        | Từ Router pfSense (`bo-wazuh`) | Từ Web Server (`Client-linux`)        | Từ Web Server (`Client-linux`)                    |
| **IP Kẻ tấn công**                  | ✅ Có (`data.src_ip`)           | ✅ Có (`data.srcip`)                   | ✅ Có (`data.srcip`)                               |
| **Cổng của kẻ tấn công (Src Port)** | ✅ Có (`data.src_port`)         | ❌ Không bóc tách (Nằm trong full_log) | ❌ Không có                                        |
| **IP Nạn nhân (Dest IP)**           | ✅ Có (`data.dest_ip`)          | ✅ Có (`agent.ip` / `hostname`)        | ❌ Không bóc tách rõ (Ngầm hiểu là server)         |
| **Cổng Nạn nhân (Dest Port)**       | ✅ Có (`data.dest_port: 80`)    | ❌ Không có                            | ❌ Không có                                        |
| **Mapping MITRE ATT&CK**            | ❌ Không có (Phải tự map)       | ==✅ Có (T1083 - Discovery)==          | ==✅ Có (T1190 - Initial Access)==                 |
| **Chuẩn tuân thủ (PCI, GDPR...)**   | ❌ Không có                     | ❌ Không có                            | ✅ **Rất đầy đủ** (`rule.pci_dss`, `rule.gdpr`...) |

1. **T1083 (Discovery - Thăm dò) từ log ModSecurity:**
    
    - Wazuh thấy WAF báo cáo chặn một truy vấn vì có "điểm bất thường" cao.
    - Một gói tin độc hại bị chặn ngay ở cửa ngõ được hệ thống phân loại là hành vi **dò quét, thử nghiệm** xem WAF có hoạt động hay không.
        
2. **T1190 (Initial Access - Khai thác) từ Access Log:**
    
    - Wazuh đọc được trực tiếp chuỗi payload thô (`UNION SELECT...`) lưu trong lịch sử web.
    - Dựa vào cú pháp này, nó nhận diện đây đích thị là SQL Injection — kỹ thuật chuyên dùng để **khai thác lỗ hổng ứng dụng web**.

**Tóm lại:** T1083 là đánh giá dựa trên **hành vi bị chặn** (đang thăm dò hệ thống), còn T1190 là đánh giá dựa trên **bản chất của mã độc** (công cụ dùng để đột nhập).

---
## Một số tấn công khác
- XSS
```
curl "http://192.168.20.150/shop.php?search=<script>alert('SOC_LAB_XSS')</script>"
```
- LFI
```
curl "http://192.168.20.150/shop.php?page=../../../../../../etc/passwd%00"
```
 
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://192.168.10.133 -w /usr/share/wordlists/dirb/common.txt -b 404 -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"

Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)

[+] Url:                     http://192.168.10.133
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.bash_history        (Status: 403) [Size: 279]
/.htaccess            (Status: 403) [Size: 279]
/.config              (Status: 403) [Size: 279]
/.git/HEAD            (Status: 403) [Size: 279]
/.hta                 (Status: 403) [Size: 279]
/.htpasswd            (Status: 403) [Size: 279]
/.bashrc              (Status: 403) [Size: 279]
/.profile             (Status: 403) [Size: 279]
/.mysql_history       (Status: 403) [Size: 279]
/.sh_history          (Status: 403) [Size: 279]
/.svn/entries         (Status: 403) [Size: 279]
/_vti_bin/_vti_adm/admin.dll (Status: 403) [Size: 279]
/_vti_bin/shtml.dll   (Status: 403) [Size: 279]
/_vti_bin/_vti_aut/author.dll (Status: 403) [Size: 279]
/admin_panel          (Status: 301) [Size: 322] [--> http://192.168.10.133/admin_panel/]
/akeeba.backend.log   (Status: 403) [Size: 279]
/awstats.conf         (Status: 403) [Size: 279]
/development.log      (Status: 403) [Size: 279]
/global.asax          (Status: 403) [Size: 279]
/global.asa           (Status: 403) [Size: 279]
/index.html           (Status: 200) [Size: 10671]
/main.mdb             (Status: 403) [Size: 279]
/php.ini              (Status: 403) [Size: 279]
/production.log       (Status: 403) [Size: 279]
/server-status        (Status: 403) [Size: 279]
/spamlog.log          (Status: 403) [Size: 279]
/thumbs.db            (Status: 403) [Size: 279]
/Thumbs.db            (Status: 403) [Size: 279]
/web.config           (Status: 403) [Size: 279]
/WS_FTP.LOG           (Status: 403) [Size: 279]
Progress: 4614 / 4614 (100.00%)
