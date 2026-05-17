

## 1. Cơ chế decoder — Tổng quan

### 1.1 Hai loại log và cách xử lý

|Loại log|Ai xử lý|Decoder ở đâu|Ví dụ|
|---|---|---|---|
|Text thuần (syslog, plain text)|Analysisd trên server|File XML trong `/var/ossec/ruleset/decoders/`|SSH, Apache, syslog, firewall|
|JSON có cấu trúc|Agent + Analysisd|C code trong Analysisd, không có file XML|Windows eventchannel|

Nguyên tắc: nếu agent đã gửi JSON có cấu trúc, server không cần regex để tách field. Nếu là log text thuần, server dùng decoder XML.

---

### 1.2 Pipeline xử lý log trên server (Analysisd)

1. **Pre-decoding** — tách header syslog: timestamp, hostname, program_name. Tự động, không cần cấu hình.
2. **Decoding** — tìm decoder cha khớp program_name, áp dụng decoder con theo cây để extract field.
3. **Rule matching** — so khớp toàn bộ ruleset, lấy rule khớp sâu nhất. Level > 2 thì tạo alert.
4. **Output** — ghi vào `alerts.json` (có alert) và `archives.json` (nếu `logall_json=yes`).

Toàn bộ pipeline chạy trong memory. Archives và alerts được ghi song song ở cuối, không phải tuần tự.

---

### 1.3 Cấu trúc decoder XML — cha và con

Ví dụ SSH log:

```
Feb 14 12:19:04 server sshd[25474]: Accepted password for john from 192.168.1.1 port 49765
```

Decoder cha — khớp theo `program_name`:

```xml
<decoder name="sshd">
  <program_name>^sshd</program_name>
</decoder>
```

Decoder con — extract field:

```xml
<decoder name="sshd-success">
  <parent>sshd</parent>
  <prematch>^Accepted</prematch>
  <regex offset="after_prematch">^ \S+ for (\S+) from (\S+) port (\S+)</regex>
  <order>user, srcip, srcport</order>
</decoder>
```

Kết quả: `user=john`, `srcip=192.168.1.1`, `srcport=49765`

---

## 2. Windows eventchannel — cơ chế đặc biệt

### 2.1 Tổng quan

Decoder `windows_eventchannel` **không có file XML** trong `/var/ossec/ruleset/decoders/`. Nó được nhúng trực tiếp vào source code C của Analysisd, compile thành binary tại `/var/ossec/bin/wazuh-analysisd`. Đây là điểm khác biệt lớn nhất so với các decoder khác — không thể xem hay sửa mà không build lại từ source.

Nhiều người nhầm rằng agent Windows đã parse event thành JSON đầy đủ trước khi gửi lên. Thực tế không phải vậy.

---

### 2.2 Agent làm gì — phân tích source code `send_channel_event()`

File gốc: `src/logcollector/read_win_event_channel.c` trên GitHub Wazuh.

**Bước 1 — `EvtRender()` chuyển event thành XML string**

```c
EvtRender(NULL, evt, EvtRenderEventXml, ...)
```

Agent gọi Windows API để lấy toàn bộ event dưới dạng XML nguyên bản. Đây là raw XML, chưa được parse.

**Bước 2 — Tách ProviderName từ XML bằng string parsing thủ công**

```c
find_prov = strstr(xml_event, "Provider Name=");
beg_prov  = strchr(find_prov, '\'');
end_prov  = strchr(beg_prov+1, '\'');
```

Agent không dùng XML parser. Nó tìm chuỗi `"Provider Name="` rồi dùng `strchr()` để lấy giá trị. Kết quả là chuỗi như `"Microsoft-Windows-Security-Auditing"`.

**Bước 3 — `get_message()` lấy field Message qua `EvtFormatMessage`**

```c
msg_from_prov = get_message(evt, wprovider_name, EvtFormatMessageEvent)
```

Dùng ProviderName vừa lấy để gọi `EvtFormatMessage()`. Đây là cách duy nhất lấy được đoạn text `"An account failed to log on..."` — field này **không có trong XML**, chỉ lấy được qua API này.

**Bước 4 — Build JSON và gửi lên server**

```c
cJSON *event_json = cJSON_CreateObject();
cJSON_AddStringToObject(event_json, "Message", msg_from_prov);
cJSON_AddStringToObject(event_json, "Event",   xml_event);
msg_sent = cJSON_PrintUnformatted(event_json);
SendMSG(logr_queue, msg_sent, "EventChannel", WIN_EVT_MQ);
```

JSON agent gửi lên chỉ có **2 field**: `Message` (text) và `Event` (raw XML string). Không phải JSON đầy đủ có `win.system.*`, `win.eventdata.*` như thấy trong `alerts.json`.

---

### 2.3 Server làm gì với JSON nhận được

Sau khi JSON `{"Message":..., "Event":"<XML>"}` vào đến Analysisd, xử lý như sau:

**Decoder — không có file XML**
Wazuh dùng decoder `windows_eventchannel` nhúng thẳng trong C binary của Analysisd — không phải file XML như SSH hay Squid. Decoder này đọc field `Event`, parse raw XML ra thành các field có cấu trúc:

```
win.system.eventID
win.system.severityValue
win.system.channel
win.eventdata.targetUserName
win.eventdata.ipAddress
...
```
Field `Message` từ agent được gán thẳng vào `win.system.message`.

**Rule matching — theo Rule ID range**
Sau khi decode xong, Analysisd so khớp với ruleset Windows. Mỗi channel có file rule riêng:

| Channel    | File rule                       | Rule ID     |
| ---------- | ------------------------------- | ----------- |
| Security   | `0580-win-security_rules.xml`   | 60100–60599 |
| System     | `0590-win-system_rules.xml`     | 61100–61599 |
| Sysmon     | `0595-win-sysmon_rules.xml`     | 61600–62099 |
| PowerShell | `0915-win-powershell_rules.xml` | 91801–92000 |

**Điểm khác biệt so với log text thuần**
Log SSH hay Squid: pre-decoding tách header syslog trước, sau đó decoder XML dùng regex để extract field.
Windows eventchannel: **bỏ qua pre-decoding** vì không có syslog header — vào thẳng Windows event decoder queue riêng, parse XML bằng C code, rồi mới rule matching.

**Sau rule matching, Analysisd đưa ra quyết định dựa trên `level` của rule khớp**
- **archives.json** — ghi khi `logall_json=yes` trong `ossec.conf`, bất kể rule level bao nhiêu, kể cả không khớp rule nào. Mục đích lưu toàn bộ để điều tra sau.
- **alerts.json** — chỉ ghi khi `level > 2`. Đây là ngưỡng cứng của Wazuh, không cấu hình được.
Hai file được ghi **song song trong memory** ở cuối pipeline — không phải tuần tự, không file nào chờ file kia.
Sau khi ghi xong, Filebeat đọc `alerts.json` và đẩy lên indexer để hiển thị trên dashboard. `archives.json` không lên dashboard mặc định.

### 2.4 So sánh agent cũ và agent mới

|Điểm so sánh|Agent cũ (WinEvtLog text)|Agent mới (eventchannel JSON)|
|---|---|---|
|Format gửi lên|`WinEvtLog: Security: AUDIT_FAILURE(4625)...`|`{"Message": ..., "Event": "<raw XML>"}`|
|Decoder xử lý|`windows`, `windows_fields` (file XML)|`windows_eventchannel` (C code)|
|Field extract|Regex trên text|Parse XML trong C|
|File decoder|`0380-windows_decoders.xml`|Nhúng trong Analysisd binary|
|Agent version|Trước Wazuh 3.x|Wazuh 3.x trở lên|

---

### 2.5 Bookmark và push model — đảm bảo không mất event

**Bookmark:** Agent dùng bookmark để track vị trí đọc cuối trong event log. Khi agent restart, nó đọc bookmark từ file trong thư mục `bookmarks/` rồi gọi `EvtSubscribe` với flag `EvtSubscribeStartAfterBookmark`. Nếu bookmark không tồn tại thì dùng `EvtSubscribeToFutureEvents`. Nhờ đó agent không bao giờ đọc lại event cũ hay bỏ sót event khi restart.

**Push model:** Agent đăng ký với Windows một lần duy nhất bằng `EvtSubscribe()`, rồi để yên. Windows giữ địa chỉ callback `event_channel_callback()` của agent. Khi có event mới xảy ra, Windows tự gọi hàm đó ngay lập tức — agent không cần polling, không cần hỏi định kỳ.

```c
channel->subscription = EvtSubscribe(
    NULL, NULL,
    wchannel,    // channel cần theo dõi, ví dụ "Security"
    wquery,      // filter XPath nếu có
    bookmark,    // đọc từ vị trí nào
    channel,     // data truyền vào callback
    (EVT_SUBSCRIBE_CALLBACK)event_channel_callback,
    flags
);
```

Sau dòng này agent không làm gì thêm. Khi event 4625 xảy ra, Windows tự gọi `event_channel_callback()` → `send_channel_event()` → gửi lên server. Toàn bộ xảy ra trong vài millisecond.

---

## 3. Danh sách decoder có sẵn theo nhóm

Tổng cộng hơn 120 file XML trong `/var/ossec/ruleset/decoders/`. Không được sửa trực tiếp — update Wazuh sẽ ghi đè. Custom decoder viết vào `/var/ossec/etc/decoders/local_decoder.xml`.

### 3.1 Network & Firewall

|Decoder|File XML|Thiết bị|
|---|---|---|
|Cisco IOS|`0065-cisco-ios_decoders.xml`|Router, switch|
|Cisco ASA|`0064-cisco-asa_decoders.xml`|Firewall ASA|
|Cisco FTD|`0062-cisco-ftd_decoders.xml`|Firepower|
|Cisco VPN|`0070-cisco-vpn_decoders.xml`|VPN concentrator|
|Cisco PIX|`0063-pix_decoders.xml`|Firewall legacy|
|Cisco eStreamer|`0060-cisco-estreamer_decoders.xml`|eStreamer API|
|Checkpoint|`0050-checkpoint_decoders.xml`|Checkpoint firewall|
|Checkpoint Smart1|`0051-checkpoint-smart1_decoders.xml`|Smart1 management|
|Palo Alto|`0505-paloalto_decoders.xml`|PAN-OS|
|FortiGate|`0100-fortigate_decoders.xml`|Fortinet firewall|
|FortiMail|`0102-fortimail_decoders.xml`|Fortinet mail|
|FortiAuth|`0103-fortiauth_decoders.xml`|FortiAuthenticator|
|FortiDDoS|`0101-fortiddos_decoders.xml`|DDoS protection|
|Huawei USG|`0377-huawei-usg_decoders.xml`|Firewall Huawei|
|Juniper JunOS|`0490-junos_decoders.xml`|Router/switch|
|Netscreen|`0165-netscreen_decoders.xml`|Juniper NetScreen|
|pfSense|`0455-pfsense_decoders.xml`|pfSense firewall|
|SonicWall|`0295-sonicwall_decoders.xml`|SonicWall|
|Barracuda|`0045-barracuda_decoders.xml`|WAF/spam filter|
|F5 BIG-IP|`0525-f5_bigip_decoders.xml`|Load balancer|
|Arbor|`0550-arbor_decoders.xml`|DDoS protection|
|Netscaler|`0160-netscaler_decoders.xml`|Citrix ADC|
|Sophos FW|`0510-sophos_fw_decoders.xml`|Sophos firewall|

### 3.2 Linux / Unix

|Decoder|File XML|Mục đích|
|---|---|---|
|SSH / OpenSSH|`0310-ssh_decoders.xml`|Auth, brute force|
|sudo|`0320-sudo_decoders.xml`|Privilege escalation|
|PAM|`0205-pam_decoders.xml`|Auth modules|
|auditd|`0040-auditd_decoders.xml`|Linux audit|
|kernel|`0140-kernel_decoders.xml`|Kernel / dmesg|
|syslog / unix|`0350-unix_decoders.xml`|Generic syslog|
|su|`0315-su_decoders.xml`|Switch user|
|OpenBSD|`0180-openbsd_decoders.xml`|OpenBSD logs|
|Solaris|`0290-solaris_decoders.xml`|Oracle Solaris|
|AIX IPSec|`0015-aix-ipsec_decoders.xml`|IBM AIX|

### 3.3 Web server

|Decoder|File XML|Mục đích|
|---|---|---|
|Apache|`0025-apache_decoders.xml`|Access/error log|
|Nginx|`0170-nginx_decoders.xml`|Access/error log|
|Web access log|`0375-web-accesslog_decoders.xml`|Generic W3C|
|Squid|`0305-squid_decoders.xml`|Proxy cache|
|IIS (Windows legacy)|`0380-windows_decoders.xml`|IIS W3C log|
|WordPress|`0385-wordpress_decoders.xml`|Audit log|
|Nextcloud|`0485-nextcloud_decoders.xml`|File sharing|
|Owncloud|`0435-owncloud_decoders.xml`|File sharing|

### 3.4 Database

|Decoder|File XML|Mục đích|
|---|---|---|
|MySQL|`0150-mysql_decoders.xml`|Query/error log|
|MariaDB|`0378-mariadb_decoders.xml`|MariaDB log|
|PostgreSQL|`0225-postgresql_decoders.xml`|pg_log|
|MSSQL Server|`0395-sqlserver_decoders.xml`|Audit log|
|MongoDB|`0405-mongodb_decoders.xml`|mongod log|
|Oracle DB|`0560-oracledb_decoders.xml`|Audit trail|
|Redis|`0250-redis_decoders.xml`|Redis log|

### 3.5 Security & Endpoint

|Decoder|File XML|Mục đích|
|---|---|---|
|Snort|`0285-snort_decoders.xml`|IDS/IPS|
|ClamAV|`0075-clamav_decoders.xml`|Antivirus|
|OpenVAS|`0450-openvas_decoders.xml`|Vulnerability scan|
|McAfee|`0475-mcafee_decoders.xml`|Endpoint AV|
|Kaspersky|`0460-kaspersky_decoders.xml`|Endpoint AV|
|Symantec|`0330-symantec_decoders.xml`|Endpoint AV|
|Trend OSCE|`0340-trend-osce_decoders.xml`|OfficeScan|
|Sophos|`0300-sophos_decoders.xml`|Endpoint AV|
|Cylance|`0430-cylance_decoders.xml`|CylancePROTECT|
|FireEye|`0555-fireeye_decoders.xml`|Threat detection|
|Imperva|`0135-imperva_decoders.xml`|WAF|
|OpenVPN|`0190-openvpn_decoders.xml`|VPN|
|RSA Auth Manager|`0260-rsa-auth-manager_decoders.xml`|SecurID|
|FreeIPA|`0105-freeipa_decoders.xml`|Identity mgmt|

### 3.6 Cloud & DevOps

|Decoder|File XML|Mục đích|
|---|---|---|
|Docker|`0410-docker_decoders.xml`|Container events|
|Jenkins|`0415-jenkins_decoders.xml`|CI/CD|
|GitLab|`0540-gitlab_decoders.xml`|Audit log|
|Azure|`0465-azure_decoders.xml`|Activity log|
|AWS EKS|`0565-aws-eks-authenticator_decoders.xml`|EKS auth|
|Proxmox VE|`0440-proxmox-ve_decoders.xml`|Virtualization|
|VMware|`0360-vmware_decoders.xml`|ESXi / vSphere|
|OpenLDAP|`0185-openldap_decoders.xml`|LDAP directory|

### 3.7 Mail server

|Decoder|File XML|Mục đích|
|---|---|---|
|Postfix|`0220-postfix_decoders.xml`|MTA|
|Sendmail|`0275-sendmail_decoders.xml`|MTA|
|Dovecot|`0085-dovecot_decoders.xml`|IMAP/POP3|
|Exim|`0445-exim_decoders.xml`|MTA|
|Courier|`0080-courier_decoders.xml`|Mail server|
|MailScanner|`0145-mailscanner_decoders.xml`|Email gateway|

### 3.8 Wazuh nội bộ & khác

|Decoder|File XML|Mục đích|
|---|---|---|
|wazuh / ossec|`0005-wazuh_decoders.xml`|Internal events|
|wazuh-api|`0007-wazuh-api_decoders.xml`|REST API log|
|JSON generic|`0006-json_decoders.xml`|Generic JSON log|
|macOS ULS|`0580-macos_decoders.xml`|macOS Unified Logging|
|dpkg|`0379-dpkg_decoders.xml`|Debian package manager|
|samba|`0270-samba_decoders.xml`|File sharing|
|named (BIND)|`0155-named_decoders.xml`|DNS server|
|ntpd|`0175-ntpd_decoders.xml`|NTP daemon|
|local_decoder.xml|`/var/ossec/etc/decoders/local_decoder.xml`|Custom decoder|

---

## 4. Custom decoder

### 4.1 Khi nào cần

- Ứng dụng nội bộ không có decoder sẵn.
- Thiết bị không có trong danh sách hỗ trợ.
- Muốn extract thêm field từ log đã có decoder.

### 4.2 Cách viết

Viết vào `/var/ossec/etc/decoders/local_decoder.xml`:

```xml
<decoder name="myapp">
  <program_name>^myapp</program_name>
</decoder>

<decoder name="myapp-login">
  <parent>myapp</parent>
  <prematch>^LOGIN</prematch>
  <regex>user=(\S+) ip=(\S+)</regex>
  <order>user, srcip</order>
</decoder>
```

### 4.3 Test và deploy

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste log vào stdin, xem `decoder.name` và các field được extract. Sau khi sửa xong:

```bash
sudo systemctl restart wazuh-manager
```

---

## 5. Lệnh kiểm tra nhanh

|Mục đích|Lệnh|
|---|---|
|Xem decoder xử lý event nào|`grep '"decoder"' /var/ossec/logs/alerts/alerts.json \| tail -5`|
|Tìm event 4625 trong archives|`grep '"eventID":"4625"' /var/ossec/logs/archives/archives.json \| tail -1`|
|Test decoder thủ công|`sudo /var/ossec/bin/wazuh-logtest`|
|Lấy raw JSON agent gửi lên|`grep '"eventID":"4625"' /var/ossec/logs/archives/archives.json \| tail -1 \| python3 -c "import sys,json; d=json.load(sys.stdin); print(d['full_log'])"`|
|Danh sách file decoder|`ls /var/ossec/ruleset/decoders/`|
|Xem custom decoder|`cat /var/ossec/etc/decoders/local_decoder.xml`|
|Đếm tổng số decoder|`sudo grep -rh '<decoder name=' /var/ossec/ruleset/decoders/ \| wc -l`|
|Kiểm tra logall bật chưa|`grep logall /var/ossec/etc/ossec.conf`|
|Số dòng archives vs alerts|`wc -l /var/ossec/logs/alerts/alerts.json /var/ossec/logs/archives/archives.json`|