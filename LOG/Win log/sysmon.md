# Sysmon 

## Sysmon là gì?

System Monitor (Sysmon) là một optional Windows feature trên Windows 11 và Windows Server 2025 — khi được bật, nó tồn tại xuyên suốt các lần reboot để monitor và ghi log system activity vào Windows Event Log. Sysmon cung cấp thông tin chi tiết về process creation, network connection, và file creation time change events. [Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/overview)

Sysmon không phân tích các event nó sinh ra, và cũng không cố gắng ẩn sự hiện diện của mình khỏi attacker. [Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/overview)

**Quan trọng — Sysmon không phải một loại log:**

```
Sysmon = Tool (Windows system service + device driver)
         ↓ sau khi cài/bật
         Tạo ra channel log tại:
         Applications and Services Logs
         → Microsoft → Windows → Sysmon → Operational
```

**Vị trí log:**

```
Event Viewer → Applications and Services Logs
             → Microsoft → Windows → Sysmon → Operational
File vật lý: C:\Windows\System32\winevt\Logs\
             Microsoft-Windows-Sysmon%4Operational.evtx
```

---

---

## Sysmon capabilities — làm được những gì

Sysmon bao gồm các khả năng sau:
- ghi log process creation với full command line cho cả process hiện tại và parent process
- ghi hash của process image file dùng SHA1 (mặc định), MD5, SHA256 hoặc IMPHASH
- có thể dùng nhiều hash cùng lúc
- bao gồm process GUID trong process create event để correlation dù Windows tái dùng process ID
- bao gồm session GUID trong mỗi event để correlation các event trong cùng logon session
- ghi log loading của driver hoặc DLL với signature và hash
- ghi log khi disk hoặc volume được mở với raw read access
- tùy chọn ghi log network connection bao gồm source process, IP address, port number, hostname
- phát hiện thay đổi file creation time — kỹ thuật malware hay dùng để xóa dấu vết
- tự động reload config nếu thay đổi trong registry
- rule filtering để include hoặc exclude event động
- sinh event từ sớm trong quá trình boot để bắt được activity của kernel-mode malware. 

---

## Sysmon cover gì — sự kiện theo nhóm

Sysmon events có thể được nhóm theo loại system behavior chúng mô tả. 

### Nhóm 1: Process Lifecycle — vòng đời process

Các event này mô tả cách process khởi động, chạy, và tương tác. 

| Event ID | Tên                | Mô tả                                                  | Mặc định    |
| -------- | ------------------ | ------------------------------------------------------ | ----------- |
| **1**    | Process Create     | Process mới được tạo — full command line, hash, parent | Bật         |
| **5**    | Process Terminated | Process kết thúc                                       | Bật         |
| **10**   | Process Access     | Một process mở process khác                            | Bật (noisy) |
| **8**    | CreateRemoteThread | Process tạo thread trong process khác                  | Bật         |
| **25**   | Process Tampering  | Phát hiện process hollowing, herpaderping              | Bật         |

### Nhóm 2: Network và DNS — kết nối mạng

Các event này mô tả cách process tương tác với mạng. 

|Event ID|Tên|Mô tả|Mặc định|
|---|---|---|---|
|**3**|Network Connect|TCP/UDP connection với process context|**Tắt** — volume cao|
|**22**|DNS Query|DNS query từ process, kể cả khi fail|Bật|

### Nhóm 3: File System — hoạt động file

Các event này mô tả file creation, modification, và deletion. 

|Event ID|Tên|Mô tả|Mặc định|
|---|---|---|---|
|**11**|File Create|File được tạo hoặc ghi đè|Bật|
|**2**|File Creation Time Change|Timestamp của file bị thay đổi|Bật|
|**23**|File Delete (archived)|File bị xóa — lưu bản copy vào ArchiveDirectory|Tắt|
|**26**|File Delete Detected|File bị xóa — không lưu copy|Tắt|
|**15**|File Create Stream Hash|Named alternate data stream — Zone.Identifier|Bật|
|**27**|File Block Executable|Chặn tạo file PE executable|Tắt|
|**28**|File Block Shredding|Chặn file shredding từ SDelete|Tắt|
|**29**|File Executable Detected|File PE mới được tạo|Tắt|

### Nhóm 4: Module và Driver Loading — load code vào memory

Các event này mô tả cách code được đưa vào memory. 

|Event ID|Tên|Mô tả|Mặc định|
|---|---|---|---|
|**7**|Image Load|DLL hoặc executable được load vào process|**Tắt** — volume rất cao|
|**6**|Driver Load|Kernel driver được load — kèm signature và hash|Bật|

### Nhóm 5: Configuration, Persistence, IPC

Các event này mô tả thay đổi cấu hình hệ thống và interprocess communication. 

|Event ID|Tên|Mô tả|Mặc định|
|---|---|---|---|
|**12**|Registry Create/Delete|Registry key hoặc value tạo/xóa|Bật|
|**13**|Registry Set Value|Registry value bị set — ghi lại giá trị DWORD/QWORD|Bật|
|**14**|Registry Rename|Registry key hoặc value đổi tên|Bật|
|**17**|Pipe Created|Named pipe được tạo|Bật|
|**18**|Pipe Connected|Kết nối đến named pipe|Bật|
|**19**|WMI Filter|WMI event filter được đăng ký|Bật|
|**20**|WMI Consumer|WMI event consumer được đăng ký|Bật|
|**21**|WMI Binding|WMI filter-consumer binding|Bật|
|**24**|Clipboard Change|Clipboard content thay đổi|Tắt|

### Nhóm 6: Sysmon Service — trạng thái Sysmon

|Event ID|Tên|Mô tả|Mặc định|
|---|---|---|---|
|**4**|Service State Change|Sysmon service start/stop|Bật|
|**16**|Configuration Change|Sysmon config được update|Bật|
|**255**|Error|Lỗi nội bộ của Sysmon|Bật|

---

## Event Type trong Sysmon

Sysmon chỉ dùng 1 loại Event Type duy nhất:

|Type|Ghi chú|
|---|---|
|**Information**|Tất cả Sysmon event đều là Information|

Không có Error, Warning, hay Audit. Sysmon event mang tính observational, không phải interpretive — không có event nào tự chỉ ra malicious activity. 

---

## Field cốt lõi

**Common fields — có trong mọi Sysmon event:**

|Field|Ý nghĩa|SOC note|
|---|---|---|
|**EventID**|Loại sự kiện|1-29 + 255|
|**UtcTime**|Thời điểm xảy ra (UTC)|Luôn UTC — chú ý timezone khi correlate|
|**ProcessGuid**|GUID duy nhất của process|Dùng để track process dù PID bị Windows tái dụng|
|**ProcessId**|PID của process|Kết hợp với ProcessGuid để chắc chắn|
|**Image**|Full path của process|`C:\Windows\System32\powershell.exe`|
|**User**|Account chạy process|`DOMAIN\username` hoặc `NT AUTHORITY\SYSTEM`|
|**RuleName**|Tên rule Sysmon match|Dùng để biết rule nào trigger event|

**Event-specific fields — quan trọng nhất theo EventID:**

|Field|EventID|Ý nghĩa|SOC note|
|---|---|---|---|
|**CommandLine**|1|Toàn bộ command line|Quan trọng nhất — detect encoded PS, lolbas|
|**ParentImage**|1|Process cha|Detect spawn bất thường|
|**ParentCommandLine**|1|Command line của process cha|Context đầy đủ hơn|
|**OriginalFileName**|1|Tên file gốc trong PE header|Detect process rename|
|**Hashes**|1, 6, 7|MD5, SHA256, IMPHASH|Lookup VirusTotal|
|**IntegrityLevel**|1|Low/Medium/High/System|High/System ngoài giờ = đáng ngờ|
|**DestinationIp**|3|IP đích của connection|Detect C2|
|**DestinationPort**|3|Port đích|4444, 1337 = common C2|
|**DestinationHostname**|3|Hostname đích||
|**QueryName**|22|Domain được query|Detect DNS C2|
|**QueryResults**|22|IP trả về từ DNS||
|**TargetFilename**|11|File được tạo|Path trong Temp/AppData = đáng ngờ|
|**TargetObject**|12/13/14|Registry key/value|Run key = persistence|
|**Details**|13|Giá trị được ghi vào registry||
|**ImageLoaded**|7|DLL được load||
|**Signed**|7|DLL có chữ ký không|false = đáng ngờ|
|**SignatureStatus**|7|Trạng thái chữ ký|Valid/Unavailable/Revoked|
|**GrantedAccess**|10|Loại access vào process|0x1010 = LSASS dump|
|**CallTrace**|10|Stack trace của access|Detect Mimikatz patterns|

---

## So sánh Sysmon với Windows Logs mặc định

|Thông tin cần biết|Security 4688|Sysmon Event 1|
|---|---|---|
|Tên process|Có|Có|
|Full path|Có|Có|
|CommandLine|Cần bật thêm|Tự động|
|Parent process|Có|Có + ParentCommandLine|
|Hash của file|Không|MD5, SHA256, IMPHASH|
|OriginalFileName|Không|Có|
|IntegrityLevel|Không|Có|
|ProcessGuid|Không|Có — cross-event correlation|
|Network connection|Không|Event 3|
|DNS query|Không|Event 22|
|DLL load|Không|Event 7|
|File creation|Cần SACL|Event 11 tự động|
|Registry change|Cần SACL|Event 12/13 tự động|
|Process injection|Không|Event 8, 10, 25|

---

## Use case SOC — các pattern quan trọng

### Detect Office spawn PowerShell — macro malware

```
Sysmon Event 1:
  Image:             powershell.exe
  CommandLine:       powershell -EncodedCommand JABjAGwAaQBlAG4AdA...
  ParentImage:       C:\Program Files\Microsoft Office\...\WINWORD.EXE
  ParentCommandLine: "WINWORD.EXE" /n "invoice.docx"
  IntegrityLevel:    Medium

= Word macro spawn PowerShell với encoded command
→ T1059.001 + T1566.001
→ Correlate Event 3 sau đó xem kết nối về đâu
```

### Detect process rename để bypass detection

```
Sysmon Event 1:
  Image:            C:\Temp\svchost.exe     ← tên trông hợp lệ
  OriginalFileName: mimikatz.exe            ← tên thật trong PE header
  Hashes:           SHA256=abc123...        ← lookup = known malware
  CommandLine:      svchost.exe sekurlsa::logonpasswords

= Process bị rename nhưng OriginalFileName lộ tên thật
→ T1036.003 Masquerading
```

### Detect LSASS credential dump

```
Sysmon Event 10:
  SourceImage:   C:\Temp\evil.exe
  TargetImage:   C:\Windows\System32\lsass.exe
  GrantedAccess: 0x1010          ← PROCESS_VM_READ + PROCESS_QUERY_INFO
  CallTrace:     C:\...\dbghelp.dll  ← MiniDump pattern

= Process đang đọc memory của LSASS = credential dump
→ T1003.001
→ Correlate Event 1 để biết evil.exe từ đâu
```

### Detect DNS-based C2

```
Sysmon Event 22:
  Image:       C:\Windows\System32\cmd.exe
  QueryName:   update.evil-domain.com
  QueryResults: 185.220.x.x

= cmd.exe query DNS cho domain lạ
→ Không phải browser → đáng ngờ
→ Correlate Event 3 xem có connection thực sự không
→ Lookup domain trên VirusTotal/ThreatIntel
```

### Detect WMI persistence

```
Sysmon Event 19: WMI Filter đăng ký
  Name: "WindowsUpdate"
  Query: "SELECT * FROM __InstanceModificationEvent WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 3"

Sysmon Event 20: WMI Consumer đăng ký
  Name: "WindowsUpdate"
  Type: "ActiveScriptEventConsumer"

Sysmon Event 21: WMI Binding
  Consumer: "WindowsUpdate"
  Filter: "WindowsUpdate"

= WMI persistence hoàn chỉnh chạy script lúc 3h sáng
→ T1546.003
```

### Detect timestomping — xóa dấu vết

```
Sysmon Event 2:
  Image:                powershell.exe
  TargetFilename:       C:\Users\Public\evil.exe
  CreationUtcTime:      2020-01-01 00:00:00    ← ngày giả
  PreviousCreationUtcTime: 2025-04-03 03:15:22 ← ngày thật

= Attacker thay đổi timestamp để giả mạo thời gian tạo file
→ T1070.006 — Indicator Removal: Timestomp
```

### Detect lateral movement qua named pipe

```
Sysmon Event 18: Pipe Connected
  Image:     C:\Windows\System32\cmd.exe
  PipeName:  \\.\pipe\MSSE-1234-server

= cmd.exe kết nối named pipe — pattern của Cobalt Strike
→ T1570 — Lateral Tool Transfer
```