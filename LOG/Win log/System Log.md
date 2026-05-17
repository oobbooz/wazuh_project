## System Log là gì?

System Log ghi lại các system event do Windows và Windows system services gửi, được phân loại là Error, Warning, hoặc Information.

Khác hoàn toàn với Security Log:

```
Security Log  ←  Audit Policy kiểm soát — phải bật mới có
System Log    ←  Windows kernel/components tự ghi — luôn có dữ liệu
```

**Vị trí:**

```
Event Viewer → Windows Logs → System
File vật lý: C:\Windows\System32\winevt\Logs\System.evtx
```

---

## Ai ghi vào System Log?

System Log chứa các Event Sources là driver và system component:

|Event Source|Vai trò|
|---|---|
|disk|Disk driver|
|Service Control Manager|Quản lý service|
|Kernel-Power|Power events|
|Kernel-General|General kernel|
|Tcpip|TCP/IP stack|
|Ntfs|File system driver|

Device drivers phải ghi vào System log — đây là quy tắc Microsoft quy định, không phải tùy chọn.

---

## System Log cover gì — sự kiện cụ thể

### Nhóm 1: Service events

Sinh ra khi Service Control Manager thao tác với service:

|Event ID|Sự kiện|Event Type|
|---|---|---|
|**7045**|Service mới được cài đặt|Information|
|**7034**|Service bị crash bất ngờ|Error|
|**7035**|Service nhận lệnh start/stop|Information|
|**7036**|Service thay đổi trạng thái (running/stopped)|Information|
|**7040**|Start type của service bị thay đổi|Information|

### Nhóm 2: Driver và hardware events

Sinh ra khi driver gặp vấn đề với phần cứng:

> Driver gặp disk controller timeout, power failure ở parallel port, data error từ network card → ghi vào System Log để admin chẩn đoán hardware.

|Event ID|Sự kiện|Event Type|
|---|---|---|
|**41**|Kernel-Power: hệ thống shutdown không sạch (unexpected reboot)|Critical|
|**6008**|Unexpected shutdown trước đó|Error|
|**1**|Disk driver: lỗi I/O|Error/Warning|
|**51**|Disk: bad sector warning|Warning|
|**55**|NTFS: file system corruption|Error|

### Nhóm 3: System startup/shutdown

Sinh ra khi Windows khởi động hoặc tắt máy:

|Event ID|Sự kiện|Event Type|
|---|---|---|
|**6005**|Event Log service started = Windows đang boot|Information|
|**6006**|Event Log service stopped = Windows shutdown bình thường|Information|
|**6008**|Previous shutdown unexpected = crash/force shutdown|Error|
|**6009**|Windows version khi boot|Information|

### Nhóm 4: Resource problems

> "Logging a Warning event when memory allocation fails can help indicate the cause of a low-memory situation" — Microsoft Logging Guidelines

|Sự kiện|Event Type|Ý nghĩa|
|---|---|---|
|Memory allocation fail|Warning|Low memory condition|
|Disk bad sector — recoverable|Warning|Disk sắp hỏng|
|Disk bad sector — unrecoverable|Error|Disk đã hỏng|

---

## Event Type trong System Log

System Log chỉ dùng 3 trong 5 loại Event Type:

|Type|Khi nào|Ví dụ|
|---|---|---|
|**Error**|Sự kiện nghiêm trọng — mất dữ liệu hoặc mất chức năng|Service không khởi động được khi boot|
|**Warning**|Chưa nghiêm trọng nhưng có thể gây vấn đề sau|Disk space thấp, bad sector lần đầu|
|**Information**|Hoạt động thành công bình thường|Service start thành công, driver load OK|

**Không có** Success Audit / Failure Audit trong System Log — hai loại đó chỉ có trong Security Log.

---

## Field cốt lõi

System Log dùng cùng cấu trúc EVENTLOGRECORD — nhưng các field EventData khác nhau theo từng Event Source.

**Common fields — luôn có:**

|Field|Ý nghĩa|SOC note|
|---|---|---|
|**EventID**|Loại sự kiện|Tra cứu theo ID|
|**TimeCreated**|Thời điểm xảy ra|Dùng để build timeline|
|**Level**|Error / Warning / Information / Critical|Filter theo mức độ nghiêm trọng|
|**Provider/Source**|Component nào sinh log|Biết ngay ai ghi — SCM, Kernel, disk driver|
|**Computer**|Tên máy|Trong môi trường nhiều máy|
|**Message**|Nội dung mô tả đầy đủ|Quan trọng nhất — đọc để hiểu sự kiện|

**Event-specific fields quan trọng nhất:**

|Field|Xuất hiện trong|Ý nghĩa|
|---|---|---|
|**ServiceName**|7045, 7034, 7036|Tên service liên quan|
|**ServiceFileName**|7045|Path của file thực thi service|
|**ServiceType**|7045|Kernel driver hay user-mode service|
|**ImagePath**|7045|Đường dẫn đầy đủ executable|
|**AccountName**|7045|Account service chạy dưới|
|**param1/param2**|7036|Trạng thái mới (running/stopped)|

---

## So sánh cấu trúc với Security Log

||Security Log|System Log|
|---|---|---|
|Ai kiểm soát|Audit Policy|Windows kernel/SCM tự động|
|Cần cấu hình|Có — phải bật Audit Policy|Không — luôn có dữ liệu|
|Event Type|Error, Warning, Info, Success/Failure Audit|Error, Warning, Information (không có Audit)|
|Nguồn ghi|LSA (Local Security Authority)|Driver, SCM, Kernel components|
|File vật lý|Security.evtx|System.evtx|

---

## Use case SOC

### Detect persistence qua service — quan trọng nhất

Event ID **7045** là event SOC cần quan tâm nhất trong System Log:

```
Pattern bình thường:
7045 → ServiceName = "Windows Update"
       ServiceFileName = "C:\Windows\System32\wuauserv.dll"
       ServiceType = "share process"
       AccountName = "LocalSystem"

Pattern đáng ngờ:
7045 → ServiceName = "svchosts"               ← tên gần giống service thật
       ServiceFileName = "C:\Users\Public\evil.exe"  ← path bất thường
       ServiceType = "kernel driver"           ← kernel level = quyền cao nhất
       AccountName = "LocalSystem"
```

Kết hợp với Security Log để tăng độ chính xác:

```
System 7045 (service mới cài)
    + Security 4697 (service install — từ Security channel)
    → Có cả SubjectUserName = biết account nào cài service
```

### Detect unexpected reboot — dấu hiệu hệ thống bị can thiệp

```
Event 41 (Kernel-Power: unexpected shutdown)
hoặc Event 6008 (previous shutdown unexpected)
    → Không có Event 6006 trước đó (shutdown bình thường)
    = Crash, forced reboot, hoặc attacker reboot sau khi cài rootkit
```

### Detect service bị tắt để bypass security

```
Pattern: Attacker tắt AV/EDR service để bypass detection
7036: Windows Defender → stopped
7036: Wazuh → stopped
    → Sau đó không có alert nào nữa
    = Attacker đã tắt monitoring trước khi hành động
```

### Detect disk failure — liên quan đến data destruction

```
Event 51 (Warning: disk error recoverable) → theo dõi
Event 7  (Error: disk I/O unrecoverable)   → nghiêm trọng
    Nhiều event này trong thời gian ngắn
    = Có thể là ransomware đang encrypt làm I/O tăng đột biến
      hoặc disk thật sự đang hỏng
    → Cần correlate với file access log
```

---

## Cấu hình Wazuh để thu System Log

Trong `ossec.conf` trên Windows agent:

xml

```xml
<localfile>
  <location>System</location>
  <log_format>eventchannel</log_format>
  <query>
    Event/System[
      EventID=7045 or    <!-- service mới cài — persistence -->
      EventID=7034 or    <!-- service crash -->
      EventID=7036 or    <!-- service state change -->
      EventID=6008 or    <!-- unexpected shutdown -->
      EventID=41         <!-- kernel power — crash -->
    ]
  </query>
</localfile>
```

Dùng `<query>` để filter tại agent — chỉ đẩy về những EventID có giá trị SOC, tránh đẩy toàn bộ System Log (rất nhiều noise từ driver thông thường).

---

## Tóm tắt để thuộc

**System Log = nơi Windows kernel và system components tự ghi — không cần Audit Policy.**

Event ID tối thiểu phải thuộc trong System Log:

|Event ID|Sự kiện|Liên quan|
|---|---|---|
|**7045**|Service mới cài|Persistence — quan trọng nhất|
|**7034**|Service crash|Có thể bị kill bởi attacker|
|**7036**|Service thay đổi state|AV/EDR bị tắt|
|**6005**|Windows boot|Baseline|
|**6006**|Windows shutdown bình thường|Baseline|
|**6008**|Unexpected shutdown|Crash, forced reboot|
|**41**|Kernel-Power crash|Cùng nhóm với 6008|

**Điểm khác biệt then chốt với Security Log:**

- System Log **luôn có dữ liệu** dù không cấu hình gì
- Không có Success/Failure Audit — chỉ có Error/Warning/Information
- Field quan trọng nhất là **ServiceName + ServiceFileName** trong 7045