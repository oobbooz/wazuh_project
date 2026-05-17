## Security Log là gì?

- Security Log là một trong 3 log chính của Windows, nằm tại:   **Event Viewer → Windows Logs → Security**  
- File vật lý:  **`C:\Windows\System32\winevt\Logs\Security.evtx`**  
- Khác với System Log và Application Log, Security Log chỉ ghi khi được cấu hình qua Audit Policy. 
- Không bật Audit Policy → Security Log trống.

## 9 Category của Audit Policy

|Category|Cover gì|Sinh ra khi nào|
|---|---|---|
|Audit Logon Events|Login/logoff trực tiếp trên máy|User đăng nhập, đăng xuất, RDP, unlock màn hình|
|Audit Account Logon Events|Xác thực tài khoản|Domain account được xác thực trên DC, local account xác thực trên chính máy|
|Audit Account Management|Thay đổi tài khoản và group|Tạo/xóa user, đổi mật khẩu, thêm/xóa khỏi group|
|Audit Directory Service Access|Truy cập AD object|User truy cập object trong Active Directory có SACL|
|Audit Object Access|Truy cập file, folder, registry, printer|User đọc/ghi/xóa object có SACL được cấu hình|
|Audit Policy Change|Thay đổi audit policy, user rights|Admin thay đổi policy, gán/thu hồi quyền|
|Audit Privilege Use|Dùng user right đặc biệt|User thực thi privilege như SeDebugPrivilege, SeBackupPrivilege|
|Audit Process Tracking|Tạo/kết thúc process|Bất kỳ process nào được tạo hoặc kết thúc trên máy|
|Audit System Events|Sự kiện ảnh hưởng hệ thống|Restart, shutdown, xóa log, đổi giờ hệ thống|

## Sinh ra khi nào — chi tiết

### Nhóm 1: Logon/Logoff — Audit Logon Events ≠ Audit Account Logon Events

|Tình huống|Audit Logon Events|Audit Account Logon|
|---|---|---|
|Domain account login vào máy A|Ghi trên **Máy A** (nơi login)|Ghi trên **DC** (nơi xác thực)|
|Local account login vào máy A|Ghi trên **Máy A**|Ghi trên **Máy A** (cùng một chỗ)|

### Nhóm 3: Object Access — phải bật 2 lớp

| Lớp   | Cấu hình                                                                | Ghi chú                                               |
| ----- | ----------------------------------------------------------------------- | ----------------------------------------------------- |
| Lớp 1 | Bật "Audit Object Access" trong Audit Policy                            | Điều kiện cần                                         |
| Lớp 2 | Cấu hình SACL (System Access Control List) trên từng file/folder cụ thể | Điều kiện đủ — thiếu một trong hai → không có log nào |

## Event ID quan trọng — Logon/Logoff

|Event ID|Sự kiện|Ghi chú|
|---|---|---|
|4624|Login thành công|Field quan trọng nhất: LogonType|
|4625|Login thất bại|Nhiều lần liên tiếp = brute force|
|4634|Logoff hoàn tất|Hệ thống ghi nhận|
|4647|User chủ động logout|User tự bấm Sign out|
|4648|Login bằng explicit credential|RunAs, lateral movement|
|4779|Ngắt RDP không logout|Session vẫn còn trên server|

## Logon Type — field quan trọng trong 4624

|Type|Tên|Đánh giá|
|---|---|---|
|2|Interactive|Bình thường client, đáng ngờ trên server|
|3|Network (SMB)|Phổ biến — xem IP nguồn|
|4|Batch|Bình thường nếu task đã biết|
|5|Service|Bình thường|
|7|Unlock|Bình thường|
|8|NetworkCleartext|Luôn đáng ngờ — password gần như plaintext|
|9|NewCredentials|Cần xem — RunAs /netonly, lateral movement|
|10|RemoteInteractive (RDP)|Bình thường với admin, đáng ngờ từ IP lạ|
|11|CachedInteractive|Bình thường khi offline|

## Event ID — Account Management

|Event ID|Sự kiện|SOC note|
|---|---|---|
|4720|Tạo user account mới|Rất nhạy cảm trên server|
|4722|User account được enable||
|4723|User đổi mật khẩu||
|4724|Admin reset mật khẩu user||
|4725|User account bị disable|Attacker disable account để gây gián đoạn|
|4726|User account bị xóa||
|4728|Thêm user vào global security group|Privilege escalation — thêm vào Administrators|
|4732|Thêm user vào local security group|Tương tự 4728|
|4738|User account bị thay đổi||
|4740|Account bị lock out|Brute force đang xảy ra|
|4756|Thêm user vào universal group|Domain-wide permission|

## Event ID — Object Access

|Event ID|Sự kiện|SOC note|
|---|---|---|
|560|Truy cập thành công vào object|Xem ObjectName + AccessMask|
|562|Handle đến object bị đóng|Kết thúc phiên truy cập|
|563|Mở object với ý định xóa|FILE_DELETE_ON_CLOSE|
|564|Object được bảo vệ bị xóa|Đáng ngờ nếu file quan trọng|
|567|Permission trên handle được dùng|Read/Write/Delete thực sự xảy ra|

## Event ID — Policy Change

|Event ID|Sự kiện|SOC note|
|---|---|---|
|608|User right được gán|Ai được thêm quyền gì|
|609|User right bị thu hồi||
|612|Audit policy bị thay đổi|Cực kỳ quan trọng — attacker tắt logging|
|617|Kerberos policy thay đổi|Nhạy cảm trên DC|
|621|System access được cấp||

## Event ID — Privilege Use

|Event ID|Sự kiện|SOC note|
|---|---|---|
|576|Privilege thêm vào access token|Xảy ra khi login|
|577|User dùng privileged system service|Privilege thực sự được dùng|
|578|Privilege dùng trên handle đang mở||

7 privilege không được audit dù đã bật policy (phải bật `FullPrivilegeAuditing` riêng): Bypass traverse checking, Debug programs, Create a token object, Replace process level token, Generate security audits, Back up/Restore files and directories.

## Event ID — Process Tracking

|Event ID|Sự kiện|SOC note|
|---|---|---|
|4688|Process tạo mới (modern)|Phải bật thêm CommandLine logging|
|4689|Process kết thúc||
|4697|Service install attempt|Persistence|
|4698|Scheduled task tạo|Persistence — T1053|

Để bật CommandLine trong 4688: `gpedit.msc → Computer Configuration → Administrative Templates → System → Audit Process Creation → "Include command line in process creation events" → Enabled`

## Event ID — System Events

|Event ID|Sự kiện|SOC note|
|---|---|---|
|512|Windows boot|Baseline|
|513|Windows shutdown||
|516|Buffer security event bị đầy — log bị mất|Attacker có thể cố tình gây ra|
|517|Security Log bị xóa|Dấu hiệu rõ ràng của attacker|
|520|Giờ hệ thống bị thay đổi|Anti-forensics|

## Field cốt lõi — System fields (metadata chung)

|Field|Ý nghĩa|
|---|---|
|EventID|Loại sự kiện|
|TimeCreated|Thời điểm xảy ra — cực kỳ quan trọng cho timeline|
|Computer|Máy nào sinh ra log|
|Channel|Luôn là "Security"|
|Level|Information / Warning / Error|

## Field cốt lõi — EventData fields (nội dung cụ thể)

|Field|Xuất hiện trong|Ý nghĩa|
|---|---|---|
|SubjectUserName|Hầu hết event|Account thực hiện hành động|
|SubjectDomainName|Hầu hết event|Domain của Subject|
|TargetUserName|Logon, account management|Account bị tác động hoặc đang login|
|LogonType|4624, 4625|Cách login — xem bảng Logon Type|
|IpAddress|4624, 4625|IP nguồn — quan trọng nhất để trace attacker|
|WorkstationName|4624, 4625|Tên máy nguồn|
|ProcessName|4688, 4689|Tên process|
|CommandLine|4688|Command line đầy đủ — chỉ có khi bật thêm|
|ParentProcessName|4688|Process cha — detect spawn bất thường|
|ObjectName|4663, 560|File/folder/registry key nào bị truy cập|
|AccessMask|4663, 560|Loại access — Read (0x1), Write (0x2), Delete (0x10000)|
|ServiceName|4697, 7045|Tên service mới|
|ServiceFileName|4697|Path của service executable|

## Use case SOC — pattern detect từ Security Log

|Pattern|Event ID cần xem|Dấu hiệu|
|---|---|---|
|Brute force|4625 → 4624|Nhiều 4625 liên tiếp từ cùng 1 IP trong vài giây, sau đó 4624 từ IP đó|
|Lateral movement|4624 LogonType 3|IpAddress = IP máy nội bộ khác (không phải DC), TargetUserName = account cao quyền, thời điểm bất thường|
|Pass-the-Hash|4624 LogonType 3|Không có 4625 nào trước đó từ IP đó, TargetUserName = Administrator|
|Backdoor account|4720 → 4728|SubjectUserName không phải IT admin, thời điểm ngoài giờ làm việc|
|Anti-forensics|517, 612, 520|Security Log bị xóa, audit policy bị tắt, giờ hệ thống bị đổi → lý do phải forward log về SIEM realtime|
|Privilege escalation|577|SeDebugPrivilege, SubjectUserName = user thường (không phải SYSTEM)|

## Tóm tắt — 3 category mặc định tắt cần bật ngay

|Category|Setting|Ghi chú thêm|
|---|---|---|
|Audit Process Tracking|Success|+ bật CommandLine logging|
|Audit Privilege Use|Success + Failure||
|Audit Object Access|Success + Failure|+ cấu hình SACL từng object|

## Event ID tối thiểu phải thuộc

|Event ID|Ý nghĩa|Cần xem gì|
|---|---|---|
|4624|Login OK|LogonType + IP + thời điểm|
|4625|Login fail|Nhiều lần = brute force|
|4648|Explicit credential|RunAs, lateral movement|
|4688|Process tạo|CommandLine + ParentProcess|
|4698|Scheduled task|Persistence|
|4720|Tạo user|Backdoor account|
|4728|Thêm vào group|Privilege escalation|
|517|Xóa log|Attacker xóa dấu vết|
|612|Đổi audit policy|Attacker tắt logging|