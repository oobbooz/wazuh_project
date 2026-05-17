## Tại sao phải học về log?

Khi một cuộc tấn công xảy ra, câu hỏi đầu tiên của SOC analyst là:

```
- Ai đã vào?
- Vào từ đâu?
- Đã làm gì?
- Khi nào?
- Còn ở đây không?
```

Câu trả lời cho tất cả những câu hỏi đó **chỉ có trong log**. Không có log → không investigate được, dù có công cụ tốt đến đâu.

Đây là lý do GVHD nhấn mạnh từ buổi đầu: **phải hiểu log từ bên trong** — không chỉ biết cách đẩy về SIEM, mà phải biết log đó sinh ra khi nào, trông như thế nào khi bình thường, và khác gì khi bị tấn công.

---

## Windows ghi log ở đâu?

Tất cả log của Windows đều được quản lý bởi một hệ thống duy nhất: **Windows Event Log**.

Mở bằng cách gõ `eventvwr.msc` — bên trong có 2 nhóm lớn:

```
Windows Event Log
│
├── Windows Logs                    ← Nhóm 1 — 5 log cố định
│   ├── Application
│   ├── Security
│   ├── Setup
│   ├── System
│   └── Forwarded Events
│
└── Applications and Services Logs  ← Nhóm 2 — 300-500+ channel, tùy máy
    └── Microsoft
        └── Windows
            ├── PowerShell/Operational
            ├── Windows Defender/Operational
            ├── TaskScheduler/Operational
            ├── Sysmon/Operational    ← chỉ có sau khi cài Sysmon
            └── ...rất nhiều channel khác
```

---

## Nhóm 1 — Windows Logs: 5 log cố định

Đây là nhóm log tồn tại từ **Windows NT 3.1** — tức là gần như mọi máy Windows đều có, không cần cài thêm gì.

| Log                  | Ai ghi                         | Cover gì                                    | Cần cấu hình               |
| -------------------- | ------------------------------ | ------------------------------------------- | -------------------------- |
| **Security**         | LSA (Local Security Authority) | Authentication, account, process, privilege | Có — phải bật Audit Policy |
| **System**           | Windows kernel, SCM, driver    | Service, driver, hardware, boot, shutdown   | Không — tự động            |
| **Application**      | Từng ứng dụng tự ghi           | Crash, error, install của app               | Không — app tự quyết       |
| **Setup**            | Windows Setup components       | Cài OS, Update, Role/Feature                | Không                      |
| **Forwarded Events** | WEF Collector nhận từ máy khác | Log được forward về từ endpoint khác        | Có — cần cấu hình WEF      |

**Điểm quan trọng:**

Security Log là log **quan trọng nhất cho SOC** nhưng lại là log **cần cấu hình nhiều nhất** — mặc định Windows tắt nhiều category cần thiết. Không bật Audit Policy đúng → Security Log trống hoặc thiếu thông tin.

---

## Nhóm 2 — Applications and Services Logs: không cố định

Đây là nhóm log mới hơn, xuất hiện từ **Windows Vista**. Mỗi component, service, hoặc ứng dụng có thể tạo channel log riêng của mình.

Không có con số cố định — chạy lệnh này để xem máy có bao nhiêu:

powershell

```powershell
(Get-WinEvent -ListLog * | Where-Object {
    $_.LogName -notmatch "^(Application|Security|System|Setup|ForwardedEvents)$"
}).Count
```

Mỗi channel có thể có 4 subtype:

|Subtype|Mục đích|Mặc định|
|---|---|---|
|Admin|Sự kiện admin cần xử lý|Thường bật|
|Operational|Theo dõi hoạt động|Thường bật|
|Analytic|Chi tiết, volume cao|**Tắt**|
|Debug|Dành cho developer|**Tắt**|

**Điểm quan trọng:** Nhiều channel quan trọng với SOC **mặc định tắt** — phải biết cái nào cần bật.

---

## Sysmon — tool cài thêm, không phải loại log

Đây là điểm hay nhầm nhất:

```
Sysmon ≠ một loại log

Sysmon = Tool (Windows system service + kernel driver)
         → Sau khi cài, tạo ra channel:
           Microsoft-Windows-Sysmon/Operational
           (nằm trong Applications and Services Logs)
```

Sysmon do Microsoft Sysinternals phát triển — phải cài thêm, không có sẵn trên máy mặc định. Nó chạy ở **kernel mode**, hook trực tiếp vào OS để thu thập những gì Windows Logs thông thường không ghi được: network connection theo process, DNS query, DLL load, process injection.

Không có Sysmon → thiếu telemetry quan trọng nhất để threat hunting.