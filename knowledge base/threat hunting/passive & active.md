## 1. Hunt Thụ Động (Passive Threat Hunting)

**Định nghĩa:** Là hình thức săn tìm dựa trên các "dấu vết đã biết" (**Known Unknowns**). Thay vì tự nghĩ ra kịch bản, sử dụng các thông tin tình báo (Threat Intelligence) hoặc các cảnh báo cấp độ thấp để truy vết ngược lại quá khứ.

- **Điểm kích hoạt (Trigger):** Nhận được danh sách **IoC** (Indicators of Compromise) từ bên ngoài hoặc các cảnh báo chưa đủ độ tin cậy từ hệ thống (EDR/SIEM).
- **Tư duy:** "Kẻ địch đã dùng 'con dao' này ở nơi khác, mình hãy kiểm tra xem trong nhà mình có dấu vết của 'con dao' này không."
- **Luồng xử lý:** 
       1. **Tiếp nhận vật chứng (Input):** Nhận một danh sách IoC từ báo cáo Threat Intelligence (ví dụ: danh sách IP của một nhóm APT vừa tấn công một ngân hàng khác).
       2. **Truy vấn lịch sử (Retro-Search):** Chạy query trên SIEM/Log để tìm kiếm các IoC này trong dữ liệu quá khứ (thường là 30-90 ngày).
       3. **Xác định điểm chạm (Match):** Nếu có kết quả trùng khớp (Match), xác định máy tính (Endpoint) nào đã liên lạc với IP đó.
       4. *Dựng dòng thời gian (Timeline):** Xâu chuỗi các sự kiện xung quanh thời điểm đó để tìm nguyên nhân gốc rễ (Root Cause).

> **Ví dụ thực tế:**
> Một báo cáo bảo mật cho biết nhóm hacker APT28 đang sử dụng địa chỉ IP `194.x.x.x` để điều khiển mã độc. Ta thực hiện **Passive Hunt** bằng cách quét lại toàn bộ Log Firewall trong 30 ngày qua. Phát hiện một máy chủ Web trong mạng nội bộ đã kết nối tới IP này vào lúc 2 giờ sáng tuần trước. Từ đó, điều tra sâu hơn để biết mã độc đã vào bằng con đường nào.

---
## 2. Hunt Chủ Động (Active Threat Hunting)

**Định nghĩa:** Đây là đỉnh cao của săn tìm mối đe dọa, dựa trên **Giả thuyết** (**Unknown Unknowns**). Ta không đợi báo cáo, không đợi cảnh báo. Ta chủ động đi tìm những hành vi bất thường mà các công cụ bảo mật tự động đã bỏ sót.

- **Điểm kích hoạt (Trigger):** Một giả thuyết tự xây dựng dựa trên kiến thức về **TTPs** (Tactics, Techniques, and Procedures) hoặc mô hình **MITRE ATT&CK**.
- **Tư duy:** "Hệ thống trông có vẻ ổn, nhưng nếu tôi là hacker, tôi sẽ lẩn trốn trong tiến trình hệ thống này. Hãy để tôi kiểm tra xem có ai đang làm việc đó không."
- **Luồng xử lý:**
      1. **Đặt giả thuyết (Hypothesis):** Dựa trên mô hình MITRE ATT&CK. Ví dụ: _"Tôi nghi ngờ hacker đang dùng kỹ thuật 'Process Injection' để lẩn trốn trong tiến trình trình duyệt."_
      2. **Thu thập dữ liệu (Telemetry):** Tập trung vào các log chi tiết như Sysmon (Windows) hoặc Auditd (Linux) để thấy được các hành vi sâu bên trong hệ điều hành.
      3. **Phân tích bất thường (Analytics):** Sử dụng kỹ thuật **Stacking** (đếm số lần xuất hiện). Ví dụ: Trong 1000 máy, có 999 máy chạy `chrome.exe` từ thư mục chuẩn, chỉ có 1 máy chạy từ thư mục `Temp` $\rightarrow$ Đây là mục tiêu cần điều tra.
      4. **Xác nhận và Củng cố:** Nếu phát hiện tấn công, chuyển sang IR. Sau đó, viết thêm Rule mới cho SIEM để sau này hệ thống tự bắt được kỹ thuật này.
        

> **Ví dụ thực tế:**
>  Đặt giả thuyết: _"Kẻ tấn công có thể đang lạm dụng các tiến trình hợp lệ của Windows (LOLBins) để tải mã độc nhằm tránh bị Antivirus phát hiện."_
> 
> Chủ động vào SIEM và query tất cả các dòng lệnh có chứa `certutil.exe` đi kèm với tham số `-urlcache` và `-split`. Kết quả cho thấy một máy tính kế toán đang dùng lệnh này để tải một file `.txt` từ một trang web lạ. Đây là hành vi cực kỳ đáng nghi dù Antivirus không hề báo đỏ. Ta đã phát hiện ra một cuộc tấn công "Fileless" nhờ việc chủ động đi tìm.

---
## 3. Bảng so sánh tổng hợp

| **Đặc điểm**        | **Hunt Thụ Động (Passive)**         | **Hunt Chủ Động (Active)**                       |
| ------------------- | ----------------------------------- | ------------------------------------------------ |
| **Dựa trên**        | Indicators of Compromise (**IoC**)  | Tactics, Techniques, & Procedures (**TTPs**)     |
| **Trọng tâm**       | Dữ liệu quá khứ (Historical Data)   | Hành vi và Giả thuyết (Behavior & Hypothesis)    |
| **Trạng thái SIEM** | Có dấu hiệu hoặc thông tin từ trước | **Hoàn toàn im lặng**                            |
| **Mục tiêu**        | Xác nhận và khoanh vùng sự cố       | Phát hiện kẻ địch đang nằm vùng (**Dwell time**) |
| **Công cụ chính**   | Log Search, Threat Intel Feeds      | EDR Query, Behavior Analytics, AI/ML             |
