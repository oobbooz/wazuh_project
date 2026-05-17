*tham khảo thêm: https://attack.mitre.org/*
## 1. Tactic = “MỤC TIÊU”
Hacker đang muốn làm gì?
Ví dụ:
- muốn vào hệ thống → Initial Access
- muốn lấy password → Credential Access
- muốn ở lại → Persistence

| #   | Tactic               | Ý nghĩa (dễ hiểu)       | Hacker đang làm gì?                           |
| --- | -------------------- | ----------------------- | --------------------------------------------- |
| 1   | Reconnaissance       | Trinh sát               | Tìm thông tin mục tiêu (scan, dò IP)          |
| 2   | Resource Development | Chuẩn bị tài nguyên     | Tạo tool, domain, server tấn công             |
| 3   | Initial Access       | Xâm nhập ban đầu        | Vào hệ thống (phishing, exploit, brute force) |
| 4   | Execution            | Thực thi                | Chạy code trên máy nạn nhân                   |
| 5   | Persistence          | Duy trì truy cập        | Cài backdoor, webshell                        |
| 6   | Privilege Escalation | Nâng quyền              | User → root/admin                             |
| 7   | Defense Evasion      | Né phòng thủ            | Tránh AV, xóa log                             |
| 8   | Credential Access    | Lấy thông tin đăng nhập | Brute force, dump password                    |
| 9   | Discovery            | Khám phá hệ thống       | Xem mạng, user, file, process                 |
| 10  | Lateral Movement     | Di chuyển nội bộ        | Sang máy khác trong network                   |
| 11  | Collection           | Thu thập dữ liệu        | Lấy file, database                            |
| 12  | Command and Control  | Điều khiển từ xa        | Kết nối C2, reverse shell                     |
| 13  | Exfiltration         | Đánh cắp dữ liệu        | Gửi dữ liệu ra ngoài                          |
| 14  | Impact               | Gây thiệt hại           | Encrypt, xóa data, ransomware                 |
## 2. Technique = “CÁCH LÀM”
Hacker làm bằng cách nào?
Ví dụ:
- brute force → T1110
- exploit web → T1190
- webshell → T1505.003
## 3. Procedure = “LÀM CỤ THỂ RA SAO”
Tool / command thật
Ví dụ: `hydra -l root -P pass.txt ssh://target`

---
```
TTP (hành vi thật)
  ↓
MITRE ATT&CK (bảng phân loại & đặt tên)
```