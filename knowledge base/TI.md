### 1. Định nghĩa thực tế

**Threat Intelligence** không phải là dữ liệu thô (Logs). Đó là **thông tin đã qua phân tích** về các mối đe dọa, giúp bạn ra quyết định phòng thủ chính xác.
- **Dữ liệu thô:** "IP 45.77.12.34 kết nối vào hệ thống." (Vô nghĩa).
- **Threat Intelligence:** "IP 45.77.12.34 thuộc nhóm APT29, chuyên dùng để thả Malware X vào web server." (Có giá trị hành động).
    
---
### 2. Ba cấp độ Intelligence

1. **Strategic (Chiến lược):** Báo cáo xu hướng, đối tượng mục tiêu (Dành cho Quản lý/CISO).
2. **Operational (Vận hành):** Hiểu kỹ thuật, thói quen tấn công - **TTPs** (Dành cho SOC Team).
3. **Tactical (Chiến thuật):** Các dấu hiệu nhận biết cụ thể - **IOCs** (Dùng cho máy/hệ thống).
    
---
### 3. Các thành phần cốt lõi

- **IOC (Indicator of Compromise):** Dấu vết để lại (IP độc, Domain lừa đảo, File Hash).
- **TTP (Tactics, Techniques, Procedures):** Cách thức hacker hành động (Cách chúng xâm nhập, leo thang đặc quyền).
- **Context (Ngữ cảnh):** Ai tấn công? Mục tiêu là gì? Mức độ nguy hiểm ra sao?
- **Vulnerability Intel:** Thông tin về các lỗ hổng đang bị khai thác thực tế (Exploit in the wild).
    
---
### 4. Mối quan hệ: TI & MITRE ATT&CK

**MITRE ATT&CK** là "cuốn từ điển" để chuẩn hóa TI:
- TI cung cấp thông tin: "Hacker dùng brute force và webshell."
- MITRE mã hóa nó thành: **T1110** (Brute Force) và **T1505.003** (Web Shell).
- **Lợi ích:** Giúp các hệ thống và chuyên gia bảo mật trên toàn thế giới hiểu chung một ngôn ngữ.
    
---
### 5. Ứng dụng trong SOC (Security Operations Center)

- **Detect (Phát hiện):** Tự động so khớp Log với danh sách IOCs độc hại.
- **Predict (Dự đoán):** Dựa vào TTPs để biết sau bước A, hacker thường sẽ làm bước B.
- **Threat Hunting:** Chủ động tìm kiếm dấu vết hacker trong hệ thống dù chưa có cảnh báo.
- **Automation:** Sử dụng chuẩn **STIX/TAXII** để tự động đẩy dữ liệu tình báo vào Firewall/SIEM.

---
### 6. Kim tự tháp "Nỗi đau" (Pyramid of Pain)

- **Thấp (Chặn Hash/IP):** Hacker thay đổi rất nhanh (Dễ làm, hiệu quả thấp).
- **Cao (Chặn TTPs):** Hacker phải thay đổi toàn bộ kỹ năng (Khó làm, hiệu quả cực cao).
![[pyramid-pain.jpg]]

---
```
IOC → phát hiện
TTP → hiểu hành vi
MITRE → chuẩn hóa TTP
Threat Intelligence → tổng hợp tất cả
```
TI
```
IP 45.77.12.34
→ thuộc botnet
→ từng brute force SSH
→ liên quan APT
```