## I. Bản chất và Tầm quan trọng của Threat Hunting

Threat Hunting không đơn thuần là một công việc kỹ thuật, mà là một **tư duy (mindset)**.
- **Định nghĩa:** Là quá trình chủ động và liên tục tìm kiếm các dấu hiệu độc hại đã lọt qua các lớp phòng thủ (Firewall, IDS, AV).
- **Triết lý "Assume Breach":** Luôn giả định rằng hệ thống **đã bị xâm nhập**. Thay vì đợi chuông báo động, Hunter tự mình đi tìm kẻ địch.
- **Mục tiêu tối thượng:** Rút ngắn **Dwell Time** (thời gian ủ bệnh). Kẻ tấn công ẩn náu càng lâu, thiệt hại càng lớn. Việc phát hiện sớm giúp ngăn chặn cuộc tấn công trước khi nó đạt đến giai đoạn cuối (như mã hóa dữ liệu).
---

| **Đặc điểm**  | **Threat Intelligence (TI)**                       | **SOC Analyst (L1/L2)**                      | **Threat Hunter**                                                       |
| ------------- | -------------------------------------------------- | -------------------------------------------- | ----------------------------------------------------------------------- |
| **Vai trò**   | Cung cấp "hồ sơ kẻ địch".                          | "Cảnh sát tuần tra" 24/7.                    | "Thám tử" điều tra chuyên sâu.                                          |
| **Trọng tâm** | Bên ngoài (hacker là ai, dùng gì?).                | Bên trong (cảnh báo từ SIEM).                | Bên trong (tìm thứ chưa có cảnh báo).                                   |
| **Tính chất** | **Thông tin (Informative):** Cung cấp nguyên liệu. | **Phản ứng (Reactive):** Xử lý khi có Alert. | **Chủ động (Proactive):** Tự tạo giả thuyết để tìm.                     |
| **Ví dụ**     | Biết mã băm (Hash) của một loại malware mới.       | Cách ly máy tính khi SIEM báo có malware.    | Kiểm tra toàn hệ thống xem có malware nào "biến dị" chưa có Hash không. |
**Mối quan hệ:** TI cung cấp "danh sách thú dữ", SOC là "hàng rào báo động", còn Hunter là người vác súng đi lùng sục những con thú đã lẻn qua hàng rào mà chuông chưa kịp kêu.

---
### II. Quá trình
Quá trình săn tìm mối đe dọa mạng thường bao gồm một số bước chính: 
1. **Tạo giả thuyết:** Dựa trên thông tin tình báo về mối đe dọa và hiểu biết về môi trường của tổ chức, những người săn tìm mối đe dọa mạng sẽ xây dựng giả thuyết về các mối đe dọa tiềm ẩn, xem xét các cuộc tấn công trong quá khứ và các mối đe dọa cụ thể trong ngành.   
2. **Thu thập dữ liệu:** Dữ liệu có liên quan từ nhiều nguồn khác nhau, chẳng hạn như nhật ký mạng, dữ liệu đo từ xa tại thiết bị đầu cuối và môi trường đám mây được thu thập để phân tích toàn diện.   
3. **Phân tích dữ liệu:** Thợ săn kiểm tra kỹ lưỡng dữ liệu đã thu thập để xác định các điểm bất thường, mô hình bất thường và hành vi có thể chỉ ra hoạt động độc hại, đôi khi sử dụng công nghệ máy học và mô hình thống kê.   
4. **Điều tra:** Những phát hiện đáng ngờ sẽ được điều tra sâu rộng để xác định xem chúng có phải là mối đe dọa thực sự hay là kết quả báo động giả hay không, đảm bảo phân bổ nguồn lực một cách hiệu quả.   
5. **Phản hồi:** Các mối đe dọa đã được xác nhận sẽ được giải quyết nhanh chóng thông qua các biện pháp ngăn chặn, xóa bỏ và phục hồi để giảm thiểu thiệt hại tiềm ẩn.   
6. **Cải tiến liên tục:** Thông tin chi tiết thu được từ mỗi cuộc săn tìm mối đe dọa chủ động sẽ được sử dụng để tinh chỉnh chính sách bảo mật, nâng cao hệ thống phát hiện mối đe dọa tự động và cải thiện các cuộc săn tìm trong tương lai.
---
## III. Framework: "Kim chỉ nam" cho cuộc săn

### 1. MITRE ATT&CK (Bách khoa toàn thư kỹ thuật)

Giống như một "bảng tuần hoàn" các hành vi của hacker.
- **Ứng dụng:** Hunter dùng nó để đặt giả thuyết. Ví dụ: "Nếu hacker dùng kỹ thuật _Scheduled Task_ để duy trì sự hiện diện, tôi sẽ tìm thấy gì trong Log?"
- **Đánh giá độ bao phủ:** Giúp tổ chức biết mình đã "quét" được bao nhiêu % các kỹ thuật mà hacker hay dùng.
### 2. Cyber Kill Chain (Tiến trình tấn công)

Gồm 7 giai đoạn (Trinh sát -> Vũ khí hóa -> Phát tán -> Khai thác -> Cài đặt -> C2 -> Hành động mục tiêu).
- **Ứng dụng:** Giúp Hunter hiểu kẻ địch đang ở chặng nào. Nếu thấy dấu hiệu ở bước _C2_, nghĩa là tình hình cực kỳ khẩn cấp. Mục tiêu là bẻ gãy Kill Chain càng sớm càng tốt.
----
## IV. Checklist: Săn tìm cái gì? (Artifacts)

- **Logins:** Tài khoản admin đăng nhập lúc 3h sáng? Tài khoản hệ thống (System) lại có hành vi đăng nhập tương tác?
- **Connections:** Máy trạm gửi lượng lớn dữ liệu ra một IP lạ ở nước ngoài? Truy vấn DNS lạ (DNS Tunneling)?
- **Processes:** Tiến trình lạ chạy từ thư mục `C:\Windows\Temp`? Tên tiến trình sai chính tả (vd: `svch0st.exe`)?
- **Persistence:** Các Service mới được cài đặt? Scheduled Task lạ xuất hiện?
- **Changes:** Logs bị xóa đột ngột? Antivirus/EDR bị vô hiệu hóa?