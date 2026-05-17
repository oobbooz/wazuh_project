## auth.log khi bị tấn công brute force.
> 
Apr  7 00:07:11 Client-linux sshd[7221]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.20.129  user=bo
Apr  7 00:07:11 Client-linux sshd[7218]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.20.129  user=bo
Apr  7 00:07:11 Client-linux sshd[7219]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.20.129  user=bo
Apr  7 00:07:11 Client-linux sshd[7220]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.20.129  user=bo
Apr  7 ==00:07:13== Client-linux sshd==7221==: Failed password for bo from 192.168.20.129 port ==52456== ssh2
Apr  7 00:07:13 Client-linux sshd==[7218]:== Failed password for bo from 192.168.20.129 port ==52438== ssh2
Apr  7 00:07:13 Client-linux sshd==[7219]:== Failed password for bo from 192.168.20.129 port ==52444== ssh2
Apr  7 ==00:07:13== Client-linux sshd==[7220]:== Failed password for bo from 192.168.20.129 port 52466 ssh2
Apr  7 00:07:15 Client-linux sshd[7220]: Failed password for bo from 192.168.20.129 port 52466 ssh2
Apr  7 00:07:15 Client-linux sshd[7221]: Failed password for bo from 192.168.20.129 port 52456 ssh2
Apr  7 00:07:15 Client-linux sshd[7219]: Failed password for bo from 192.168.20.129 port 52444 ssh2
Apr  7 00:07:15 Client-linux sshd[7218]: Failed password for bo from 192.168.20.129 port 52438 ssh2
Apr  7 00:07:18 Client-linux sshd[7220]: Failed password for bo from 192.168.20.129 port 52466 ssh2
Apr  7 00:07:18 Client-linux sshd[7221]: Failed password for bo from 192.168.20.129 port 52456 ssh2
Apr  7 00:07:18 Client-linux sshd[7219]: Failed password for bo from 192.168.20.129 port 52444 ssh2
Apr  7 00:07:18 Client-linux sshd[7218]: Failed password for bo from 192.168.20.129 port 52438 ssh2
Apr  7 00:07:20 Client-linux sshd[7218]: Connection closed by authenticating user bo 192.168.20.129 port 52438 [preauth]
Apr  7 00:07:20 Client-linux sshd[7218]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.20.129  user=bo
Apr  7 00:07:21 Client-linux sshd[7221]: Failed password for bo from 192.168.20.129 port 52456 ssh2
Apr  7 00:07:21 Client-linux sshd[7220]: Failed password for bo from 192.168.20.129 port 52466 ssh2
Apr  7 00:07:21 Client-linux sshd[7219]: Failed password for bo from 192.168.20.129 port 52444 ssh2
Apr  7 00:07:22 Client-linux sshd[7220]: Connection closed by authenticating user bo 192.168.20.129 port 52466 [preauth]
Apr  7 00:07:22 Client-linux sshd[7220]: PAM 3 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.20.129  user=bo
Apr  7 00:07:22 Client-linux sshd[7220]: PAM service(sshd) ignoring max retries; 4 > 3
Apr  7 00:07:22 Client-linux sshd[7221]: Connection closed by authenticating user bo 192.168.20.129 port 52456 [preauth]
Apr  7 00:07:22 Client-linux sshd[7221]: PAM 3 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.20.129  user=bo
Apr  7 00:07:22 Client-linux sshd[7221]: ==PAM service(sshd) ignoring max retries; 4 > 3==
Apr  7 00:07:22 Client-linux sshd[7219]: Connection closed by authenticating user bo 192.168.20.129 port 52444 [preauth]
Apr  7 00:07:22 Client-linux sshd[7219]: PAM 3 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.20.129  user=bo
Apr  7 00:07:22 Client-linux sshd[7219]: PAM service(sshd) ignoring max retries; 4 > 3

- **Thời gian:** `00:07:11` - `00:07:22` | **IP:** `192.168.20.129` (Kali Linux)
- **Tần suất dồn dập:** Chỉ trong **11 giây** mà có hàng chục dòng log.
- **Xử lý song song:** Xuất hiện nhiều PID khác nhau (`7218`, `7219`, `7220`, `7221`) cùng thử mật khẩu trong cùng một giây.
- **Vượt ngưỡng hệ thống:** Dòng `ignoring max retries; 4 > 3`. Đây là bằng chứng cho thấy công cụ (Hydra) đang cố "nhồi" mật khẩu nhanh hơn mức SSH Server cho phép xử lý.
- **Port nhảy liên tục:** `52424`, `52456`, `52438`, `52444`... Mỗi lần thử là một kết nối mới.

## auth.log lúc người dùng nhập sai mk thông thường

>Apr  7 00:12:00 Client-linux sshd[7247]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.20.1  user=bo
Apr  7 00:12:02 Client-linux sshd[7247]: Failed password for bo from 192.168.20.1 port 61058 ssh2
Apr  7 00:12:15 Client-linux sshd[7247]: ==message repeated 2 times==: [ Failed password for bo from 192.168.20.1 port 61058 ssh2]
Apr  7 00:12:15 Client-linux sshd[7247]: Connection reset by authenticating user bo 192.168.20.1 port 61058 [preauth]
Apr  7 00:12:15 Client-linux sshd[7247]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.20.1  user=bo

- **Tốc độ con người:** Lần thử đầu với các lần sau cách nhau vài giây
- **Thông báo gộp:** `message repeated 2 times`. Thay vì mở nhiều tiến trình như Hydra, ở đây chỉ có một PID duy nhất (`7247`) đang kiên nhẫn đợi người dùng gõ.
---
### Bảng So Sánh Dấu Hiệu Nhận Biết

| **Đặc điểm**                 | **Đăng xuất/Gõ sai (Benign)**                                                                                   | **Tấn công Hydra (Malicious)**                               | **Ý nghĩa đối với SOC**                                   |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ | --------------------------------------------------------- |
| **Tần suất (Velocity)**      | Thấp (1 dòng mỗi 10-15s). Tốc độ con người.                                                                     | **Cực cao (4-10 dòng/giây).** Tốc độ máy.                    | Tốc độ là dấu hiệu đầu tiên để phân biệt Bot/Script.      |
| **Tiến trình (PID)**         | Duy nhất **1 PID** xử lý xuyên suốt (vd: `7247`).                                                               | **Nhiều PID chạy song song** (vd: `7218, 7219, 7220, 7221`). | Tấn công đa luồng (Multi-threading) để dò nhanh hơn.      |
| **Cổng nguồn (Source Port)** | Cố định 1 Port cho đến khi kết nối bị ngắt.                                                                     | **Nhảy Port liên tục** (vd: `52438 -> 52444 -> 52456`).      | Mỗi lần thử mật khẩu là một kết nối TCP mới từ công cụ.   |
| **Thông báo từ PAM**         | `session closed` hoặc `message repeated 2 times`. (Cơ chế gộp log của syslog khi cùng 1 PID lặp lại hành động). | **`ignoring max retries; 4 > 3`**                            | Dấu hiệu kẻ tấn công đang "ép" hệ thống làm việc quá tải. |
| **Trạng thái kết nối**       | `Disconnected by user` (Chủ động thoát).                                                                        | **`Connection closed [preauth]`** (Bị hệ thống đá văng).     | Hệ thống tự bảo vệ khi phát hiện hành vi bất thường.      |
| **Địa chỉ IP (Rhost)**       | IP quản trị quen thuộc (vd: `.1`).                                                                              | **IP lạ hoặc IP máy tấn công (vd: `.129`).**                 | Định danh đối tượng thực hiện hành vi.                    |
### 3. Phân tích chi tiết sự khác biệt

#### A. Kỹ thuật "Song song" vs "Tuần tự"

- **Brute Force:** Bạn sẽ thấy các PID `7218`, `7219`, `7220`, `7221` cùng báo lỗi tại giây `:11`. Điều này chứng tỏ kẻ tấn công đang dùng công cụ (như Hydra, Medusa) để mở đồng thời 4-5 luồng tấn công nhằm tiết kiệm thời gian.
- **Thông thường:** Chỉ có PID `7247` làm việc từ đầu đến cuối. Người dùng nhập sai lần 1, rồi lần 2, rồi lần 3 trên **cùng một cửa sổ kết nối**

#### B. Dấu hiệu "Vượt rào" (Max Retries)

- Trong log Brute Force, xuất hiện dòng:
    
    > `PAM service(sshd) ignoring max retries; 4 > 3`
    
- **Ý nghĩa:** Cấu hình SSH thông thường chỉ cho phép thử 3 lần mỗi session. Công cụ Brute Force cố tình đẩy thêm lần thứ 4 trong khi session chưa kịp đóng, khiến hệ thống PAM phải đưa ra cảnh báo này. Đây là "chữ ký" điển hình của các script tấn công tự động.
    
#### C. IP nguồn và Port

- **Brute Force:** IP `192.168.20.129` sử dụng các port nguồn khác nhau liên tục (`52456`, `52438`, `52444`...) để tạo các session mới.
    
- **Thông thường:** IP `192.168.20.1` giữ nguyên port `61058` trong suốt quá trình thử sai mật khẩu cho đến khi bị reset.

---

### 4. Cách thiết lập Rule nhận diện trong Wazuh

Dựa trên sự khác biệt này, Wazuh thường dùng các Rule sau để phân biệt:

1. **Authentication Failure (Rule 5710):** Đơn giản là nhập sai mật khẩu (Level 5).
    
2. **Brute Force Attack (Rule 5712):** Nếu Rule 5710 xuất hiện **8 lần trong vòng 30 giây** từ cùng một IP nguồn.
    
3. **Multiple Failed Logins (Rule 40101):** Nếu phát hiện nhiều PID khác nhau từ cùng một IP cùng báo lỗi đăng nhập (đánh dấu tấn công đa luồng).
    

**Lời khuyên:** * Nếu bạn thấy `ignoring max retries`, đó chắc chắn là tấn công.

- Nếu bạn thấy `message repeated X times`, đó thường là người dùng thật đang cố nhớ mật khẩu.