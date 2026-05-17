### 1. `auth.log` lưu trữ những loại Log gì?
`auth.log` (viết tắt của **Authentication Log**) là file nhật ký quan trọng nhất trên các hệ điều hành Debian/Ubuntu dùng để ghi lại mọi sự kiện liên quan đến **Xác thực (Authentication)** và **Cấp quyền (Authorization)**.
Các sự kiện chính bao gồm:
- **SSH Logins:** Ghi lại mọi nỗ lực đăng nhập qua giao thức SSH (thành công, thất bại, sai user, sai password).
- **Sudo Actions:** Ghi lại các lệnh được thực thi với quyền `root` thông qua lệnh `sudo`.
- **User Management:** Các sự kiện tạo mới user (`useradd`), đổi mật khẩu (`passwd`), hoặc xóa user.
- **PAM Events:** Các thông báo từ _Pluggable Authentication Modules_ - hệ thống quản lý xác thực trung tâm của Linux.
- **Cron Jobs:** Các tiến trình tự động chạy dưới quyền của một user cụ thể.
- **Polkit/pkexec:** Các yêu cầu cấp quyền cho các ứng dụng chạy giao diện đồ họa hoặc dịch vụ hệ thống.
### 2. Log Syntax
Một dòng log trong `auth.log` thường tuân thủ định dạng chuẩn của Syslog bao gồm 5 thành phần chính:

| **STT** | **Thành phần** | **Mô tả**                                           | **Ví dụ**                                   |
| ------- | -------------- | --------------------------------------------------- | ------------------------------------------- |
| **1**   | **Timestamp**  | Thời gian sự kiện xảy ra (Tháng Ngày Giờ:Phút:Giây) | `Apr 6 10:13:36`                            |
| **2**   | **Hostname**   | Tên của máy tính phát sinh ra log                   | `Client-linux`                              |
| **3**   | **Process**    | Tên ứng dụng/dịch vụ thực hiện ghi log              | `sshd` hoặc `sudo`                          |
| **4**   | **PID**        | Mã định danh tiến trình (Process ID) nằm trong `[]` | `[5547]`                                    |
| **5**   | **Message**    | Nội dung chi tiết của sự kiện (User, IP, Hành động) | `Failed password for bo từ 192.168.20.1...` |

### 3. Case Study
### Ví dụ A: Tấn công SSH (Failed Login)
- Log từ Tầng Hệ thống (OS Layer - PAM)
> **Log:** `Apr 6 10:13:34 Client-linux sshd[5547]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.20.1 user=bo`

- **Thành phần bóc tách:**
    - **`pam_unix(sshd:auth)`**: Module xác thực trung tâm của Linux (PAM) đang xử lý yêu cầu cho dịch vụ SSH.
    - **`uid=0`**: Tiến trình kiểm tra mật khẩu đang chạy với quyền cao nhất (root) để có thể truy cập file `/etc/shadow`.
    - **`rhost=192.168.20.1`**: Địa chỉ IP của máy thực hiện kết nối.
- **Ý nghĩa:** Đây là **điểm khởi đầu** của sự kiện. Nó cho biết hệ thống bảo mật cốt lõi của Linux đã nhận diện mật khẩu cung cấp là **sai**. Log này chứng minh tầng nhân (Kernel/OS) đã chặn đứng nỗ lực xâm nhập thành công.
- Log từ Tầng Ứng dụng (Application Layer - SSH)
> **Log:** `Apr 6 10:13:36 Client-linux sshd[5547]: Failed password for bo from 192.168.20.1 port 56432 ssh2`

- **Thành phần bóc tách:**
    - **`Failed password`**: Thông báo tóm tắt trạng thái cuối cùng của dịch vụ.
    - **`port 56432`**: Cổng dịch vụ trên máy kẻ tấn công dùng để tạo kết nối.
    - **`ssh2`**: Phiên bản giao thức SSH được sử dụng.
- **Ý nghĩa:** Đây là **kết quả tóm tắt**. Dòng log này thường được các bộ lọc của Wazuh (Decoders) ưu tiên sử dụng để đếm số lần vi phạm. Nó cung cấp thông tin mạng đầy đủ hơn (IP + Port) để hỗ trợ việc truy vết (Forensics).
### Ví dụ B: Thực thi quyền quản trị (Sudo Usage)

> `Apr 6 10:13:11 Client-linux sudo: bo : TTY=pts/0 ; PWD=/home/bo ; USER=root ; COMMAND=/usr/sbin/ufw reload`

- **Phân tích chi tiết hành vi:**
    - **Người thực hiện:** User `bo`.
    - **Vị trí thực hiện:** `PWD=/home/bo` (Thư mục nhà của user).
    - **Quyền hạn mượn:** `USER=root`.
    - **Lệnh thực thi:** `ufw reload` (Tải lại cấu hình tường lửa).
    - **Kết luận:** Đây là một hành vi quản trị hệ thống hợp lệ nếu `bo` là Admin. Tuy nhiên, trong SOC, việc thay đổi Firewall (`ufw`) luôn là sự kiện cần được ghi lại để truy vết nếu có sự cố mạng xảy ra sau đó.