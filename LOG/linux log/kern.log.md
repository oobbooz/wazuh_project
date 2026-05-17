`kern.log` là nơi ghi lại các thông báo từ **Nhân (Kernel)** của hệ điều hành. Trong bảo mật, đây là nơi "tố cáo" các hành vi can thiệp vào phần cứng hoặc bị Firewall chặn đứng.
### Nội dung lưu trữ
Đây là khi cấu hình log ở mức **Low** hoặc **Medium** để tránh làm đầy ổ cứng. Còn nếu để mức High thì những gói ALLOW, AUDIT vẫn được lưu.
- **Firewall Events:** Các gói tin bị UFW hoặc Iptables chặn (`[UFW BLOCK]`).
- **Hardware Errors:** Lỗi ổ đĩa, CPU quá nhiệt, lỗi RAM.
- **App Armor/SELinux:** Các ngăn chặn bảo mật ở mức nhân khi một ứng dụng cố tình truy cập file trái phép.
- **OOM (Out Of Memory):** Khi hệ thống hết RAM và Kernel buộc phải "giết" một tiến trình (thường là dấu hiệu của tấn công từ chối dịch vụ - DoS).
### Log 
- xem log `sudo tail -f /var/log/kern.log`
*Đây là log nhóm thu thập được
`Apr 6 11:03:58 Client-linux kernel: [ 3292.911293] [UFW BLOCK] IN=ens37 OUT= MAC=... SRC=192.168.20.129 DST=192.168.20.150 LEN=44 TOS=0x00 PREC=0x00 TTL=51 ID=16025 PROTO=TCP SPT=64644 DPT=23 WINDOW=1024 RES=0x00 SYN URGP=0`

- **`[UFW BLOCK]`**: Hành động của Firewall. Gói tin bị chặn đứng ngay tại tầng Kernel (Nhân), không cho phép tiếp cận ứng dụng.
- **`SRC=192.168.20.129`**: Nguồn phát động tấn công.
- **`DST=192.168.20.150`**: Mục tiêu tấn công (Máy Victim).
- **`DPT=23` (Destination Port)**: Cổng đích là 23 (Telnet). Kẻ tấn công đang tìm kiếm các dịch vụ quản trị từ xa không mã hóa để khai thác.
- **`PROTO=TCP` & `SYN`**:  Cờ **SYN** (Synchronize) cho thấy kẻ tấn công đang thực hiện bước đầu tiên của quy trình bắt tay 3 bước (3-way handshake). Việc có nhiều gói SYN vào nhiều cổng khác nhau trong 1 giây là dấu hiệu đặc trưng của **TCP SYN Scan**.
- **`WINDOW=1024`**: Kích thước cửa sổ nhận dữ liệu rất nhỏ (1024), thường là giá trị mặc định của các công cụ quét như `nmap`.

-> **Thời điểm:** `11:03:58`.
- **Hành vi:** Trong vòng chưa đầy 1 giây, IP `.129` đã quét qua 4 cổng: `23` (Telnet), `443` (HTTPS), `3306` (MySQL), `21` (FTP).
- **Kỹ thuật:** Sử dụng **Stealth Scan (SYN Scan)**. Kẻ tấn công gửi gói SYN, nếu nhận được SYN-ACK nghĩa là cổng mở, nếu nhận được RST nghĩa là cổng đóng. Ở đây, UFW đã chặn (BLOCK) nên kẻ tấn công sẽ nhận được kết quả là `Filtered` (Bị lọc).
- **Mục đích:** Tìm kiếm lỗ hổng trong các dịch vụ yếu (FTP, Telnet) hoặc chiếm quyền điều khiển cơ sở dữ liệu (MySQL).