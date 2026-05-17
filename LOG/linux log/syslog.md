**Syslog** vừa là một giao thức (protocol), vừa là một dịch vụ (service - thường là `rsyslog` hoặc `syslog-ng`), vừa là một tệp tin lưu trữ (`/var/log/syslog` trên Ubuntu/Debian hoặc `/var/log/messages` trên CentOS/RHEL).
Nó đóng vai trò là **"Hub trung tâm"**:
1. **Nhận log** từ các ứng dụng, dịch vụ nền (daemons), và kernel.
2. **Phân loại** dựa trên nguồn (Facility) và mức độ (Severity).
3. **Xử lý:** Ghi vào file cục bộ hoặc đẩy sang máy chủ Log tập trung (như Wazuh Manager).
---
`tail -f /var/log/syslog`
```
Apr  6 11:15:03 Client-linux systemd[1]: Stopping OpenBSD Secure Shell server...
Apr  6 11:15:03 Client-linux systemd[1]: ssh.service: Deactivated successfully.
Apr  6 11:15:03 Client-linux systemd[1]: Stopped OpenBSD Secure Shell server.
Apr  6 11:15:03 Client-linux systemd[1]: Starting OpenBSD Secure Shell server...
Apr  6 11:15:03 Client-linux systemd[1]: Started OpenBSD Secure Shell server.
Apr  6 11:15:11 Client-linux kernel: [ 3965.899970] [UFW AUDIT] IN= OUT=ens37 SR
```
-> Đây là log từ `systemd` (quản lý dịch vụ). Nó ghi lại quá trình bạn khởi động lại (`restart`) SSH server.

```
Apr  6 11:15:11 Client-linux kernel: [ 3965.899970] [UFW AUDIT] IN= OUT=ens37 SRC=192.168.20.150 DST=192.168.20.143 LEN=354 TOS=0x00 PREC=0x00 TTL=64 ID=13673 DF PROTO=TCP SPT=59059 DPT=1514 WINDOW=350 RES=0x00 ACK PSH URGP=0 
```
-> Đây là log từ `kernel`. Nó ghi lại một gói tin đi qua Firewall. **Kernel log** (Nhãn `kern`) có một đặc quyền là "xuất hiện ở cả hai nơi".