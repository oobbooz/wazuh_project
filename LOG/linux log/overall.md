## I. Các dạng log trong Linux

Log Linux có thể được phân thành **3 dạng chính** dựa vào cách chúng được tạo ra và lưu trữ:

| Dạng log                                  | Đặc điểm                                                                              | Ví dụ                                                                                         |
| ----------------------------------------- | ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| **1. System logs (log hệ thống)**         | Ghi lại hoạt động của kernel, các dịch vụ nền, tiến trình khởi động, định thời (cron) | `/var/log/syslog`,<br>`/var/log/messages`,<br>`/var/log/kern.log`,<br>`/var/log/cron`         |
| **2. Authentication logs (log xác thực)** | Ghi lại các sự kiện đăng nhập, đăng xuất, sudo, xác thực PAM, thất bại SSH            | `/var/log/auth.log` (Debian/Ubuntu), <br>`/var/log/secure` (RHEL/CentOS)                      |
| **3. Application logs (log ứng dụng)**    | Do các ứng dụng tự tạo, thường nằm trong thư mục riêng hoặc gửi qua syslog            | `/var/log/apache2/access.log`, <br>`/var/log/mysql/error.log`,<br>`/var/log/nginx/access.log` |

Ngoài ra còn có **log của systemd-journald** (dạng nhị phân) – không phải file text thông thường, xem qua `journalctl`.

---
## II. Syntax

Log trong Linux tuân theo **Syslog protocol** với hai phiên bản phổ biến: **RFC 3164 (BSD syslog – cũ)** và **RFC 5424 (hiện đại)**.
### 1. RFC 3164 (old syslog)
- **Đặc điểm nhận dạng:** timestamp dạng `Mmm dd hh:mm:ss` (không có năm, không múi giờ), không có structured data.
- **Cấu trúc:**  
    `<PRI>timestamp hostname tag[pid]: message`
### 2. RFC 5424 (hiện đại – khuyến nghị)
- **Đặc điểm nhận dạng:** timestamp đầy đủ (ISO 8601), có structured data `[ ... ]`, version field.
- **Cấu trúc đầy đủ:**  
    `<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
*Chi tiết syntax ở phần từng loại log.
---

## III. Các file log quan trọng – vị trí và ý nghĩa

Tất cả đều nằm trong **`/var/log/`** (trừ một số log người dùng).

| File log                             | Hệ điều hành                      | Nội dung chính                                                                 |
| ------------------------------------ | --------------------------------- | ------------------------------------------------------------------------------ |
| `/var/log/syslog`                    | Debian/Ubuntu                     | Toàn bộ hoạt động hệ thống (trừ auth, cron riêng)                              |
| `/var/log/messages`                  | RHEL/CentOS                       | Tương tự syslog                                                                |
| `/var/log/auth.log`                  | Debian/Ubuntu                     | Đăng nhập thành công/thất bại, sudo, PAM, SSH                                  |
| `/var/log/secure`                    | RHEL/CentOS                       | Tương tự auth.log                                                              |
| `/var/log/kern.log`                  | Mọi distro                        | Log từ kernel (driver, lỗi phần cứng, OOM)                                     |
| `/var/log/cron`                      | Mọi distro                        | Log của cron jobs (thời gian chạy, output)                                     |
| `/var/log/boot.log`                  | Mọi distro                        | Thông tin khởi động hệ thống                                                   |
| `/var/log/dpkg.log` (hoặc `yum.log`) | Ubuntu/Debian (dpkg) / RHEL (yum) | Lịch sử cài đặt/gỡ bỏ gói phần mềm                                             |
| `/var/log/faillog`                   | Mọi distro                        | Ghi lại các lần đăng nhập thất bại (định dạng nhị phân, dùng `faillog` để đọc) |
| `/var/log/lastlog`                   | Mọi distro                        | Thời gian đăng nhập gần nhất của từng user (nhị phân, dùng `lastlog`)          |
| `/var/log/wtmp` / `/var/log/btmp`    | Mọi distro                        | Lịch sử đăng nhập (wtmp: thành công; btmp: thất bại) – dùng `last`, `lastb`    |

**Ví dụ thực tế một số log ứng dụng:**
- Apache: `/var/log/apache2/access.log`, `error.log`
- Nginx: `/var/log/nginx/access.log`, `error.log`
- MySQL: `/var/log/mysql/error.log`
- PostgreSQL: `/var/log/postgresql/postgresql-`

[reference]: https://www.loggly.com/ultimate-guide/linux-logging-basics/]
---
### journald (`journalctl`)
*Tầm quan trọng của `systemd-journald`
Trong các bản Ubuntu mới, `rsyslog` (tạo ra các file `.log`) và `journald` chạy song song.
- `journald` thu thập log ngay khi máy vừa khởi động (trước cả khi các file log trong `/var/log` được ghi).
- Trong SOC, nếu kẻ tấn công xóa sạch file trong `/var/log/`,  vẫn có thể khôi phục dấu vết bằng cách truy vấn `journalctl` vì nó lưu trữ ở định dạng nhị phân khó can thiệp hơn.*
Vì là file nhị phân, bạn phải dùng lệnh `journalctl` để đọc. Dưới đây là các lệnh:
#### Xem toàn bộ log (từ mới đến cũ)

```
sudo journalctl -r
```

_(Tham số `-r` là reverse, xem những gì vừa xảy ra xong)._
#### Xem log của một dịch vụ cụ thể

Nếu nghi ngờ SSH bị tấn công hoặc Wazuh-agent bị sập:

```
sudo journalctl -u ssh
sudo journalctl -u wazuh-agent
```
#### Xem log theo khoảng thời gian

Muốn biết chuyện gì xảy ra vào 10 phút trước?
```
sudo journalctl --since "10 minutes ago"
# Hoặc chính xác ngày giờ:
sudo journalctl --since "2026-04-06 10:00:00" --until "2026-04-06 11:00:00"
```
#### Xem log theo mức độ nghiêm trọng (Severity)
Chỉ xem các lỗi từ mức Error trở lên:
```
sudo journalctl -p err..emerg
```
