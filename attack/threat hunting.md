
- từ trang threat hunting, thấy 3 log level > 12 (nghiêm trọng) -> event thì thấy là rule 40112 (2 lần) và 40501 (1 lần)
-> hunt 1: theo 40112 trước
1. hunt 40112
bước 1: lọc event gốc
`rule.id: 40112`
![[Pasted image 20260424200811.png]]
- lấy được timestamp, data.script (kẻ tấn công?), user bị tấn công
Bước 2 — Pivot theo IP attacker (±30 phút)
![[Pasted image 20260424152720.png]]
-> thấy được toàn bộ cuộc tấn công.

- Attacker (192.168.10.147) thử password liên tục → mỗi lần fail ra rule 5760
- Sau nhiều lần fail → Wazuh tổng hợp ra rule 40111 (multiple failures)
- **Đột ngột thành công** → rule 40112 kích hoạt — có nghĩa là password đã bị đoán đúng
- Điều này xảy ra **2 lần** trong vòng 1 phút → có thể attacker đã vào được 2 tài khoản khác nhau, hoặc cùng 1 tài khoản 2 session
**Điểm quan trọng cần lưu ý:** Giữa 2 event 40112 (00:50:03 và 00:50:47) có khoảng cách 44 giây — trong khoảng này attacker có thể đã bắt đầu thực hiện hành động. Cần trace tiếp trong bước 3.
#### Bước 3 — Xác định user bị compromise

**Query:**

```
agent.name: "Client-linux" AND rule.id: (5715 OR 5501) AND data.srcip: "192.168.10.147"
```

Rule 5715 = `sshd: authentication success`, rule 5501 = `PAM: Login session opened`. Hai rule này sẽ cho bạn thấy **username chính xác** đăng nhập thành công.
![[Pasted image 20260424211624.png]]

Bước 4 — Hunt hành vi sau login (CRITICAL)
- tìm file/process bất thường : rule.id : 550
![[Pasted image 20260424201827.png]]

-> client-linux, bị thay đổi file
-> nen lọc thêm trường gì để xem chi tiết event này?
-> cái này thể hiện điều gì?

2. hunt theo 40501
 Từ cái gì (Trigger – dữ liệu thật)

- `rule.id: 40501` → _Attacks followed by the addition of a user_
- `rule.id: 5902` → _New user added to the system_
Thấy được 40501 từ level >12, nhưng làm sao thấy được 5902 chỉ trong khi nhìn sơ qua để biết mà hunt?
`rule.id: (40501 or 5902)`
![[Pasted image 20260424155506.png]]
Pivot theo user vừa tạo
`data.dstuser: "sysupdate"`
![[Pasted image 20260424155739.png]]

1, thời gian sau, user đó có đăng nhập lại, 
`agent.name: "Client-linux" AND data.srcuser: "sysupdate" AND rule.id: (5715 OR 5501)`
và tạo backdoor.php
![[Pasted image 20260424210636.png]]
![[Pasted image 20260424211123.png]]
![[Ảnh chụp màn hình 2026-04-24 210101.png]]
từ máy bị tấn công, xác nhận
![[Pasted image 20260424160103.png]]
phân tích xem nó thể hiện điều gì
 => từ 2 hunt trên cho thấy cái gì, đã đúng quy trình, kĩ thuật hunt thực tế chưa.
# Hunt #3: Web Application Exploit thành công

1. Từ cái gì (Trigger – dữ liệu thật)


- `31106` → **Web attack nhưng trả HTTP 200 (SUCCESS)** 🔥
- `30411` → ModSecurity **block request**
- `31151` → nhiều HTTP 400 (attacker fuzzing)
- `31103`, `31152` → SQL Injection
- `31105` → XSS

👉 Insight quan trọng:

> Attacker thử rất nhiều (bị block) → cuối cùng có request **trả 200 = bypass thành công**?
> Làm sao biết được mấy cái id đó ở đâu ra.

## 🔹 Bước 1 — Lọc attack thành công

rule.id: 31106
![[Pasted image 20260424195356.png]]
=> 192.168.20.129
-> nên query gì tiếp
```data.srcip: "192.168.20.129"
and rule.id: (31151 or 31103 or 31105 or 31152 or 31106)
```

![[Pasted image 20260424200043.png]]
**Phân tích URL:** `/shop.php?id=SELECT%20USER` — đây là SQL injection payload cực kỳ rõ ràng:

- `SELECT USER` là hàm MySQL trả về user database đang chạy
- Trả về HTTP 200 → server đã **execute câu query này** và trả về kết quả
- Attacker đã biết được DB user đang chạy → bước đầu trong SQL injection chain
- 