https://youtu.be/YWCpXdqj1wU?si=KfPaRYmzDodN6Edm
https://documentation.wazuh.com/current/proof-of-concept-guide/detect-remove-malware-virustotal.html
---
- tạm tắt tính năng antivirus của squid để tải file mã độc về
- theo dõi /tmp/malware
- thêm api key virustotal
-> detect được malware
trên log, có thể nhấn vào link, redirect trang virustotal.
![[Pasted image 20260427003145.png]]
![[Pasted image 20260427003206.png]]
![[Pasted image 20260427002845.png]]
- trên agent, thêm script tự động xóa khi phát hiện malware /var/ossec/active-response/bin/remove-threat.sh
- trên mana, kích hoạt active-response
- thêm local_rule để có alert

![[Pasted image 20260427002125.png]]
- **Sự kiện 1 (00:13:06.221 - Rule 87105):**
    - Wazuh phát hiện tệp mới nhờ FIM (Syscheck).
    - Nó gửi hash lên VirusTotal.
    - VirusTotal trả về kết quả "Dương tính" (66/66 engines). Wazuh bắn cảnh báo 87105.

- **Sự kiện 2 (00:13:06.252 - Rule 100092):**
    - Ngay khi rule 87105 bị kích hoạt, **Active Response** được gọi.
    - Script `remove-threat.sh` chạy và xóa tệp tin.
        
- **Sự kiện 3 (00:13:06.320 - Rule 553):**
    - FIM (Syscheck) nhận thấy tệp tin đã biến mất khỏi hệ thống. Nó ghi log: "File deleted" (Rule 553) để xác nhận hành động xóa đã thành công.
---
## yara
![[Ảnh chụp màn hình 2026-04-28 191259.png]]
