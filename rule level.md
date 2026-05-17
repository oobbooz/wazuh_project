### Chênh lệch thang đo nguy hiểm (Alert Rule)

- **Suricata:** phân tích gói tin, khớp chữ ký và gán mức độ cực kỳ nguy hiểm. Nó xuất ra log: `event_type: alert` kèm theo trường `alert.severity: 1` (hoặc 2). Theo thang đo 1-4 của Suricata, số 1 là **Đỏ (Critical)**.
    
- **Wazuh (Mặc định)?** Wazuh nhận file JSON, nó thấy `event_type: alert`. Mặc định của Wazuh được lập trình sẵn một luật gom chung (Catch-all Rule `86601`).
```
<rule id="86601" level="3">
        <if_sid>86600</if_sid>
        <field name="event_type">^alert$</field>
        <description>Suricata: Alert - $(alert.signature)</description>
        <options>no_full_log</options>
</rule>
```
=> Cần sửa, theo alert.severity gửi về từ suricata, alert.severity = 1 (critical) -> level 10, alert.severity = 2 (medium) -> level 7 (có thể fix level cho phù hợp hơn)
sửa ở `sudo nano /var/ossec/etc/rules/local_rules.xml`
```
<group name="ids,suricata,">

    <rule id="100010" level="10">
        <decoded_as>suricata-raw-fix</decoded_as>
        <field name="event_type">^alert$</field>
        <field name="alert.severity">^1$</field>
        <description>Suricata: Critical Alert - $(alert.signature)</description>
        <options>no_full_log</options>
    </rule>

    <rule id="100011" level="7">
        <decoded_as>suricata-raw-fix</decoded_as>
        <field name="event_type">^alert$</field>
        <field name="alert.severity">^2$</field>
        <description>Suricata: Warning Alert - $(alert.signature)</description>
        <options>no_full_log</options>
    </rule>

</group>

```

Ví dụ log trên wazuh mana sau khi sửa

| Trường                      | Giá trị                                                                               | Ý nghĩa                                           |
| --------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------- |
| **_index**                  | wazuh-alerts-4.x-2026.04.26                                                           | Index lưu trữ alert trong Wazuh                   |
| **agent.id**                | 000                                                                                   | ID agent (000 thường là manager)                  |
| **agent.name**              | bo-wazuh                                                                              | Tên agent/manager                                 |
| **data.alert.action**       | allowed                                                                               | Traffic được cho phép (không bị drop)             |
| **data.alert.category**     | Web Application Attack                                                                | Loại tấn công web                                 |
| **data.alert.gid**          | 1                                                                                     | Generator ID (Suricata/Snort)                     |
| **data.alert.rev**          | 7                                                                                     | Version của rule                                  |
| ==**data.alert.severity**== | ==1==                                                                                 | Mức độ nghiêm trọng (1 = cao nhất trong Suricata) |
| **data.alert.signature**    | ET WEB_SERVER SELECT USER SQL Injection Attempt in URI                                | Tên rule phát hiện                                |
| **data.alert.signature_id** | 2010963                                                                               | ID của rule                                       |
| **data.app_proto**          | http                                                                                  | Giao thức ứng dụng                                |
| **data.dest_ip**            | 192.168.10.133                                                                        | IP đích (web server / pfSense WAN)                |
| **data.dest_port**          | 80                                                                                    | Port HTTP                                         |
| **data.direction**          | to_server                                                                             | Hướng traffic (client → server)                   |
| **data.event_type**         | alert                                                                                 | Loại sự kiện                                      |
| **data.flow_id**            | 1288184615784680.000000                                                               | ID của flow network                               |
| **data.in_iface**           | em0                                                                                   | Interface nhận packet                             |
| **data.payload**            | (base64 encoded)                                                                      | Payload request (HTTP request bị encode)          |
| **data.pkt_src**            | wire/pcap                                                                             | Nguồn packet                                      |
| **data.proto**              | TCP                                                                                   | Giao thức mạng                                    |
| **data.src_ip**             | 192.168.10.147                                                                        | IP attacker                                       |
| **data.src_port**           | 34228                                                                                 | Port nguồn                                        |
| **data.stream**             | 1                                                                                     | ID stream TCP                                     |
| **data.timestamp**          | Apr 26, 2026 @ 21:09:24.706                                                           | Thời gian Suricata ghi nhận                       |
| **data.tx_id**              | 0                                                                                     | Transaction ID                                    |
| **decoder.name**            | suricata-raw-fix                                                                      | Decoder xử lý log                                 |
| **id**                      | 1777212565.301084                                                                     | ID duy nhất của event                             |
| **input.type**              | log                                                                                   | Kiểu input                                        |
| **location**                | 192.168.20.128                                                                        | IP hệ thống gửi log (Wazuh agent)                 |
| **manager.name**            | bo-wazuh                                                                              | Tên Wazuh manager                                 |
| **rule.description**        | Suricata: ==Critical Alert== - ET WEB_SERVER SELECT USER SQL Injection Attempt in URI | Mô tả alert                                       |
| **rule.firedtimes**         | 1                                                                                     | Số lần rule được kích hoạt                        |
| **rule.groups**             | ids, suricata                                                                         | Nhóm rule                                         |
| **rule.id**                 | 100010                                                                                | ID rule trong Wazuh                               |
| ==**rule.level**==          | ==10==                                                                                | Mức độ cảnh báo trong Wazuh (cao)                 |
| **rule.mail**               | false                                                                                 | Không gửi email                                   |
| **timestamp**               | Apr 26, 2026 @ 21:09:25.172                                                           | Thời gian Wazuh ghi nhận                          |