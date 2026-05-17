
---

## 1. Cơ chế filter field trong Wazuh
Wazuh không có tính năng "chặn field trước khi thu thập" mà log vẫn vào hết. Filter xảy ra ở tầng **decode**: chỉ field nào được đặt tên trong `<order>` mới được lưu vào alert. Field không đặt tên bị bỏ qua hoàn toàn, không xuất hiện trong `alerts.json` hay `archives.json`.

```
Log thô vào → pre-decode → decode (chỉ giữ field trong <order>) → rule match → alert
```

Hai cách giảm dung lượng:
1. **Dùng `<order>` có chọn lọc** — chỉ đặt tên field thực sự cần, bỏ qua phần còn lại.
2. **Dùng `json_null_field: discard`** — với log JSON, bỏ field có giá trị null thay vì lưu chuỗi `"null"`.
---
## 2. Field có sẵn trong `<order>`

Wazuh có hai loại field trong `<order>`:
**Static fields** — tên cố định, Wazuh hiểu ngữ nghĩa và dùng trong rule:

|Field|Ý nghĩa|
|---|---|
|`srcip`|IP nguồn|
|`dstip`|IP đích|
|`srcport`|Port nguồn|
|`dstport`|Port đích|
|`srcuser`|User thực hiện hành động|
|`dstuser`|User bị tác động|
|`user`|Alias của dstuser|
|`protocol`|Giao thức|
|`action`|Hành động (block, pass, accept...)|
|`status`|Trạng thái (success, failure...)|
|`id`|Event ID|
|`url`|URL|
|`data`|Data chung|
|`extra_data`|Data bổ sung|
|`system_name`|Tên hệ thống|

**Dynamic fields** — tên tự đặt, lưu vào `data.*` trong alert:

```xml
<order>targetUser, sourceIP, processName</order>
```

Chỉ đặt tên field nào thực sự cần cho rule hoặc dashboard. Field không đặt tên → không tốn dung lượng.

---

## 3. Windows eventchannel

### Vấn đề

Windows eventchannel dùng decoder C nhúng trong binary — không thể sửa `<order>` như decoder XML thông thường. Field được extract mặc định gồm toàn bộ `win.system.*` và `win.eventdata.*`, bao gồm nhiều field ít dùng như `threadID`, `processID`, `opcode`, `version`, `keywords`.
Ngoài ra field `message` trong `win.system.message` chứa đoạn text giải thích rất dài — đây là nguồn chiếm dung lượng lớn nhất.
### Cách giảm dung lượng

**Cách 1 — Dùng XPath query để filter event trước khi thu**

Chỉ thu event thực sự cần, bỏ event ít quan trọng. Ít event vào = ít dung lượng.

```xml
<!-- Chỉ lấy event level <= 3 (Critical, Error, Warning) -->
<localfile>
  <location>System</location>
  <log_format>eventchannel</log_format>
  <query>Event/System[Level<=3]</query>
</localfile>

<!-- Chỉ lấy một số Event ID quan trọng trong Security channel -->
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
  <query>
    <QueryList>
      <Query Id="0" Path="Security">
        <Select Path="Security">
          *[System[(EventID=4624 or EventID=4625 or EventID=4688
            or EventID=4720 or EventID=4726 or EventID=4732
            or EventID=4740 or EventID=4756)]]
        </Select>
      </Query>
    </QueryList>
  </query>
</localfile>
```

**Cách 2 — Viết rule chặn alert cho event ít quan trọng**

Event vẫn vào archives nhưng không tạo alert — giảm dung lượng `alerts.json`.

```xml
<!-- Trong /var/ossec/etc/rules/local_rules.xml -->
<!-- Chặn alert cho event 4634 (logoff) — thường rất nhiều, ít giá trị -->
<rule id="100001" level="0">
  <if_group>windows_security</if_group>
  <field name="win.system.eventID">^4634$</field>
  <description>Suppress logoff events</description>
</rule>
```

**Cách 3 — Dùng `<discard>` trong rule để không lưu vào archives**

```xml
<rule id="100002" level="0">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^4663$</field>
  <description>Discard object access audit noise</description>
  <options>no_log</options>
</rule>
```

### Event ID quan trọng nên giữ - Cần tìm hiểu kĩ và bổ sung để tránh thiếu dữ kiện

|Event ID|Mô tả|
|---|---|
|4624|Logon thành công|
|4625|Logon thất bại|
|4688|Process creation|
|4720|Tạo user mới|
|4726|Xóa user|
|4732|Thêm user vào group|
|4740|Account bị lock|
|4756|Thêm vào security group|
|1|Sysmon process create|
|3|Sysmon network connection|
|11|Sysmon file create|

### Event ID nên filter bỏ (nhiều, ít giá trị) - Cần tìm hiểu kĩ và bổ sung

|Event ID|Mô tả|Lý do bỏ|
|---|---|---|
|4634|Logoff|Quá nhiều, ít giá trị|
|4658|Handle closed|Noise|
|4663|Object access|Rất nhiều nếu audit bật|
|4656|Handle request|Noise|
|5156|Network connection allowed|Quá nhiều|
|5158|Bind socket|Noise|

---

## 4. pfSense syslog

### Cấu trúc log pfSense

```
Nov 8 12:37:34 pfSense filterlog: 5,,,1000102433,em0,match,block,in,4,0x0,,128,24677,0,none,17,udp,186,10.9.0.119,10.9.0.255,17500,17600,166
```

Decoder `pf-fields` gốc đã extract: `id`, `action`, `protocol`, `srcip`, `dstip`, `srcport`, `dstport`, `length`.

### Field nên giữ và bỏ

Field decoder gốc extract ra là vừa đủ cho hầu hết use case. Nếu muốn bỏ thêm, viết custom decoder đè lên, chỉ đặt tên field cần:

```xml
<!-- /var/ossec/etc/decoders/local_decoder.xml -->

<!-- Decoder cha giữ nguyên -->
<decoder name="pf-custom">
  <parent>pf</parent>
  <use_own_name>true</use_own_name>
  <!-- Chỉ lấy action, srcip, dstip, dstport — bỏ id, protocol, srcport, length -->
  <regex>^\S*,\S*,\S*,\S*,\S*,\S*,(\S*),</regex>
  <order>action</order>
</decoder>

<decoder name="pf-custom">
  <parent>pf</parent>
  <regex offset="after_regex">\S*,\S*,\S*,\S*,\S*,\S*,\S*,\S*,\S*,(\S*),\S*,(\S*),(\S*),</regex>
  <order>protocol,srcip,dstip</order>
</decoder>

<decoder name="pf-custom">
  <parent>pf</parent>
  <regex offset="after_regex">\d*,(\d*),</regex>
  <order>dstport</order>
</decoder>
```

### Giảm noise ở tầng rule

```xml
<!-- Bỏ alert cho traffic nội bộ pass — thường rất nhiều -->
<rule id="100010" level="0">
  <if_group>pf</if_group>
  <match>action: pass</match>
  <srcip>192.168.0.0/16</srcip>
  <description>Suppress internal pass traffic</description>
</rule>
```

---

## 5. Log text thuần — Linux, Apache, Squid, ClamAV, IDPS

### Nguyên tắc chung

Với log text thuần, `<order>` là công cụ filter trực tiếp. Chỉ đặt tên field cần thiết.

**Ví dụ Apache** — decoder gốc extract nhiều field, nếu chỉ cần `srcip`, `url`, `id` (HTTP status):

```xml
<decoder name="apache-custom">
  <parent>apache</parent>
  <use_own_name>true</use_own_name>
  <prematch>^\S+ \S+ \S+ </prematch>
  <regex after_prematch="true">"(\w+) (\S+)[^"]*" (\d+)</regex>
  <order>action, url, id</order>
  <!-- bỏ: size, referer, user_agent — tiết kiệm dung lượng đáng kể -->
</decoder>
```

**Ví dụ Squid** — chỉ lấy srcip, url, action, bỏ thời gian xử lý và byte count:

```xml
<decoder name="squid-custom">
  <parent>squid</parent>
  <use_own_name>true</use_own_name>
  <regex>^\d+\.\d+ \s*\d+ (\S+) (\w+)/(\d+) \d+ \w+ (\S+)</regex>
  <order>srcip, status, id, url</order>
</decoder>
```

**Ví dụ ClamAV** — thường chỉ cần file bị phát hiện và loại virus:

```xml
<decoder name="clamav-custom">
  <parent>clamav</parent>
  <use_own_name>true</use_own_name>
  <prematch>^/</prematch>
  <regex>^(\S+): (\S+) FOUND</regex>
  <order>data, extra_data</order>
  <!-- data = đường dẫn file, extra_data = tên virus -->
  <!-- bỏ: timestamp lặp lại, engine version -->
</decoder>
```

**Ví dụ Snort/Suricata IDPS** — chỉ lấy field cần cho alert:

```xml
<decoder name="snort-custom">
  <parent>snort</parent>
  <use_own_name>true</use_own_name>
  <regex>^\[(\d+:\d+:\d+)\] (.+) \[Classification</regex>
  <order>id, extra_data</order>
  <!-- bỏ: priority text lặp lại, hex payload -->
</decoder>
```

### Field thường bỏ với log text

|Loại log|Field nên bỏ|Lý do|
|---|---|---|
|Apache|`user_agent`, `referer`, byte size|Dài, ít dùng trong rule|
|Squid|Thời gian xử lý (ms), byte count|Ít giá trị security|
|ClamAV|Engine version, DB version|Không đổi, ít giá trị|
|IDPS|Raw packet hex, payload|Rất dài, tốn dung lượng|
|Linux syslog|PID lặp lại, facility|Đã có trong pre-decode|
|SSH|Banner version|Ít giá trị|

---

## 6. JSON log — dùng `json_null_field` và `json_array_structure`

Với log JSON từ ứng dụng hiện đại, hai option này giúp giảm dung lượng:

```xml
<decoder name="myapp-json">
  <program_name>myapp</program_name>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
  <!-- Bỏ field null thay vì lưu chuỗi "null" -->
  <json_null_field>discard</json_null_field>
  <!-- Chuyển array thành CSV thay vì JSON array — ngắn hơn -->
  <json_array_structure>csv</json_array_structure>
</decoder>
```

`json_null_field: discard` đặc biệt hiệu quả với log Windows eventchannel vì nhiều field trong `eventdata` là null tùy event.

---

## 7. Workflow thực tế khi thêm log source mới

Khi thêm một nguồn log mới (ví dụ Squid, ClamAV), làm theo thứ tự:

**Bước 1 — Xem decoder gốc extract những field gì**

```bash
sudo /var/ossec/bin/wazuh-logtest
# paste một dòng log mẫu vào
```

Xem output `Phase 2` — liệt kê toàn bộ field được extract.

**Bước 2 — Xác định field nào thực sự cần**

Câu hỏi để lọc: field này có được dùng trong rule không? Field này có xuất hiện trên dashboard không? Nếu không thì bỏ.

**Bước 3 — Viết custom decoder đè lên decoder gốc**

```xml
<!-- /var/ossec/etc/decoders/local_decoder.xml -->
<decoder name="ten-custom">
  <parent>ten-decoder-goc</parent>
  <use_own_name>true</use_own_name>
  <prematch>...</prematch>
  <regex>...</regex>
  <order>chi, giu, field, can</order>
</decoder>
```

**Bước 4 — Test lại**

```bash
sudo /var/ossec/bin/wazuh-logtest
# paste log mẫu, kiểm tra Phase 2 chỉ còn field cần
```

**Bước 5 — Deploy**

```bash
sudo systemctl restart wazuh-manager
```

**Bước 6 — Kiểm tra dung lượng sau vài ngày**

```bash
wc -l /var/ossec/logs/alerts/alerts.json
du -sh /var/ossec/logs/alerts/
du -sh /var/ossec/logs/archives/
```

---

## 8. Tổng hợp — bảng field nên giữ theo loại log

| Log source       | Field nên giữ                                                          | Field nên bỏ                          |
| ---------------- | ---------------------------------------------------------------------- | ------------------------------------- |
| Windows Security | `eventID`, `severityValue`, `targetUserName`, `ipAddress`, `logonType` | `opcode`, `version`, `message` dài    |
| Windows Sysmon   | `eventID`, `image`, `commandLine`, `srcip`, `dstip`, `dstport`         | chưa chắc                             |
| pfSense          | `action`, `srcip`, `dstip`, `dstport`, `protocol`                      | `id` rule number, `length`, chưa chắc |
| Apache           | `srcip`, `url`, `id` (status), `action` (method)                       | `user_agent`, `referer`, byte size    |
| Squid            | `srcip`, `url`, `action`, `status`                                     | Thời gian xử lý, byte count           |
| ClamAV           | `data` (file path), `extra_data` (virus name)                          | Engine version, DB version            |
| Snort/Suricata   | `id` (signature), `srcip`, `dstip`, `extra_data`                       | Raw payload hex                       |
| Linux SSH        | `srcip`, `srcuser`, `status`                                           | PID, banner                           |
| Linux sudo       | `srcuser`, `dstuser`, `data` (command)                                 | TTY, PWD nếu không cần                |

---

## 9. Lưu ý quan trọng

**Không sửa file trong `/var/ossec/ruleset/decoders/`** — update Wazuh sẽ ghi đè. Mọi custom decoder viết vào `/var/ossec/etc/decoders/local_decoder.xml`.

**`use_own_name: true`** — bắt buộc khi muốn decoder con có tên riêng thay vì kế thừa tên decoder cha. Cần thiết khi muốn đè lên decoder gốc.

**Thứ tự load** — file trong `/var/ossec/etc/decoders/` load SAU `/var/ossec/ruleset/decoders/`. Nếu cùng tên decoder cha, decoder custom sẽ chạy sau decoder gốc — cả hai đều chạy, không phải thay thế. Muốn thay thế hoàn toàn thì dùng tên khác + `use_own_name`.

**Field `message` của Windows** — đây là field tốn dung lượng nhất. Không thể bỏ ở tầng decoder (vì decoder C nhúng), nhưng có thể dùng rule `no_log` để không lưu toàn bộ event vào archives với một số Event ID ít quan trọng.