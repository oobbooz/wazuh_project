

---

### 1. Tại sao cần phân loại Threat?

Câu hỏi thực tế: SIEM vừa tạo alert — có ai đó đang scan hệ thống từ ngoài vào. Bạn có 15 phút để quyết định mức độ ưu tiên phản ứng. Đây là script kiddie chạy tool scan ngẫu nhiên, hay là APT do quốc gia bảo trợ đang reconnaissance trước khi tấn công có chủ đích?

Câu trả lời quyết định tất cả: mức độ alert, nguồn lực phân bổ, loại response, và thậm chí ai cần được thông báo.

**Vấn đề cốt lõi:** Không có hệ thống phân loại chuẩn hóa, mỗi người mô tả threat theo cách khác nhau — analyst A nói "hacker nước ngoài", analyst B nói "APT", CISO nghe "tội phạm mạng". Không ai hiểu nhau và không thể so sánh, phân tích ở cấp chiến lược. Threat classification giải quyết điều này bằng cách tạo ra **ngôn ngữ chung** để mô tả, phân loại, và so sánh mối đe dọa một cách nhất quán.

---

### 2. Câu chuyện tấn công thực tế — SolarWinds và bài học về Supply Chain

Năm 2020, hàng nghìn tổ chức bị compromise thông qua bản cập nhật phần mềm SolarWinds Orion — một công cụ IT monitoring được tin tưởng và cài đặt rộng rãi. Attacker đã cấy mã độc **Sunburst** vào trong chính bản build hợp lệ của SolarWinds.

Đây không phải script kiddie, không phải hacktivist, không phải tội phạm tài chính thông thường. Đây là **nation-state APT** (sau này được xác định là SVR của Nga) với đặc điểm:

- Hoạt động ẩn mình hơn **9 tháng** trước khi bị phát hiện
- Nhắm mục tiêu cụ thể: cơ quan chính phủ Mỹ và tập đoàn công nghệ chiến lược
- Dùng **supply chain** làm vector — bypass hoàn toàn perimeter security

**Bài học:** Hiểu **ai** đang tấn công bạn quyết định **cách** bạn phòng thủ. Nếu nhầm nation-state APT với script kiddie → đánh giá thấp, phản ứng chậm, thiệt hại nghiêm trọng. Threat classification là nền tảng của threat modeling đúng đắn.

---

### 3. Sáu nhóm Threat Actors — Biết ai để biết cách phòng

#### 3.1 Nation-State Actors — Kẻ thù mạnh nhất

**Nation-state actors** là threat actors được quốc gia bảo trợ — có bốn lợi thế mà không nhóm nào khác có đủ:

- **Nguồn lực lớn** — ngân sách không giới hạn, có thể mua zero-day exploit giá hàng triệu đô
- **Công cụ tấn công nâng cao** — phát triển malware riêng, custom implant
- **Nhân lực chuyên môn cao** — team hàng trăm người, chuyên nghiệp
- **Thời gian dài hạn** — sẵn sàng ẩn mình nhiều tháng, nhiều năm

Nation-state actors thường liên quan đến **APT (Advanced Persistent Threat)** — chiến dịch tấn công có tính dài hạn, nhắm mục tiêu cụ thể, được thực hiện bởi tổ chức năng lực cao.

Mục tiêu phù hợp với **lợi ích chiến lược quốc gia**: gián điệp chính trị, đánh cắp bí mật quân sự, phá hoại hạ tầng kinh tế đối thủ.

> 🔍 **Exam tip:** APT = Advanced Persistent Threat. Ba chữ quan trọng: Advanced (năng lực cao), Persistent (dài hạn, không bỏ cuộc), Threat (có chủ đích cụ thể). Nation-state là nhóm điển hình nhất của APT.

---

#### 3.2 Organized Crime — Tiền là động lực

**Organized crime** hoạt động thuần túy vì **financial gain** — mô hình kinh doanh ngầm, có tổ chức, hoạt động xuyên quốc gia.

Ví dụ điển hình:

- **Ransomware attacks** — mã hóa dữ liệu, đòi tiền chuộc; một số nhóm vận hành theo mô hình **Ransomware-as-a-Service**
- Chiến dịch lừa đảo quy mô lớn — BEC (Business Email Compromise), financial fraud

Đặc điểm: chuyên nghiệp như doanh nghiệp thật — có support team, có SLA trả key sau khi nhận tiền, có affiliate program cho các nhóm tấn công nhỏ hơn.

---

#### 3.3 Hacktivists — Tư tưởng là vũ khí

**Hacktivists** kết hợp hacking với activism — sử dụng tấn công mạng để phục vụ mục tiêu chính trị, triết học, hoặc xã hội.

Có thể là cá nhân đơn lẻ hoặc nhóm lớn như **Anonymous**. Hành động điển hình: DDoS vào website tổ chức bị phản đối, defacement (thay đổi giao diện website), leak dữ liệu nội bộ ra công chúng.

**Đánh giá hacktivist threat cần trả lời hai câu hỏi:**

- Tổ chức có thuộc ngành dễ bị nhắm không? (dầu mỏ, vũ khí, chính phủ gây tranh cãi)
- Có xung đột chính trị hoặc xã hội nào liên quan đến tổ chức không?

---

#### 3.4 Script Kiddies — Không tinh vi nhưng vẫn nguy hiểm

**Script kiddies** là cá nhân sử dụng **công cụ có sẵn** mà **không hiểu sâu** cách chúng hoạt động — áp dụng kỹ thuật một cách thiếu tinh vi, không có chiến lược cụ thể.

Nghe có vẻ không đáng lo — nhưng nếu công cụ đủ mạnh (exploit framework, DDoS tool), thiệt hại vẫn có thể lớn. Script kiddie không nhắm mục tiêu cụ thể — họ scan internet và tấn công bất kỳ hệ thống nào vulnerable.

> ⚠️ **CySA+ CS0-003 nhấn mạnh hơn** về script kiddies so với phiên bản trước — đừng bỏ qua nhóm này.

---

#### 3.5 Insider Threats — Kẻ thù đã ở trong nhà

**Insider threats** đến từ người có quyền truy cập hợp pháp — nhân viên, nhà thầu, đối tác. Đây là nhóm nguy hiểm nhất về mặt phát hiện vì:

- Có **trusted position** — bypass nhiều cơ chế kiểm soát
- Biết rõ hệ thống nội bộ — biết dữ liệu quan trọng ở đâu, cơ chế giám sát có gì
- Traffic và hành vi trông hợp lệ với hệ thống giám sát thông thường

**Hai loại quan trọng phải phân biệt:**

|Loại|Mô tả|Ví dụ|
|---|---|---|
|**Intentional insider threat**|Cố ý gây hại hoặc đánh cắp|Nhân viên bán data cho đối thủ, sabotage hệ thống trước khi nghỉ việc|
|**Unintentional insider threat**|Vô ý, do bất cẩn hoặc thiếu kiến thức|Click phishing email, cắm USB lạ vào máy công ty, cấu hình sai S3 bucket|

Insider threats được xem là **nguyên nhân phổ biến của breach** — và unintentional thường chiếm tỷ lệ cao hơn intentional.

> ⚠️ **Exam trap:** Đề hỏi "loại insider threat nào phổ biến hơn" → **unintentional** thường được trích dẫn nhiều hơn. Nhưng intentional nguy hiểm hơn về mức độ thiệt hại tiềm năng.

---

#### 3.6 Supply Chain Threat Actors — Tấn công qua chuỗi tin tưởng

**Supply chain threat actors** không tấn công trực tiếp vào mục tiêu — thay vào đó, họ **compromise một bên thứ ba được tin tưởng** trong chuỗi cung ứng:

- Cấy mã độc vào **phần mềm hoặc firmware** trước khi phân phối
- Chèn **backdoor** vào thiết bị phần cứng
- Tấn công nhà cung cấp dịch vụ để tiếp cận nhiều khách hàng cùng lúc

Tại sao nguy hiểm đặc biệt: phần mềm/thiết bị đến từ nguồn hợp lệ, có chữ ký số hợp lệ — vượt qua hoàn toàn mọi kiểm tra thông thường.

Các cuộc tấn công supply chain gần đây (SolarWinds, 3CX, XZ Utils) đã thúc đẩy ngành phát triển:

- **Integrity validation** — kiểm tra tính toàn vẹn của mọi component
- **Trusted supply chain models** — SBOM (Software Bill of Materials), code signing verification

> ⚠️ **CySA+ CS0-003 nhấn mạnh hơn** về supply chain so với phiên bản trước — nhóm này ngày càng phổ biến.

---

### 4. Organizational Threat Assessment — Đừng dùng danh sách chung

Danh sách sáu nhóm trên **không phải đầy đủ tuyệt đối** — và không phải nhóm nào cũng liên quan đến mọi tổ chức.

Tổ chức cần thực hiện **organizational threat assessment** để trả lời ba câu hỏi:

**Ai có khả năng nhắm vào tổ chức này?** — Ngân hàng lo organized crime nhiều hơn hacktivist. Nhà thầu quốc phòng lo nation-state nhiều hơn script kiddie.

**Động cơ là gì?** — Tài chính, gián điệp, phá hoại, hay trả thù?

**Khả năng kỹ thuật của họ ra sao?** — Quyết định loại control cần triển khai để phòng thủ hiệu quả.

---

### 5. TTP — Ngôn ngữ phân tích APT

**TTP (Tactics, Techniques, and Procedures)** là framework phân tích hành vi của threat actor — đặc biệt APT. Hiểu TTP của một nhóm = có thể dự đoán hành động tiếp theo của họ và xây dựng detection phù hợp.

#### Tactics — Mục tiêu cấp cao

**Tactics** là **mục tiêu cấp cao** của attacker trong từng giai đoạn tấn công — trả lời câu hỏi "họ đang cố làm gì?"

Ví dụ theo MITRE ATT&CK framework:

- **Initial access** — xâm nhập ban đầu vào mạng
- **Privilege escalation** — leo thang từ user thường lên admin/root
- **Lateral movement** — di chuyển từ máy này sang máy khác trong mạng
- **Exfiltration** — tuồn dữ liệu ra ngoài

---

#### Techniques — Phương pháp cụ thể

**Techniques** là **phương pháp cụ thể** để thực hiện một tactic — trả lời câu hỏi "họ làm điều đó bằng cách nào?"

Ví dụ:

- Initial access qua **spear phishing** (email lừa đảo nhắm mục tiêu cụ thể)
- Privilege escalation qua **exploit vulnerability** trong OS
- Credential dumping để lấy password hash từ memory

---

#### Procedures — Cách triển khai đặc trưng

**Procedures** là cách một **nhóm APT cụ thể** triển khai technique đó trong thực tế — trả lời câu hỏi "nhóm này làm nó theo cách đặc trưng nào?"

Đây là thứ tạo nên **fingerprint** của từng nhóm:

- Dùng biến thể malware riêng với tên file đặc trưng
- Domain giả mạo theo pattern nhất định
- Hạ tầng C2 trên một số ASN quen thuộc
- Cách xóa dấu vết (cleanup) theo quy trình cố định

---

#### TTP trong phân tích APT thực tế

Phân tích APT toàn diện bao gồm tám góc độ:

|Góc độ|Ý nghĩa|
|---|---|
|**Campaign initiation**|Chiến dịch bắt đầu như thế nào|
|**Reconnaissance**|Thu thập thông tin mục tiêu bằng phương pháp nào|
|**Initial probing**|Thăm dò ban đầu — scan, test vulnerability|
|**Social engineering**|Kỹ thuật thao túng con người được dùng|
|**Infrastructure usage**|Hạ tầng C2, domain, IP range đặc trưng|
|**Compromise process**|Quy trình xâm nhập từng bước|
|**Cleanup process**|Cách xóa dấu vết để tránh bị phát hiện|
|**Identifying traits**|Đặc trưng nhận diện tổng hợp của nhóm|

Những đặc điểm này kết hợp tạo thành **identifying traits** — cho phép analyst nhận ra "đây là nhóm APT X" ngay cả khi chưa có attribution chính thức.

---

### 6. Bảng thuật ngữ bắt buộc nhớ

**Threat classification** — hệ thống phân loại mối đe dọa tiêu chuẩn hóa; tạo ngôn ngữ chung để mô tả và so sánh threat

**Standard descriptive schemes** — phương pháp mô tả tiêu chuẩn hóa; nền tảng của threat classification

**Organizational threat assessment** — đánh giá mối đe dọa ở cấp tổ chức; xác định ai nhắm vào mình, động cơ gì, năng lực ra sao

**Nation-state actors** — threat actors được quốc gia bảo trợ; nguồn lực lớn, công cụ nâng cao, hoạt động dài hạn

**APT (Advanced Persistent Threat)** — mối đe dọa dai dẳng nâng cao; Advanced + Persistent + Targeted; điển hình là nation-state

**Organized crime** — tội phạm có tổ chức; động cơ tài chính; ransomware, fraud; mô hình kinh doanh ngầm

**Ransomware** — mã độc mã hóa dữ liệu đòi tiền chuộc; công cụ điển hình của organized crime

**Hacktivists** — hack + activists; mục tiêu chính trị/triết học/xã hội; DDoS, defacement, data leak

**Script kiddies** — dùng tool có sẵn không hiểu sâu; không tinh vi nhưng vẫn gây thiệt hại; nhấn mạnh hơn trong CS0-003

**Insider threats** — mối đe dọa nội bộ từ người có trusted access; hai loại: intentional và unintentional

**Intentional insider threat** — cố ý gây hại; bán data, sabotage; thiệt hại lớn hơn

**Unintentional insider threat** — vô ý do bất cẩn; click phishing, cấu hình sai; phổ biến hơn

**Supply chain threat actors** — tấn công qua chuỗi cung ứng; cấy malware vào software/firmware; bypass perimeter security; nhấn mạnh hơn trong CS0-003

**Integrity validation** — kiểm tra tính toàn vẹn component trong supply chain; phòng thủ chính chống supply chain attack

**Trusted supply chain models** — mô hình chuỗi cung ứng đáng tin cậy; SBOM, code signing

**TTP (Tactics, Techniques, and Procedures)** — framework phân tích hành vi APT; ba cấp độ từ cao xuống chi tiết

**Tactics** — mục tiêu cấp cao của attacker trong từng giai đoạn; "họ đang cố làm gì?"

**Techniques** — phương pháp cụ thể để thực hiện tactic; "họ làm bằng cách nào?"

**Procedures** — cách triển khai đặc trưng của một nhóm cụ thể; "nhóm này làm theo cách riêng nào?"

**Identifying traits** — đặc trưng nhận diện tổng hợp của một nhóm APT; fingerprint của threat actor

**Campaign initiation** — cách chiến dịch APT bắt đầu; phần đầu của TTP analysis

**Lateral movement** — di chuyển ngang trong mạng sau khi xâm nhập; tactic phổ biến trong APT

**Credential dumping** — kỹ thuật lấy password hash từ memory; technique phổ biến cho privilege escalation

**Spear phishing** — email lừa đảo nhắm mục tiêu cụ thể; technique phổ biến cho initial access

**Cleanup process** — quy trình xóa dấu vết; đặc trưng nhận diện của từng APT group

---

### 7. Tóm tắt nhanh cho kỳ thi

**Sáu nhóm threat actors** → Nation-State + Organized Crime + Hacktivists + Script Kiddies + Insider Threats + Supply Chain; CS0-003 nhấn mạnh hơn Script Kiddies và Supply Chain

**Nation-state** = APT, dài hạn, có chủ đích, nguồn lực lớn; **Organized crime** = tài chính, ransomware; **Hacktivist** = chính trị/tư tưởng; **Script kiddie** = tool có sẵn, không tinh vi

**Insider threats** → hai loại: intentional (cố ý, thiệt hại lớn hơn) và unintentional (vô ý, phổ biến hơn)

**Supply chain** → không tấn công trực tiếp mục tiêu; compromise bên thứ ba được tin tưởng; bypass perimeter hoàn toàn

**TTP** → Tactics = mục tiêu cấp cao ("làm gì?"); Techniques = phương pháp cụ thể ("làm bằng cách nào?"); Procedures = cách triển khai đặc trưng của nhóm cụ thể ("nhóm này làm thế nào riêng?")

**Organizational threat assessment** → đừng dùng danh sách chung; phải xác định ai nhắm vào mình cụ thể, động cơ gì, năng lực ra sao

**APT** = Advanced + Persistent + Threat; ba chữ đều quan trọng; nation-state là điển hình nhất

**Identifying traits** → fingerprint của APT group; kết hợp TTP để attribution và detection