### 1. Tại sao cần Threat Intelligence?

Câu hỏi thực tế: một lỗ hổng nghiêm trọng của Microsoft vừa được công bố. Exploit code xuất hiện trên internet sau 48 giờ. Vendor IDS/IPS của bạn cam kết cung cấp detection rules "up-to-date" — nhưng mất hơn **2 tuần** để release rule mới. Trong 2 tuần đó, hệ thống bị phơi nhiễm hoàn toàn. Rule tự viết chắp vá không hoạt động hiệu quả.

**Vấn đề cốt lõi:** Threat intelligence không phải là thứ bạn có thể lấy từ một nguồn duy nhất rồi tin tưởng tuyệt đối. Mỗi nguồn có điểm mạnh, điểm yếu, tốc độ cập nhật khác nhau. Analyst giỏi biết **đánh giá, kết hợp, và ra quyết định** từ nhiều nguồn — không phải chỉ subscribe một feed rồi thôi.

---

### 2. Câu chuyện tấn công thực tế — Khi một feed không đủ

Năm 2017, WannaCry ransomware lan rộng toàn cầu trong vài giờ. Nhiều tổ chức đã có thông tin về lỗ hổng EternalBlue từ nhiều tuần trước qua OSINT và các CERT warning — nhưng không patch vì **threat feed nội bộ chưa đánh giá là critical**, và team security chưa kịp cross-check với các nguồn khác.

Các tổ chức dùng nhiều feed, bao gồm cả dark web intelligence (nơi exploit đã được rao bán trước đó), đã nhận ra mức độ nghiêm trọng sớm hơn và kịp patch hoặc isolate hệ thống vulnerable.

**Bài học:** Một feed trễ hoặc không đủ là điểm mù chết người. Multiple feeds để cross-check không phải xa xỉ — đó là requirement cơ bản của threat intelligence program hiệu quả.

---

### 3. Hai loại nguồn Threat Intelligence

#### 3.1 Open Source Intelligence (OSINT) — Công khai nhưng cần đánh giá kỹ

**Nguồn công khai tiêu biểu:**

**SANS Internet Storm Center (ISC)** — theo dõi threat và attack trend toàn cầu theo thời gian thực. Cập nhật liên tục, miễn phí, đáng tin cậy cao. isc.sans.org

**VirusShare** — cung cấp thông tin về malware được upload lên VirusTotal. Hữu ích cho malware research và file analysis. virusshare.com

**Spamhaus** — tập trung vào block lists, bao gồm bốn danh sách quan trọng:

|Danh sách|Mô tả|
|---|---|
|**SBL** (Spamhaus Block List)|Danh sách IP nguồn spam|
|**XBL** (Exploits Block List)|Máy bị hijacked hoặc compromised|
|**PBL** (Policy Block List)|IP không nên gửi mail trực tiếp|
|**DROP** (Don't Route or Peer)|Netblock không nên cho phép traffic — stolen/hijacked address space|

Nhiều quốc gia cũng duy trì cổng thông tin an ninh mạng quốc gia — ví dụ **Australian Signals Directorate's Cyber Security Centre** (cyber.gov.au). Chuyên gia bảo mật cần làm quen với intelligence providers lớn tại các quốc gia nơi tổ chức hoạt động.

---

**Các nguồn OSINT quan trọng khác:**

**Social Media** — thông tin **rất kịp thời** (highly timely), thường là nơi đầu tiên threat mới xuất hiện. Nhưng **khó xác định veracity** (tính xác thực) — tin đồn, thông tin sai có thể lan rộng. Xác thực thông tin từ nguồn kém tin cậy tốn nhiều thời gian và tài nguyên.

**Blogs và Forums** — ít phổ biến hơn trước nhưng vẫn hữu ích cho **in-depth analysis** và chi tiết kỹ thuật. Nhiều researcher chia sẻ phân tích malware chi tiết qua blog cá nhân trước khi được publish chính thức.

**CERT và CSIRT** — Computer Emergency Response Team và Cybersecurity Incident Response Team công bố thông tin qua website và social media. Đặc biệt hữu ích khi xác định được CERT/CSIRT **cùng ngành** — họ đối mặt với threat tương tự và chia sẻ intelligence liên quan trực tiếp.

**Dark Web và Deep Web** — hai khái niệm khác nhau:

- **Dark web**: Site chỉ truy cập qua **Tor browser** — nơi threat actors mua bán exploit, credential, và chia sẻ tool
- **Deep web**: Phần internet không được index bởi search engine thông thường — forums kín, closed services, private communities

Commercial data feeds thường thu thập intelligence từ threat actor forums, underground marketplaces, và human-sourced intelligence trên dark/deep web. Xác thực khó nhưng **visibility trực tiếp vào hoạt động của threat actors mang lại giá trị rất cao và kịp thời** — bạn thấy threat đang được chuẩn bị trước khi nó tấn công.

---

#### 3.2 Proprietary và Closed Source Intelligence — Trả tiền để có chất lượng

Commercial security vendors, government organizations, và security-centric organizations xây dựng **proprietary intelligence** với:

- Custom tools và analysis models riêng
- Dữ liệu đã được curate và validated
- Cung cấp dưới dạng paid feeds hoặc chỉ dùng nội bộ

**Ba lý do tổ chức dùng proprietary intelligence thay vì chỉ OSINT:**

**Confidentiality** — giữ bí mật dữ liệu; không muốn threat actors biết mình đang theo dõi gì.

**Trade secrets** — intelligence được bán hoặc cấp phép như tài sản thương mại; đây là sản phẩm kinh doanh.

**Tránh bị phản detect** — nếu OSINT public, threat actors cũng đọc được và điều chỉnh TTP để bypass.

Commercial closed source intelligence thường là một phần của **security subscription service** — giúp tổ chức không bị quá tải bởi lượng OSINT khổng lồ, nhận threat data đã được xử lý, và giảm chi phí phân tích nội bộ.

---

### 4. Đánh giá Threat Intelligence — Ba tiêu chí cốt lõi

Bất kể nguồn nào — public hay proprietary — threat intelligence phải được đánh giá theo ba tiêu chí:

#### Timeliness — Tính kịp thời

Feed trễ khiến bạn phản ứng khi threat đã **không còn liên quan** hoặc đã gây thiệt hại xong. Trong câu chuyện mở đầu, 2 tuần chờ detection rule là thảm họa.

#### Accuracy — Tính chính xác

Ba câu hỏi cần trả lời:

- Có thể tin tưởng assessment này không?
- Dựa vào một hay nhiều nguồn?
- Các nguồn đó có **lịch sử chính xác** không?

#### Relevancy — Tính liên quan

Threat có nhắm đúng **platform** bạn đang dùng không? Đúng **industry** của bạn không? Ảnh hưởng đến **tổ chức của bạn** không?

Dữ liệu có thể rất chính xác nhưng **hoàn toàn không liên quan** — threat nhắm vào SAP ERP trong khi tổ chức bạn không dùng SAP. Đừng lãng phí tài nguyên vào intelligence không liên quan.

---

### 5. Confidence Score — Định lượng mức tin cậy

Thay vì đánh giá chủ quan "tin hay không tin", dùng **confidence score** để định lượng. Hệ thống của ThreatConnect là ví dụ điển hình:

|Mức|Score|Ý nghĩa|
|---|---|---|
|**Confirmed**|90–100|Xác minh qua independent sources hoặc direct analysis|
|**Probable**|70–89|Dựa trên logical inference; có cơ sở tốt|
|**Possible**|50–69|Có bằng chứng nhưng chưa xác nhận hoàn toàn|
|**Doubtful**|30–49|Có thể đúng nhưng không phải khả năng cao nhất|
|**Improbable**|2–29|Ít hợp lý hoặc bị phản bác bởi thông tin khác|
|**Discredited**|1|Đã được xác nhận là **sai**|

**Nguyên tắc sử dụng:**

- Low confidence intelligence → **không bỏ qua hoàn toàn** — có thể là early warning signal
- Nhưng **không dùng làm cơ sở cho quyết định quan trọng** — không block production traffic chỉ dựa trên Possible intelligence

---

### 6. Bốn lĩnh vực ứng dụng Threat Intelligence Sharing

Threat intelligence được chia sẻ để phục vụ bốn lĩnh vực — tất cả đều phục vụ **risk management**:

**Incident Response** — nhận diện threat actor, hiểu TTP, hỗ trợ response planning. Biết đang đối mặt với ai → điều chỉnh containment strategy phù hợp.

**Vulnerability Management** — ưu tiên patch dựa trên **active exploitation** thay vì chỉ CVSS score; xử lý zero-day khẩn cấp khi có exploit in-the-wild.

**Detection và Monitoring** — cập nhật detection rules theo threat mới; tăng khả năng behavioral detection dựa trên TTP đã biết.

**Security Engineering** — thiết kế hệ thống có tính đến xu hướng threat; tích hợp threat awareness vào kiến trúc bảo mật từ đầu.

---

### 7. Ba chuẩn chia sẻ Threat Intelligence

Để các tổ chức chia sẻ intelligence với nhau theo cách có thể machine-readable và tự động hóa, có ba chuẩn quan trọng:

#### STIX — Ngôn ngữ mô tả threat

**STIX (Structured Threat Information Expression)** — ngôn ngữ XML do DHS tài trợ, phiên bản hiện tại là **STIX 2.1**.

Định nghĩa **12 STIX domain objects** bao gồm: attack patterns, identities, malware, threat actors, tools, và các loại khác.

Quan hệ giữa các object được mô tả qua:

- **Relationship** — mô tả mối liên hệ giữa hai object
- **Sighting** — ghi nhận việc một indicator được quan sát thấy

Hình dung STIX như **ngôn ngữ chung** để mọi tổ chức mô tả threat theo cùng một cách — như JSON API nhưng cho threat intelligence.

#### TAXII — Giao thức truyền tải

**TAXII (Trusted Automated Exchange of Indicator Information)** — giao thức truyền threat intelligence qua HTTPS, thiết kế để hỗ trợ STIX exchange.

Nếu STIX là nội dung (cái gì), thì TAXII là phương tiện vận chuyển (bằng cách nào). Hai thứ hoạt động cùng nhau.

#### OpenIOC — Framework IOC của Mandiant

**OpenIOC** — framework XML-based do Mandiant phát triển, mô tả IOC gồm bốn thành phần:

- **Metadata** — thông tin mô tả về IOC
- **Investigation reference** — tham chiếu điều tra liên quan
- **Maturity information** — mức độ hoàn thiện của IOC
- **Indicator definition** — định nghĩa chính xác của indicator

> 🔍 **Exam tip:** STIX = nội dung/format. TAXII = giao thức truyền tải. Hai cái này thường đi cùng nhau. OpenIOC = framework riêng của Mandiant. Đề hay hỏi phân biệt ba chuẩn này.

---

### 8. Intelligence Cycle — Vòng đời của Threat Intelligence

Threat intelligence không phải thu thập một lần rồi xong — đây là **vòng lặp liên tục** gồm năm bước:

#### Bước 1 — Requirements Gathering

Xác định **cần biết gì**:

- Phân tích breach trước đó — threat nào đã tấn công mình?
- Xác định thông tin nào có thể đã ngăn chặn sự cố
- Đánh giá thiếu sót trong security controls hiện tại

#### Bước 2 — Data Collection

Thu thập dữ liệu từ các threat intelligence sources đã xác định. Có thể lặp lại khi requirements thay đổi — nếu tổ chức mở rộng sang thị trường mới, threat landscape thay đổi, cần thu thập lại.

#### Bước 3 — Data Processing and Analysis

- **Chuẩn hóa format** — dữ liệu từ nhiều nguồn có format khác nhau, phải normalize
- **Phân tích** — tìm pattern, correlation, và actionable insight
- **Feed vào automated systems** hoặc viết báo cáo cho con người đọc

#### Bước 4 — Intelligence Dissemination

Phân phối intelligence đến đúng đối tượng:

- **Leadership** — executive summary, risk implications
- **Operational teams** — technical details, detection rules, IOCs

#### Bước 5 — Feedback

Thu thập phản hồi từ người nhận intelligence — có hữu ích không, có đủ chi tiết không, có kịp thời không — để cải tiến liên tục chương trình.

---

### 9. Threat Intelligence Community — Ai chia sẻ với ai?

#### ISAC — Information Sharing and Analysis Centers

**ISAC** ra đời năm **1998** theo Presidential Decision Directive 63 (PDD-63). Mô hình hoạt động:

- Chia sẻ threat và vulnerability information giữa các tổ chức **cùng ngành**
- Hoạt động theo **trust model** — thành viên tin tưởng lẫn nhau, chia sẻ thông tin nhạy cảm
- Nhiều ISAC hoạt động **24/7**

Ví dụ: FS-ISAC cho tài chính, H-ISAC cho y tế, E-ISAC cho điện lực. Nếu bạn ở ngành ngân hàng, FS-ISAC là nguồn intelligence cực kỳ liên quan.

#### CISA và các cơ quan quốc gia tương đương

|Quốc gia|Cơ quan|
|---|---|
|**Mỹ**|CISA (Cybersecurity and Infrastructure Security Agency)|
|**Anh**|CPNI (Centre for the Protection of National Infrastructure)|
|**Úc**|ASD Cyber Security Centre (cyber.gov.au)|

Nhiều quốc gia có cơ quan tương tự — chuyên gia bảo mật cần biết cơ quan nào tại các quốc gia nơi tổ chức hoạt động.

---

### 10. Bảng thuật ngữ bắt buộc nhớ

**Threat intelligence** — thông tin có thể hành động được về threat actors, capabilities, và IOCs

**OSINT (Open Source Intelligence)** — intelligence từ nguồn công khai; timeliness tốt nhưng cần xác thực

**SANS ISC** — Internet Storm Center; theo dõi threat toàn cầu real-time; nguồn OSINT đáng tin cậy

**VirusShare** — thông tin malware từ VirusTotal; hữu ích cho malware research

**Spamhaus** — chuyên về block lists; SBL, XBL, PBL, DROP

**SBL** — Spamhaus Block List; IP nguồn spam

**XBL** — Exploits Block List; máy bị hijacked hoặc compromised

**PBL** — Policy Block List; IP không nên gửi mail trực tiếp

**DROP** — Don't Route or Peer; netblock stolen/hijacked không nên cho phép traffic

**CERT / CSIRT** — tổ chức phản ứng sự cố; publish threat information; đặc biệt hữu ích khi cùng ngành

**Dark web** — chỉ truy cập qua Tor; nơi threat actors hoạt động; visibility cao nhưng xác thực khó

**Deep web** — phần internet không được search engine index; forums kín, closed services

**Veracity** — tính xác thực của thông tin; thách thức lớn nhất với social media intelligence

**Proprietary intelligence** — closed source; validated, curated; trả phí; tránh threat actors biết mình đang theo dõi

**Timeliness** — tính kịp thời; feed trễ = phản ứng muộn

**Accuracy** — tính chính xác; nhiều nguồn cross-check tốt hơn một nguồn

**Relevancy** — tính liên quan; chính xác nhưng không liên quan = lãng phí tài nguyên

**Confidence score** — định lượng mức tin cậy; Confirmed (90-100) → Discredited (1)

**Confirmed** — 90-100; xác minh qua independent sources hoặc direct analysis

**Discredited** — score 1; đã xác nhận là sai

**STIX** — Structured Threat Information Expression; XML; DHS; STIX 2.1; 12 domain objects; mô tả **nội dung** threat

**TAXII** — Trusted Automated Exchange of Indicator Information; giao thức HTTPS; truyền tải STIX; mô tả **cách truyền**

**OpenIOC** — XML framework của Mandiant; mô tả IOC gồm metadata, investigation reference, maturity, indicator definition

**Intelligence Cycle** — 5 bước: Requirements → Collection → Processing/Analysis → Dissemination → Feedback

**Requirements Gathering** — bước 1; xác định cần biết gì dựa trên breach trước và thiếu sót hiện tại

**Intelligence Dissemination** — bước 4; phân phối đến leadership và operational teams

**ISAC** — Information Sharing and Analysis Centers; ra đời 1998 theo PDD-63; chia sẻ theo ngành; trust model; nhiều ISAC 24/7

**PDD-63** — Presidential Decision Directive 63; văn bản pháp lý tạo ra ISAC năm 1998

**CISA** — Cybersecurity and Infrastructure Security Agency; cơ quan threat intelligence quốc gia của Mỹ

**CPNI** — Centre for the Protection of National Infrastructure; tương đương CISA tại Anh

**Multiple feeds** — cross-check giữa nhiều nguồn; best practice khi một feed có thể cập nhật chậm hơn feed khác

---

### 11. Tóm tắt nhanh cho kỳ thi

**Hai loại nguồn** → OSINT (public, kịp thời, cần xác thực) và Proprietary (trả phí, validated, confidential)

**Spamhaus block lists** → SBL (spam), XBL (compromised machines), PBL (policy), DROP (stolen netblocks); nhớ đủ bốn cái

**Dark web ≠ Deep web** → Dark web = Tor only; Deep web = không được search engine index

**Ba tiêu chí đánh giá** → Timeliness + Accuracy + Relevancy; dữ liệu chính xác nhưng không liên quan = vô dụng

**Confidence score** → Confirmed (90-100) đến Discredited (1); low confidence không bỏ qua nhưng không dùng cho quyết định quan trọng

**STIX vs TAXII** → STIX = format/nội dung (XML, 12 domain objects); TAXII = giao thức truyền tải (HTTPS); thường đi cùng nhau

**OpenIOC** → Mandiant; XML; metadata + investigation reference + maturity + indicator definition

**Intelligence Cycle** → 5 bước: Requirements → Collection → Processing → Dissemination → Feedback; vòng lặp liên tục

**ISAC** → 1998, PDD-63, chia sẻ theo ngành, trust model, 24/7

**Multiple feeds** → cross-check; một feed chậm không đủ; vendor có thể mất 2 tuần update rule

**Bốn lĩnh vực ứng dụng** → Incident Response + Vulnerability Management + Detection/Monitoring + Security Engineering; tất cả phục vụ Risk Management