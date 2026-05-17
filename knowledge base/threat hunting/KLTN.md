# BÁO CÁO CHI TIẾT: PHƯƠNG PHÁP LUẬN VÀ HỆ THỐNG TRỢ LÝ SOC THÔNG MINH TRONG SĂN LÙNG MỐI ĐE DỌA (THREAT HUNTING)

## 1. Bối cảnh Chiến lược và Thách thức của SOC Hiện đại

Trong môi trường an ninh mạng đương đại, các kỹ thuật tấn công đang trải qua sự chuyển dịch mang tính thế hệ. Theo báo cáo điều tra vi phạm dữ liệu năm 2024 của Verizon, các tác nhân đe dọa không còn chỉ dựa vào mã độc (malware) đơn giản mà đã nâng cấp lên các chiến dịch tấn công có chủ đích (APT) và khai thác lỗ hổng chưa biết (Zero-day). Đáng chú ý, các cuộc tấn công hiện nay thường sử dụng kỹ thuật "Living off the Land" (LotL) — lợi dụng chính các công cụ quản trị hợp lệ trong hệ thống để thực hiện hành vi độc hại, khiến chúng trở nên vô hình trước các hệ thống phòng thủ truyền thống.

Các Trung tâm Điều hành An ninh mạng (SOC) đang dần trở nên lỗi thời trước áp lực dữ liệu vì những lý do cốt lõi:

- **Sự thất bại của hệ thống Rule-based:** Các quy tắc thiết lập sẵn và so sánh mẫu nhận dạng (signature matching) không thể bắt kịp các kỹ thuật tấn công tùy chỉnh hoặc LotL vốn mang diện mạo của hành động hợp pháp.
- **Hội chứng "mệt mỏi vì cảnh báo" (Alert fatigue):** Khối lượng log khổng lồ tạo ra hàng nghìn cảnh báo mỗi ngày với tỷ lệ dương tính giả (false positive) cực cao, làm suy kiệt khả năng phân tích của con người.
- **Phòng thủ thụ động vs. Săn lùng chủ động:** Trong khi Phản ứng sự cố (Incident Response) chỉ kích hoạt khi có cảnh báo rõ ràng, Săn lùng mối đe dọa (Threat Hunting) giả định rằng hệ thống đã bị xâm nhập để chủ động đi tìm các thực thể ẩn mình.

Để giải quyết sự thiếu hụt nhân sự trình độ cao và tối ưu hóa năng lực điều tra, AI đóng vai trò là "cầu nối" chiến lược, chuyển đổi SOC từ trạng thái phản ứng sang săn lùng chủ động bằng khả năng phân tích ngữ nghĩa quy mô lớn.

## 2. Hệ thống Săn lùng Mối đe dọa (Threat Hunting): Khung lý thuyết và Công cụ

Một quy trình săn lùng hiệu quả đòi hỏi sự kết hợp chặt chẽ giữa phương pháp luận và hệ sinh thái công nghệ chuẩn hóa.

### Phân loại phương pháp săn lùng chủ đạo

Hệ thống triển khai dựa trên 03 phương pháp tiếp cận chiến lược:

1. **Dựa trên tình báo (Intelligence-Driven):** Sử dụng các nguồn Threat Intelligence (TI) để đối soát các chỉ dấu đã biết.
2. **Dựa trên giả thuyết (Hypothesis-Driven):** Đặt ra kịch bản (ví dụ: leo thang đặc quyền) và truy vấn dữ liệu để chứng minh sự hiện diện của kỹ thuật đó.
3. **Dựa trên phân tích (Analytics/AI-Driven):** Ứng dụng Machine Learning/AI để phát hiện hành vi bất thường vượt ngoài quy tắc tĩnh.

### Vai trò của ELK Stack và Tiêu chuẩn hóa ECS

Hệ thống quản lý log tập trung dựa trên **Elasticsearch, Logstash và Kibana** là nền tảng cốt lõi. Trong đó, việc áp dụng **Elastic Common Schema (ECS)** không chỉ đơn giản là chuẩn hóa tên trường (ví dụ: `src_ip` thành `source.ip`) mà còn là "chìa khóa" để vận hành AI. Nếu không có ECS, cơ chế RAG (Retrieval-Augmented Generation) sẽ trở nên cực kỳ phức tạp vì LLM phải học hàng chục cấu trúc mapping khác nhau cho cùng một loại dữ liệu, gây lãng phí token và giảm độ chính xác của truy vấn.

### Giá trị chiến thuật của Chỉ dấu xâm phạm (IoC)

Trong Threat Hunting, không phải mọi IoC đều có giá trị như nhau. Hệ thống phân loại IoC dựa trên giá trị định danh:

|   |   |   |
|---|---|---|
|Loại IoC|Giá trị Chiến thuật|Độ tin cậy & Độ bền (Persistence)|
|**IP Address**|Định danh nguồn tấn công/C2 server.|Thấp (Dễ thay đổi, thường là proxy/VPN).|
|**Domain/URL**|Phát hiện chiến dịch lừa đảo, hạ tầng điều khiển.|Trung bình (Cung cấp manh mối về hạ tầng kẻ địch).|
|**File Hash (SHA-256)**|Định danh chính xác tệp tin độc hại.|Cao (Duy nhất cho từng mẫu mã độc, khó thay đổi).|

Dù dữ liệu đã được chuẩn hóa, việc xây dựng các câu lệnh Elasticsearch DSL phức tạp vẫn là rào cản lớn, đòi hỏi một giải pháp AI tích hợp để "dịch" ý định của chuyên gia thành mã máy.

## 3. Kiến trúc Hệ thống "Intelligent SOC Assistant"

Hệ thống được thiết kế theo tư duy phân tầng nhằm tự động hóa quy trình điều tra và tối ưu hóa hiệu năng thực thi.

### Phân tầng kiến trúc (03 Tầng)

1. **Tầng dữ liệu (Data Layer):** Backend SIEM dựa trên Elasticsearch để lưu trữ và quản lý log tập trung.
2. **Tầng xử lý logic (Logic Layer):** Sử dụng framework LangChain để điều phối luồng thông tin giữa người dùng, cơ sở dữ liệu vector và LLM.
3. **Tầng AI (AI Layer):** Nơi LLM (GPT-4 hoặc Llama) thực hiện suy luận ngữ nghĩa và sinh câu truy vấn.

### Cơ chế RAG và Kỹ thuật "Làm phẳng" (Flattening Properties)

Để khắc phục hiện tượng "ảo giác" (hallucination) khi xử lý cấu trúc dữ liệu JSON lồng nhau phức tạp của Elasticsearch, hệ thống áp dụng kỹ thuật trọng tâm: **Flattening Properties**.

- **Tại sao cần làm phẳng?** LLM thường gặp khó khăn với các cấu trúc lồng nhau sâu (nested objects) do sự mơ hồ về đường dẫn và tiêu tốn nhiều token để hiểu phân cấp tree-structure.
- **Giải pháp:** Hệ thống chuyển đổi cấu trúc cây mapping thành một danh sách các "đường dẫn phẳng" (flat paths). Kỹ thuật này giúp cơ sở dữ liệu vector ChromaDB thực hiện tìm kiếm tương đồng (similarity search) chính xác hơn, giải quyết triệt để bài toán "Mapping explosion" trong môi trường SIEM doanh nghiệp và cung cấp ngữ cảnh schema sạch nhất cho LLM.

## 4. Cơ chế Bảo mật Dữ liệu nhạy cảm (Data Masking)

Chủ quyền dữ liệu là điều kiện tiên quyết khi ứng dụng AI đám mây (Cloud AI) trong các ngành nghề có quy định nghiêm ngặt. Hệ thống tích hợp module **Data Masker** hoạt động hai chiều để bảo mật hạ tầng:

1. **Quy trình Masking (Tại chỗ):** Trước khi gửi dữ liệu log thô lên AI, hệ thống sử dụng Regex để nhận diện và ẩn danh các thực thể nhạy cảm bao gồm: **Địa chỉ IP, Email, Tài khoản người dùng (User) và Tên máy (Hostname)**.
2. **Quy trình Unmasking:** Sau khi nhận kết quả phân tích từ AI, hệ thống thực hiện khôi phục (mapping ngược) lại giá trị thực để hiển thị cho quản trị viên.

Cơ chế này đóng vai trò là "Enabler" — cho phép doanh nghiệp tận dụng sức mạnh suy luận của GPT-4 mà không vi phạm các tiêu chuẩn tuân thủ bảo mật quốc tế, do dữ liệu định danh thực tế không bao giờ rời khỏi tầm kiểm soát nội bộ.

## 5. Các Module Chức năng và Quy trình Thực thi

Quy trình điều tra được khép kín thông qua 03 module cốt lõi:

- **Module Log Hunter:** Chuyển đổi ngôn ngữ tự nhiên sang Elasticsearch DSL. Xóa bỏ rào cản cú pháp, cho phép chuyên gia tập trung vào chiến thuật điều tra.
- **Module Tích hợp Threat Intelligence:** Tự động trích xuất IoC từ log thô và đối soát thời gian thực với **Abuse.ch** và **VirusTotal** để xác thực mức độ độc hại.
- **Module AI SOC Analyst (Pivoting Logic):** Đây là module mô phỏng tư duy thợ săn thực thụ. Thay vì chỉ nhìn vào một cảnh báo đơn lẻ, AI thực hiện chiến lược **"Xoay trục" (Pivoting)**: Tự động sử dụng mốc thời gian của cảnh báo (Timestamp) để truy vấn dữ liệu trong các khung giờ lân cận (ví dụ: T-5 phút và T+5 phút) nhằm tìm kiếm bằng chứng tương quan và xâu chuỗi kịch bản tấn công hoàn chỉnh.

## 6. Thực nghiệm, Đánh giá Hiệu năng và Kịch bản Thực tế

Hệ thống được đánh giá định lượng trong môi trường Lab với các tiêu chí khắt khe.

### Đánh giá Mô hình và SSR (Syntax Success Rate)

**SSR (Tỷ lệ chính xác cú pháp)** là chỉ số đo lường khả năng sinh mã DSL hợp lệ mà Elasticsearch có thể thực thi được ngay lập tức.

|   |   |   |
|---|---|---|
|Tiêu chí|GPT-4o-mini (Cloud)|Llama 3.1 (Local/Offline)|
|**Tỷ lệ SSR**|**88.7%**|87.3%|
|**Thời gian phản hồi**|**3.2 giây**|Chậm hơn (Phụ thuộc hạ tầng)|
|**Đánh giá chiến lược**|Tối ưu cho hiệu năng thời gian thực.|Lựa chọn tối thượng cho bảo mật/offline.|

### Phân tích kịch bản tấn công thực tế

Hệ thống đã chứng minh hiệu quả qua 03 kịch bản trọng điểm:

1. **URL độc hại:** Phát hiện kết nối đến hạ tầng đen thông qua đối soát TI (Abuse.ch).
2. **Reverse Shell qua Macro:** AI nhận diện hành vi thực thi mã từ xa từ tài liệu văn bản, xác định chính xác luồng truyền thông với máy chủ C2 và đề xuất cô lập.
3. **Mã độc Mimikatz:** Định danh chính xác tệp tin thông qua đối soát mã băm **SHA-256** trùng khớp tuyệt đối với dữ liệu tình báo mã độc.

## 7. Kết luận và Lộ trình Phát triển

Hệ thống "Intelligent SOC Assistant" đã giải quyết thành công bài toán tối ưu hóa nguồn lực SOC thông qua sự kết hợp đột phá giữa kỹ thuật làm phẳng mapping và lớp bảo mật Data Masker.

**Hướng phát triển chiến lược:** Trong tương lai, hệ thống sẽ được nâng cấp từ một "Trợ lý" thành một thực thể có khả năng **Phản ứng tự động (Automated Response)** tương tự các hệ thống SOAR. Lộ trình phát triển tập trung vào việc tra cứu giá trị động để giảm ảo giác và tích hợp khả năng cô lập thiết bị, chặn kết nối mạng trực tiếp trên hạ tầng ngay khi AI xác nhận mối đe dọa với độ tin cậy cao. Việc tích hợp AI không còn là một lựa chọn thêm vào, mà là một yêu cầu sống còn để nâng cao năng lực phản ứng nhanh trước các hiểm họa an ninh mạng tinh vi.

## Luồng xử lý từ trái sang phải:

### 1. Đầu vào – User Query

- Người dùng (quản trị viên SOC) nhập câu hỏi bằng **ngôn ngữ tự nhiên**.
    
- Câu hỏi này được gửi qua **Data Masker** – thành phần che giấu các thông tin nhạy cảm (IP, username, hostname…) thành các biến giả `__LABEL_ID__` trước khi gửi tới các thành phần xử lý khác.
    

### 2. Truy xuất ngữ cảnh schema (RAG – Retrieval)

- **Flattened mappings**: Cấu trúc JSON mapping của Elasticsearch đã được "làm phẳng" thành danh sách các đường dẫn trường (ví dụ: `host.name`, `source.ip`).
    
- **Embedding Model (`all-MiniLM-L6-v2`)**: Chuyển đổi câu hỏi đã được mask thành **vector truy vấn** (Query Vector).
    
- **Vector Store (ChromaDB)**: Lưu trữ các flattened mappings dưới dạng vector số học.
    
- **Similarity Search**: Thực hiện tìm kiếm tương đồng ngữ nghĩa giữa Query Vector và các vector trong ChromaDB.
    
- **Top-K Context (k=5)**: Lấy ra 5 trường dữ liệu có độ tương đồng cao nhất để làm ngữ cảnh cho LLM.
    

### 3. Sinh truy vấn – Generation

- **Prompt Template**: Kết hợp câu hỏi gốc (đã mask) + Top-K context (5 trường dữ liệu) thành một prompt hoàn chỉnh.
    
- **LLM Model** (GPT-4o-mini hoặc Llama 3.1): Sinh ra câu lệnh **Elasticsearch Query DSL** dựa trên ngữ cảnh được cung cấp.
    

### 4. Thực thi và trả kết quả

- **Execute & Result**: Truy vấn DSL được gửi tới Elasticsearch để thực thi, trả về dữ liệu log thô.
    
- **Data Unmasker**: Khôi phục các biến giả `__LABEL_ID__` thành giá trị thật (IP, hostname, user…) trước khi hiển thị kết quả cuối cùng cho người dùng.


###  Về khả năng hiểu ngữ cảnh

|Hạn chế|Giải thích|
|---|---|
|**RAG chỉ hiểu schema, không hiểu data**|Biết trường `event.action` là keyword, nhưng không biết giá trị hợp lệ là `deletion` (sinh ra `deleted` → query rỗng)|
|**Không xâu chuỗi hành vi**|Trả về log rời rạc, không kết nối được `Excel.exe → powershell.exe → tải payload → kết nối C2`|
|**Không dùng MITRE ATT&CK**|Không xác định được chiến thuật/kỹ thuật (VD: T1059), không biết đang ở giai đoạn nào của kill chain|
|**Không đặt giả thuyết**|Chỉ phản ứng với cảnh báo có sẵn, không chủ động săn lùng|

→ **Hệ thống không hiểu "câu chuyện" tấn công, chỉ nhìn từng mảnh rời.**

---

### 2. Về AI và xử lý

|Hạn chế|Giải thích|
|---|---|
|**Phụ thuộc LLM bên thứ ba**|Dùng GPT-4o-mini qua API → mất Internet hoặc OpenAI đổi chính sách là tê liệt|
|**Llama 3.1 quá chậm**|24.8 giây so với 3.2 giây của GPT → không dùng thực tế cho môi trường offline|
|**Data Masker lỗi logic**|AI cố tính toán trên placeholder (`__IP_0__ + 256`) → lỗi parse|
|**Không tự động phản ứng**|Chỉ đề xuất khắc phục, không tự cô lập máy, block IP, kill process|

---

### 3. Về quy mô và dữ liệu

|Hạn chế|Giải thích|
|---|---|
|**Chưa test scale lớn**|Mới chạy trong lab, chưa đánh giá với hàng nghìn endpoint, triệu log/ngày|
|**Nguồn TI hạn chế**|Chỉ [Abuse.ch](https://abuse.ch/) + VirusTotal (public/free), thiếu feed thương mại, MISP, OpenCTI, STIX/TAXII|
|**Chưa tích hợp đa dạng log source**|Chủ yếu log Windows, thiếu log network, firewall, cloud|

---

### 4. Về vai trò và kết luận

|Hạn chế|Giải thích|
|---|---|
|**Chưa thay thế được con người**|Vẫn cần chuyên gia SOC tự đánh giá, kết luận, quyết định xử lý|
|**Kết luận "High severity" thiếu ngữ cảnh**|Dựa chủ yếu vào TI ([Abuse.ch](https://abuse.ch/), VT), không dựa vào hành vi thực tế|
|**Báo cáo dạng template**|Không sinh báo cáo theo đúng kịch bản tấn công cụ thể|

---

### Một câu tóm gọn:

> **Hệ thống giỏi lấy log, nhưng dốt hiểu chuyện. Nó là trợ lý truy vấn nhanh, chưa phải thợ săn mối đe dọa thực thụ.**

k = 5 và pivot đang fix cứng 5p ?

## Đúng. Cả hai đều đang **fix cứng**:

|Tham số|Giá trị fix cứng|Vấn đề|
|---|---|---|
|**k (RAG)**|5|Không thay đổi theo độ phức tạp của câu hỏi|
|**Pivot (thời gian)**|±5 phút|Không điều chỉnh theo loại tấn công|

---

### 1. k=5 fix cứng

- **Thực nghiệm chọn k=5** vì nó cho SSR cao nhất (88.7%) so với k=1 (84%) và k=10 (76.7%)
    
- **Nhưng:** Dù câu hỏi đơn giản hay phức tạp, vẫn luôn lấy đúng 5 trường
    
- **Vấn đề:** Câu hỏi đơn giản (VD: "Tìm log theo IP") không cần 5 trường → lãng phí token. Câu hỏi phức tạp có thể cần >5 trường nhưng bị giới hạn.
    

---

### 2. Pivot ±5 phút fix cứng

- Module AI SOC Analyst tự động mở rộng khung thời gian **±5 phút** quanh mốc cảnh báo
    
- **Vấn đề:**
    
    - Có hành vi diễn ra trong **vài giây** (VD: khai thác lỗ hổng) → 5p quá rộng, nhiễu
        
    - Có hành vi diễn ra trong **nhiều giờ hoặc ngày** (VD: APT leo thang đặc quyền) → 5p quá hẹp, bỏ sót
        
    - Không phân biệt loại tấn công → dùng một cửa sổ cho mọi kịch bản