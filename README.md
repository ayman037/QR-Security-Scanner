# QR Security Scanner | فاحص الروابط الآمن لرموز QR

### [English Description]
A web-based security tool built with **Python** and **Flask** that scans QR codes from images, extracts the embedded URLs, and analyzes them for potential security threats using the **VirusTotal API**. It features a modern, dark-themed UI and provides real-time analysis of link safety.

**Key Features:**
* **QR Decoding:** Uses OpenCV to accurately read QR codes.
* **Security Analysis:** Integrates with VirusTotal v3 API to check URLs against 70+ antivirus engines.
* **Modern UI:** Responsive dark-mode interface built with Bootstrap 5.
* **Environment Safety:** Uses `.env` files to protect sensitive API keys.

---

### [الوصف باللغة العربية]
أداة أمنية مبنية باستخدام لغة **باثيون** وإطار عمل **Flask**، تقوم بفحص رموز الـ QR من الصور المستخرجة، وتحليل الروابط بداخلها للكشف عن التهديدات الأمنية باستخدام **واجهة برمجة تطبيقات VirusTotal**. يتميز المشروع بواجهة مستخدم عصرية ونظام فحص فوري لسلامة الروابط.

**المميزات الرئيسية:**
* **فك رموز QR:** يستخدم مكتبة OpenCV لقراءة الأكواد بدقة.
* **التحليل الأمني:** يتكامل مع VirusTotal لفحص الروابط عبر أكثر من 70 محرك فحص عالمي.
* **واجهة احترافية:** واجهة مستخدم متجاوبة بنظام "الوضع الداكن" باستخدام Bootstrap 5.
* **حماية البيانات:** يعتمد على ملفات `.env` لحماية مفاتيح الـ API الخاصة بالمستخدم.

---

## How to Run | كيفية التشغيل

1. **Clone the repository | تحميل المشروع:**
   ```bash
   git clone [https://github.com/ayman037/QR-Security-Scanner.git](https://github.com/ayman037/QR-Security-Scanner.git)
   cd QR-Security-Scanner