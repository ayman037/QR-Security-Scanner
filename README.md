# 🛡️ QR Security Scanner & Threat Intelligence
**أداة متقدمة لفحص رموز QR وتحليل التهديدات الأمنية**

---

## 🌍 Overview | نظرة عامة
This is a full-stack cybersecurity tool that extracts URLs from QR codes and performs deep security analysis using **VirusTotal v3 API**. It's designed to protect users from phishing and malicious links.

أداة أمنية متكاملة لاستخراج الروابط من رموز QR وإجراء تحليل أمني عميق لها. تهدف الأداة لحماية المستخدمين من الروابط الخبيثة وهجمات التصيد الاحتيالي.

---

## ✨ Key Features | المميزات الرئيسية
* **🔍 Advanced QR Decoding:** Precise QR reading using OpenCV.
* **🛡️ Threat Intelligence:** Get detailed reports from 70+ antivirus engines (Google, Kaspersky, Symantec, etc.).
* **🎨 Modern Security Dashboard:** A professional dark-mode UI with real-time status badges.
* **🔒 Safe Environment:** Fully secured using environment variables (`.env`).
* **🚀 URL Unshortening:** Detecting the final destination of shortened links.

---

## 🛠️ Built With | التقنيات المستخدمة
* **Python (Flask)** - Backend Logic
* **OpenCV** - Image Processing
* **VirusTotal API v3** - Threat Intelligence
* **Bootstrap 5** - Responsive Frontend UI
* **Python-Dotenv** - Security & Configuration

---

## 🚀 Installation & Setup | التثبيت والتشغيل

1. **Clone & Install:**
   ```bash
   git clone [https://github.com/ayman037/QR-Security-Scanner.git](https://github.com/ayman037/QR-Security-Scanner.git)
   cd QR-Security-Scanner
   pip install -r requirements.txt