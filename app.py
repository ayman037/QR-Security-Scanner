from flask import Flask, request, render_template
import cv2
import requests
import os
import time
from dotenv import load_dotenv  

load_dotenv()  

app = Flask(__name__)


API_KEY = os.getenv("VT_API_KEY")

def analyze_url(url):
    if url.lower().startswith("https"):
        return "🔒 Secure (HTTPS)"
    else:
        return "⚠️ Not Secure (No HTTPS)"

def scan_url(url):
    if not API_KEY:
        return "⚠️ API Key not set"

    headers = {"x-apikey": API_KEY}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})

    if response.status_code != 200:
        return "❌ Error submitting URL"

    analysis_id = response.json()["data"]["id"]
    
    for i in range(10): 
        report = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        
        if report.status_code == 200:
            attributes = report.json()["data"]["attributes"]
            if attributes["status"] == "completed":
                results = attributes["results"]
                detected_by = []
                
                # استخراج المحركات التي قالت أن الرابط خبيث
                for engine, data in results.items():
                    if data['category'] == 'malicious':
                        detected_by.append(f"{engine} ({data['result']})")
                
                stats = attributes["stats"]
                malicious = stats.get("malicious", 0)
                
                if malicious > 0:
                    details = " | Detected by: " + ", ".join(detected_by[:3]) # سنعرض أول 3 محركات فقط للاختصار
                    return f"🚨 Malicious ({malicious} detections){details}"
                else:
                    return f"✅ Safe ({stats.get('harmless', 0)} checks)"
            
        time.sleep(2)
    return "⏳ Analysis is still in progress..."
    
    for i in range(10): 
        report = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )
        
        if report.status_code == 200:
            attributes = report.json()["data"]["attributes"]
            status = attributes["status"]
            
            if status == "completed":
                stats = attributes["stats"]
                malicious = stats.get("malicious", 0)
                harmless = stats.get("harmless", 0)
                
                if malicious > 0:
                    return f"🚨 Malicious ({malicious} detections)"
                else:
                    return f"✅ Safe ({harmless} checks)"
            
        time.sleep(2) 
    
    return "⏳ Analysis is still in progress... please try again."

def read_qr(image_path):
    img = cv2.imread(image_path)
    if img is None:
        return None
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(img)
    return data

@app.route('/', methods=['GET', 'POST'])
def index():
    result = ""
    url_found = ""

    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            filename = "upload.png"
            file.save(filename)
            
            url_found = read_qr(filename)
            
            if url_found:
                security = analyze_url(url_found)
                scan_result = scan_url(url_found)
                result = f"URL: {url_found} | {security} | {scan_result}"
            else:
                result = "❌ No QR Code detected"
                
    return render_template('index.html', result=result)

if __name__ == "__main__":
    app.run(debug=True, port=8080)