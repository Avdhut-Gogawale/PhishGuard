# PhishGuard - SOC Phishing Detection Tool

<p align="center">
  <img src="https://github.com/user-attachments/assets/d105ce54-b92f-4c88-9d57-ba7719b47f8a" alt="PhishGuard Logo">
</p>

PhishGuard is a sophisticated, Python-based security engine designed for Security Operations Center (SOC) analysts to quickly identify and analyze phishing threats. By combining local heuristic analysis with global threat intelligence from VirusTotal, PhishGuard provides a comprehensive risk assessment for both suspicious URLs and email files (.eml).

🚀 **Live Demo**: [https://phishguard-bykp.onrender.com](https://phishguard-bykp.onrender.com)

---

## 🎯 Project Objective
The primary goal of PhishGuard is to bridge the gap between simple manual inspection and complex enterprise security suites. It achieves this by providing:
- **Instant Triage**: Rapid classification of links and emails as Low, Medium, or High risk.
- **Forensic Detail**: Breaking down exactly *why* an item is suspicious (e.g., typosquatting, display name spoofing).
- **Enriched Intelligence**: Deep integration with VirusTotal to provide real-time vendor reputation data.

## 🚀 Key Features
- **🌐 Advanced URL Analysis**: Detects typosquatting (e.g., `googIe.com`), IP-based hostnames, excessive subdomains, and deceptive URL patterns.
- **📧 Deep Email Inspection**: Parses `.eml` files to detect display name spoofing, phishing keywords in subjects, and hidden redirects.
- **🛡️ Multi-Vector VirusTotal Integration**: 
    - Standalone URL scanning.
    - Automatic scanning of all links discovered within an email.
    - **SHA-256 Hashing** of email attachments to check for known malware without uploading the actual file.
- **📊 Risk Scoring Model**: A weighted algorithm that calculates a threat score (0-100) based on multiple security indicators.
- **✨ Modern Dashboard**: A premium, dark-themed Flask interface featuring glassmorphism design for real-time alert monitoring.

---

## 🔄 Technical Flow
1. **Data Ingestion**: The user submits a URL or uploads a `.eml` file via the web dashboard.
2. **Heuristic Engine**: 
    - The `URLAnalyzer` checks for structural anomalies and typosquatting using Levenshtein distance.
    - The `EmailAnalyzer` parses headers for spoofing signatures and extracts all body text, links, and attachments.
3. **Threat Intelligence Enrichment**: The backend sends extracted URLs and attachment hashes to the VirusTotal API.
4. **Scoring & Classification**: Detection results are aggregated. If VT flags an item or multiple heuristic rules are triggered, the score increases, determining the final severity (Low/Medium/High).
5. **Visualization**: A detailed forensic report is generated and displayed on the SOC dashboard for immediate analyst review.

---

## 🛠️ Installation & Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/YourUsername/PhishGuard.git
   cd PhishGuard
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables**:
   Create a `.env` file in the root directory and add your VirusTotal API Key:
   ```env
   VIRUSTOTAL_API_KEY=your_actual_api_key_here
   ```

4. **Run the Application**:
   ```bash
   python app.py
   ```
   Navigate to `http://127.0.0.1:5000` in your browser.

---

## 📈 What PhishGuard Achieves
PhishGuard significantly reduces the time required for initial phishing investigations. Instead of manually checking multiple sites and analyzing headers, an analyst gets a unified view of the threat. It identifies advanced tactics like **display name spoofing** (e.g., "PayPal Security" <hacker@gmail.com>) and **encoded malicious redirects** that are often missed by standard filters.

---

## 🛡️ Future Enhancements
- [ ] **OCR Analysis**: Scanning images within emails for text-based phishing.
- [ ] **Sandboxing**: Automated screenshotting of suspicious URLs in a headless browser.
- [ ] **Exportable Reports**: Generating PDF/JSON forensic reports for incident documentation.
- [ ] **Dark Web Check**: Checking if sender domains or emails have been part of recent data breaches.

---
*Developed by Avdhut Gogawale (CyberSecurity Enthusiastic).*
