# PhishGuard - SOC Phishing Detection Tool

PhishGuard is a sophisticated phishing detection engine designed for SOC analysts. It analyzes URLs and email files (.eml) using heuristic rules, typosquatting detection, and VirusTotal threat intelligence.

## Features
- **URL Analysis:** Detects typosquatting, suspicious Top-Level Domains (TLDs), IP-based hostnames, and excessive subdomains.
- **Email Analysis:** Parses `.eml` files to detect display name spoofing, phishing keywords in subjects, and malicious embedded links.
- **Risk Scoring:** Assigns a score (0-100) and severity level (Low, Medium, High) based on weighted detection rules.
- **VirusTotal Integration:** Enriches analysis with real-time reputation data from VirusTotal.
- **Modern Dashboard:** A premium, dark-themed Flask dashboard for monitoring and investigating alerts.

## Installation

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. (Optional) Configure VirusTotal:
   - Create a `.env` file based on `.env.example`.
   - Add your [VirusTotal API Key](https://www.virustotal.com/gui/my-apikey).

3. Run the application:
   ```bash
   python app.py
   ```

4. Open your browser and navigate to `http://127.0.0.1:5000`.

## Testing
- Use the provided `sample_phishing.eml` to test email analysis.
- Try scanning URLs like `googlev-security-check.com` to see typosquatting detection in action.

## Technologies Used
- **Backend:** Python, Flask, BS4, TLDextract, Levenshtein
- **Frontend:** Vanilla CSS (Glassmorphism), Vanilla JavaScript
- **Security:** Rule-based heuristics, Threat Intelligence API
