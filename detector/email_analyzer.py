import email
from email import policy
from email.parser import BytesParser
import re
import hashlib
from bs4 import BeautifulSoup
from .url_analyzer import URLAnalyzer

class EmailAnalyzer:
    PHISHING_KEYWORDS = [
        "urgent", "action required", "verify your account", "suspended",
        "unauthorized login", "password reset", "invoice", "payment",
        "security alert", "limited time", "click here"
    ]

    def __init__(self):
        self.url_analyzer = URLAnalyzer()

    def extract_urls(self, body):
        """Extract URLs from plain text or HTML body."""
        # Improved regex for URLs (handles IP addresses and paths better)
        url_pattern = r'https?://(?:[a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+(?::\d+)?(?:/[^\s<"\']*)?'
        urls = re.findall(url_pattern, body)
        return list(set(urls))

    def analyze_eml(self, file_path):
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        analysis = {
            "subject": str(msg['subject']),
            "from": str(msg['from']),
            "to": str(msg['to']),
            "date": str(msg['date']),
            "body": "",
            "urls": [],
            "attachments": [],
            "suspicious_indicators": [],
            "score": 0,
            "severity": "Low"
        }

        # Extract body and attachments
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))

                if "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        payload = part.get_payload(decode=True)
                        if payload:
                            file_hash = hashlib.sha256(payload).hexdigest()
                            analysis["attachments"].append({
                                "filename": filename,
                                "type": content_type,
                                "size": len(payload),
                                "sha256": file_hash
                            })
                
                if content_type == 'text/plain' or content_type == 'text/html':
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            analysis["body"] += payload.decode(errors='ignore')
                    except Exception:
                        pass
        else:
            # Handle non-multipart emails
            payload = msg.get_payload(decode=True)
            if payload:
                analysis["body"] = payload.decode(errors='ignore')

        # 1. Check for Phishing Keywords in Subject
        subject_lower = analysis["subject"].lower() if analysis["subject"] else ""
        for keyword in self.PHISHING_KEYWORDS:
            if keyword in subject_lower:
                analysis["suspicious_indicators"].append(f"Phishing keyword found in subject: '{keyword}'")
                analysis["score"] += 15

        # 2. Check for Header Spoofing
        # Looking for "display name" <email@addr.com> where display name might be deceptive
        from_header = analysis["from"] or ""
        match = re.search(r'"?([^"<]+)"?\s*<([^>]+)>', from_header)
        if match:
            display_name, email_addr = match.groups()
            # If display name looks like a reputable company but email domain doesn't match
            reputable_companies = ["PayPal", "Google", "Microsoft", "Apple", "Amazon", "Bank"]
            for company in reputable_companies:
                if company.lower() in display_name.lower() and company.lower() not in email_addr.lower():
                    analysis["suspicious_indicators"].append(f"Possible display name spoofing: '{display_name}' vs {email_addr}")
                    analysis["score"] += 30

        # 3. Analyze URLs in Body
        urls = self.extract_urls(analysis["body"])
        for url in urls:
            url_res = self.url_analyzer.analyze(url)
            analysis["urls"].append({
                "url": url,
                "analysis": url_res
            })
            if url_res["is_suspicious"]:
                analysis["suspicious_indicators"].append(f"Suspicious URL found: {url}")
                analysis["score"] += url_res["score"]

        # 4. Check for HTML-only emails with masked links
        if '<a href=' in analysis["body"]:
            soup = BeautifulSoup(analysis["body"], 'html.parser')
            for a in soup.find_all('a', href=True):
                link_text = a.get_text().strip()
                link_href = a['href']
                if "http" in link_text and link_text != link_href:
                    analysis["suspicious_indicators"].append(f"Link text looks like a URL but points elsewhere: {link_text} -> {link_href}")
                    analysis["score"] += 25

        # Final Score to Severity Mapping
        if analysis["score"] >= 70:
            analysis["severity"] = "High"
        elif analysis["score"] >= 30:
            analysis["severity"] = "Medium"
        else:
            analysis["severity"] = "Low"

        return analysis
