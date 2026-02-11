import tldextract
import validators
import re
from Levenshtein import distance

class URLAnalyzer:
    COMMON_DOMAINS = [
        "google.com", "facebook.com", "microsoft.com", "apple.com", "amazon.com",
        "paypal.com", "netflix.com", "linkedin.com", "twitter.com", "chase.com",
        "wellsfargo.com", "bankofamerica.com", "outlook.com", "gmail.com"
    ]

    def __init__(self):
        pass

    def check_typosquatting(self, domain):
        """Check if the domain is a typo of a common domain."""
        for common in self.COMMON_DOMAINS:
            if domain == common:
                return False, None
            
            # If distance is small, it's likely typosquatting
            dist = distance(domain, common)
            if 0 < dist <= 2:
                return True, common
        return False, None

    def analyze(self, url):
        results = {
            "is_suspicious": False,
            "reasons": [],
            "score": 0
        }

        if not validators.url(url):
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            if not validators.url(url):
                results["is_suspicious"] = True
                results["reasons"].append("Invalid URL format")
                results["score"] = 100
                return results

        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        
        # 1. Typosquatting
        is_typo, target = self.check_typosquatting(domain)
        if is_typo:
            results["is_suspicious"] = True
            results["reasons"].append(f"Possible typosquatting of {target}")
            results["score"] += 40

        # 2. Suspicious Patterns
        # IP as hostname
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ext.domain):
            results["is_suspicious"] = True
            results["reasons"].append("URL uses an IP address instead of a domain name")
            results["score"] += 30

        # Too many subdomains
        subdomains = ext.subdomain.split('.')
        if len(subdomains) > 3:
            results["is_suspicious"] = True
            results["reasons"].append("Excessive number of subdomains")
            results["score"] += 15

        # Presence of @ symbol (can be used to hide real domain)
        if "@" in url:
            results["is_suspicious"] = True
            results["reasons"].append("URL contains '@' symbol (potential credential phishing)")
            results["score"] += 25

        # Unusual characters
        if re.search(r"[_%&?]", ext.domain):
            results["is_suspicious"] = True
            results["reasons"].append("Domain contains suspicious characters")
            results["score"] += 20

        # Length check
        if len(url) > 75:
            results["reasons"].append("URL is unusually long")
            results["score"] += 10

        if results["score"] > 0:
            results["is_suspicious"] = True

        return results
