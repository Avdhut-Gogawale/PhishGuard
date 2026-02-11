import requests
import os
import hashlib

class VTChecker:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"

    def check_url(self, url):
        """Check URL reputation on VirusTotal."""
        if not self.api_key:
            return {"error": "API Key not provided", "status": "unknown"}

        # VT requires URLs to be base64 encoded without padding for the URL endpoint
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        headers = {
            "x-apikey": self.api_key
        }

        try:
            response = requests.get(f"{self.base_url}/urls/{url_id}", headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                return {
                    "malicious": stats['malicious'],
                    "suspicious": stats['suspicious'],
                    "harmless": stats['harmless'],
                    "undetected": stats['undetected'],
                    "status": "success"
                }
            elif response.status_code == 404:
                # URL not found, need to submit for scanning
                return {"status": "not_found", "message": "URL not found in VT database"}
            else:
                return {"status": "error", "message": f"API returned {response.status_code}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def check_domain(self, domain):
        """Check domain reputation on VirusTotal."""
        if not self.api_key:
            return {"error": "API Key not provided", "status": "unknown"}

        headers = {
            "x-apikey": self.api_key
        }

        try:
            response = requests.get(f"{self.base_url}/domains/{domain}", headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                return {
                    "malicious": stats['malicious'],
                    "suspicious": stats['suspicious'],
                    "status": "success"
                }
            else:
                return {"status": "error", "message": f"API returned {response.status_code}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def check_file_hash(self, file_hash):
        """Check file reputation on VirusTotal using hash."""
        if not self.api_key:
            return {"error": "API Key not provided", "status": "unknown"}

        headers = {
            "x-apikey": self.api_key
        }

        try:
            response = requests.get(f"{self.base_url}/files/{file_hash}", headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                return {
                    "malicious": stats['malicious'],
                    "suspicious": stats['suspicious'],
                    "harmless": stats['harmless'],
                    "status": "success"
                }
            elif response.status_code == 404:
                return {"status": "not_found", "message": "File hash not found in VT database"}
            else:
                return {"status": "error", "message": f"API returned {response.status_code}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
