import requests
import os
import hashlib
import base64
import datetime


class VTChecker:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.timeout = 8  # seconds – must stay under Vercel's 10s limit

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _headers(self):
        return {"x-apikey": self.api_key}

    @staticmethod
    def _empty(status="error", message="", **extra):
        """Return a result dict that always contains 'status' and 'malicious'."""
        result = {
            "status": status,
            "message": message,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total": 0,
            "scan_date": "",
            "permalink": "",
        }
        result.update(extra)
        return result

    def _handle_response_error(self, response):
        """Check for common HTTP error codes and return an appropriate dict,
        or None if the caller should continue processing."""
        if response.status_code == 429:
            return self._empty(
                status="rate_limited",
                message="VirusTotal free tier limit reached (4 req/min). Try again in 60 seconds.",
            )
        if response.status_code in (401, 403):
            return self._empty(
                status="no_key",
                message="VirusTotal API key missing or invalid.",
            )
        return None

    def _wrap_request(self, method, url, **kwargs):
        """Execute a request and translate common errors into result dicts.

        Returns (response | None, error_dict | None).
        Exactly one of the two will be non-None.
        """
        kwargs.setdefault("timeout", self.timeout)
        try:
            response = method(url, **kwargs)
            err = self._handle_response_error(response)
            if err:
                return None, err
            return response, None
        except requests.exceptions.Timeout:
            return None, self._empty(
                status="timeout",
                message="VirusTotal did not respond in time.",
            )
        except Exception as e:
            return None, self._empty(
                status="error",
                message=str(e),
            )

    @staticmethod
    def _parse_stats(attributes):
        """Extract analysis stats and metadata from a VT attributes dict."""
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        # last_analysis_date is a UNIX timestamp
        analysis_ts = attributes.get("last_analysis_date")
        if analysis_ts:
            scan_date = datetime.datetime.utcfromtimestamp(analysis_ts).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )
        else:
            scan_date = ""

        return {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total": total,
            "scan_date": scan_date,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def check_url(self, url):
        """Check URL reputation on VirusTotal.

        Strategy (avoids Vercel 10-s timeout):
        1. Compute the base64url (unpadded) URL ID.
        2. GET the cached report — instant if VT already knows the URL.
        3. If 404, POST a fresh scan submission and return status='pending'.
        """
        if not self.api_key:
            return self._empty(
                status="no_key",
                message="VirusTotal API key missing or invalid.",
            )

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        # --- Step 1: try the cached report ---
        resp, err = self._wrap_request(
            requests.get,
            f"{self.base_url}/urls/{url_id}",
            headers=self._headers(),
        )
        if err:
            return err

        if resp.status_code == 200:
            data = resp.json()
            attributes = data.get("data", {}).get("attributes", {})
            result = self._parse_stats(attributes)
            result["status"] = "success"
            result["message"] = ""
            # Construct permalink to the VT GUI
            result["permalink"] = f"https://www.virustotal.com/gui/url/{url_id}/detection"
            return result

        if resp.status_code == 404:
            # --- Step 2: submit fresh scan ---
            post_resp, post_err = self._wrap_request(
                requests.post,
                f"{self.base_url}/urls",
                headers={**self._headers(), "content-type": "application/x-www-form-urlencoded"},
                data={"url": url},
            )
            if post_err:
                return post_err
            return self._empty(
                status="pending",
                message="VT scan submitted. Results will be available shortly.",
            )

        # Unexpected status
        return self._empty(
            status="error",
            message=f"VirusTotal API returned HTTP {resp.status_code}",
        )

    def check_domain(self, domain):
        """Check domain reputation on VirusTotal."""
        if not self.api_key:
            return self._empty(
                status="no_key",
                message="VirusTotal API key missing or invalid.",
            )

        resp, err = self._wrap_request(
            requests.get,
            f"{self.base_url}/domains/{domain}",
            headers=self._headers(),
        )
        if err:
            return err

        if resp.status_code == 200:
            data = resp.json()
            attributes = data.get("data", {}).get("attributes", {})
            result = self._parse_stats(attributes)
            result["status"] = "success"
            result["message"] = ""
            result["permalink"] = f"https://www.virustotal.com/gui/domain/{domain}/detection"
            return result

        return self._empty(
            status="error",
            message=f"VirusTotal API returned HTTP {resp.status_code}",
        )

    def check_file_hash(self, file_hash):
        """Check file reputation on VirusTotal using hash."""
        if not self.api_key:
            return self._empty(
                status="no_key",
                message="VirusTotal API key missing or invalid.",
            )

        resp, err = self._wrap_request(
            requests.get,
            f"{self.base_url}/files/{file_hash}",
            headers=self._headers(),
        )
        if err:
            return err

        if resp.status_code == 200:
            data = resp.json()
            attributes = data.get("data", {}).get("attributes", {})
            result = self._parse_stats(attributes)
            result["status"] = "success"
            result["message"] = ""
            result["permalink"] = f"https://www.virustotal.com/gui/file/{file_hash}/detection"
            return result

        if resp.status_code == 404:
            return self._empty(
                status="error",
                message="File hash not found in VT database.",
            )

        return self._empty(
            status="error",
            message=f"VirusTotal API returned HTTP {resp.status_code}",
        )
