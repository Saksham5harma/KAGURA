import requests
import time
from urllib.parse import urlparse


class HTTPAnalyzer:

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "KAGURA-Security-Scanner/1.0"
        })

    def analyze_http_security(self, host):

        findings = []

        urls = [
            f"http://{host}",
            f"https://{host}"
        ]

        for url in urls:

            try:
                start = time.time()

                r = self.session.get(
                    url,
                    timeout=10,
                    verify=False,
                    allow_redirects=True
                )

                latency = round((time.time() - start) * 1000, 2)
                headers = r.headers

                final_url = r.url
                status = r.status_code

                security_checks = {
                    "Strict-Transport-Security": (
                        "Missing HSTS Header", "MEDIUM", 5.9
                    ),
                    "Content-Security-Policy": (
                        "Missing CSP Header", "HIGH", 7.2
                    ),
                    "X-Frame-Options": (
                        "Clickjacking Protection Missing", "MEDIUM", 6.1
                    ),
                    "X-Content-Type-Options": (
                        "MIME Sniffing Enabled", "LOW", 3.7
                    ),
                    "Referrer-Policy": (
                        "Weak Referrer Policy", "LOW", 3.0
                    ),
                    "Permissions-Policy": (
                        "Missing Permissions Policy", "LOW", 2.8
                    )
                }

                for header, (title, severity, cvss) in security_checks.items():

                    if header not in headers:

                        findings.append({
                            "type": "HEADER_SECURITY",
                            "host": host,
                            "url": final_url,
                            "status_code": status,
                            "title": title,
                            "severity": severity,
                            "cvss": cvss,
                            "evidence": f"{header} not present",
                            "latency_ms": latency
                        })

                if "Server" in headers:
                    findings.append({
                        "type": "INFO_DISCLOSURE",
                        "host": host,
                        "url": final_url,
                        "title": "Server Header Exposed",
                        "severity": "LOW",
                        "cvss": 3.1,
                        "evidence": headers.get("Server"),
                        "status_code": status
                    })

                if "X-Powered-By" in headers:
                    findings.append({
                        "type": "INFO_DISCLOSURE",
                        "host": host,
                        "url": final_url,
                        "title": "Technology Stack Exposed",
                        "severity": "LOW",
                        "cvss": 3.2,
                        "evidence": headers.get("X-Powered-By"),
                        "status_code": status
                    })

                if headers.get("Access-Control-Allow-Origin") == "*":
                    findings.append({
                        "type": "CORS_MISCONFIG",
                        "host": host,
                        "url": final_url,
                        "title": "Permissive CORS Policy",
                        "severity": "MEDIUM",
                        "cvss": 6.5,
                        "evidence": "Access-Control-Allow-Origin: *",
                        "status_code": status
                    })

                break

            except Exception:
                continue

        return findings
