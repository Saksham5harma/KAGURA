import requests
import re
from urllib.parse import urljoin


SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "Stripe Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "JWT Token": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]+",
    "Private Key": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    "API Key": r"(?i)(api_key|apikey|api-key)['\"\s:=]+['\"]?([a-zA-Z0-9_\-]{16,})",
    "Password Leak": r"(?i)(password|passwd|pwd)['\"\s:=]+['\"]?([^'\"]{6,})"
}


JS_REGEX = r'src=["\']([^"\']+\.js[^"\']*)["\']'


def scan_js_secrets(host):

    findings = []
    seen = set()

    try:
        base_url = f"https://{host}"

        r = requests.get(
            base_url,
            timeout=10,
            verify=False,
            headers={"User-Agent": "KAGURA-JS-Scanner"}
        )

        js_files = re.findall(JS_REGEX, r.text)

        for js in js_files[:15]:

            js_url = urljoin(base_url, js)

            try:
                js_r = requests.get(
                    js_url,
                    timeout=8,
                    verify=False,
                    headers={"User-Agent": "KAGURA-JS-Scanner"}
                )

                content = js_r.text

                for secret_type, pattern in SECRET_PATTERNS.items():

                    matches = re.findall(pattern, content)

                    for match in matches:

                        key = f"{host}-{secret_type}-{match}"

                        if key in seen:
                            continue

                        seen.add(key)

                        confidence = 95 if len(match) > 20 else 75

                        findings.append({
                            "type": "JS_SECRET",
                            "host": host,
                            "title": f"Sensitive Data Exposed: {secret_type}",
                            "severity": "CRITICAL",
                            "cvss": 9.8,
                            "confidence": confidence,
                            "evidence": {
                                "js_url": js_url,
                                "match_sample": str(match)[:30],
                                "pattern_type": secret_type
                            },
                            "description": f"Secret pattern detected in JavaScript file: {js_url}"
                        })

            except Exception:
                continue

    except Exception:
        pass

    return findings
