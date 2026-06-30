import requests
import time


WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
    "AWS WAF": ["awselb", "x-amzn-requestid"],
    "Akamai": ["akamai", "ak_bmsc"],
    "Imperva": ["incapsula", "visid_incap"],
    "F5 BIG-IP": ["bigip", "ts="],
    "Sucuri": ["sucuri", "x-sucuri-id"],
    "Fortinet": ["fortigate", "fortiweb"],
    "ModSecurity": ["mod_security", "modsecurity"],
}


def detect_waf(host):

    findings = []

    url = f"https://{host}"

    try:
        start = time.time()

        r = requests.get(
            url,
            timeout=10,
            verify=False,
            headers={
                "User-Agent": "KAGURA-WAF-Scanner/1.0",
                "X-Origin-Test": "true"
            }
        )

        latency = round((time.time() - start) * 1000, 2)

        response_blob = (r.text + str(r.headers)).lower()

        detected = []
        matched_signatures = {}

        for waf, signatures in WAF_SIGNATURES.items():

            for sig in signatures:

                if sig.lower() in response_blob:

                    detected.append(waf)

                    matched_signatures.setdefault(waf, []).append(sig)

                    break

        waf_block_indicators = [
            r.status_code in [403, 406, 429],
            "captcha" in response_blob,
            "access denied" in response_blob,
            "request blocked" in response_blob
        ]

        block_score = sum(1 for i in waf_block_indicators if i)

        if detected or block_score >= 2:

            confidence = min(100, (len(detected) * 30) + (block_score * 20))

            findings.append({
                "type": "WAF_DETECTION",
                "host": host,
                "title": f"WAF Detected: {', '.join(set(detected)) if detected else 'Generic WAF'}",
                "severity": "INFO",
                "cvss": 0.0,
                "confidence": confidence,
                "evidence": {
                    "matched_wafs": list(set(detected)),
                    "matched_signatures": matched_signatures,
                    "status_code": r.status_code,
                    "latency_ms": latency
                },
                "description": "Web Application Firewall detected based on signatures + behavior"
            })

        else:

            findings.append({
                "type": "WAF_DETECTION",
                "host": host,
                "title": "No WAF Detected",
                "severity": "MEDIUM",
                "cvss": 5.2,
                "confidence": 70,
                "evidence": {
                    "status_code": r.status_code,
                    "latency_ms": latency
                },
                "description": "No WAF signatures or blocking behavior detected"
            })

    except Exception as e:

        findings.append({
            "type": "WAF_DETECTION",
            "host": host,
            "title": "WAF Detection Failed",
            "severity": "INFO",
            "cvss": 0.0,
            "confidence": 0,
            "evidence": str(e),
            "description": "Request failed during WAF detection"
        })

    return findings
