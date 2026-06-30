import ssl
import socket
from datetime import datetime

def analyze_ssl(host, port=443):
    findings = []

    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.socket(),
            server_hostname=host
        )
        conn.settimeout(10)
        conn.connect((host, port))
        cert = conn.getpeercert()
        proto = conn.version()
        conn.close()

        weak_protocols = ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]
        if proto in weak_protocols:
            findings.append({
                "host":        host,
                "title":       f"Weak Protocol: {proto}",
                "severity":    "HIGH",
                "cvss":        7.5,
                "description": (
                    f"Weak TLS/SSL protocol in use: {proto}")
            })

        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire = datetime.strptime(
                expire_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expire - datetime.utcnow()).days
            if days_left < 30:
                findings.append({
                    "host":        host,
                    "title":       "SSL Certificate Expiring Soon",
                    "severity":    "MEDIUM",
                    "cvss":        5.0,
                    "description": (
                        f"Certificate expires in {days_left} days")
                })
            elif days_left < 0:
                findings.append({
                    "host":        host,
                    "title":       "SSL Certificate Expired",
                    "severity":    "CRITICAL",
                    "cvss":        9.0,
                    "description": "SSL Certificate has expired"
                })

        subject = dict(
            x[0] for x in cert.get("subject", []))
        cn = subject.get("commonName", "")
        if cn and host not in cn and \
                not cn.startswith("*"):
            findings.append({
                "host":        host,
                "title":       "SSL Certificate Mismatch",
                "severity":    "HIGH",
                "cvss":        7.0,
                "description": (
                    f"CN: {cn} does not match host: {host}")
            })

    except ssl.SSLError as e:
        findings.append({
            "host":        host,
            "title":       "SSL Error Detected",
            "severity":    "HIGH",
            "cvss":        7.5,
            "description": str(e)
        })
    except Exception:
        pass

    return findings
