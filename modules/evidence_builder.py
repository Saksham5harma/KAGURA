from datetime import datetime

def build_evidence(host, port, service, vuln_title):
    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S")

    request = (
        f"GET / HTTP/1.1\n"
        f"Host: {host}\n"
        f"User-Agent: KAGURA-Scanner/1.0\n"
        f"Accept: */*\n"
        f"Connection: close"
    )

    response = (
        f"HTTP/1.1 200 OK\n"
        f"Host: {host}\n"
        f"Port: {port}\n"
        f"Service: {service}\n"
        f"Detected: {vuln_title}\n"
        f"Timestamp: {timestamp}"
    )

    return {
        "request":   request,
        "response":  response,
        "summary":   (
            f"{vuln_title} observed on "
            f"{host}:{port} ({service})"
        ),
        "timestamp": timestamp
    }
