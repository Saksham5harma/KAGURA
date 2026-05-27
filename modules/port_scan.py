import socket
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135,
    139, 143, 443, 445, 1433, 2375,
    3306, 3389, 4848, 5432, 5601,
    6379, 8080, 8443, 8888, 9090,
    9200, 27017
]

def grab_banner(ip, port, timeout=1.0):
    try:
        sock = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(
            "utf-8", errors="ignore").strip()
        sock.close()

        for line in banner.splitlines():
            if line.lower().startswith("server:"):
                return line.split(":", 1)[1].strip()
        return banner[:80] if banner else ""
    except Exception:
        return ""

def scan_single_port(ip, host, port, timeout=1.0):
    try:
        sock = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except Exception:
                service = "unknown"
            banner = ""
            if port in [80, 443, 8080, 8443, 8888]:
                banner = grab_banner(ip, port)
            return {
                "host":    host,
                "ip":      ip,
                "port":    port,
                "service": service,
                "banner":  banner
            }
    except Exception:
        pass
    return None

def scan_ports(host):
    results = []
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return results

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = [
            executor.submit(
                scan_single_port, ip, host, port)
            for port in COMMON_PORTS
        ]
        for f in futures:
            try:
                res = f.result(timeout=5)
                if res:
                    results.append(res)
            except Exception:
                pass

    return results
