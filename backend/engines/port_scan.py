import socket
import ssl
import time
import requests

from concurrent.futures import ThreadPoolExecutor


class PortScanner:

    COMMON_PORTS = [
        21, 22, 23, 25, 53,
        80, 110, 111, 135,
        139, 143, 443, 445,
        993, 995, 1433, 1521,
        3306, 3389, 5432,
        5900, 6379, 8080,
        8443, 9200, 27017
    ]

    SERVICE_MAP = {
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "ORACLE",
        3306: "MYSQL",
        3389: "RDP",
        5432: "POSTGRESQL",
        5900: "VNC",
        6379: "REDIS",
        8080: "HTTP-ALT",
        8443: "HTTPS-ALT",
        9200: "ELASTICSEARCH",
        27017: "MONGODB"
    }

    def scan(self, host):

        results = []

        try:
            host_ip = socket.gethostbyname(host)

        except Exception:
            return []

        with ThreadPoolExecutor(max_workers=150) as executor:

            futures = [
                executor.submit(
                    self.scan_single_port,
                    host,
                    host_ip,
                    port
                )
                for port in self.COMMON_PORTS
            ]

            for future in futures:

                result = future.result()

                if result:
                    results.append(result)

        return sorted(
            results,
            key=lambda x: x["port"]
        )

    def scan_single_port(
        self,
        hostname,
        ip,
        port
    ):

        start = time.time()

        try:

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            sock.settimeout(1)

            status = sock.connect_ex(
                (ip, port)
            )

            latency = round(
                (time.time() - start) * 1000,
                2
            )

            if status == 0:

                banner = self.grab_banner(
                    ip,
                    port
                )

                http_info = self.http_probe(
                    hostname,
                    port
                )

                return {
                    "port": port,
                    "state": "open",
                    "service": self.SERVICE_MAP.get(
                        port,
                        "unknown"
                    ),
                    "risk": self.calculate_risk(
                        port
                    ),
                    "latency_ms": latency,
                    "banner": banner,
                    "http_info": http_info
                }

        except Exception:
            pass

        return None

    def grab_banner(
        self,
        ip,
        port
    ):

        try:

            sock = socket.socket()

            sock.settimeout(2)

            sock.connect(
                (ip, port)
            )

            sock.send(
                b"HEAD / HTTP/1.0\r\n\r\n"
            )

            banner = sock.recv(
                1024
            )

            sock.close()

            return banner.decode(
                errors="ignore"
            )[:300]

        except Exception:
            return ""

    def http_probe(
        self,
        host,
        port
    ):

        try:

            scheme = (
                "https"
                if port in [443, 8443]
                else "http"
            )

            url = (
                f"{scheme}://{host}:{port}"
            )

            r = requests.get(
                url,
                timeout=5,
                verify=False,
                allow_redirects=True
            )

            title = ""

            if "<title>" in r.text.lower():

                try:

                    title = (
                        r.text.lower()
                        .split("<title>")[1]
                        .split("</title>")[0]
                    )[:100]

                except:
                    pass

            return {
                "status_code": r.status_code,
                "server": r.headers.get(
                    "Server",
                    ""
                ),
                "title": title
            }

        except Exception:

            return {}

    def calculate_risk(
        self,
        port
    ):

        critical_ports = [
            23,
            445,
            6379,
            27017,
            9200
        ]

        high_ports = [
            21,
            3306,
            5432,
            1433,
            1521
        ]

        medium_ports = [
            22,
            3389,
            5900
        ]

        if port in critical_ports:
            return "Critical"

        if port in high_ports:
            return "High"

        if port in medium_ports:
            return "Medium"

        return "Low"
