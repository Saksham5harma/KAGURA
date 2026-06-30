import socket


class PortScanner:

    COMMON_PORTS = [
        21,
        22,
        25,
        53,
        80,
        110,
        143,
        443,
        445,
        3306,
        3389,
        5432,
        6379,
        8080,
        8443
    ]

    def scan(self, host):

        results = []

        for port in self.COMMON_PORTS:

            try:

                sock = socket.socket()

                sock.settimeout(1)

                status = sock.connect_ex(
                    (host, port)
                )

                if status == 0:

                    results.append({
                        "port": port,
                        "status": "open"
                    })

                sock.close()

            except:
                pass

        return results
