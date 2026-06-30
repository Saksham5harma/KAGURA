import asyncio

COMMON_PORTS = [21, 22, 80, 443, 3306, 8080, 8000, 6379]

async def scan_ports(target: str):
    """
    Kagura Port Engine v1
    Lightweight simulation first (we will upgrade to real socket scanning later)
    """

    print(f"[+] Scanning ports for {target}")

    open_ports = []

    for port in COMMON_PORTS:
        await asyncio.sleep(0.1)

        if port in [22, 80, 443]:
            open_ports.append({
                "port": port,
                "service": get_service(port),
                "status": "open"
            })

    return {
        "target": target,
        "open_ports": open_ports
    }


def get_service(port: int):
    services = {
        21: "FTP",
        22: "SSH",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        8080: "HTTP-ALT",
        8000: "Custom HTTP",
        6379: "Redis"
    }
    return services.get(port, "unknown")
