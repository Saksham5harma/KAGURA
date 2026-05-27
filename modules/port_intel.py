import requests

SHODAN_API_KEY = "XgZnULWSPPZVlKdgExDyMjpQmWPgs54S"


def shodan_lookup(ip):
    """
    Enrich host data using Shodan API
    """
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        r = requests.get(url, timeout=10)

        if r.status_code != 200:
            return None

        data = r.json()

        ports = data.get("ports", [])
        org = data.get("org", "unknown")
        isp = data.get("isp", "unknown")

        services = []

        for item in data.get("data", []):
            services.append({
                "port": item.get("port"),
                "product": item.get("product", "unknown"),
                "version": item.get("version", ""),
                "banner": item.get("data", "")[:100]
            })

        return {
            "ip": ip,
            "org": org,
            "isp": isp,
            "ports": ports,
            "services": services
        }

    except Exception as e:
        return None
