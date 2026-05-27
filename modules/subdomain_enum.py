import requests

def enumerate_subdomains(domain):
    found = set()
    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            headers=headers,
            timeout=20
        )
        if r.ok and r.text.strip().startswith("["):
            for entry in r.json():
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if domain in sub and "*" not in sub:
                        found.add(sub)
    except Exception:
        pass

    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=15
        )
        if r.ok and "error" not in r.text.lower():
            for line in r.text.splitlines():
                parts = line.split(",")
                if parts and domain in parts[0]:
                    found.add(parts[0].strip().lower())
    except Exception:
        pass

    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/"
            f"domain/{domain}/passive_dns",
            headers=headers,
            timeout=15
        )
        if r.ok:
            for entry in r.json().get("passive_dns", []):
                hostname = entry.get("hostname", "")
                if domain in hostname and "*" not in hostname:
                    found.add(hostname.strip().lower())
    except Exception:
        pass

    try:
        r = requests.get(
            f"https://rapiddns.io/subdomain/{domain}?full=1",
            headers=headers,
            timeout=15
        )
        if r.ok:
            for line in r.text.splitlines():
                if domain in line and "<td>" in line:
                    sub = line.replace("<td>", "").replace(
                        "</td>", "").strip().lower()
                    if domain in sub and "*" not in sub:
                        found.add(sub)
    except Exception:
        pass

    found.add(domain)

    return sorted(list(found))
