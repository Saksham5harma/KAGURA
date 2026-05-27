import subprocess
import requests

def run_command(cmd, event_bus, endpoints):
    try:
        out = subprocess.check_output(
            cmd,
            stderr=subprocess.DEVNULL,
            timeout=60
        ).decode().strip()
        for line in out.splitlines():
            line = line.strip()
            if line and line.startswith("http"):
                endpoints.add(line)
                if event_bus:
                    event_bus("endpoint", line)
    except Exception:
        pass

def discover_endpoints(domain, event_bus=None):
    endpoints = set()

    commands = [
        ["gau", "--threads", "5", domain],
        ["katana", "-u", f"https://{domain}",
         "-silent", "-d", "2"],
    ]

    for cmd in commands:
        run_command(cmd, event_bus, endpoints)

    if not endpoints:
        common_paths = [
            "/robots.txt", "/sitemap.xml",
            "/api", "/api/v1", "/api/v2",
            "/graphql", "/swagger", "/docs",
            "/health", "/status", "/admin",
            "/login", "/dashboard",
            "/.well-known/security.txt",
            "/wp-admin", "/wp-login.php",
        ]
        for path in common_paths:
            url = f"https://{domain}{path}"
            try:
                r = requests.get(
                    url, timeout=5,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                if r.status_code in [200, 301, 302, 403]:
                    endpoints.add(url)
                    if event_bus:
                        event_bus("endpoint",
                            f"[{r.status_code}] {url}")
            except Exception:
                pass

    skip = [".jpg", ".png", ".svg", ".css",
            ".woff", ".gif", ".jpeg", ".ico",
            ".ttf", ".eot", ".woff2"]

    filtered = [
        ep for ep in endpoints
        if not any(x in ep.lower() for x in skip)
    ]

    return sorted(filtered)
