import requests

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/backup.zip",
    "/backup.sql",
    "/db.sql",
    "/config.php",
    "/wp-config.php",
    "/web.config",
    "/.htaccess",
    "/phpinfo.php",
    "/server-status",
    "/admin",
    "/login",
    "/.DS_Store",
    "/package.json",
    "/composer.json",
    "/README.md",
    "/CHANGELOG.md",
    "/.travis.yml",
    "/Dockerfile",
    "/docker-compose.yml",
]

SEVERITY_MAP = {
    "/.env":            ("CRITICAL", 9.8),
    "/.git/config":     ("CRITICAL", 9.5),
    "/backup.zip":      ("CRITICAL", 9.0),
    "/backup.sql":      ("CRITICAL", 9.0),
    "/db.sql":          ("CRITICAL", 9.0),
    "/wp-config.php":   ("CRITICAL", 9.5),
    "/web.config":      ("HIGH",     7.5),
    "/config.php":      ("HIGH",     7.5),
    "/phpinfo.php":     ("HIGH",     7.0),
    "/server-status":   ("HIGH",     7.0),
    "/.htaccess":       ("MEDIUM",   5.5),
    "/admin":           ("MEDIUM",   5.0),
    "/package.json":    ("LOW",      3.1),
    "/composer.json":   ("LOW",      3.1),
}

def detect_sensitive_files(host):
    findings = []

    for path in SENSITIVE_PATHS:
        url = f"https://{host}{path}"
        try:
            r = requests.get(
                url,
                timeout=5,
                verify=False,
                allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if r.status_code in [200, 403]:
                severity, cvss = SEVERITY_MAP.get(
                    path, ("LOW", 3.0))
                findings.append({
                    "host":        host,
                    "title":       (
                        f"Sensitive File Found: {path}"),
                    "severity":    severity,
                    "cvss":        cvss,
                    "description": (
                        f"HTTP {r.status_code} — "
                        f"{url}")
                })
        except Exception:
            pass

    return findings
