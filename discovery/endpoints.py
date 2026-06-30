import subprocess
import requests
import re
from urllib.parse import urlparse, urlunparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

def _clean_url(raw):
    """Strip status-code prefix like '[200] https://...' and normalise."""
    raw = raw.strip()
    raw = re.sub(r'^\[\d{3}\]\s*', '', raw)
    try:
        p = urlparse(raw)

        return urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ''))
    except Exception:
        return raw


def _is_interesting(url):
    """
    Return True if the URL is worth keeping as an endpoint.
    We only drop pure static assets — NOT .js files, because
    JS files can expose API endpoints and secrets.
    """
    skip_ext = (
        '.jpg', '.jpeg', '.png', '.gif', '.svg',
        '.ico', '.css', '.woff', '.woff2',
        '.ttf', '.eot', '.otf', '.mp4', '.mp3',
        '.wav', '.pdf', '.zip', '.tar', '.gz',
        '.bmp', '.webp', '.tiff',
    )
    try:
        path = urlparse(url).path.lower().split('?')[0]
        return not any(path.endswith(x) for x in skip_ext)
    except Exception:
        return True


def _is_same_scope(url, domain):
    """Only keep URLs that belong to the target domain or its subdomains."""
    try:
        host = urlparse(url).netloc.lower()
        base = domain.lower().lstrip('www.')
        return host == base or host.endswith('.' + base)
    except Exception:
        return False

def _run_tool(cmd, domain, event_bus, endpoints, timeout=120):
    try:
        out = subprocess.check_output(
            cmd,
            stderr=subprocess.DEVNULL,
            timeout=timeout
        ).decode(errors='ignore').strip()

        for line in out.splitlines():
            url = _clean_url(line)
            if not url.startswith('http'):
                continue
            if not _is_same_scope(url, domain):
                continue
            if not _is_interesting(url):
                continue
            if url not in endpoints:
                endpoints.add(url)
                if event_bus:
                    event_bus("endpoint", url)

    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

COMMON_PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/swagger", "/api/docs", "/api/graphql",
    "/graphql", "/graphiql",
    "/swagger", "/swagger-ui", "/swagger-ui.html",
    "/swagger/v1/swagger.json", "/openapi.json", "/openapi.yaml",
    "/docs", "/redoc", "/api-docs",
    "/health", "/healthz", "/health/check", "/health/ready",
    "/status", "/ping", "/version", "/info",
    "/metrics", "/actuator", "/actuator/health",
    "/actuator/env", "/actuator/mappings", "/actuator/beans",
    "/admin", "/admin/login", "/admin/dashboard", "/admin/panel",
    "/administrator", "/manager", "/management",
    "/login", "/signin", "/signup", "/register", "/logout",
    "/auth", "/oauth", "/oauth2", "/auth/login", "/auth/callback",
    "/sso", "/saml", "/oidc",
    "/dashboard", "/portal", "/panel", "/cp", "/controlpanel",
    "/user", "/users", "/profile", "/account", "/accounts",
    "/config", "/configuration", "/settings", "/setup",
    "/env", "/.env", "/.env.local", "/.env.production",
    "/debug", "/test", "/dev", "/staging",
    "/backup", "/backup.zip", "/backup.sql", "/db.sql",
    "/db", "/database", "/console", "/shell",
    "/server-status", "/server-info",
    "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG",
    "/.svn/entries", "/.htaccess", "/.htpasswd",
    "/.well-known/security.txt", "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/.well-known/openid-configuration",
    "/wp-admin", "/wp-login.php", "/wp-json/wp/v2/users",
    "/xmlrpc.php", "/wp-config.php", "/wp-content/debug.log",
    "/phpmyadmin", "/phpinfo.php", "/info.php", "/test.php",
    "/upload", "/uploads", "/files", "/static", "/assets", "/media",
    "/cgi-bin/", "/cgi-bin/admin",
    "/old", "/new", "/v1", "/v2", "/internal", "/private",
    "/secret", "/token", "/tokens", "/keys", "/credentials",
    "/reset", "/forgot-password", "/verify", "/activate",
    "/download", "/export", "/import", "/report", "/reports",
    "/search", "/query", "/ajax", "/xhr",
    "/socket.io/", "/ws", "/websocket",
    "/.DS_Store", "/thumbs.db",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/trace.axd", "/elmah.axd",
    "/jmx-console", "/web-console", "/invoker/",
    "/manager/html", "/host-manager/html",
]


def _probe_paths(domain, event_bus, endpoints):
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; "
                      "+http://www.google.com/bot.html)"
    })

    def probe(path):
        url = f"https://{domain}{path}"
        try:
            r = session.get(url, timeout=6, allow_redirects=True,
                            verify=False)
            if r.status_code in (200, 201, 204, 301, 302, 307,
                                  308, 400, 401, 403, 405, 500):
                clean = _clean_url(url)
                if clean not in endpoints:
                    endpoints.add(clean)
                    if event_bus:
                        event_bus("endpoint",
                                  f"[{r.status_code}] {clean}")
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=25) as ex:
        list(ex.map(probe, COMMON_PATHS))

def discover_endpoints(domain, event_bus=None):
    """
    Discover endpoints using passive tools + active path probing.
    Always runs both — tools are NOT a fallback for path probe.
    """
    endpoints = set()

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    tool_commands = [

        ["gau", "--threads", "5",
         "--blacklist", "jpg,jpeg,png,gif,svg,ico,css,woff,woff2,ttf,eot,otf,mp4,mp3,wav",
         "--timeout", "60",
         domain],

        ["katana", "-u", f"https://{domain}",
         "-silent", "-d", "3",
         "-jc",
         "-kf", "all",
         "-timeout", "20",
         "-c", "10"],

        ["waybackurls", domain],

        ["hakrawler",
         "-url", f"https://{domain}",
         "-depth", "3",
         "-plain",
         "-timeout", "20"],
    ]

    with ThreadPoolExecutor(max_workers=4) as ex:
        futures = [
            ex.submit(_run_tool, cmd, domain, event_bus, endpoints)
            for cmd in tool_commands
        ]
        for f in as_completed(futures):
            pass

    _probe_paths(domain, event_bus, endpoints)

    return sorted(endpoints)
