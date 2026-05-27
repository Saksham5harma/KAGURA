import time
from concurrent.futures import ThreadPoolExecutor

from modules.subdomain_enum   import enumerate_subdomains
from modules.port_scan        import scan_ports
from modules.vuln_engine      import analyze_vulnerabilities
from modules.report_gen       import generate_report
from modules.cvss_engine      import calculate_cvss
from modules.evidence_builder import build_evidence

try:
    from discovery.endpoints import discover_endpoints
except ImportError:
    def discover_endpoints(domain, event_bus=None):
        return []


def run_scan(domain, event_bus=None):

    start_time = time.time()

    result = {
        "target":          domain,
        "subdomains":      [],
        "assets":          [],
        "vulnerabilities": [],
        "endpoints":       [],
        "meta":            {}
    }

    if event_bus:
        event_bus(
            "status",
            "Phase 1 — Subdomain Enumeration..."
        )

    try:
        subdomains = enumerate_subdomains(domain)
    except Exception:
        subdomains = []

    subdomains = list(set(subdomains))

    if domain not in subdomains:
        subdomains.append(domain)

    result["subdomains"] = subdomains

    for sub in subdomains:

        if event_bus:
            event_bus("recon", sub)

    if event_bus:
        event_bus("progress", 15)

    if event_bus:
        event_bus(
            "status",
            "Phase 1b — Endpoint Discovery..."
        )

    try:
        endpoints = discover_endpoints(domain, event_bus)

        if not endpoints:
            endpoints = [
                f"https://{domain}/",
                f"https://{domain}/login",
                f"https://{domain}/admin",
                f"https://{domain}/api",
                f"https://{domain}/dashboard",
                f"https://{domain}/robots.txt",
                f"https://{domain}/sitemap.xml"
            ]

    except Exception:

        endpoints = [
            f"https://{domain}/",
            f"https://{domain}/login",
            f"https://{domain}/admin",
            f"https://{domain}/api",
            f"https://{domain}/dashboard",
            f"https://{domain}/robots.txt",
            f"https://{domain}/sitemap.xml"
        ]

    endpoints = list(set(endpoints))

    result["endpoints"] = endpoints

    if event_bus:
        for ep in endpoints:
            event_bus("endpoint", ep)

    if event_bus:
        event_bus("progress", 30)

    if event_bus:
        event_bus(
            "status",
            "Phase 2 — Port Scanning All Hosts..."
        )

    all_assets = []
    all_vulns  = []

    def process_host(host):

        try:
            ports = scan_ports(host)
        except Exception:
            ports = []

        try:
            vulns = analyze_vulnerabilities(host, ports)
        except Exception:
            vulns = []

        return host, ports, vulns

    total = len(subdomains)
    done  = 0

    with ThreadPoolExecutor(max_workers=10) as executor:

        futures = {
            executor.submit(process_host, host): host
            for host in subdomains
        }

        for future in futures:

            try:
                host, ports, vulns = future.result(
                    timeout=20
                )

            except Exception:
                done += 1
                continue

            done += 1

            pct = int(
                30 + (done / total) * 40
            )

            if event_bus:
                event_bus("progress", pct)

            for p in ports:

                banner = p.get("banner", "")

                server = (
                    f" | Server: {banner}"
                    if banner else ""
                )

                if event_bus:
                    event_bus(
                        "port",
                        f"{host} | "
                        f"Port {p['port']} | "
                        f"{p.get('service', 'unknown')}"
                        f"{server}"
                    )


            enriched = []

            for v in vulns:

                try:
                    cvss = calculate_cvss(
                        v.get("severity", "LOW"),
                        v.get("endpoint_type", "ASSET"),
                        len(ports)
                    )

                except Exception:
                    cvss = v.get("cvss", 5.0)

                try:
                    evidence = build_evidence(
                        host,
                        v.get("port", 0),
                        v.get("service", "unknown"),
                        v.get("title", "Unknown")
                    )

                except Exception:

                    evidence = {
                        "request":  "N/A",
                        "response": "N/A",
                        "summary":  "N/A"
                    }

                v["cvss"]     = cvss
                v["evidence"] = evidence

                enriched.append(v)

                if event_bus:

                    event_bus(
                        "vuln",
                        f"{v.get('severity', 'LOW')} | "
                        f"{host} | "
                        f"{v.get('title', 'Unknown')} | "
                        f"CVSS {cvss}"
                    )


            all_assets.extend([

                {
                    "host":    host,
                    "port":    p["port"],
                    "service": p.get("service", "unknown"),
                    "banner":  p.get("banner", ""),
                    "ip":      p.get("ip", "")
                }

                for p in ports

            ])

            all_vulns.extend(enriched)

    unique_vulns = []

    seen = set()

    for v in all_vulns:

        key = (
            v.get("host"),
            v.get("title"),
            v.get("severity")
        )

        if key not in seen:

            seen.add(key)

            unique_vulns.append(v)

    result["assets"]          = all_assets
    result["vulnerabilities"] = unique_vulns

    if event_bus:
        event_bus("progress", 80)


    if event_bus:
        event_bus(
            "status",
            "Phase 3 — Generating Report..."
        )

    elapsed = round(
        time.time() - start_time,
        2
    )

    result["meta"] = {

        "target":          domain,

        "subdomain_count": len(subdomains),

        "asset_count":     len(all_assets),

        "vuln_count":      len(unique_vulns),

        "endpoint_count":  len(endpoints),

        "scan_time":       elapsed,

        "findings":        unique_vulns
    }

    try:
        generate_report(result)

    except Exception as e:
        print(f"[!] Report generation failed: {e}")

    if event_bus:

        event_bus("progress", 100)

        event_bus(
            "report",
            result["meta"]
        )

        event_bus(
            "status",
            "Scan Complete ✓"
        )

    return result
