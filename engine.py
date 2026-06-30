import time
from concurrent.futures import ThreadPoolExecutor, as_completed

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

MAX_SUBDOMAIN_EP_PROBES = 20


def _discover_all_endpoints(domain, subdomains, event_bus):
    """
    Probe root domain + top N subdomains for endpoints.
    Runs all probes in parallel so total time ≈ single probe time.
    """
    candidates = [domain]
    for s in subdomains:
        s = s.strip().lower()
        if s and s != domain and '*' not in s:
            candidates.append(s)
        if len(candidates) >= MAX_SUBDOMAIN_EP_PROBES + 1:
            break

    all_endpoints = set()

    if event_bus:
        event_bus(
            "status",
            f"Phase 1b — Endpoint Discovery "
            f"({len(candidates)} hosts)..."
        )

    def probe_host(host):
        found = []
        try:
            eps = discover_endpoints(host, event_bus)
            found = eps or []
        except Exception:
            pass
        return found

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(probe_host, h): h for h in candidates}
        for future in as_completed(futures):
            try:
                for ep in future.result():
                    all_endpoints.add(ep)
            except Exception:
                pass

    return sorted(all_endpoints)


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
        event_bus("status", "Phase 1 — Subdomain Enumeration...")

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

    endpoints = _discover_all_endpoints(domain, subdomains, event_bus)

    guaranteed = [
        f"https://{domain}/",
        f"https://{domain}/robots.txt",
        f"https://{domain}/sitemap.xml",
    ]
    ep_set = set(endpoints)
    for g in guaranteed:
        ep_set.add(g)
    endpoints = sorted(ep_set)

    result["endpoints"] = endpoints

    if event_bus:
        event_bus("progress", 30)

    if event_bus:
        event_bus("status", "Phase 2 — Port Scanning All Hosts...")

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

        for future in as_completed(futures):

            try:
                host, ports, vulns = future.result(timeout=25)
            except Exception:
                done += 1
                continue

            done += 1
            pct = int(30 + (done / max(total, 1)) * 50)
            if event_bus:
                event_bus("progress", pct)

            for p in ports:
                banner = p.get("banner", "")
                server = f" | Server: {banner}" if banner else ""
                if event_bus:
                    event_bus(
                        "port",
                        f"{host} | Port {p['port']} | "
                        f"{p.get('service', 'unknown')}{server}"
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
                v["host"]     = host
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
        key = (v.get("host"), v.get("title"), v.get("severity"))
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)

    result["assets"]          = all_assets
    result["vulnerabilities"] = unique_vulns

    if event_bus:
        event_bus("progress", 82)

    if event_bus:
        event_bus("status", "Phase 3 — Generating Report...")

    elapsed = round(time.time() - start_time, 2)

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
        if event_bus:
            event_bus("error", f"Report generation failed: {e}")
        else:
            print(f"[!] Report generation failed: {e}")

    if event_bus:
        event_bus("progress", 100)
        event_bus("report",   result["meta"])
        event_bus("status",   "Scan Complete ✓")

    return result
