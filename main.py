import os
import time

from intro import show_banner
from engine import run_scan
from modules.report_gen import generate_report


def main():

    show_banner()

    domain = input("\nEnter target domain: ").strip()

    if not domain:
        print("[!] No domain provided. Exiting.")
        return

    print("\n[ENGINE] Starting KAGURA Scan Pipeline...\n")

    start_time = time.time()

    try:
        result = run_scan(domain)

    except Exception as e:
        print(f"[!] Engine crashed: {e}")
        return

    subdomains = result.get("subdomains", [])
    assets = result.get("assets", [])
    vulnerabilities = result.get("vulnerabilities", [])
    endpoints = result.get("endpoints", [])

    meta = result.get("meta", {})

    meta.setdefault("subdomain_count", len(subdomains))
    meta.setdefault("asset_count", len(assets))
    meta.setdefault("vuln_count", len(vulnerabilities))
    meta.setdefault("endpoint_count", len(endpoints))

    scan_time = round(time.time() - start_time, 2)

    print("\n────────────────────────────────────")
    print("[✓] KAGURA Scan Completed")
    print("────────────────────────────────────")

    print(f"[+] Target            : {domain}")
    print(f"[+] Subdomains Found  : {meta['subdomain_count']}")
    print(f"[+] Endpoints Found   : {meta['endpoint_count']}")
    print(f"[+] Assets Found      : {meta['asset_count']}")
    print(f"[+] Vulnerabilities   : {meta['vuln_count']}")
    print(f"[+] Scan Time         : {scan_time}s")

    severity_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for v in vulnerabilities:
        sev = (v.get("severity") or "LOW").upper()
        if sev in severity_map:
            severity_map[sev] += 1

    print("\n[+] Severity Breakdown:")
    print(f"    CRITICAL : {severity_map['CRITICAL']}")
    print(f"    HIGH     : {severity_map['HIGH']}")
    print(f"    MEDIUM   : {severity_map['MEDIUM']}")
    print(f"    LOW      : {severity_map['LOW']}")

    if endpoints:
        print("\n[+] Sample Endpoints:")
        for ep in endpoints[:10]:
            print(f"    - {ep}")

    print("\n[+] Generating professional report...\n")

    os.makedirs("reports", exist_ok=True)

    timestamp = time.strftime("%Y%m%d_%H%M%S")

    output_file = os.path.abspath(
        f"reports/KAGURA_REPORT_{domain}_{timestamp}.html"
    )

    try:
        generate_report(
            result,
            output_file
        )

        print("[✓] Report successfully generated")
        print("[+] Saved at:")
        print(output_file)

    except Exception as e:
        print(f"[!] Report generation failed: {e}")

    print("\n[✓] KAGURA Finished.")


if __name__ == "__main__":
    main()
