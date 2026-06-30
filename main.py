import os
import sys
import time

from intro import show_banner
from engine import run_scan

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
GOLD   = "\033[33m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def cli_event_bus(event, data):
    """
    Callback passed to run_scan() so live output streams to terminal.
    Same (event, data) signature used by the GUI — engine.py is identical
    for both paths.
    """
    if event == "recon":
        print(f"  {BLUE}[RECON]{RESET}  {data}")

    elif event == "port":
        print(f"  {GREEN}[PORT]{RESET}   {data}")

    elif event == "vuln":
        raw = str(data).upper()
        color = (
            RED    if "CRITICAL" in raw else
            YELLOW if "HIGH"     in raw else
            CYAN   if "MEDIUM"   in raw else
            BLUE
        )
        print(f"  {color}[VULN]{RESET}   {data}")

    elif event == "endpoint":
        print(f"  {GOLD}[URL]{RESET}    {data}")

    elif event == "status":
        print(f"\n  {BOLD}[>>]{RESET}    {data}")

    elif event == "progress":
        pct  = int(data)
        done = int(pct / 5)
        bar  = "█" * done + "░" * (20 - done)
        print(f"\r  {CYAN}[{bar}]{RESET} {pct}%",
              end="", flush=True)
        if pct >= 100:
            print()

    elif event == "error":
        print(f"  {RED}[ERROR]{RESET}  {data}", file=sys.stderr)

    elif event == "report":
        pass


def main():

    show_banner()

    domain = input("\nEnter target domain: ").strip()

    if not domain:
        print("[!] No domain provided. Exiting.")
        return

    print(f"\n{BOLD}[ENGINE] Starting KAGURA Scan Pipeline...{RESET}\n")

    start_time = time.time()

    try:
        result = run_scan(domain, event_bus=cli_event_bus)
    except Exception as e:
        print(f"\n{RED}[!] Engine crashed: {e}{RESET}")
        import traceback
        traceback.print_exc()
        return

    subdomains      = result.get("subdomains",      [])
    assets          = result.get("assets",          [])
    vulnerabilities = result.get("vulnerabilities", [])
    endpoints       = result.get("endpoints",       [])

    scan_time = round(time.time() - start_time, 2)

    div = "─" * 44
    print(f"\n{div}")
    print(f"{GREEN}{BOLD}[✓] KAGURA Scan Completed{RESET}")
    print(div)

    print(f"{BOLD}[+] Target            :{RESET} {domain}")
    print(f"{BOLD}[+] Subdomains Found  :{RESET} "
          f"{BLUE}{len(subdomains)}{RESET}")
    print(f"{BOLD}[+] Endpoints Found   :{RESET} "
          f"{GOLD}{len(endpoints)}{RESET}")
    print(f"{BOLD}[+] Assets Found      :{RESET} "
          f"{GREEN}{len(assets)}{RESET}")
    print(f"{BOLD}[+] Vulnerabilities   :{RESET} "
          f"{RED}{len(vulnerabilities)}{RESET}")
    print(f"{BOLD}[+] Scan Time         :{RESET} {scan_time}s")

    sev_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in vulnerabilities:
        sev = (v.get("severity") or "LOW").upper()
        if sev in sev_map:
            sev_map[sev] += 1

    print(f"\n{BOLD}[+] Severity Breakdown:{RESET}")
    print(f"    {RED}CRITICAL : {sev_map['CRITICAL']}{RESET}")
    print(f"    {YELLOW}HIGH     : {sev_map['HIGH']}{RESET}")
    print(f"    {CYAN}MEDIUM   : {sev_map['MEDIUM']}{RESET}")
    print(f"    {BLUE}LOW      : {sev_map['LOW']}{RESET}")

    if endpoints:
        print(f"\n{BOLD}[+] Sample Endpoints "
              f"({len(endpoints)} total):{RESET}")
        for ep in endpoints[:15]:
            print(f"    {GOLD}-{RESET} {ep}")
        if len(endpoints) > 15:
            print(f"    {GOLD}... and {len(endpoints) - 15} more{RESET}")

    reports_dir = os.path.expanduser("~/KAGURA/reports/")
    print(f"\n{BOLD}[+] Reports directory :{RESET} {reports_dir}")
    print(f"\n{GREEN}{BOLD}[✓] KAGURA Finished.{RESET}\n")


if __name__ == "__main__":
    main()
