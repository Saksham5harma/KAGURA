import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


from engines.subdomain_enum import SubdomainEnum
from engines.port_scan import PortScanner
from engines.discovery_engine import DiscoveryEngine
from engines.tech_fingerprint import TechFingerprint

from engines.http_security_analyzer import analyze_http_security
from engines.ssl_tls_analyzer import analyze_ssl
from engines.waf_detector import detect_waf
from engines.javascript_analyzer import scan_js_secrets

from engines.vuln_engine import VulnEngine
from api.ws_dashboard import push_event
from engines.risk_engine import calculate_risk_score


class ScanOrchestrator:

    def __init__(self, event_bus=None, max_workers=10):

        self.event_bus = event_bus
        self.max_workers = max_workers

        self.subdomain_engine = SubdomainEnum()
        self.port_engine = PortScanner()
        self.discovery_engine = DiscoveryEngine()
        self.tech_engine = TechFingerprint()

        self.vuln_engine = VulnEngine(event_bus=event_bus)

    def emit(self, event_type, message):
        if self.event_bus:
            self.event_bus(event_type, message)

    def run_recon(self, target):

        push_event("status", "Phase 1 — Reconnaissance started")

        subdomains = self.subdomain_engine.enumerate(target)
        ports = self.port_engine.scan(target)
        endpoints = self.discovery_engine.find_endpoints(target)
        tech = self.tech_engine.identify(target)

        return subdomains, ports, endpoints, tech

    def run_analysis(self, target, subdomains):

        self.emit("status", "Phase 2 — Security Analysis (Parallel)")

        findings = []

        analyzers = [
            analyze_http_security,
            analyze_ssl,
            detect_waf,
            scan_js_secrets
        ]

        def run_analyzer(fn):
            try:
                return fn(target)
            except Exception:
                return []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:

            future_map = {
                executor.submit(run_analyzer, fn): fn.__name__
                for fn in analyzers
            }

            for future in as_completed(future_map):

                try:
                    results = future.result()

                    for r in results:
                        findings.append(r)

                        self.emit(
                            "vuln",
                            f"{r.get('severity')} | {r.get('host')} | {r.get('title')}"
                        )

                except Exception:
                    continue

        return findings

    def run_vuln_engine(self, target, subdomains, ports, endpoints):

        self.emit("status", "Phase 3 — Vulnerability Correlation")

        return self.vuln_engine.run_full_scan(target)

    def run_risk_engine(self, vulns):

        self.emit("status", "Phase 4 — Risk Calculation")

        return calculate_risk_score(vulns)

    def run(self, target):

        start_time = datetime.utcnow().isoformat()

        self.emit("status", f"Scan started for {target}")

        subdomains, ports, endpoints, tech = self.run_recon(target)

        analysis_findings = self.run_analysis(target, subdomains)

        vulns = self.run_vuln_engine(target, subdomains, ports, endpoints)

        all_vulns = vulns + analysis_findings

        risk = self.run_risk_engine(all_vulns)

        self.emit("status", "Scan Completed")

        return {
            "target": target,
            "scan_time": start_time,

            "recon": {
                "subdomains": subdomains,
                "ports": ports,
                "endpoints": endpoints,
                "technology": tech
            },

            "vulnerabilities": all_vulns,

            "risk": risk,

            "meta": {
                "total_vulnerabilities": len(all_vulns),
                "total_subdomains": len(subdomains),
                "total_ports": len(ports)
            }
        }
