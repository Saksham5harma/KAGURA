from datetime import datetime

from engines.discovery_engine import DiscoveryEngine
from engines.subdomain_enum import SubdomainEnum
from engines.port_scan import PortScanner
from engines.tech_fingerprint import TechFingerprint

from engines.vuln_db import VulnerabilityDB
from engines.cvss_engine import CVSSEngine
from engines.evidence_builder import EvidenceBuilder


class VulnEngine:

    def __init__(self):
        self.discovery = DiscoveryEngine()
        self.subdomains = SubdomainEnum()
        self.ports = PortScanner()
        self.tech = TechFingerprint()

        self.vuln_db = VulnerabilityDB()
        self.cvss = CVSSEngine()
        self.evidence = EvidenceBuilder()

    def run_full_scan(self, target, event_bus=None):

        def emit(event, data):
            if event_bus:
                event_bus(event, data)

        start = datetime.utcnow()

        emit("status", "Phase 1 — Subdomain Enumeration")

        subdomains = self.subdomains.enumerate(target)
        for s in subdomains:
            emit("recon", s)

        emit("status", "Phase 2 — Port Scanning")

        ports = self.ports.scan(target)
        for p in ports:
            emit("port", str(p))

        emit("status", "Collecting Endpoints")

        endpoints = self.discovery.find_endpoints(target)
        for e in endpoints:
            emit("endpoint", e)

        emit("status", "Fingerprinting Technology")

        tech = self.tech.identify(target)

        emit("status", "Phase 3 — Vulnerability Analysis")

        vulns = self.vuln_db.analyze(subdomains, ports, endpoints)

        for v in vulns:
            v["cvss"] = self.cvss.calculate(v)
            v["evidence"] = self.evidence.build(v, target)
            emit("vuln", f"{v.get('severity')} | {v.get('title')}")

        end = datetime.utcnow()

        return {
            "target": target,
            "scan_time": (end - start).total_seconds(),

            "subdomains": subdomains,
            "ports": ports,
            "technology": tech,
            "endpoints": endpoints,
            "vulnerabilities": vulns
        }
