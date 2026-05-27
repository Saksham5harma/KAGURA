def analyze_vulnerabilities(host, ports):

    findings = []

    critical_ports = {
        6379:  ("Redis Exposed — Likely Unauthenticated", "CRITICAL", 9.8),
        8080:  ("Tomcat/Jenkins Panel Exposed", "CRITICAL", 9.8),
        27017: ("MongoDB Exposed", "CRITICAL", 9.8),
        2375:  ("Docker API Exposed", "CRITICAL", 9.8),
        4848:  ("GlassFish Admin Exposed", "CRITICAL", 9.0),
        9200:  ("Elasticsearch Exposed", "CRITICAL", 9.4),
        5000:  ("Docker Registry Exposed", "CRITICAL", 9.1),
        11211: ("Memcached Exposed", "CRITICAL", 9.0),
    }

    high_ports = {
        22:   ("SSH Service Exposed", "HIGH", 7.5),
        21:   ("FTP Service Running", "HIGH", 7.1),
        3306: ("MySQL Database Exposed", "HIGH", 7.5),
        5432: ("PostgreSQL Exposed", "HIGH", 7.5),
        5601: ("Kibana Dashboard Exposed", "HIGH", 7.2),
        8443: ("HTTPS Alternate Port Open", "HIGH", 7.0),
        3389: ("RDP Service Exposed", "HIGH", 8.0),
        5900: ("VNC Service Exposed", "HIGH", 8.1),
        1521: ("Oracle Database Exposed", "HIGH", 7.8),
        4444: ("Metasploit Handler Port Open", "HIGH", 8.5),
    }

    medium_ports = {
        25:   ("SMTP Port Open", "MEDIUM", 5.0),
        445:  ("SMB Port Exposed", "MEDIUM", 5.5),
        110:  ("POP3 Exposed", "MEDIUM", 4.8),
        143:  ("IMAP Exposed", "MEDIUM", 4.8),
        8888: ("HTTP Alternate Port", "MEDIUM", 5.0),
        9090: ("Admin Panel Suspected", "MEDIUM", 5.5),
        8000: ("Development Server Exposed", "MEDIUM", 5.8),
        3000: ("NodeJS Dev Server Exposed", "MEDIUM", 5.9),
        7001: ("WebLogic Console Exposed", "MEDIUM", 6.5),
    }

    low_ports = {
        80:  ("HTTP Unencrypted", "LOW", 3.1),
        443: ("HTTPS Open", "LOW", 2.0),
        53:  ("DNS Port Exposed", "LOW", 3.0),
    }

    sensitive_keywords = {
        'admin':    ("Admin Panel Subdomain Exposed", "HIGH", 7.2),
        'internal': ("Internal Service Publicly Exposed", "HIGH", 7.5),
        'vpn':      ("VPN Service Exposed", "HIGH", 7.8),
        'dev':      ("Development Environment Exposed", "HIGH", 7.0),
        'staging':  ("Staging Environment Exposed", "MEDIUM", 6.1),
        'jenkins':  ("Jenkins CI Exposed", "CRITICAL", 9.1),
        'git':      ("Git Service Exposed", "HIGH", 7.5),
        'backup':   ("Backup Service Exposed", "HIGH", 7.8),
        'test':     ("Test Environment Exposed", "MEDIUM", 5.5),
        'api':      ("API Endpoint Exposed", "MEDIUM", 6.0),
        'db':       ("Database Service Exposed", "HIGH", 7.5),
        'portal':   ("Portal Exposed", "MEDIUM", 5.8),
        'secret':   ("Secret/Config Exposed", "CRITICAL", 9.0),
        'config':   ("Config Endpoint Exposed", "HIGH", 7.2),
        'grafana':  ("Grafana Dashboard Exposed", "HIGH", 7.8),
        'kibana':   ("Kibana Dashboard Exposed", "HIGH", 7.5),
        'monitor':  ("Monitoring Panel Exposed", "MEDIUM", 5.5),
    }

    dangerous_banners = {
        'apache/2.2': ("Outdated Apache Version Detected", "HIGH", 7.5),
        'php/5': ("Outdated PHP Version Detected", "HIGH", 8.0),
        'openssh 5': ("Outdated OpenSSH Version", "HIGH", 7.2),
        'iis/6.0': ("Outdated IIS Version Detected", "HIGH", 8.1),
        'ubuntu': ("Server Information Disclosure", "LOW", 3.5),
    }

    for p in ports:

        port = p.get('port')
        service = p.get('service', 'unknown')
        banner = p.get('banner', '')

        for port_map in [
            critical_ports,
            high_ports,
            medium_ports,
            low_ports,
        ]:

            if port in port_map:

                title, severity, cvss = port_map[port]

                findings.append({
                    'host': host,
                    'title': title,
                    'severity': severity,
                    'cvss': cvss,
                    'port': port,
                    'service': service,
                    'description': (
                        f"Port {port} ({service}) is open on {host}. "
                        f"Banner: {banner if banner else 'N/A'}"
                    )
                })

                break

        if banner:

            banner_lower = banner.lower()

            for sig, vuln_data in dangerous_banners.items():

                if sig in banner_lower:

                    title, severity, cvss = vuln_data

                    findings.append({
                        'host': host,
                        'title': title,
                        'severity': severity,
                        'cvss': cvss,
                        'port': port,
                        'service': service,
                        'description': (
                            f"Potential vulnerable banner detected on "
                            f"{host}:{port} -> {banner}"
                        )
                    })

            if 'x-frame-options' not in banner_lower:

                findings.append({
                    'host': host,
                    'title': "Missing X-Frame-Options Header",
                    'severity': "LOW",
                    'cvss': 3.1,
                    'port': port,
                    'service': service,
                    'description': (
                        f"X-Frame-Options header not detected on {host}:{port}"
                    )
                })

            if 'strict-transport-security' not in banner_lower:

                findings.append({
                    'host': host,
                    'title': "Missing HSTS Header",
                    'severity': "MEDIUM",
                    'cvss': 5.0,
                    'port': port,
                    'service': service,
                    'description': (
                        f"HSTS header not detected on {host}:{port}"
                    )
                })

            if 'server:' in banner_lower:

                findings.append({
                    'host': host,
                    'title': "Server Version Disclosure",
                    'severity': "LOW",
                    'cvss': 3.7,
                    'port': port,
                    'service': service,
                    'description': (
                        f"Server banner discloses version information "
                        f"on {host}:{port}"
                    )
                })

    host_lower = host.lower()

    for keyword, (title, severity, cvss) in sensitive_keywords.items():

        if keyword in host_lower:

            findings.append({
                'host': host,
                'title': title,
                'severity': severity,
                'cvss': cvss,
                'port': None,
                'service': "subdomain",
                'description': (
                    f"Subdomain '{host}' contains sensitive "
                    f"keyword '{keyword}' and is publicly accessible."
                )
            })

    unique_findings = []

    seen = set()

    for finding in findings:

        key = (
            finding.get('host'),
            finding.get('title'),
            finding.get('port')
        )

        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)

    return unique_findings


def vuln_scan(subdomains):

    all_findings = []

    for item in subdomains:

        try:

            if isinstance(item, dict):

                host = item.get("host") or item.get("subdomain")

                ports = item.get("ports", [])

            else:

                host = str(item)

                ports = []

            findings = analyze_vulnerabilities(host, ports)

            all_findings.extend(findings)

        except Exception as e:

            print(f"[!] Vulnerability scan failed for {item}: {e}")

    return all_findings
