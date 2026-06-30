class VulnerabilityDB:

    def analyze(
        self,
        subdomains,
        ports,
        endpoints,
        technologies
    ):

        findings = []

        findings.extend(
            self.analyze_ports(ports)
        )

        findings.extend(
            self.analyze_endpoints(
                endpoints
            )
        )

        findings.extend(
            self.analyze_technologies(
                technologies
            )
        )

        findings.extend(
            self.analyze_headers(
                technologies
            )
        )

        return findings

    def analyze_ports(
        self,
        ports
    ):

        findings = []

        port_rules = {

            21: (
                "FTP Service Exposed",
                "High",
                8.0,
                "CWE-200"
            ),

            22: (
                "SSH Service Exposed",
                "Low",
                3.5,
                "CWE-200"
            ),

            23: (
                "Telnet Service Exposed",
                "Critical",
                9.8,
                "CWE-319"
            ),

            445: (
                "SMB Service Exposed",
                "High",
                8.6,
                "CWE-200"
            ),

            3306: (
                "MySQL Service Exposed",
                "High",
                8.8,
                "CWE-200"
            ),

            5432: (
                "PostgreSQL Service Exposed",
                "High",
                8.4,
                "CWE-200"
            ),

            6379: (
                "Redis Service Exposed",
                "Critical",
                9.4,
                "CWE-200"
            ),

            9200: (
                "ElasticSearch Exposed",
                "Critical",
                9.8,
                "CWE-200"
            ),

            27017: (
                "MongoDB Exposed",
                "Critical",
                9.8,
                "CWE-200"
            )
        }

        for port in ports:

            port_num = port.get(
                "port"
            )

            if port_num in port_rules:

                title, sev, cvss, cwe = (
                    port_rules[port_num]
                )

                findings.append({

                    "title": title,

                    "severity": sev,

                    "cvss": cvss,

                    "cwe": cwe,

                    "evidence":
                    f"Port {port_num} is publicly accessible",

                    "remediation":
                    "Restrict access using firewall rules"
                })

        return findings

    def analyze_endpoints(
        self,
        endpoints
    ):

        findings = []

        for endpoint in endpoints:

            ep = endpoint.lower()

            if "admin" in ep:

                findings.append({

                    "title":
                    "Administrative Interface Found",

                    "severity":
                    "Medium",

                    "cvss":
                    5.3,

                    "cwe":
                    "CWE-200",

                    "evidence":
                    endpoint,

                    "remediation":
                    "Restrict admin panel access"
                })

            if "login" in ep:

                findings.append({

                    "title":
                    "Authentication Endpoint Identified",

                    "severity":
                    "Info",

                    "cvss":
                    0.0,

                    "cwe":
                    "N/A",

                    "evidence":
                    endpoint,

                    "remediation":
                    "Review authentication security controls"
                })

            if "upload" in ep:

                findings.append({

                    "title":
                    "File Upload Functionality Detected",

                    "severity":
                    "Medium",

                    "cvss":
                    6.5,

                    "cwe":
                    "CWE-434",

                    "evidence":
                    endpoint,

                    "remediation":
                    "Validate uploaded files"
                })

            if ".git" in ep:

                findings.append({

                    "title":
                    "Potential Git Repository Exposure",

                    "severity":
                    "Critical",

                    "cvss":
                    9.1,

                    "cwe":
                    "CWE-200",

                    "evidence":
                    endpoint,

                    "remediation":
                    "Block access to .git directories"
                })

            if ".env" in ep:

                findings.append({

                    "title":
                    "Potential Environment File Exposure",

                    "severity":
                    "Critical",

                    "cvss":
                    9.8,

                    "cwe":
                    "CWE-200",

                    "evidence":
                    endpoint,

                    "remediation":
                    "Prevent public access to .env files"
                })

            if "swagger" in ep:

                findings.append({

                    "title":
                    "Swagger Interface Detected",

                    "severity":
                    "Medium",

                    "cvss":
                    5.5,

                    "cwe":
                    "CWE-200",

                    "evidence":
                    endpoint,

                    "remediation":
                    "Restrict API documentation access"
                })

            if "graphql" in ep:

                findings.append({

                    "title":
                    "GraphQL Endpoint Found",

                    "severity":
                    "Info",

                    "cvss":
                    0.0,

                    "cwe":
                    "N/A",

                    "evidence":
                    endpoint,

                    "remediation":
                    "Review GraphQL security configuration"
                })

        return findings

    def analyze_technologies(
        self,
        technologies
    ):

        findings = []

        for tech in technologies:

            if not isinstance(
                tech,
                dict
            ):
                continue

            if (
                tech.get("type")
                == "Library"
            ):

                lib = tech.get(
                    "value",
                    ""
                )

                version = tech.get(
                    "version",
                    ""
                )

                if (
                    lib == "jQuery"
                    and version.startswith(
                        ("1.", "2.")
                    )
                ):

                    findings.append({

                        "title":
                        "Outdated jQuery Version Detected",

                        "severity":
                        "High",

                        "cvss":
                        8.1,

                        "cwe":
                        "CWE-1104",

                        "evidence":
                        f"jQuery {version}",

                        "remediation":
                        "Upgrade jQuery to latest version"
                    })

        return findings

    def analyze_headers(
        self,
        technologies
    ):

        findings = []

        security_headers = []

        for item in technologies:

            if (
                isinstance(item, dict)
                and item.get("type")
                == "SecurityHeaders"
            ):

                security_headers = item.get(
                    "value",
                    []
                )

        required = [

            "Content-Security-Policy",

            "Strict-Transport-Security",

            "X-Frame-Options",

            "X-Content-Type-Options"
        ]

        for header in required:

            if header not in security_headers:

                findings.append({

                    "title":
                    f"Missing Security Header: {header}",

                    "severity":
                    "Medium",

                    "cvss":
                    5.3,

                    "cwe":
                    "CWE-693",

                    "evidence":
                    f"{header} not present",

                    "remediation":
                    f"Implement {header}"
                })

        return findings
