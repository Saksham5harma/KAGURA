VULN_DB = {
    "redis": [
        {
            "cve": "CVE-2022-0543",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "description": "Redis Lua sandbox escape leading to remote code execution (RCE).",
            "condition": "unauthenticated or exposed redis instance",
            "attack_vector": "network",
            "impact": "remote code execution",
            "exploit_available": True
        }
    ],

    "apache_tomcat": [
        {
            "cve": "CVE-2023-28708",
            "cvss": 9.1,
            "severity": "CRITICAL",
            "description": "Tomcat misconfiguration / authentication bypass leading to admin access.",
            "condition": "exposed manager interface or default credentials",
            "attack_vector": "network",
            "impact": "auth bypass / RCE",
            "exploit_available": True
        }
    ],

    "nginx": [
        {
            "cve": "CVE-2021-23017",
            "cvss": 7.5,
            "severity": "HIGH",
            "description": "Nginx resolver vulnerability leading to memory corruption.",
            "condition": "older nginx versions using resolver feature",
            "attack_vector": "network",
            "impact": "memory corruption",
            "exploit_available": False
        }
    ],

    "mysql": [
        {
            "cve": "CVE-2021-2471",
            "cvss": 6.5,
            "severity": "MEDIUM",
            "description": "MySQL information disclosure via misconfiguration.",
            "condition": "exposed database or weak configuration",
            "attack_vector": "network",
            "impact": "data exposure",
            "exploit_available": False
        }
    ]
}
