# ⚔ KAGURA
### Offensive Security Intelligence Framework
> *For Red Teamers — By Saksham Sharma*

---

## About

KAGURA is an open source red team reconnaissance
and vulnerability assessment framework built for
**authorized** penetration testing engagements.

It automates the information gathering and
vulnerability assessment phase of a red team
engagement — subdomain enumeration, port scanning,
endpoint discovery, vulnerability analysis and
professional report generation — all in one tool.

The name is inspired by Hinokami Kagura —
the Sun Breathing technique from Demon Slayer —
representing speed, precision and power in
offensive security.

---

## ⚠ Legal Disclaimer

**KAGURA is strictly for authorized use only.**

This tool is intended exclusively for:
- Authorized penetration testing engagements
- Security research on systems you own
- CTF (Capture The Flag) competitions
- Educational purposes in controlled environments

Unauthorized use of this tool against systems,
networks or organizations without explicit written
permission is **illegal** under the Computer Fraud
and Abuse Act (CFAA), IT Act 2000 (India), and
equivalent laws worldwide.

**The author Saksham Sharma assumes zero liability
for any misuse, damage or illegal activity
conducted using this tool. Use responsibly.**

---

## Features

-  **Subdomain Enumeration** — crt.sh,
  HackerTarget, AlienVault OTX, RapidDNS
-  **Port Scanning** — TCP scan with banner
  grabbing across all discovered subdomains
-  **Vulnerability Analysis** — CVSS scoring,
  severity classification (Critical/High/Medium/Low)
-  **Endpoint Discovery** — GAU, Katana,
  passive HTTP probing
-  **Professional HTML Reports** — Executive
  summary, findings, evidence, CVSS scores
-  **Multi-threaded Pipeline** — Fast concurrent
  scanning across all subdomains
-  **GUI Interface** — Built with PyQt6,
  real-time scan output across tabbed interface
-  **Cinematic Intro Animation** — Inspired by
  Hinokami Kagura / Demon Slayer

---

## Installation

```bash
# Clone the repository
git clone https://github.com/Saksham5harma/KAGURA.git
cd KAGURA

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

---

## Optional Tools

Install for enhanced scanning capability:

```bash
# Subfinder — subdomain enumeration
go install github.com/projectdiscovery/subfinder/\
v2/cmd/subfinder@latest

# GAU — endpoint discovery
go install github.com/lc/gau/v2/cmd/gau@latest

# Katana — web crawler
go install github.com/projectdiscovery/katana/\
cmd/katana@latest
```

---

## Usage

### GUI Mode
```bash
python3 kagura_gui.py
```

### CLI Mode
```bash
python3 main.py
```

---

## Scan Pipeline
Target Domain
│
├── Phase 1  — Subdomain Enumeration
├── Phase 1b — Endpoint Discovery
├── Phase 2  — Port Scanning (all subdomains)
├── Phase 3  — Vulnerability Analysis
└── Phase 4  — HTML Report Generation

---

## Project Structure
KAGURA/
├── kagura_gui.py        GUI entry point
├── main.py              CLI entry point
├── engine.py            Core scan pipeline
├── modules/
│   ├── subdomain_enum.py
│   ├── port_scan.py
│   ├── vuln_engine.py
│   ├── cvss_engine.py
│   ├── evidence_builder.py
│   └── report_gen.py
├── discovery/
│   └── endpoints.py
├── reports/
├── requirements.txt
└── README.md

---

## Report Output

Every scan generates a professional HTML report
saved to `reports/` containing:

- Executive Summary with key metrics
- Subdomain enumeration results
- Open ports and services per host
- Discovered web endpoints
- Vulnerability findings with CVSS scores
- Request/response evidence per finding

---

## Author

**Saksham Sharma**
GitHub: [@Saksham5harma](https://github.com/Saksham5harma)

Built as a learning project during an authorized
red team internship engagement.

---

## License

MIT License

Copyright (c) 2026 Saksham Sharma

Permission is hereby granted, free of charge,
to any person obtaining a copy of this software
to use, copy, modify, merge, publish, distribute,
sublicense and/or sell copies of the Software,
subject to the following conditions:

The above copyright notice and this permission
notice shall be included in all copies.

THE SOFTWARE IS PROVIDED AS IS, WITHOUT WARRANTY
OF ANY KIND. THE AUTHOR IS NOT LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY.

**IMPORTANT: Only use on systems you are
authorized to test.**
