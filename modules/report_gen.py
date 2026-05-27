import os
from datetime import datetime


def generate_report(result):
    meta      = result.get("meta", {})
    subdoms   = result.get("subdomains", [])
    assets    = result.get("assets", [])
    vulns     = result.get("vulnerabilities", [])
    endpoints = result.get("endpoints", [])
    target    = meta.get("target", "UNKNOWN")

    reports_dir = os.path.expanduser("~/KAGURA/reports/")
    os.makedirs(reports_dir, exist_ok=True)

    filename = os.path.join(
        reports_dir,
        f"KAGURA_REPORT_{target}_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    )

    def sev_color(s):
        return {
            "CRITICAL": "#b71c1c",
            "HIGH":     "#e65100",
            "MEDIUM":   "#f57f17",
            "LOW":      "#1565c0"
        }.get((s or "").upper(), "#333333")

    vuln_rows = ""
    for v in vulns:
        sev   = (v.get("severity") or "LOW").upper()
        color = sev_color(sev)
        evid  = v.get("evidence", {})
        vuln_rows += f"""
        <tr>
          <td>{v.get('host','')}</td>
          <td style="color:{color};font-weight:bold">
            {sev}</td>
          <td>{v.get('title','')}</td>
          <td>{v.get('cvss','N/A')}</td>
          <td style="font-size:11px;font-family:monospace">
            {evid.get('summary','')}</td>
        </tr>"""

    subdomain_rows = "".join(
        f"<tr><td>{s}</td></tr>" for s in subdoms)

    asset_rows = ""
    for a in assets:
        asset_rows += f"""
        <tr>
          <td>{a.get('host','')}</td>
          <td>{a.get('port','')}</td>
          <td>{a.get('service','')}</td>
          <td>{a.get('banner','')}</td>
        </tr>"""

    endpoint_rows = "".join(
        f"<tr><td style='font-family:monospace'>"
        f"{e}</td></tr>"
        for e in endpoints
    )

    crit = sum(1 for v in vulns
               if (v.get('severity') or '').upper()
               == 'CRITICAL')
    high = sum(1 for v in vulns
               if (v.get('severity') or '').upper()
               == 'HIGH')
    med  = sum(1 for v in vulns
               if (v.get('severity') or '').upper()
               == 'MEDIUM')
    low  = sum(1 for v in vulns
               if (v.get('severity') or '').upper()
               == 'LOW')

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>KAGURA Report — {target}</title>
<style>
  body {{
    font-family: Arial, sans-serif;
    background: #f5f7fa;
    color: #111;
    margin: 0; padding: 0;
  }}
  .header {{
    background: linear-gradient(
      to right, #0d1b2a, #1565c0);
    color: white;
    padding: 30px 40px;
  }}
  .header h1 {{
    margin: 0;
    font-size: 32px;
    letter-spacing: 2px;
  }}
  .header p {{
    margin: 6px 0 0 0;
    color: goldenrod;
    font-size: 13px;
    letter-spacing: 3px;
  }}
  .container {{ padding: 30px 40px; }}
  .summary {{
    display: flex;
    gap: 16px;
    margin-bottom: 30px;
  }}
  .card {{
    flex: 1;
    background: white;
    border-radius: 10px;
    padding: 20px;
    text-align: center;
    border: 2px solid #e0e0e0;
    box-shadow: 0 2px 6px rgba(0,0,0,0.06);
  }}
  .card .val {{
    font-size: 36px;
    font-weight: bold;
  }}
  .card .lbl {{
    font-size: 12px;
    color: #777;
    letter-spacing: 1px;
    margin-top: 4px;
  }}
  .section {{
    background: white;
    border-radius: 10px;
    padding: 20px 24px;
    margin-bottom: 24px;
    border: 1px solid #e0e0e0;
    box-shadow: 0 2px 6px rgba(0,0,0,0.04);
  }}
  .section h2 {{
    font-size: 16px;
    border-bottom: 2px solid #e0e0e0;
    padding-bottom: 8px;
    margin-top: 0;
    color: #1565c0;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }}
  th, td {{
    border: 1px solid #e0e0e0;
    padding: 9px 12px;
    text-align: left;
  }}
  th {{
    background: #f0f4f8;
    font-weight: bold;
    color: #333;
  }}
  tr:nth-child(even) {{ background: #fafafa; }}
  .sev-badge {{
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: bold;
    color: white;
  }}
  .footer {{
    text-align: center;
    padding: 20px;
    font-size: 12px;
    color: #aaa;
  }}
</style>
</head>
<body>

<div class="header">
  <h1>⚔ KAGURA SECURITY REPORT</h1>
  <p>OFFENSIVE SECURITY INTELLIGENCE FRAMEWORK</p>
  <p style="color:#ccc;font-size:12px;letter-spacing:1px">
    Target: {target} &nbsp;|&nbsp;
    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  </p>
</div>

<div class="container">

  <!-- Summary Cards -->
  <div class="summary">
    <div class="card">
      <div class="val" style="color:#1565c0">
        {len(subdoms)}</div>
      <div class="lbl">SUBDOMAINS</div>
    </div>
    <div class="card">
      <div class="val" style="color:#2e7d32">
        {len(assets)}</div>
      <div class="lbl">OPEN PORTS</div>
    </div>
    <div class="card">
      <div class="val" style="color:#6a1b9a">
        {len(endpoints)}</div>
      <div class="lbl">ENDPOINTS</div>
    </div>
    <div class="card">
      <div class="val" style="color:#b71c1c">
        {len(vulns)}</div>
      <div class="lbl">VULNERABILITIES</div>
    </div>
  </div>

  <!-- Severity Breakdown -->
  <div class="section">
    <h2>Severity Breakdown</h2>
    <div style="display:flex;gap:12px">
      <div class="card" style="border-color:#b71c1c">
        <div class="val" style="color:#b71c1c">
          {crit}</div>
        <div class="lbl">CRITICAL</div>
      </div>
      <div class="card" style="border-color:#e65100">
        <div class="val" style="color:#e65100">
          {high}</div>
        <div class="lbl">HIGH</div>
      </div>
      <div class="card" style="border-color:#f57f17">
        <div class="val" style="color:#f57f17">
          {med}</div>
        <div class="lbl">MEDIUM</div>
      </div>
      <div class="card" style="border-color:#1565c0">
        <div class="val" style="color:#1565c0">
          {low}</div>
        <div class="lbl">LOW</div>
      </div>
    </div>
  </div>

  <!-- Subdomains -->
  <div class="section">
    <h2>Subdomain Enumeration
      ({len(subdoms)} found)</h2>
    <table>
      <tr><th>Subdomain</th></tr>
      {subdomain_rows}
    </table>
  </div>

  <!-- Ports -->
  <div class="section">
    <h2>Open Ports &amp; Services
      ({len(assets)} found)</h2>
    <table>
      <tr>
        <th>Host</th><th>Port</th>
        <th>Service</th><th>Banner</th>
      </tr>
      {asset_rows}
    </table>
  </div>

  <!-- Endpoints -->
  <div class="section">
    <h2>Discovered Endpoints
      ({len(endpoints)} found)</h2>
    <table>
      <tr><th>URL</th></tr>
      {endpoint_rows if endpoint_rows
       else "<tr><td>No endpoints found</td></tr>"}
    </table>
  </div>

  <!-- Vulnerabilities -->
  <div class="section">
    <h2>Security Findings
      ({len(vulns)} found)</h2>
    <table>
      <tr>
        <th>Host</th><th>Severity</th>
        <th>Finding</th><th>CVSS</th>
        <th>Evidence</th>
      </tr>
      {vuln_rows if vuln_rows
       else "<tr><td colspan='5'>"
            "No vulnerabilities detected</td></tr>"}
    </table>
  </div>

</div>

<div class="footer">
  Generated by KAGURA Security Intelligence
  Framework v1.0 &nbsp;⚔&nbsp;
  {datetime.now().strftime('%Y-%m-%d')}
</div>

</body>
</html>"""

    with open(filename, "w") as f:
        f.write(html)

    print(f"[✓] Report saved: {filename}")
    return filename
