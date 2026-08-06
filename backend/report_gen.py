from datetime import datetime

def generate_html_report(scan_results):
    """Generate a standalone executive security audit HTML report."""
    target = scan_results.get("target", "Unknown Target")
    hostname = scan_results.get("hostname", target)
    ip = scan_results.get("ip", "N/A")
    score = scan_results.get("score", 100)
    grade = scan_results.get("grade", "A+")
    timestamp = scan_results.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    open_ports = scan_results.get("open_ports", [])
    subdomains = scan_results.get("subdomains", [])
    tech_stack = scan_results.get("tech_stack", [])
    ssl_info = scan_results.get("ssl", {})
    vulnerabilities = scan_results.get("vulnerabilities", [])
    cve_intel = scan_results.get("cve_intel", [])
    remediations = scan_results.get("remediation_scripts", {})

    vuln_rows = ""
    for v in vulnerabilities:
        sev_color = "#ef4444" if v["severity"] in ["CRITICAL", "HIGH"] else ("#f59e0b" if v["severity"] == "MEDIUM" else "#3b82f6")
        verify_step = v.get("verification_steps", "Inspect target configuration")
        vuln_rows += f"""
        <tr>
            <td style="padding:12px 16px; border-bottom:1px solid #1e293b;">
                <span style="background:{sev_color}; color:#fff; padding:4px 10px; border-radius:6px; font-weight:700; font-size:11px; text-transform:uppercase;">{v['severity']}</span>
            </td>
            <td style="padding:12px 16px; border-bottom:1px solid #1e293b; font-weight:600; color:#f8fafc;">{v['title']}</td>
            <td style="padding:12px 16px; border-bottom:1px solid #1e293b; color:#cbd5e1; font-size:13px;">{v['impact']}</td>
            <td style="padding:12px 16px; border-bottom:1px solid #1e293b; color:#94a3b8; font-family:monospace; font-size:12px;">{verify_step}</td>
            <td style="padding:12px 16px; border-bottom:1px solid #1e293b; color:#38bdf8; font-family:monospace; font-size:12px;">{v['remediation']}</td>
        </tr>
        """

    port_rows = ""
    for p in open_ports:
        port_rows += f"""
        <tr style="border-bottom:1px solid #1e293b;">
            <td style="padding:10px 16px; font-weight:bold; color:#00f2fe; font-family:monospace; font-size:14px;">:{p['port']}</td>
            <td style="padding:10px 16px; color:#4ade80; font-weight:600; font-size:13px;">{p['state']}</td>
            <td style="padding:10px 16px; color:#f8fafc; font-size:13px;">{p['service']}</td>
            <td style="padding:10px 16px; color:#94a3b8; font-family:monospace; font-size:12px;">{p.get('banner', 'N/A')}</td>
        </tr>
        """

    sub_rows = ""
    for sub in subdomains:
        sub_rows += f"""
        <tr style="border-bottom:1px solid #1e293b;">
            <td style="padding:10px 16px; font-weight:bold; color:#06b6d4; font-family:monospace; font-size:13px;">{sub['subdomain']}</td>
            <td style="padding:10px 16px; color:#cbd5e1; font-family:monospace; font-size:13px;">{sub['ip']}</td>
            <td style="padding:10px 16px; color:#4ade80; font-size:13px;">{sub['status']}</td>
        </tr>
        """

    cve_rows = ""
    for cve in cve_intel:
        cve_rows += f"""
        <tr style="border-bottom:1px solid #1e293b;">
            <td style="padding:10px 16px; font-weight:bold; color:#ef4444; font-family:monospace;">{cve['cve']}</td>
            <td style="padding:10px 16px; font-weight:bold; color:#f8fafc;">{cve['title']}</td>
            <td style="padding:10px 16px; color:#f59e0b; font-weight:bold;">CVSS {cve['cvss']}</td>
            <td style="padding:10px 16px; color:#cbd5e1; font-size:13px;">{cve['summary']}</td>
        </tr>
        """

    tech_badges = "".join([f'<span style="background:#0f172a; color:#00f2fe; border:1px solid #00f2fe33; padding:5px 12px; border-radius:6px; font-size:12px; font-weight:600; margin-right:6px; display:inline-block; margin-bottom:4px;">{t}</span>' for t in tech_stack])

    nginx_code = remediations.get("nginx", "# No Nginx hardening script needed.")
    apache_code = remediations.get("apache", "# No Apache hardening script needed.")
    firewall_code = remediations.get("firewall", "# No Firewall hardening script needed.")

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vanguard Recon Executive Report — {hostname}</title>
    <style>
        :root {{
            --bg-main: #060913;
            --bg-card: #0d1324;
            --border-subtle: #1e293b;
            --accent-cyan: #00f2fe;
            --accent-blue: #38bdf8;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
        }}
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background-color: var(--bg-main);
            color: var(--text-primary);
            margin: 0;
            padding: 40px 20px;
            line-height: 1.6;
        }}
        .report-wrapper {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        .report-header {{
            border-bottom: 2px solid var(--accent-cyan);
            padding-bottom: 24px;
            margin-bottom: 32px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .brand {{
            font-size: 26px;
            font-weight: 800;
            color: var(--accent-cyan);
            font-family: monospace;
            letter-spacing: 1px;
        }}
        .score-card {{
            background: var(--bg-card);
            border-radius: 16px;
            padding: 32px;
            display: flex;
            gap: 40px;
            align-items: center;
            border: 1px solid var(--border-subtle);
            margin-bottom: 36px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
        }}
        .grade-box {{
            width: 100px;
            height: 100px;
            border-radius: 50%;
            background: linear-gradient(135deg, #0284c7, #00f2fe);
            color: #030712;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 46px;
            font-weight: 900;
            box-shadow: 0 0 24px rgba(0, 242, 254, 0.4);
            flex-shrink: 0;
        }}
        .section-title {{
            font-size: 19px;
            font-weight: 700;
            color: var(--accent-cyan);
            margin-top: 36px;
            margin-bottom: 16px;
            border-left: 4px solid var(--accent-cyan);
            padding-left: 14px;
            letter-spacing: 0.3px;
        }}
        table.data-table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-card);
            border-radius: 12px;
            overflow: hidden;
            margin-bottom: 28px;
            border: 1px solid var(--border-subtle);
        }}
        table.data-table th {{
            background: #090e1a;
            text-align: left;
            padding: 14px 16px;
            color: var(--text-secondary);
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 2px solid var(--border-subtle);
        }}
        .code-snippet-box {{
            background: #030611;
            border: 1px solid var(--border-subtle);
            border-radius: 10px;
            padding: 16px;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 12.5px;
            color: #38bdf8;
            margin-bottom: 20px;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .print-btn {{
            background: linear-gradient(135deg, #00f2fe, #0284c7);
            color: #030712;
            border: none;
            padding: 10px 22px;
            border-radius: 8px;
            font-weight: 700;
            font-size: 13.5px;
            cursor: pointer;
            box-shadow: 0 4px 15px rgba(0, 242, 254, 0.3);
        }}
        @media print {{
            .no-print {{ display: none !important; }}
            body {{ background: #fff !important; color: #000 !important; padding: 0 !important; }}
            .score-card, table.data-table, .code-snippet-box {{ background: #fff !important; color: #000 !important; border: 1px solid #ccc !important; box-shadow: none !important; }}
            .grade-box {{ background: #0284c7 !important; color: #fff !important; }}
            .section-title {{ color: #0284c7 !important; border-left-color: #0284c7 !important; }}
        }}
    </style>
</head>
<body>
    <div class="report-wrapper">
        <div class="report-header">
            <div>
                <div class="brand">🛡️ VANGUARD RECON SUITE v3.0 PRO</div>
                <div style="color: var(--text-secondary); font-size: 14px; margin-top: 4px;">Executive Security Audit & Threat Intelligence Report</div>
            </div>
            <div style="text-align: right;" class="no-print">
                <button onclick="window.print()" class="print-btn">🖨️ Print / Save PDF</button>
                <div style="color: var(--text-secondary); font-size: 12px; margin-top: 8px;">Generated: {timestamp}</div>
            </div>
        </div>

        <div class="score-card">
            <div class="grade-box">{grade}</div>
            <div>
                <h2 style="margin: 0 0 8px 0; color: #f8fafc; font-size: 24px;">Target Host: <span style="color:var(--accent-cyan);">{hostname}</span> ({ip})</h2>
                <div style="font-size: 18px; color: #cbd5e1;">Overall Security Posture Score: <strong style="color: var(--accent-cyan); font-size:22px;">{score} / 100</strong></div>
                <div style="margin-top: 12px;">{tech_badges}</div>
            </div>
        </div>

        <div class="section-title">Critical & Priority Security Findings</div>
        <table class="data-table">
            <thead>
                <tr>
                    <th style="width:110px;">Severity</th>
                    <th>Finding Title</th>
                    <th>Impact Description</th>
                    <th>Defensive Verification Audit Method</th>
                    <th>Recommended Remediation</th>
                </tr>
            </thead>
            <tbody>
                {vuln_rows if vuln_rows else '<tr><td colspan="5" style="padding:16px; color:#4ade80; text-align:center;">✓ Zero security vulnerabilities identified.</td></tr>'}
            </tbody>
        </table>

        {f'''
        <div class="section-title">Threat Intelligence & CVE Vulnerabilities</div>
        <table class="data-table">
            <thead>
                <tr>
                    <th>CVE ID</th>
                    <th>Vulnerability Title</th>
                    <th>CVSS Score</th>
                    <th>Threat Summary</th>
                </tr>
            </thead>
            <tbody>
                {cve_rows}
            </tbody>
        </table>
        ''' if cve_rows else ''}

        <div class="section-title">Open Port & Service Enumeration</div>
        <table class="data-table">
            <thead>
                <tr>
                    <th style="width:90px;">Port</th>
                    <th style="width:100px;">State</th>
                    <th style="width:180px;">Service Name</th>
                    <th>Banner / Header Signature</th>
                </tr>
            </thead>
            <tbody>
                {port_rows if port_rows else '<tr><td colspan="4" style="padding:18px; text-align:center; color:#94a3b8;">No open standard ports detected.</td></tr>'}
            </tbody>
        </table>

        <div class="section-title">Active Subdomains Discovered</div>
        <table class="data-table">
            <thead>
                <tr>
                    <th>Subdomain</th>
                    <th>Resolved IP Address</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {sub_rows if sub_rows else '<tr><td colspan="3" style="padding:18px; text-align:center; color:#94a3b8;">No public subdomains enumerated.</td></tr>'}
            </tbody>
        </table>

        <div class="section-title">SSL / TLS Certificate Audit</div>
        <div style="background:var(--bg-card); padding:20px; border-radius:12px; border:1px solid var(--border-subtle); color:#cbd5e1; font-size:14px; margin-bottom:28px;">
            <strong>SSL Status:</strong> <span style="color:#4ade80; font-weight:bold;">{ssl_info.get('status', 'N/A')}</span> | 
            <strong>Protocol:</strong> {ssl_info.get('version', 'N/A')} | 
            <strong>Cipher Suite:</strong> {ssl_info.get('cipher', 'N/A')} | 
            <strong>Issuer:</strong> {ssl_info.get('issuer_o', 'N/A')}
        </div>

        <div class="section-title">Automated Server Hardening Snippets</div>
        <div style="font-weight:600; color:var(--text-secondary); margin-bottom:6px; font-size:13px;">Nginx Security Headers Hardening:</div>
        <div class="code-snippet-box">{nginx_code}</div>
        
        <div style="font-weight:600; color:var(--text-secondary); margin-bottom:6px; font-size:13px;">Apache .htaccess Security Headers:</div>
        <div class="code-snippet-box">{apache_code}</div>

        <div style="font-weight:600; color:var(--text-secondary); margin-bottom:6px; font-size:13px;">UFW / Firewall Rules:</div>
        <div class="code-snippet-box">{firewall_code}</div>
    </div>
</body>
</html>
"""
    return html_content
