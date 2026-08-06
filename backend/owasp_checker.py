import urllib.request
import urllib.error
import urllib.parse
import ssl
import json
import re

REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections and mitigates SSL stripping and MITM attacks.",
        "severity": "HIGH",
        "score_impact": 15
    },
    "Content-Security-Policy": {
        "description": "Mitigates Cross-Site Scripting (XSS), data injection, and unauthorized frame embedding.",
        "severity": "HIGH",
        "score_impact": 20
    },
    "X-Frame-Options": {
        "description": "Prevents Clickjacking attacks by restricting page framing.",
        "severity": "MEDIUM",
        "score_impact": 10
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing vulnerabilities on served static resources.",
        "severity": "MEDIUM",
        "score_impact": 10
    },
    "Referrer-Policy": {
        "description": "Controls referrer information leaked in HTTP requests across origin requests.",
        "severity": "LOW",
        "score_impact": 5
    },
    "Permissions-Policy": {
        "description": "Restricts browser feature APIs (camera, microphone, geolocation, payment).",
        "severity": "LOW",
        "score_impact": 5
    }
}

SENSITIVE_FILES = [
    {"path": "/.env", "name": "Environment Credentials Config", "severity": "CRITICAL"},
    {"path": "/.git/HEAD", "name": "Git Repository Source Metadata", "severity": "CRITICAL"},
    {"path": "/wp-config.php.bak", "name": "WordPress DB Config Backup", "severity": "HIGH"},
    {"path": "/config.json", "name": "Application Configuration File", "severity": "HIGH"},
    {"path": "/server-status", "name": "Apache Server Diagnostics Page", "severity": "MEDIUM"},
    {"path": "/api/v1/docs", "name": "Swagger API Documentation", "severity": "LOW"},
    {"path": "/admin", "name": "Administrative Login Portal", "severity": "MEDIUM"}
]

PUBLIC_INDEXED_FILES = [
    {"path": "/robots.txt", "name": "Robots Crawling Policy"},
    {"path": "/sitemap.xml", "name": "Sitemap Index Structure"}
]

CVE_DATABASE = [
    {
        "cve": "CVE-2023-44487",
        "title": "HTTP/2 Rapid Reset DDoS Vulnerability",
        "severity": "HIGH",
        "cvss": 7.5,
        "keywords": ["http/2", "h2"],
        "affected": "HTTP/2 Web Servers",
        "summary": "Flaw in HTTP/2 protocol stream handling permits denial-of-service via reset frames.",
        "remediation": "Update web server to latest patch release and limit HTTP/2 concurrent stream thresholds."
    },
    {
        "cve": "CVE-2021-44228",
        "title": "Log4Shell Remote Code Execution (Apache Log4j)",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "keywords": ["log4j", "log4shell"],
        "affected": "Apache Log4j 2.0-beta9 to 2.14.1",
        "summary": "JNDI lookup feature allows unauthenticated RCE via crafted log payload string.",
        "remediation": "Upgrade Log4j to 2.17.1+ or set -Dlog4j2.formatMsgNoLookups=true."
    },
    {
        "cve": "CVE-2022-22965",
        "title": "Spring4Shell RCE in Spring Framework",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "keywords": ["spring", "spring4shell"],
        "affected": "Spring Framework 5.3.0 to 5.3.17 on JDK 9+",
        "summary": "Data binding flaw enables remote code execution via class loader manipulation.",
        "remediation": "Upgrade Spring Framework to 5.3.18 or 5.2.20."
    },
    {
        "cve": "CVE-2019-0708",
        "title": "BlueKeep Remote Code Execution (RDP)",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "port": 3389,
        "keywords": ["rdp", "ms-wbt-server"],
        "affected": "Microsoft Windows RDP (Port 3389)",
        "summary": "Pre-authentication RCE vulnerability in Remote Desktop Services.",
        "remediation": "Apply Microsoft Security Advisory Patch KB4499175 and enable NLA authentication."
    },
    {
        "cve": "CVE-2022-0543",
        "title": "Redis Lua Sandbox Escape RCE",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "port": 6379,
        "keywords": ["redis"],
        "affected": "Redis Server (Port 6379)",
        "summary": "Flaw in Lua library dynamic loading permits arbitrary host OS command execution.",
        "remediation": "Upgrade Redis package and restrict port 6379 access via firewall rules."
    },
    {
        "cve": "CVE-2021-3449",
        "title": "OpenSSL TLSv1.3 NULL Pointer DoS",
        "severity": "HIGH",
        "cvss": 7.5,
        "keywords": ["openssl 1.1.1k"],
        "affected": "OpenSSL 1.1.1k and prior",
        "summary": "Crafted ClientHello message causes server crash during renegotiation.",
        "remediation": "Upgrade OpenSSL package to 1.1.1l or 3.0.0+."
    },
    {
        "cve": "CVE-2020-15778",
        "title": "OpenSSH scp Command Injection",
        "severity": "HIGH",
        "cvss": 7.8,
        "port": 22,
        "keywords": ["openssh_8.3", "scp"],
        "affected": "OpenSSH 8.3p1 and prior (Port 22)",
        "summary": "Command injection vulnerability in scp command-line parameter handling.",
        "remediation": "Use SFTP instead of SCP or upgrade OpenSSH package."
    },
    {
        "cve": "CVE-2019-2386",
        "title": "MongoDB Unauthenticated Access Risk",
        "severity": "HIGH",
        "cvss": 8.6,
        "port": 27017,
        "keywords": ["mongodb"],
        "affected": "MongoDB Instance (Port 27017)",
        "summary": "Default binding on public interfaces permits unauthenticated database dump.",
        "remediation": "Enable auth in mongod.conf and bind strictly to 127.0.0.1."
    },
    {
        "cve": "CVE-2015-1427",
        "title": "Elasticsearch Groovy Script RCE",
        "severity": "HIGH",
        "cvss": 8.5,
        "port": 9200,
        "keywords": ["elasticsearch"],
        "affected": "Elasticsearch 1.4.x (Port 9200)",
        "summary": "Unauthenticated REST payload permits sandbox escape and shell command execution.",
        "remediation": "Disable dynamic scripting or upgrade Elasticsearch engine."
    }
]

def search_cve_db(query):
    """Search CVE database by query term or CVE ID."""
    if not query:
        return CVE_DATABASE
    query_lower = query.lower().strip()
    results = []
    for cve in CVE_DATABASE:
        if (query_lower in cve["cve"].lower() or 
            query_lower in cve["title"].lower() or 
            query_lower in cve["affected"].lower() or
            query_lower in cve["summary"].lower()):
            results.append(cve)
    return results

def audit_http_headers(target_url):
    """Audit HTTP security headers for presence and recommendations."""
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    headers_found = {}
    missing_headers = []
    info_leakage = []
    html_body = ""

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        target_url,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 VanguardRecon/3.0"}
    )

    try:
        with urllib.request.urlopen(req, timeout=6.0, context=ctx) as response:
            resp_headers = {k.title(): v for k, v in response.headers.items()}
            try:
                html_body = response.read(15000).decode('utf-8', errors='ignore')
            except Exception:
                html_body = ""

            for header, info in REQUIRED_SECURITY_HEADERS.items():
                match_val = resp_headers.get(header.title())
                
                # Special check for CSP report-only mode or strict policies
                if header == "Content-Security-Policy" and not match_val:
                    if "Content-Security-Policy-Report-Only" in resp_headers:
                        match_val = resp_headers["Content-Security-Policy-Report-Only"] + " (Report-Only Mode)"

                if match_val:
                    headers_found[header] = match_val
                else:
                    missing_headers.append({
                        "header": header,
                        "description": info["description"],
                        "severity": info["severity"],
                        "score_impact": info["score_impact"]
                    })

            if "Server" in resp_headers:
                info_leakage.append({
                    "header": "Server",
                    "value": resp_headers["Server"],
                    "risk": "Reveals web server signature and version details."
                })
            if "X-Powered-By" in resp_headers:
                info_leakage.append({
                    "header": "X-Powered-By",
                    "value": resp_headers["X-Powered-By"],
                    "risk": "Exposes backend application framework (PHP/Express/ASP.NET)."
                })

            tech_stack = detect_tech_stack(resp_headers, html_body)

            return {
                "success": True,
                "target_url": target_url,
                "status_code": response.status,
                "headers_found": headers_found,
                "missing_headers": missing_headers,
                "info_leakage": info_leakage,
                "tech_stack": tech_stack
            }

    except urllib.error.HTTPError as e:
        resp_headers = {k.title(): v for k, v in e.headers.items()}
        tech_stack = detect_tech_stack(resp_headers, "")
        return {
            "success": True,
            "target_url": target_url,
            "status_code": e.code,
            "headers_found": resp_headers,
            "missing_headers": [],
            "info_leakage": [],
            "tech_stack": tech_stack or ["Standard Web Server"]
        }
    except Exception as e:
        return {
            "success": False,
            "target_url": target_url,
            "error": f"Failed to connect: {str(e)}",
            "tech_stack": []
        }

def detect_tech_stack(headers, html_body):
    """Detect technologies, CMS, and web frameworks."""
    stack = []
    server = headers.get("Server", "").lower()
    powered_by = headers.get("X-Powered-By", "").lower()
    alt_svc = headers.get("Alt-Svc", "").lower()

    if "gws" in server or "google" in server:
        stack.append("Google Web Server (GWS)")
        stack.append("Google Infrastructure / CDN")
    if "nginx" in server: stack.append("Nginx Web Server")
    if "apache" in server: stack.append("Apache HTTP Server")
    if "cloudflare" in server: stack.append("Cloudflare WAF / CDN")
    if "litespeed" in server: stack.append("LiteSpeed Web Server")

    if "h3" in alt_svc or "quic" in alt_svc:
        stack.append("HTTP/3 (QUIC Protocol)")

    if "express" in powered_by: stack.append("Express.js (Node)")
    if "php" in powered_by: stack.append("PHP Backend")
    if "asp.net" in powered_by: stack.append("ASP.NET Framework")

    if "wp-content" in html_body or "wp-includes" in html_body: stack.append("WordPress CMS")
    if "react" in html_body.lower() or "_next" in html_body: stack.append("React / Next.js")
    if "vue" in html_body.lower() or "v-data" in html_body: stack.append("Vue.js Frontend")
    if "bootstrap" in html_body.lower(): stack.append("Bootstrap CSS Framework")
    if "jquery" in html_body.lower(): stack.append("jQuery Library")

    if not stack:
        stack.append("Standard HTML5 / HTTP Server")

    return list(set(stack))

import concurrent.futures

def check_single_sensitive_file(base_url, item, ctx):
    full_url = base_url + item["path"]
    req = urllib.request.Request(
        full_url,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VanguardRecon/3.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=1.5, context=ctx) as response:
            if response.status == 200:
                return {
                    "path": item["path"],
                    "url": full_url,
                    "name": item["name"],
                    "severity": item["severity"],
                    "status": "EXPOSED"
                }
    except urllib.error.HTTPError as e:
        if e.code == 403:
            return {
                "path": item["path"],
                "url": full_url,
                "name": item["name"],
                "severity": "LOW",
                "status": "PROTECTED (403 Forbidden)"
            }
    except Exception:
        pass
    return None

def scan_sensitive_files(base_url):
    """Check for exposed sensitive files or directories concurrently."""
    base_url = base_url.rstrip("/")
    if not base_url.startswith("http://") and not base_url.startswith("https://"):
        base_url = "https://" + base_url

    disclosures = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(check_single_sensitive_file, base_url, item, ctx) for item in SENSITIVE_FILES]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                disclosures.append(res)

    return disclosures

def generate_cli_commands(hostname, open_ports):
    """Generate copy-paste CLI penetration testing commands for security engineers."""
    port_list = ",".join(str(p["port"]) for p in open_ports) if open_ports else "80,443,22"
    return {
        "nmap": f"nmap -sV -sC -p {port_list} {hostname}",
        "curl": f"curl -I -v --tls-max 1.3 https://{hostname}",
        "nikto": f"nikto -h https://{hostname} -ssl",
        "gobuster": f"gobuster dir -u https://{hostname} -w /usr/share/wordlists/dirb/common.txt"
    }

def generate_remediation_scripts(missing_headers, open_ports):
    """Generate copy-pasteable Nginx, Apache, and Firewall hardening rules."""
    nginx_lines = ["# Vanguard Recon v3.0 - Nginx Security Hardening Configuration Snippet"]
    apache_lines = ["# Vanguard Recon v3.0 - Apache .htaccess Security Headers"]

    for m in missing_headers:
        hdr = m["header"]
        if hdr == "Strict-Transport-Security":
            nginx_lines.append("add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;")
            apache_lines.append("Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"")
        elif hdr == "Content-Security-Policy":
            nginx_lines.append("add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';\" always;")
            apache_lines.append("Header always set Content-Security-Policy \"default-src 'self';\"")
        elif hdr == "X-Frame-Options":
            nginx_lines.append("add_header X-Frame-Options \"SAMEORIGIN\" always;")
            apache_lines.append("Header always set X-Frame-Options \"SAMEORIGIN\"")
        elif hdr == "X-Content-Type-Options":
            nginx_lines.append("add_header X-Content-Type-Options \"nosniff\" always;")
            apache_lines.append("Header always set X-Content-Type-Options \"nosniff\"")
        elif hdr == "Referrer-Policy":
            nginx_lines.append("add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;")
            apache_lines.append("Header always set Referrer-Policy \"strict-origin-when-cross-origin\"")

    firewall_cmd = "# Vanguard Recon - Automated UFW / Iptables Hardening Commands\n"
    for p in open_ports:
        if p["port"] in [22, 3389, 21, 23, 6379, 27017, 9200]:
            firewall_cmd += f"sudo ufw deny {p['port']}/tcp  # Block exposed service on port {p['port']}\n"
            firewall_cmd += f"iptables -A INPUT -p tcp --dport {p['port']} -j DROP\n"

    if len(firewall_cmd.splitlines()) == 1:
        firewall_cmd += "# All open ports adhere to perimeter firewall security standards."

    return {
        "nginx": "\n".join(nginx_lines),
        "apache": "\n".join(apache_lines),
        "firewall": firewall_cmd
    }

def evaluate_cve_threats(open_ports, tech_stack):
    """Cross-reference open services with Threat Intelligence CVE Database."""
    cve_findings = []
    for item in open_ports:
        port = item["port"]
        service_str = (item["service"] + " " + item.get("banner", "")).lower()
        for cve_item in CVE_DATABASE:
            cve_port = cve_item.get("port")
            keywords = cve_item.get("keywords", [])
            # Match strictly on designated port or explicit software keywords
            if (cve_port and cve_port == port) or any(kw in service_str for kw in keywords):
                cve_findings.append(cve_item)
                break
    return cve_findings

def evaluate_owasp_risks(header_audit, sensitive_files, open_ports, hostname=""):
    """Calculate overall security score (0 to 100) and risk grade."""
    score = 100
    vulnerabilities = []

    missing_hdrs = header_audit.get("missing_headers", [])
    if header_audit.get("success"):
        for missing in missing_hdrs:
            score -= missing["score_impact"]
            vulnerabilities.append({
                "category": "OWASP Security Headers",
                "title": f"Missing Header: {missing['header']}",
                "severity": missing["severity"],
                "impact": missing["description"],
                "verification_steps": f"Run 'curl -I {header_audit.get('target_url', 'https://target')}' and confirm '{missing['header']}' is absent from response headers.",
                "remediation": f"Configure web server to emit '{missing['header']}' in response headers."
            })

        for leak in header_audit.get("info_leakage", []):
            if "gws" not in leak.get("value", "").lower():
                score -= 3
                vulnerabilities.append({
                    "category": "Information Disclosure",
                    "title": f"Server Banner Leakage: {leak['header']}",
                    "severity": "LOW",
                    "impact": leak["risk"],
                    "verification_steps": f"Execute 'curl -I {header_audit.get('target_url', 'https://target')}' and observe the exposed '{leak['header']}: {leak['value']}' header.",
                    "remediation": f"Disable or obscure '{leak['header']}' in web server response configuration."
                })

    for disc in sensitive_files:
        if disc["status"] == "EXPOSED":
            if disc["severity"] == "CRITICAL":
                score -= 25
            elif disc["severity"] == "HIGH":
                score -= 15
            elif disc["severity"] == "MEDIUM":
                score -= 10
            
            vulnerabilities.append({
                "category": "Sensitive File Exposure",
                "title": f"Exposed File: {disc['path']}",
                "severity": disc["severity"],
                "impact": f"{disc['name']} is publicly accessible over HTTP/HTTPS.",
                "verification_steps": f"Send an HTTP GET request to '{disc['url']}' and verify if status code 200 is returned instead of 403/404.",
                "remediation": f"Restrict public access to '{disc['path']}' in server access rules."
            })

    cve_intel = evaluate_cve_threats(open_ports, header_audit.get("tech_stack", []))
    for cve in cve_intel:
        score -= 20 if cve["severity"] == "CRITICAL" else 12
        vulnerabilities.append({
            "category": "Threat Intel CVE",
            "title": f"{cve['cve']} — {cve['title']}",
            "severity": cve["severity"],
            "impact": cve["summary"],
            "verification_steps": f"Inspect installed service version for '{cve['affected']}' against security advisory {cve['cve']}.",
            "remediation": cve["remediation"]
        })

    score = max(0, min(100, score))
    grade = "A+"
    if score < 50: grade = "F"
    elif score < 65: grade = "D"
    elif score < 75: grade = "C"
    elif score < 88: grade = "B"
    elif score < 95: grade = "A"

    remediations = generate_remediation_scripts(missing_hdrs, open_ports)
    cli_commands = generate_cli_commands(hostname or "target", open_ports)

    return {
        "score": score,
        "grade": grade,
        "vulnerabilities": vulnerabilities,
        "cve_intel": cve_intel,
        "remediation_scripts": remediations,
        "cli_commands": cli_commands
    }
