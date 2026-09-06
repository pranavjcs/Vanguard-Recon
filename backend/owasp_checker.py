import urllib.request
import urllib.error
import urllib.parse
import ssl
import json
import re

REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections and mitigates SSL stripping and MITM attacks.",
        "severity": "MEDIUM",
        "score_impact": 5
    },
    "Content-Security-Policy": {
        "description": "Mitigates Cross-Site Scripting (XSS), data injection, and unauthorized frame embedding.",
        "severity": "MEDIUM",
        "score_impact": 6
    },
    "X-Frame-Options": {
        "description": "Prevents Clickjacking attacks by restricting page framing.",
        "severity": "LOW",
        "score_impact": 4
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing vulnerabilities on served static resources.",
        "severity": "LOW",
        "score_impact": 4
    },
    "Referrer-Policy": {
        "description": "Controls referrer information leaked in HTTP requests across origin requests.",
        "severity": "LOW",
        "score_impact": 3
    },
    "Permissions-Policy": {
        "description": "Restricts browser feature APIs (camera, microphone, geolocation, payment).",
        "severity": "LOW",
        "score_impact": 3
    }
}

QUICK_SENSITIVE_FILES = [
    {"path": "/.env", "name": "Environment Credentials Config", "severity": "CRITICAL", "content_check": lambda b: b"=" in b and b"<html" not in b.lower()},
    {"path": "/.git/HEAD", "name": "Git Repository Source Metadata", "severity": "CRITICAL", "content_check": lambda b: b"ref: refs/" in b or (len(b.strip()) == 40 and b"<html" not in b.lower())},
    {"path": "/wp-config.php.bak", "name": "WordPress DB Config Backup", "severity": "HIGH", "content_check": lambda b: b"DB_PASSWORD" in b or b"<?php" in b},
    {"path": "/config.json", "name": "Application Configuration File", "severity": "HIGH", "content_check": lambda b: b"{" in b and b"<html" not in b.lower()},
    {"path": "/admin", "name": "Administrative Login Portal", "severity": "LOW", "content_check": lambda b: True}
]

FULL_SENSITIVE_FILES = [
    {"path": "/.env", "name": "Environment Credentials Config", "severity": "CRITICAL", "content_check": lambda b: b"=" in b and b"<html" not in b.lower()},
    {"path": "/.git/HEAD", "name": "Git Repository Source Metadata", "severity": "CRITICAL", "content_check": lambda b: b"ref: refs/" in b or (len(b.strip()) == 40 and b"<html" not in b.lower())},
    {"path": "/wp-config.php.bak", "name": "WordPress DB Config Backup", "severity": "HIGH", "content_check": lambda b: b"DB_PASSWORD" in b or b"<?php" in b},
    {"path": "/config.json", "name": "Application Configuration File", "severity": "HIGH", "content_check": lambda b: b"{" in b and b"<html" not in b.lower()},
    {"path": "/.aws/credentials", "name": "AWS Cloud IAM Credentials", "severity": "CRITICAL", "content_check": lambda b: b"aws_access_key_id" in b.lower() or b"[default]" in b},
    {"path": "/.dockerenv", "name": "Docker Container Signature", "severity": "MEDIUM", "content_check": lambda b: True},
    {"path": "/phpinfo.php", "name": "PHP Diagnostic Info Page", "severity": "HIGH", "content_check": lambda b: b"PHP Version" in b or b"phpinfo()" in b},
    {"path": "/.DS_Store", "name": "macOS Directory Index Leak", "severity": "LOW", "content_check": lambda b: b"Bud1" in b or len(b) > 10},
    {"path": "/backup.sql", "name": "Raw SQL Database Dump", "severity": "CRITICAL", "content_check": lambda b: b"CREATE TABLE" in b or b"INSERT INTO" in b},
    {"path": "/backup.zip", "name": "Full Application Code Backup", "severity": "CRITICAL", "content_check": lambda b: b.startswith(b"PK")},
    {"path": "/server-status", "name": "Apache Server Diagnostics Page", "severity": "MEDIUM", "content_check": lambda b: b"Apache Server Status" in b or b"Server Version" in b},
    {"path": "/api/v1/docs", "name": "Swagger API Documentation", "severity": "LOW", "content_check": lambda b: b"swagger" in b.lower() or b"openapi" in b.lower()},
    {"path": "/.htaccess", "name": "Apache Access Control Config", "severity": "HIGH", "content_check": lambda b: b"RewriteEngine" in b or b"Order allow,deny" in b},
    {"path": "/.gitlab-ci.yml", "name": "CI/CD Pipeline Workflow Config", "severity": "MEDIUM", "content_check": lambda b: b"stages:" in b or b"image:" in b},
    {"path": "/web.config", "name": "IIS ASP.NET Application Config", "severity": "HIGH", "content_check": lambda b: b"<configuration>" in b},
    {"path": "/admin", "name": "Administrative Login Portal", "severity": "LOW", "content_check": lambda b: True}
]

SENSITIVE_FILES = FULL_SENSITIVE_FILES

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

def audit_http_headers(target_url, scan_mode="quick"):
    """Audit HTTP security headers, cookies, and CORS policies."""
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    headers_found = {}
    missing_headers = []
    info_leakage = []
    cookie_findings = []
    cors_findings = []
    html_body = ""

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        target_url,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"}
    )

    try:
        with urllib.request.urlopen(req, timeout=6.0, context=ctx) as response:
            raw_headers = {k.lower(): v for k, v in response.headers.items()}
            try:
                html_body = response.read(15000).decode('utf-8', errors='ignore')
            except Exception:
                html_body = ""

            for header, info in REQUIRED_SECURITY_HEADERS.items():
                hdr_lower = header.lower()
                match_val = raw_headers.get(hdr_lower)
                
                # Special check for CSP report-only mode
                if header == "Content-Security-Policy" and not match_val:
                    if "content-security-policy-report-only" in raw_headers:
                        match_val = raw_headers["content-security-policy-report-only"] + " (Report-Only Mode)"

                if match_val:
                    headers_found[header] = match_val
                else:
                    missing_headers.append({
                        "header": header,
                        "description": info["description"],
                        "severity": info["severity"],
                        "score_impact": info["score_impact"]
                    })

            # Server Version Disclosure
            server_val = raw_headers.get("server", "")
            if server_val and any(char.isdigit() for char in server_val):
                info_leakage.append({
                    "header": "Server",
                    "value": server_val,
                    "risk": f"Discloses exact web server software version ({server_val})."
                })

            powered_by = raw_headers.get("x-powered-by", "")
            if powered_by:
                info_leakage.append({
                    "header": "X-Powered-By",
                    "value": powered_by,
                    "risk": f"Exposes backend application framework ({powered_by})."
                })

            # Deep Mode: Cookie Security & CORS Analysis
            if scan_mode == "full":
                cookies = response.headers.get_all('Set-Cookie') if hasattr(response.headers, 'get_all') else []
                if not cookies and "set-cookie" in raw_headers:
                    cookies = [raw_headers["set-cookie"]]

                for cookie_str in cookies:
                    cookie_name = cookie_str.split(';')[0].split('=')[0].strip()
                    c_lower = cookie_str.lower()
                    if "httponly" not in c_lower:
                        cookie_findings.append({
                            "cookie": cookie_name,
                            "issue": "Missing 'HttpOnly' flag",
                            "severity": "MEDIUM",
                            "impact": "Cookie is accessible via client-side JavaScript, increasing XSS session theft vulnerability."
                        })
                    if "secure" not in c_lower and target_url.startswith("https"):
                        cookie_findings.append({
                            "cookie": cookie_name,
                            "issue": "Missing 'Secure' flag",
                            "severity": "MEDIUM",
                            "impact": "Cookie can be transmitted over unencrypted HTTP connections in cleartext."
                        })
                    if "samesite" not in c_lower:
                        cookie_findings.append({
                            "cookie": cookie_name,
                            "issue": "Missing 'SameSite' attribute",
                            "severity": "LOW",
                            "impact": "Cookie lacks explicit Cross-Site Request Forgery (CSRF) protection."
                        })

                # CORS Analysis
                cors_origin = raw_headers.get("access-control-allow-origin", "")
                cors_cred = raw_headers.get("access-control-allow-credentials", "").lower()
                if cors_origin == "*" and cors_cred == "true":
                    cors_findings.append({
                        "issue": "Permissive Wildcard CORS with Credentials",
                        "severity": "HIGH",
                        "impact": "Insecure CORS configuration allows arbitrary origins to make credentialed requests."
                    })

            tech_stack = detect_tech_stack(raw_headers, html_body)

            return {
                "success": True,
                "target_url": target_url,
                "status_code": response.status,
                "headers_found": headers_found,
                "missing_headers": missing_headers,
                "info_leakage": info_leakage,
                "cookie_findings": cookie_findings,
                "cors_findings": cors_findings,
                "tech_stack": tech_stack
            }

    except urllib.error.HTTPError as e:
        raw_headers = {k.lower(): v for k, v in e.headers.items()}
        tech_stack = detect_tech_stack(raw_headers, "")
        
        for header, info in REQUIRED_SECURITY_HEADERS.items():
            hdr_lower = header.lower()
            match_val = raw_headers.get(hdr_lower)
            if match_val:
                headers_found[header] = match_val
            else:
                missing_headers.append({
                    "header": header,
                    "description": info["description"],
                    "severity": info["severity"],
                    "score_impact": info["score_impact"]
                })

        return {
            "success": True,
            "target_url": target_url,
            "status_code": e.code,
            "headers_found": headers_found,
            "missing_headers": missing_headers,
            "info_leakage": info_leakage,
            "cookie_findings": [],
            "cors_findings": [],
            "tech_stack": tech_stack or ["Standard Web Server"]
        }
    except Exception as e:
        if target_url.startswith("https://"):
            fallback_url = "http://" + target_url[8:]
            return audit_http_headers(fallback_url, scan_mode=scan_mode)
        return {
            "success": False,
            "target_url": target_url,
            "error": f"Failed to connect: {str(e)}",
            "tech_stack": []
        }

def detect_tech_stack(headers, html_body):
    """Detect technologies, CMS, and web frameworks."""
    stack = []
    server = headers.get("server", "").lower()
    powered_by = headers.get("x-powered-by", "").lower()
    alt_svc = headers.get("alt-svc", "").lower()

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
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"}
    )
    try:
        with urllib.request.urlopen(req, timeout=1.8, context=ctx) as response:
            if response.status == 200:
                body_chunk = response.read(1024)
                checker = item.get("content_check", lambda b: True)
                if checker(body_chunk):
                    return {
                        "path": item["path"],
                        "url": full_url,
                        "name": item["name"],
                        "severity": item["severity"],
                        "status": "EXPOSED"
                    }
    except urllib.error.HTTPError as e:
        if e.code in [401, 403]:
            return {
                "path": item["path"],
                "url": full_url,
                "name": item["name"],
                "severity": "LOW",
                "status": f"PROTECTED ({e.code} Restricted)"
            }
    except Exception:
        pass
    return None

def scan_sensitive_files(base_url, scan_mode="quick"):
    """Check for exposed sensitive files tailored to Quick vs Full depth."""
    base_url = base_url.rstrip("/")
    if not base_url.startswith("http://") and not base_url.startswith("https://"):
        base_url = "https://" + base_url

    disclosures = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    file_list = FULL_SENSITIVE_FILES if scan_mode == "full" else QUICK_SENSITIVE_FILES
    max_workers = 12 if scan_mode == "full" else 6

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(check_single_sensitive_file, base_url, item, ctx) for item in file_list]
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

def evaluate_owasp_risks(header_audit, sensitive_files, open_ports, hostname="", ssl_info=None, scan_mode="quick"):
    """
    Calculate an accurate, dynamic 4-pillar security score (0 to 100) and risk grade:
    - Quick Scan Mode: Focuses on perimeter attack surface, SSL encryption, and primary headers.
    - Full Audit Mode: Comprehensive evaluation including deep ports, deep sensitive files, cookie security flags, and CORS configurations.
    """
    vulnerabilities = []
    
    # ----------------------------------------------------
    # PILLAR 1: SSL/TLS & Transport Security (25 Points)
    # ----------------------------------------------------
    p1_score = 25
    if ssl_info:
        if ssl_info.get("status") == "VALID":
            if ssl_info.get("version") == "TLSv1.3":
                p1_score = 25
            else:
                p1_score = 22
        elif ssl_info.get("status") == "WARNING":
            p1_score = 10
            vulnerabilities.append({
                "category": "SSL/TLS Encryption",
                "title": "SSL Certificate Warning / Untrusted Issuer",
                "severity": "HIGH",
                "impact": ssl_info.get("details", "SSL Certificate has validation warnings."),
                "verification_steps": f"Run 'openssl s_client -connect {hostname}:443' and review certificate chain.",
                "remediation": "Deploy a valid, CA-signed SSL/TLS certificate (e.g. Let's Encrypt)."
            })
        else:
            p1_score = 5
            vulnerabilities.append({
                "category": "SSL/TLS Encryption",
                "title": "Unencrypted HTTP / Missing SSL",
                "severity": "HIGH",
                "impact": "Traffic is unencrypted and vulnerable to eavesdropping and MITM attacks.",
                "verification_steps": f"Verify if port 443 HTTPS is active on {hostname}.",
                "remediation": "Install an SSL/TLS certificate and enforce HTTPS redirection."
            })
    else:
        p1_score = 22

    # ----------------------------------------------------
    # PILLAR 2: Perimeter & Port Exposure (25 Points)
    # ----------------------------------------------------
    p2_score = 25
    for p in open_ports:
        port = p.get("port")
        if port in [6379, 27017, 9200, 1433, 1521, 3306, 5432, 2375, 11211]:
            p2_score -= 15
            vulnerabilities.append({
                "category": "Perimeter Exposure",
                "title": f"Critical Service/Database Port Publicly Exposed: {port} ({p.get('service', 'Service')})",
                "severity": "CRITICAL",
                "impact": f"Internal database/daemon service listening directly on public internet interface.",
                "verification_steps": f"Test connection: 'nc -zv {hostname} {port}'",
                "remediation": f"Bind database to localhost (127.0.0.1) or block port {port} using firewall rules."
            })
        elif port in [23, 21]:
            p2_score -= 10
            vulnerabilities.append({
                "category": "Perimeter Exposure",
                "title": f"Unencrypted Protocol Exposed: Port {port} ({p.get('service', 'Legacy')})",
                "severity": "HIGH",
                "impact": "Cleartext credentials can be intercepted over the network.",
                "remediation": f"Disable port {port} and use encrypted alternatives (SSH / SFTP)."
            })
        elif port in [3389, 5900]:
            p2_score -= 10
            vulnerabilities.append({
                "category": "Perimeter Exposure",
                "title": f"Remote Desktop Protocol Exposed (Port {port})",
                "severity": "HIGH",
                "impact": "Direct remote access exposes system to brute-force and credential stuffing attacks.",
                "remediation": "Place remote desktop behind a VPN or enable multi-factor authentication."
            })
        elif port in [2082, 2086]:
            p2_score -= 5
            vulnerabilities.append({
                "category": "Perimeter Exposure",
                "title": f"Unencrypted Hosting Control Panel: Port {port}",
                "severity": "MEDIUM",
                "impact": "Unencrypted cPanel/WHM management interface exposed.",
                "remediation": f"Use SSL-encrypted ports 2083 or 2087 instead."
            })
        elif port == 22:
            p2_score -= 2
    p2_score = max(0, min(25, p2_score))

    # ----------------------------------------------------
    # PILLAR 3: Sensitive File & Credential Disclosure (30 Points)
    # ----------------------------------------------------
    p3_score = 30
    for disc in sensitive_files:
        if disc.get("status") == "EXPOSED":
            sev = disc.get("severity", "MEDIUM")
            if sev == "CRITICAL":
                p3_score -= 25
            elif sev == "HIGH":
                p3_score -= 15
            else:
                p3_score -= 8
            
            file_url = disc.get("url", f"https://{hostname}{disc.get('path', '')}")
            vulnerabilities.append({
                "category": "Sensitive File Exposure",
                "title": f"Exposed File: {disc['path']}",
                "severity": sev,
                "impact": f"{disc['name']} is publicly accessible over HTTP/HTTPS.",
                "verification_steps": f"Send HTTP GET request to '{file_url}' and verify response status 200.",
                "remediation": f"Restrict public access to '{disc['path']}' in web server access rules."
            })
    p3_score = max(0, min(30, p3_score))

    # ----------------------------------------------------
    # PILLAR 4: OWASP HTTP Security Headers & Deep Audit (20 Points)
    # ----------------------------------------------------
    p4_score = 20
    missing_hdrs = header_audit.get("missing_headers", [])
    if header_audit.get("success"):
        for missing in missing_hdrs:
            p4_score -= missing.get("score_impact", 3)
            vulnerabilities.append({
                "category": "OWASP Security Headers",
                "title": f"Missing Header: {missing.get('header', 'Security Header')}",
                "severity": missing.get("severity", "MEDIUM"),
                "impact": missing.get("description", "Missing recommended security header."),
                "verification_steps": f"Run 'curl -I {header_audit.get('target_url', 'https://target')}' and verify '{missing.get('header', '')}' is missing.",
                "remediation": f"Configure web server to add '{missing.get('header', '')}' response header."
            })

        for leak in header_audit.get("info_leakage", []):
            p4_score -= 2
            vulnerabilities.append({
                "category": "Information Disclosure",
                "title": f"Server Banner Leakage: {leak['header']}",
                "severity": "LOW",
                "impact": leak["risk"],
                "verification_steps": f"Execute 'curl -I {header_audit.get('target_url', 'https://target')}' and check '{leak['header']}' header.",
                "remediation": f"Disable or hide '{leak['header']}' in web server response configuration."
            })

        # Deep Audit Mode: Cookie & CORS Evaluation
        if scan_mode == "full":
            for c_issue in header_audit.get("cookie_findings", []):
                p4_score -= 2
                vulnerabilities.append({
                    "category": "Session & Cookie Security",
                    "title": f"Cookie Security: {c_issue['cookie']} ({c_issue['issue']})",
                    "severity": c_issue["severity"],
                    "impact": c_issue["impact"],
                    "remediation": f"Configure application to set {c_issue['issue']} on Set-Cookie headers."
                })

            for cors_issue in header_audit.get("cors_findings", []):
                p4_score -= 4
                vulnerabilities.append({
                    "category": "CORS Policy Security",
                    "title": f"CORS Misconfiguration: {cors_issue['issue']}",
                    "severity": cors_issue["severity"],
                    "impact": cors_issue["impact"],
                    "remediation": "Restrict Access-Control-Allow-Origin to trusted domains and disallow wildcard with credentials."
                })

    p4_score = max(0, min(20, p4_score))

    # CVE Threat Intel Deductions
    cve_intel = evaluate_cve_threats(open_ports, header_audit.get("tech_stack", []))
    cve_deduction = 0
    for cve in cve_intel:
        cve_deduction += 15 if cve["severity"] == "CRITICAL" else 8
        vulnerabilities.append({
            "category": "Threat Intel CVE",
            "title": f"{cve['cve']} — {cve['title']}",
            "severity": cve["severity"],
            "impact": cve["summary"],
            "verification_steps": f"Inspect installed service version for '{cve['affected']}' against {cve['cve']}.",
            "remediation": cve["remediation"]
        })

    # Final Normalized Score Calculation
    total_score = max(0, min(100, (p1_score + p2_score + p3_score + p4_score) - cve_deduction))

    grade = "A+"
    if total_score < 40: grade = "F"
    elif total_score < 55: grade = "D"
    elif total_score < 70: grade = "C"
    elif total_score < 85: grade = "B"
    elif total_score < 95: grade = "A"

    remediations = generate_remediation_scripts(missing_hdrs, open_ports)
    cli_commands = generate_cli_commands(hostname or "target", open_ports)

    return {
        "score": total_score,
        "grade": grade,
        "scan_mode": scan_mode,
        "vulnerabilities": vulnerabilities,
        "cve_intel": cve_intel,
        "remediation_scripts": remediations,
        "cli_commands": cli_commands
    }


