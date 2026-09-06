import os
import json
import urllib.request
import urllib.error

def get_gemini_api_key():
    """Retrieve Gemini API Key from environment variable, config.json, or .env."""
    if os.environ.get("GEMINI_API_KEY"):
        return os.environ.get("GEMINI_API_KEY").strip()
    
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # 1. Check config.json fallback
    config_path = os.path.join(root_dir, "config.json")
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                key = data.get("gemini_api_key", data.get("GEMINI_API_KEY", "")).strip()
                if key:
                    return key
        except Exception:
            pass

    # 2. Check .env fallback
    env_file = os.path.join(root_dir, ".env")
    if os.path.exists(env_file):
        try:
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        k, v = line.split("=", 1)
                        if k.strip() == "GEMINI_API_KEY":
                            return v.strip().strip('"').strip("'")
        except Exception:
            pass

    return ""

def format_scan_context(context: dict) -> str:
    """Format detailed scan data into structured facts for Gemini."""
    if not context or not isinstance(context, dict):
        return ""

    lines = ["[Active Audit Scan Context]"]
    
    target = context.get("target") or context.get("hostname", "N/A")
    lines.append(f"- Target Hostname: {target}")
    if context.get("ip"):
        lines.append(f"- Resolved IP: {context.get('ip')}")
    if context.get("score") is not None and context.get("grade"):
        lines.append(f"- Security Risk Score: {context.get('score')}/100 (Grade: {context.get('grade')})")
    
    tech = context.get("tech_stack")
    if tech:
        if isinstance(tech, list):
            lines.append(f"- Detected Technologies: {', '.join(tech)}")
        else:
            lines.append(f"- Detected Technologies: {tech}")

    ports = context.get("open_ports", [])
    if ports:
        port_strs = []
        for p in ports:
            port_num = p.get("port")
            svc = p.get("service", "TCP")
            banner = p.get("banner", "")
            port_strs.append(f"{port_num}/{svc}" + (f" ({banner})" if banner else ""))
        lines.append(f"- Open TCP Ports ({len(ports)} detected): {', '.join(port_strs)}")

    headers = context.get("headers", {})
    if isinstance(headers, dict):
        missing = headers.get("missing_headers", [])
        if missing:
            missing_names = [m.get("header") if isinstance(m, dict) else str(m) for m in missing]
            lines.append(f"- Missing Security Headers: {', '.join(missing_names)}")
        leakage = headers.get("info_leakage", [])
        if leakage:
            leak_names = [l.get("header") if isinstance(l, dict) else str(l) for l in leakage]
            lines.append(f"- Information Leakage Headers: {', '.join(leak_names)}")

    vulns = context.get("vulnerabilities", [])
    if vulns:
        lines.append(f"- Identified Vulnerabilities ({len(vulns)} items):")
        for v in vulns[:10]:
            title = v.get("title", "Finding")
            sev = v.get("severity", "INFO")
            lines.append(f"  * [{sev}] {title}")

    sens = context.get("sensitive_files", [])
    if sens:
        exposed = [s.get("path") or s.get("name") for s in sens if s.get("status") == "EXPOSED"]
        if exposed:
            lines.append(f"- Exposed Sensitive Files: {', '.join(exposed)}")

    ssl_info = context.get("ssl", {})
    if ssl_info and isinstance(ssl_info, dict):
        status = ssl_info.get("status", "N/A")
        cipher = ssl_info.get("cipher", "N/A")
        issuer = ssl_info.get("issuer_o", "N/A")
        lines.append(f"- SSL/TLS Status: {status} (Cipher: {cipher}, Issuer: {issuer})")

    cves = context.get("cve_intel", [])
    if cves:
        cve_ids = [c.get("cve") for c in cves if c.get("cve")]
        if cve_ids:
            lines.append(f"- Associated CVE Intelligence: {', '.join(cve_ids)}")

    return "\n".join(lines)

def query_gemini_assistant(user_query: str, context: dict = None):
    """
    Calls Google Gemini API with enriched scan context to return precise, 
    actionable, non-generic security remediation answers.
    """
    api_key = get_gemini_api_key()
    if not api_key:
        return get_intelligent_fallback_response(user_query, context, "Gemini API key not configured")

    scan_context_str = format_scan_context(context)

    system_instruction = (
        "You are Vanguard Security Copilot, an elite enterprise Cybersecurity Defense and DevSecOps Architect.\n"
        "Your mission is to provide an exact, highly targeted, technically thorough response specifically addressing the user's inquiry.\n\n"
        "Core Directives:\n"
        "1. DIRECT & EXACT: Answer the user's specific query directly and precisely without generic intros, repetitive fluff, or preambles.\n"
        "2. CONTEXT-AWARE: If scan audit data is provided below, directly reference the target's actual findings (domain, open ports, web server, missing headers, vulnerabilities).\n"
        "3. COPY-PASTE CODE: For configuration or remediation requests, provide complete, production-ready code blocks for the detected technology stack (e.g. Nginx, Apache, Express, Caddy, Docker, UFW, AWS).\n"
        "4. VERIFICATION COMMANDS: Always include exact terminal verification commands (curl, openssl, nmap, ufw) so the analyst can test the fix.\n"
        "5. PRIORITIZE IMPACT: Focus on the highest-severity risk and direct remediation steps."
    )

    if scan_context_str:
        full_prompt = (
            f"{system_instruction}\n\n"
            f"{scan_context_str}\n\n"
            f"[User Question]\n{user_query.strip()}"
        )
    else:
        full_prompt = (
            f"{system_instruction}\n\n"
            f"[User Question]\n{user_query.strip()}"
        )

    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": full_prompt}]
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 4096
        }
    }

    # Modern active Gemini models in order of speed and capability
    models = ["gemini-3.1-flash-lite", "gemini-3.6-flash", "gemini-3.5-flash", "gemini-flash-latest"]
    last_error = ""

    for model in models:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=14) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                candidates = res_data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts and "text" in parts[0]:
                        ans = parts[0]["text"].strip()
                        if ans:
                            return {
                                "success": True,
                                "model": model,
                                "answer": ans
                            }
        except urllib.error.HTTPError as e:
            if e.code == 429:
                last_error = "Rate limit reached on Gemini API."
            else:
                last_error = f"HTTP {e.code}: {e.reason}"
        except Exception as ex:
            last_error = str(ex)

    # If Gemini API calls fail, run the intelligent topic-based fallback engine
    return get_intelligent_fallback_response(user_query, context, last_error)

def get_intelligent_fallback_response(query: str, context: dict, error_msg: str = "") -> dict:
    """
    Intelligent context-driven fallback engine that provides precise, 
    topic-specific remediation for all OWASP categories, ports, and headers.
    """
    q = query.lower().strip()
    target_host = "example.com"
    tech_stack_desc = "Nginx / Apache"
    if context and isinstance(context, dict):
        target_host = context.get("hostname") or context.get("target") or "target system"
        stack = context.get("tech_stack", [])
        if stack:
            tech_stack_desc = ", ".join(stack)

    # 1. Target Summary / Findings Query
    if any(k in q for k in ["summary", "findings", "score", "grade", "vulnerabilit", "result", "what did you find", "report"]):
        if context and isinstance(context, dict):
            score = context.get("score", "N/A")
            grade = context.get("grade", "N/A")
            ports = [str(p.get("port")) for p in context.get("open_ports", [])]
            vulns = context.get("vulnerabilities", [])
            headers = context.get("headers", {}).get("missing_headers", [])
            
            ans = f"### Security Audit Summary for `{target_host}`\n\n"
            ans += f"- **Security Score**: `{score}/100` (Grade: **{grade}**)\n"
            ans += f"- **Open Ports**: {', '.join(ports) if ports else 'No open high-risk ports detected'}\n"
            ans += f"- **Missing Headers**: {len(headers)} missing security headers detected\n"
            ans += f"- **Total Vulnerabilities**: {len(vulns)} issues requiring attention\n\n"
            if vulns:
                ans += "#### Priority Vulnerabilities:\n"
                for v in vulns[:5]:
                    ans += f"- **[{v.get('severity', 'WARN')}]** {v.get('title')}: {v.get('remediation', '')}\n"
            ans += f"\n*Ask for exact configuration blocks for any specific finding (e.g. 'How to fix HSTS', 'How to close port {ports[0] if ports else 3306}').*"
            return {"success": True, "model": "offline-intel", "answer": ans}

    # 2. HSTS / HTTPS
    if "hsts" in q or "strict-transport" in q:
        ans = (
            f"### Exact Remediation: HTTP Strict Transport Security (HSTS)\n"
            f"**Target**: `{target_host}`\n\n"
            f"HSTS instructs browsers to strictly communicate over HTTPS, mitigating SSL stripping, cookie hijacking, and downgrade attacks.\n\n"
            f"#### 1. Nginx Configuration (`/etc/nginx/sites-available/default`)\n"
            f"Add inside the `server {{ listen 443 ssl; ... }}` block:\n"
            f"```nginx\n"
            f"server {{\n"
            f"    listen 443 ssl http2;\n"
            f"    server_name {target_host};\n\n"
            f"    # Enforce 1-year HSTS with subdomains and preload eligibility\n"
            f"    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n"
            f"}}\n"
            f"```\n"
            f"Test and reload:\n"
            f"```bash\n"
            f"sudo nginx -t && sudo systemctl reload nginx\n"
            f"```\n\n"
            f"#### 2. Apache Configuration (`.htaccess` or `default-ssl.conf`)\n"
            f"```apache\n"
            f"<IfModule mod_headers.c>\n"
            f"    Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n"
            f"</IfModule>\n"
            f"```\n\n"
            f"#### 3. Verification Command\n"
            f"```bash\n"
            f"curl -sI https://{target_host} | grep -i strict-transport-security\n"
            f"```"
        )
        return {"success": True, "model": "offline-intel", "answer": ans}

    # 3. Content Security Policy (CSP)
    if "csp" in q or "content-security-policy" in q:
        ans = (
            f"### Exact Remediation: Content Security Policy (CSP)\n"
            f"**Target**: `{target_host}`\n\n"
            f"CSP restricts resource origins (scripts, styles, frames, connections) to prevent Cross-Site Scripting (XSS), data exfiltration, and Clickjacking.\n\n"
            f"#### 1. Recommended Production CSP Header\n"
            f"```http\n"
            f"Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none';\n"
            f"```\n\n"
            f"#### 2. Nginx Deployment\n"
            f"```nginx\n"
            f"add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'none';\" always;\n"
            f"```\n\n"
            f"#### 3. Verification Command\n"
            f"```bash\n"
            f"curl -sI https://{target_host} | grep -i content-security-policy\n"
            f"```"
        )
        return {"success": True, "model": "offline-intel", "answer": ans}

    # 4. Clickjacking / X-Frame-Options
    if "frame" in q or "clickjack" in q or "x-frame" in q:
        ans = (
            f"### Exact Remediation: X-Frame-Options & Clickjacking Prevention\n"
            f"**Target**: `{target_host}`\n\n"
            f"Prevents your web pages from being embedded inside `<iframe>` tags on untrusted malicious websites.\n\n"
            f"#### Nginx Configuration\n"
            f"```nginx\n"
            f"# Completely deny framing from any domain\n"
            f"add_header X-Frame-Options \"DENY\" always;\n"
            f"```\n\n"
            f"#### Apache Configuration (`.htaccess`)\n"
            f"```apache\n"
            f"Header always set X-Frame-Options \"DENY\"\n"
            f"```\n\n"
            f"#### Node.js / Express\n"
            f"```javascript\n"
            f"const helmet = require('helmet');\n"
            f"app.use(helmet.frameguard({ action: 'deny' }));\n"
            f"```\n\n"
            f"#### Verification Command\n"
            f"```bash\n"
            f"curl -sI https://{target_host} | grep -i x-frame-options\n"
            f"```"
        )
        return {"success": True, "model": "offline-intel", "answer": ans}

    # 5. MIME Sniffing / X-Content-Type-Options
    if "sniff" in q or "content-type-options" in q or "mime" in q:
        ans = (
            f"### Exact Remediation: MIME-Type Sniffing Prevention\n"
            f"**Target**: `{target_host}`\n\n"
            f"Forces the browser to strictly adhere to the declared `Content-Type`, preventing user-uploaded files (like images) from executing as JavaScript.\n\n"
            f"#### Nginx Configuration\n"
            f"```nginx\n"
            f"add_header X-Content-Type-Options \"nosniff\" always;\n"
            f"```\n\n"
            f"#### Apache Configuration\n"
            f"```apache\n"
            f"Header always set X-Content-Type-Options \"nosniff\"\n"
            f"```\n\n"
            f"#### Verification Command\n"
            f"```bash\n"
            f"curl -sI https://{target_host} | grep -i x-content-type-options\n"
            f"```"
        )
        return {"success": True, "model": "offline-intel", "answer": ans}

    # 6. Open Port & Database Hardening (MySQL 3306, Postgres 5432, Redis 6379, SSH 22, FTP 21, RDP 3389)
    if any(k in q for k in ["3306", "mysql", "database", "5432", "postgres", "6379", "redis", "21", "ftp", "22", "ssh", "3389", "rdp", "port", "firewall", "ufw"]):
        ans = (
            f"### Exact Remediation: Network Port Hardening & Firewall Setup\n"
            f"**Target**: `{target_host}`\n\n"
            f"Exposing management or database ports (MySQL, Redis, PostgreSQL, RDP) to the public internet allows unauthorized brute-force and credential stuffing.\n\n"
            f"#### 1. UFW Firewall Rules (Ubuntu/Debian Linux)\n"
            f"```bash\n"
            f"# Set default deny for incoming connections\n"
            f"sudo ufw default deny incoming\n"
            f"sudo ufw default allow outgoing\n\n"
            f"# Allow only web traffic and SSH\n"
            f"sudo ufw allow 22/tcp comment 'SSH'\n"
            f"sudo ufw allow 80/tcp comment 'HTTP'\n"
            f"sudo ufw allow 443/tcp comment 'HTTPS'\n\n"
            f"# Explicitly block database ports from the internet\n"
            f"sudo ufw deny 3306/tcp comment 'Block MySQL'\n"
            f"sudo ufw deny 5432/tcp comment 'Block Postgres'\n"
            f"sudo ufw deny 6379/tcp comment 'Block Redis'\n"
            f"sudo ufw deny 21/tcp   comment 'Block FTP'\n"
            f"sudo ufw deny 3389/tcp comment 'Block RDP'\n\n"
            f"# Enable and review firewall status\n"
            f"sudo ufw enable\n"
            f"sudo ufw status numbered\n"
            f"```\n\n"
            f"#### 2. Bind MySQL to Localhost (`/etc/mysql/my.cnf` or `/etc/mysql/mysql.conf.d/mysqld.cnf`)\n"
            f"```ini\n"
            f"[mysqld]\n"
            f"bind-address = 127.0.0.1\n"
            f"```\n"
            f"Restart service:\n"
            f"```bash\n"
            f"sudo systemctl restart mysql\n"
            f"```\n\n"
            f"#### 3. Verification Command\n"
            f"```bash\n"
            f"sudo ss -tulpn | grep 3306\n"
            f"```"
        )
        return {"success": True, "model": "offline-intel", "answer": ans}

    # 7. Sensitive Files Disclosure (.env, .git, config.json, backups)
    if any(k in q for k in [".env", ".git", "wp-config", "sensitive", "disclosure", "backup", "robots.txt", "phpinfo"]):
        ans = (
            f"### Exact Remediation: Sensitive File Disclosure Prevention\n"
            f"**Target**: `{target_host}`\n\n"
            f"Public exposure of `.env`, `.git/HEAD`, or database backup files provides attackers with direct credentials, API keys, and source code.\n\n"
            f"#### 1. Nginx Access Block (Global Site Config)\n"
            f"Place inside your `server {{ ... }}` block:\n"
            f"```nginx\n"
            f"# Block access to hidden files (.env, .git, etc.)\n"
            f"location ~ /\\.(?!well-known) {{\n"
            f"    deny all;\n"
            f"    return 404;\n"
            f"}}\n\n"
            f"# Block backup and database dump files\n"
            f"location ~* \\.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist)$ {{\n"
            f"    deny all;\n"
            f"    return 404;\n"
            f"}}\n"
            f"```\n\n"
            f"#### 2. Apache Access Block (`.htaccess`)\n"
            f"```apache\n"
            f"<FilesMatch \"^\\.(.*)|.*\\.(bak|config|sql|log|env)$\">\n"
            f"    Order allow,deny\n"
            f"    Deny from all\n"
            f"</FilesMatch>\n"
            f"```\n\n"
            f"#### 3. Verification Command\n"
            f"```bash\n"
            f"curl -sI https://{target_host}/.env | grep -E \"HTTP/|404|403\"\n"
            f"```"
        )
        return {"success": True, "model": "offline-intel", "answer": ans}

    # 8. Server Banner Leakage & Tech Stack Obfuscation
    if any(k in q for k in ["server_tokens", "banner", "info leakage", "x-powered-by", "hide server", "version"]):
        ans = (
            f"### Exact Remediation: Hiding Server Banners & Tech Stack Info\n"
            f"**Target**: `{target_host}`\n\n"
            f"Suppressing the `Server` and `X-Powered-By` headers prevents automated scanners from profiling your exact software versions.\n\n"
            f"#### 1. Nginx (`/etc/nginx/nginx.conf`)\n"
            f"```nginx\n"
            f"http {{\n"
            f"    server_tokens off;\n"
            f"}}\n"
            f"```\n\n"
            f"#### 2. Apache (`/etc/apache2/conf-available/security.conf`)\n"
            f"```apache\n"
            f"ServerTokens Prod\n"
            f"ServerSignature Off\n"
            f"```\n\n"
            f"#### 3. PHP (`php.ini`)\n"
            f"```ini\n"
            f"expose_php = Off\n"
            f"```\n\n"
            f"#### 4. Node.js / Express\n"
            f"```javascript\n"
            f"app.disable('x-powered-by');\n"
            f"```"
        )
        return {"success": True, "model": "offline-intel", "answer": ans}

    # 9. SSL/TLS Certificate & Cipher Hardening
    if any(k in q for k in ["ssl", "tls", "cert", "cipher", "https"]):
        ans = (
            f"### Exact Remediation: SSL/TLS Certificate & Cipher Suite Hardening\n"
            f"**Target**: `{target_host}`\n\n"
            f"#### 1. Modern Nginx TLS Configuration (`Mozilla Modern Guidelines`)\n"
            f"```nginx\n"
            f"ssl_protocols TLSv1.2 TLSv1.3;\n"
            f"ssl_prefer_server_ciphers off;\n"
            f"ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;\n"
            f"ssl_session_timeout 1d;\n"
            f"ssl_session_cache shared:MozSSL:10m;\n"
            f"ssl_session_tickets off;\n"
            f"```\n\n"
            f"#### 2. Verification Command\n"
            f"```bash\n"
            f"openssl s_client -connect {target_host}:443 -tls1_3\n"
            f"```"
        )
        return {"success": True, "model": "offline-intel", "answer": ans}

    # 10. Default Targeted Security Response
    ans = (
        f"### Security Guidance for `{target_host}`\n\n"
        f"**Question Asked**: *\"{query}\"*\n\n"
        f"#### Core Security Recommendations for `{target_host}`:\n"
        f"1. **Enforce Complete OWASP Headers**: Deploy `Strict-Transport-Security`, `Content-Security-Policy`, and `X-Frame-Options: DENY`.\n"
        f"2. **Restrict Public Network Ports**: Use UFW/iptables to deny direct internet access to administrative and database ports.\n"
        f"3. **Block Directory Traversal & Metadata**: Block `.env`, `.git/`, and configuration file paths at the reverse proxy level.\n"
        f"4. **Suppress Server Fingerprints**: Disable `server_tokens` in Nginx and set `expose_php = Off` in PHP.\n\n"
        f"*Tip: Specify the specific technology or finding (e.g. 'Nginx HSTS setup', 'PostgreSQL firewall rule', 'XSS prevention') for copy-pasteable configurations.*"
    )
    return {"success": True, "model": "offline-intel", "answer": ans}
