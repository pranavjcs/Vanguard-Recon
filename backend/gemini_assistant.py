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

def query_gemini_assistant(user_query, context=None):
    """
    Calls Google Gemini API for thorough and complete defensive security remediation guidance.
    """
    api_key = get_gemini_api_key()
    if not api_key:
        return {
            "success": False,
            "error": "Gemini API Key missing. Please configure GEMINI_API_KEY in config.json.",
            "answer": "⚠️ **Gemini API Key Missing**: Please set your `gemini_api_key` in `config.json` or as environment variable `GEMINI_API_KEY` to enable live AI security remediation advice."
        }

    system_context = (
        "You are Vanguard Security Copilot, an expert enterprise AI Cybersecurity & Defense Engineering Assistant.\n"
        "Your mission is to deliver complete, thorough, step-by-step, and fully detailed security remediation guidance.\n"
        "Rules:\n"
        "1. Provide complete, copy-pasteable configuration code blocks for web servers (Nginx, Apache, IIS).\n"
        "2. Provide explicit Linux CLI commands (UFW, iptables, systemctl, apt/yum patch commands).\n"
        "3. Explain the OWASP threat risk, root cause, verification test commands, and mitigation steps.\n"
        "4. DO NOT shorten or truncate your output. Provide comprehensive and complete answers."
    )

    if context:
        prompt = f"{system_context}\n\n[Active Scan Context]\nTarget: {context.get('hostname', 'N/A')}\nScore: {context.get('score', 'N/A')}/100 Grade: {context.get('grade', 'N/A')}\nVulnerabilities Identified:\n{json.dumps(context.get('vulnerabilities', []), indent=2)}\n\n[User Question]\n{user_query}"
    else:
        prompt = f"{system_context}\n\n[User Question]\n{user_query}"

    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": prompt}]
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 8192
        }
    }

    # Try Gemini models in order of preference
    models = ["gemini-2.0-flash", "gemini-2.5-flash", "gemini-1.5-flash", "gemini-flash-latest"]
    
    last_error = ""

    for model in models:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
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
            err_text = e.read().decode("utf-8", errors="ignore") if e.fp else ""
            if e.code == 429:
                last_error = "Rate limit (429) hit on Gemini API."
            else:
                last_error = f"HTTP {e.code}: {e.reason}"
        except Exception as ex:
            last_error = str(ex)

    # High-quality comprehensive fallback security playbooks
    fallback_response = (
        f"**Vanguard Security Copilot (Offline Playbook)**:\n\n"
        f"*(Notice: {last_error} Providing complete built-in defensive remediation guide below.)*\n\n"
    )

    q_lower = user_query.lower()
    if "hsts" in q_lower:
        fallback_response += (
            "### Complete Remediation Guide: HTTP Strict Transport Security (HSTS)\n\n"
            "**Overview**: HSTS forces browsers to communicate over HTTPS only, protecting users against SSL stripping and man-in-the-middle attacks.\n\n"
            "#### 1. Nginx Configuration\n"
            "Open `/etc/nginx/sites-available/default` or your SSL site config and insert into the `server` block (port 443):\n"
            "```nginx\n"
            "server {\n"
            "    listen 443 ssl http2;\n"
            "    server_name example.com;\n\n"
            "    # Enforce HSTS for 1 year including subdomains and preload consent\n"
            "    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n"
            "}\n"
            "```\n"
            "Test and reload Nginx:\n"
            "```bash\n"
            "sudo nginx -t && sudo systemctl reload nginx\n"
            "```\n\n"
            "#### 2. Apache Configuration\n"
            "Ensure `mod_headers` is enabled:\n"
            "```bash\n"
            "sudo a2enmod headers\n"
            "```\n"
            "Add to your SSL VirtualHost block inside `/etc/apache2/sites-available/default-ssl.conf` or `.htaccess`:\n"
            "```apache\n"
            "<IfModule mod_headers.c>\n"
            "    Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n"
            "</IfModule>\n"
            "```\n"
            "Reload Apache:\n"
            "```bash\n"
            "sudo systemctl restart apache2\n"
            "```\n\n"
            "#### 3. Verification Command\n"
            "```bash\n"
            "curl -sI https://yourdomain.com | grep -i strict-transport-security\n"
            "```"
        )
    elif "csp" in q_lower or "content-security-policy" in q_lower:
        fallback_response += (
            "### Complete Remediation Guide: Content Security Policy (CSP)\n\n"
            "**Overview**: CSP prevents Cross-Site Scripting (XSS), clickjacking, and code injection by restricting allowed resource origins.\n\n"
            "#### 1. Recommended Production CSP Header\n"
            "```http\n"
            "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; frame-ancestors 'none'; object-src 'none'; base-uri 'self';\n"
            "```\n\n"
            "#### 2. Nginx Deployment\n"
            "```nginx\n"
            "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none';\" always;\n"
            "```\n\n"
            "#### 3. Verification Test\n"
            "```bash\n"
            "curl -sI https://yourdomain.com | grep -i content-security-policy\n"
            "```"
        )
    elif "port" in q_lower or "ufw" in q_lower or "firewall" in q_lower:
        fallback_response += (
            "### Complete Remediation Guide: Firewall Hardening & Port Closing\n\n"
            "**Overview**: Restrict open network ports to minimize the external attack surface.\n\n"
            "#### 1. UFW Firewall Setup (Ubuntu/Debian)\n"
            "```bash\n"
            "# Set default policies\n"
            "sudo ufw default deny incoming\n"
            "sudo ufw default allow outgoing\n\n"
            "# Allow critical services\n"
            "sudo ufw allow 22/tcp comment 'SSH Access'\n"
            "sudo ufw allow 80/tcp comment 'HTTP Web Server'\n"
            "sudo ufw allow 443/tcp comment 'HTTPS Web Server'\n\n"
            "# Enable UFW firewall\n"
            "sudo ufw enable\n"
            "sudo ufw status verbose\n"
            "```\n\n"
            "#### 2. Close Specific Unused Ports (e.g. MySQL 3306 or FTP 21)\n"
            "```bash\n"
            "sudo ufw deny 3306/tcp\n"
            "sudo ufw deny 21/tcp\n"
            "```"
        )
    else:
        fallback_response += (
            "### Comprehensive Web Application Hardening Guide\n\n"
            "#### 1. OWASP Top 10 Security Headers Setup\n"
            "Add these headers to your Nginx/Apache web server configuration:\n\n"
            "```nginx\n"
            "# Enforce HTTPS\n"
            "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n\n"
            "# Prevent Clickjacking\n"
            "add_header X-Frame-Options \"DENY\" always;\n\n"
            "# Prevent MIME Sniffing\n"
            "add_header X-Content-Type-Options \"nosniff\" always;\n\n"
            "# Control Referrer Leakage\n"
            "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n\n"
            "# Restrict Unused Browser Features\n"
            "add_header Permissions-Policy \"geolocation=(), microphone=(), camera=()\" always;\n"
            "```\n\n"
            "#### 2. Hide Web Server Info Banners\n"
            "- **Nginx**: Add `server_tokens off;` inside `nginx.conf`.\n"
            "- **Apache**: Set `ServerTokens Prod` and `ServerSignature Off` inside `httpd.conf`.\n\n"
            "#### 3. Verification Command\n"
            "```bash\n"
            "curl -sI https://yourdomain.com\n"
            "```"
        )

    return {
        "success": True,
        "model": "fallback",
        "answer": fallback_response
    }
