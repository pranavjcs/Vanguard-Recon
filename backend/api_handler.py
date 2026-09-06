import json
import urllib.parse
from datetime import datetime

from backend.scanner import resolve_target, run_port_scan, audit_ssl_tls, enumerate_subdomains
from backend.owasp_checker import audit_http_headers, scan_sensitive_files, evaluate_owasp_risks, search_cve_db
from backend.report_gen import generate_html_report
from backend.gemini_assistant import query_gemini_assistant
from backend.auth import (
    authenticate_user,
    register_user,
    get_current_user_from_token,
    update_user_profile,
    change_password,
    verify_jwt
)

def extract_auth_token(headers: dict) -> str:
    """Extract Bearer token from headers dict (case-insensitive)."""
    auth_header = None
    for k, v in headers.items():
        if k.lower() == "authorization":
            auth_header = v
            break
        if k.lower() == "x-auth-token":
            return v.strip()

    if auth_header and auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return None

def handle_api_request(method: str, path: str, query_string: str, body_bytes: bytes, headers: dict):
    """
    Unified API request dispatcher.
    Returns: (status_code, headers_dict, response_body_bytes)
    """
    method = method.upper()
    parsed_path = urllib.parse.urlparse(path).path
    query_params = urllib.parse.parse_qs(query_string or "")
    
    # Common response headers
    cors_headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Auth-Token",
        "Cache-Control": "no-cache, no-store, must-revalidate"
    }

    if method == "OPTIONS":
        return 204, cors_headers, b""

    # Parse JSON body for POST/PUT requests
    body = {}
    if body_bytes:
        try:
            body = json.loads(body_bytes.decode("utf-8"))
        except Exception:
            body = {}

    token = extract_auth_token(headers)

    # Normalize /api/index.py or /api rewrites from Vercel
    if parsed_path in ["/api/index.py", "/api", "/api/"]:
        if "__route" in query_params and query_params["__route"]:
            parsed_path = "/api/" + query_params["__route"][0].lstrip("/")
        elif "x-matched-path" in headers and headers["x-matched-path"] != "/api/index.py":
            parsed_path = headers["x-matched-path"].split("?")[0]
        elif "x-forwarded-uri" in headers and headers["x-forwarded-uri"] != "/api/index.py":
            parsed_path = headers["x-forwarded-uri"].split("?")[0]
        elif isinstance(body, dict):
            if "target" in body:
                parsed_path = "/api/scan"
            elif "old_password" in body and "new_password" in body:
                parsed_path = "/api/auth/change-password"
            elif "identifier" in body and "password" in body:
                parsed_path = "/api/auth/login"
            elif "email" in body and "username" in body and "password" in body:
                parsed_path = "/api/auth/register"
            elif "query" in body or "prompt" in body:
                parsed_path = "/api/copilot"
            elif "hostname" in body and "score" in body:
                parsed_path = "/api/report"

    # ----------------------------------------------------
    # AUTHENTICATION ENDPOINTS
    # ----------------------------------------------------
    if parsed_path == "/api/auth/login" and method == "POST":
        identifier = body.get("identifier", body.get("username", body.get("email", "")))
        password = body.get("password", "")
        res = authenticate_user(identifier, password)
        status = 200 if res.get("success") else 401
        return status, cors_headers, json.dumps(res).encode("utf-8")

    elif parsed_path == "/api/auth/register" and method == "POST":
        username = body.get("username", "")
        email = body.get("email", "")
        password = body.get("password", "")
        full_name = body.get("full_name", "")
        role = body.get("role", "")
        org = body.get("organization", "")
        res = register_user(username, email, password, full_name, role, org)
        status = 201 if res.get("success") else 400
        return status, cors_headers, json.dumps(res).encode("utf-8")

    elif parsed_path == "/api/auth/me" and method == "GET":
        if not token:
            return 401, cors_headers, json.dumps({"success": False, "error": "Authorization token required"}).encode("utf-8")
        valid, user_or_err = get_current_user_from_token(token)
        if not valid:
            return 401, cors_headers, json.dumps({"success": False, "error": str(user_or_err)}).encode("utf-8")
        return 200, cors_headers, json.dumps({"success": True, "user": user_or_err}).encode("utf-8")

    elif parsed_path == "/api/auth/profile" and method in ["POST", "PUT"]:
        if not token:
            return 401, cors_headers, json.dumps({"success": False, "error": "Authorization token required"}).encode("utf-8")
        valid, token_data = verify_jwt(token)
        if not valid:
            return 401, cors_headers, json.dumps({"success": False, "error": "Invalid or expired session"}).encode("utf-8")
        
        user_id = token_data.get("user_id")
        res = update_user_profile(user_id, body)
        status = 200 if res.get("success") else 400
        return status, cors_headers, json.dumps(res).encode("utf-8")

    elif parsed_path == "/api/auth/change-password" and method == "POST":
        if not token:
            return 401, cors_headers, json.dumps({"success": False, "error": "Authorization token required"}).encode("utf-8")
        valid, token_data = verify_jwt(token)
        if not valid:
            return 401, cors_headers, json.dumps({"success": False, "error": "Invalid or expired session"}).encode("utf-8")
        
        user_id = token_data.get("user_id")
        old_pwd = body.get("old_password", "")
        new_pwd = body.get("new_password", "")
        res = change_password(user_id, old_pwd, new_pwd)
        status = 200 if res.get("success") else 400
        return status, cors_headers, json.dumps(res).encode("utf-8")

    elif parsed_path == "/api/auth/logout" and method == "POST":
        return 200, cors_headers, json.dumps({"success": True, "message": "Logged out successfully"}).encode("utf-8")

    # ----------------------------------------------------
    # GENERAL / SCANNING / REPORTING ENDPOINTS
    # ----------------------------------------------------
    elif parsed_path in ["/api/status", "/api/health", "/health", "/healthz"] and method == "GET":
        res = {
            "status": "healthy",
            "version": "3.0.0",
            "timestamp": str(datetime.now()),
            "auth_enabled": True
        }
        return 200, cors_headers, json.dumps(res).encode("utf-8")

    elif parsed_path == "/api/cve" and method == "GET":
        q = query_params.get("q", [""])[0]
        results = search_cve_db(q)
        return 200, cors_headers, json.dumps({"success": True, "count": len(results), "cve_list": results}).encode("utf-8")

    elif parsed_path == "/api/cve/search" and method == "POST":
        q = body.get("query", "")
        results = search_cve_db(q)
        return 200, cors_headers, json.dumps({"success": True, "count": len(results), "cve_list": results}).encode("utf-8")

    elif parsed_path == "/api/scan" and method == "POST":
        target = body.get("target", "").strip()
        if not target:
            return 400, cors_headers, json.dumps({"success": False, "error": "Target URL or domain is required"}).encode("utf-8")

        res = resolve_target(target)
        if not res["success"]:
            return 400, cors_headers, json.dumps({"success": False, "error": res["error"]}).encode("utf-8")

        hostname = res["hostname"]
        ip = res["ip"]

        custom_ports = body.get("ports", None)
        scan_mode = body.get("scan_mode", "quick")
        
        if scan_mode == "quick" and custom_ports is None:
            custom_ports = [80, 443, 22, 21, 25, 3306, 8080, 8443, 3389]

        open_ports = run_port_scan(ip, custom_ports, hostname=hostname, scan_mode=scan_mode)
        subdomains = enumerate_subdomains(hostname, scan_mode=scan_mode)

        open_port_nums = [p["port"] for p in open_ports]
        if not target.startswith("http://") and not target.startswith("https://"):
            if 443 in open_port_nums:
                target_url = f"https://{hostname}"
            elif 80 in open_port_nums:
                target_url = f"http://{hostname}"
            else:
                target_url = f"https://{hostname}"
        else:
            target_url = target

        # Audit SSL only if port 443 is open or if ports weren't restricted
        if 443 in open_port_nums or not custom_ports:
            ssl_info = audit_ssl_tls(hostname)
        else:
            ssl_info = {
                "status": "INACTIVE",
                "version": "N/A",
                "cipher": "N/A",
                "cipher_strength": "NONE",
                "subject_cn": hostname,
                "issuer_o": "N/A",
                "san_count": 0,
                "issue_detected": True,
                "details": "Port 443 (HTTPS) is not active on target host."
            }

        header_audit = audit_http_headers(target_url, scan_mode=scan_mode)
        effective_url = header_audit.get("target_url", target_url)
        sensitive_disc = scan_sensitive_files(effective_url, scan_mode=scan_mode)
        risk_eval = evaluate_owasp_risks(header_audit, sensitive_disc, open_ports, hostname=hostname, ssl_info=ssl_info, scan_mode=scan_mode)

        scan_output = {
            "success": True,
            "target": target,
            "hostname": hostname,
            "ip": ip,
            "scan_mode": scan_mode,
            "scan_profile_label": "Full Audit" if scan_mode == "full" else "Quick Scan",
            "audit_depth": {
                "ports_checked": len(custom_ports) if custom_ports else (35 if scan_mode == "full" else 10),
                "subdomains_checked": 38 if scan_mode == "full" else 12,
                "files_audited": 16 if scan_mode == "full" else 5,
                "cookie_analysis": scan_mode == "full",
                "cors_analysis": scan_mode == "full"
            },
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "score": risk_eval["score"],
            "grade": risk_eval["grade"],
            "vulnerabilities": risk_eval["vulnerabilities"],
            "cve_intel": risk_eval.get("cve_intel", []),
            "open_ports": open_ports,
            "subdomains": subdomains,
            "headers": header_audit,
            "tech_stack": header_audit.get("tech_stack", ["Standard HTTP Server"]),
            "sensitive_files": sensitive_disc,
            "ssl": ssl_info,
            "remediation_scripts": risk_eval.get("remediation_scripts", {}),
            "cli_commands": risk_eval.get("cli_commands", {})
        }
        return 200, cors_headers, json.dumps(scan_output).encode("utf-8")

    elif parsed_path == "/api/report" and method == "POST":
        html_report = generate_html_report(body)
        rep_headers = dict(cors_headers)
        rep_headers["Content-Type"] = "text/html; charset=utf-8"
        return 200, rep_headers, html_report.encode("utf-8")

    elif parsed_path in ["/api/copilot", "/api/chat"] and method == "POST":
        query = body.get("query", body.get("prompt", ""))
        context = body.get("context", None)
        res = query_gemini_assistant(query, context=context)
        return 200, cors_headers, json.dumps(res).encode("utf-8")

    # ----------------------------------------------------
    # STATIC ASSET & PAGE FALLBACK (For Serverless Environments like Vercel)
    # ----------------------------------------------------
    elif method == "GET":
        import os
        root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        candidate_dirs = [os.path.join(root_dir, "public"), os.path.join(root_dir, "static")]

        req_path = parsed_path.lstrip("/")
        if not req_path or req_path == "index.html":
            target_filename = "index.html"
        elif req_path in ["login", "attack", "profile", "history", "threats", "topology", "hardening"]:
            target_filename = f"{req_path}.html"
        else:
            target_filename = req_path

        mime_types = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".json": "application/json; charset=utf-8",
            ".svg": "image/svg+xml",
            ".png": "image/png",
            ".ico": "image/x-icon"
        }

        ext = os.path.splitext(target_filename)[1].lower()
        content_type = mime_types.get(ext, "text/plain")

        for d in candidate_dirs:
            file_path = os.path.join(d, target_filename)
            if os.path.isfile(file_path):
                try:
                    with open(file_path, "rb") as f:
                        file_bytes = f.read()
                    res_headers = dict(cors_headers)
                    res_headers["Content-Type"] = content_type
                    return 200, res_headers, file_bytes
                except Exception:
                    pass

        return 404, cors_headers, json.dumps({"success": False, "error": f"API endpoint not found: {method} {parsed_path}"}).encode("utf-8")

    else:
        return 404, cors_headers, json.dumps({"success": False, "error": f"API endpoint not found: {method} {parsed_path}"}).encode("utf-8")
