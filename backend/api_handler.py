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
    elif parsed_path == "/api/status" and method == "GET":
        res = {
            "status": "ONLINE",
            "version": "3.0-Hackathon-Pro",
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

        open_ports = run_port_scan(ip, custom_ports, hostname=hostname)
        subdomains = enumerate_subdomains(hostname)
        ssl_info = audit_ssl_tls(hostname)

        target_url = f"https://{hostname}" if not target.startswith("http") else target
        header_audit = audit_http_headers(target_url)
        sensitive_disc = scan_sensitive_files(target_url)
        risk_eval = evaluate_owasp_risks(header_audit, sensitive_disc, open_ports, hostname=hostname)

        scan_output = {
            "success": True,
            "target": target,
            "hostname": hostname,
            "ip": ip,
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

    else:
        return 404, cors_headers, json.dumps({"success": False, "error": f"API endpoint not found: {method} {parsed_path}"}).encode("utf-8")
