import http.server
import socketserver
import json
import urllib.parse
import os
import sys
from datetime import datetime

# Import backend modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from backend.scanner import resolve_target, run_port_scan, audit_ssl_tls, enumerate_subdomains
from backend.owasp_checker import audit_http_headers, scan_sensitive_files, evaluate_owasp_risks, search_cve_db
from backend.report_gen import generate_html_report
from backend.gemini_assistant import query_gemini_assistant

PORT = 8000
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

class ThreadingVanguardServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

class VanguardRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def log_message(self, format, *args):
        # Suppress noisy connection reset logs in console
        pass

    def handle_error(self, request, client_address):
        # Gracefully handle client socket disconnects
        pass

    def end_headers(self):
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        super().end_headers()

    def do_GET(self):
        try:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/api/status":
                self.send_json({"status": "ONLINE", "version": "3.0-Hackathon-Pro", "timestamp": str(datetime.now())})
                return

            if parsed.path == "/api/cve":
                query_params = urllib.parse.parse_qs(parsed.query)
                q = query_params.get("q", [""])[0]
                results = search_cve_db(q)
                self.send_json({"success": True, "count": len(results), "cve_list": results})
                return

            if parsed.path == "/":
                self.path = "/index.html"
            return super().do_GET()
        except Exception:
            pass

    def do_POST(self):
        try:
            parsed = urllib.parse.urlparse(self.path)
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')

            try:
                body = json.loads(post_data) if post_data else {}
            except Exception:
                body = {}

            if parsed.path == "/api/scan":
                self.handle_scan_request(body)
            elif parsed.path == "/api/report":
                self.handle_report_request(body)
            elif parsed.path in ["/api/copilot", "/api/chat"]:
                query = body.get("query", body.get("prompt", ""))
                context = body.get("context", None)
                res = query_gemini_assistant(query, context=context)
                self.send_json(res)
            elif parsed.path == "/api/cve/search":
                q = body.get("query", "")
                results = search_cve_db(q)
                self.send_json({"success": True, "count": len(results), "cve_list": results})
            else:
                self.send_error(404, "API endpoint not found")
        except Exception as e:
            try:
                self.send_json({"success": False, "error": f"Server processing error: {str(e)}"}, status=500)
            except Exception:
                pass

    def handle_scan_request(self, body):
        target = body.get("target", "").strip()
        if not target:
            self.send_json({"success": False, "error": "Target URL or domain is required"}, status=400)
            return

        res = resolve_target(target)
        if not res["success"]:
            self.send_json({"success": False, "error": res["error"]}, status=400)
            return

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

        self.send_json(scan_output)

    def handle_report_request(self, body):
        html_report = generate_html_report(body)
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(html_report.encode('utf-8'))

    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

def run_server():
    print("==================================================")
    print(" VANGUARD RECON - MULTI-THREADED SECURITY SERVER")
    print(f" Server active at: http://localhost:{PORT}")
    print("==================================================")
    with ThreadingVanguardServer(("", PORT), VanguardRequestHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server...")

if __name__ == "__main__":
    run_server()
