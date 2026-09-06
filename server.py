import http.server
import socketserver
import urllib.parse
import os
import sys

# Import backend modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from backend.api_handler import handle_api_request

PORT = int(os.environ.get("PORT", 8000))
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

    def do_OPTIONS(self):
        parsed = urllib.parse.urlparse(self.path)
        status, headers, body = handle_api_request("OPTIONS", parsed.path, parsed.query, b"", dict(self.headers))
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        try:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path in ["/health", "/healthz"]:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(b'{"status":"healthy","version":"3.0.0"}')
                return

            if parsed.path.startswith("/api/"):
                status, headers, body = handle_api_request("GET", parsed.path, parsed.query, b"", dict(self.headers))
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)
                return

            clean_routes = {
                "/": "/index.html",
                "/login": "/login.html",
                "/attack": "/attack.html",
                "/profile": "/profile.html",
                "/history": "/history.html",
                "/threats": "/threats.html",
                "/topology": "/topology.html",
                "/hardening": "/hardening.html",
            }
            if parsed.path in clean_routes:
                self.path = clean_routes[parsed.path]
            return super().do_GET()
        except Exception as e:
            try:
                self.send_error(500, f"Server error: {str(e)}")
            except Exception:
                pass

    def do_POST(self):
        self._handle_with_body("POST")

    def do_PUT(self):
        self._handle_with_body("PUT")

    def _handle_with_body(self, method):
        try:
            parsed = urllib.parse.urlparse(self.path)
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length) if content_length > 0 else b""

            if parsed.path.startswith("/api/"):
                status, headers, body = handle_api_request(method, parsed.path, parsed.query, post_data, dict(self.headers))
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)
                return
            else:
                self.send_error(404, "Endpoint not found")
        except Exception as e:
            try:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(f'{{"success": false, "error": "{str(e)}"}}'.encode('utf-8'))
            except Exception:
                pass

def run_server():
    print("==================================================")
    print(" VANGUARD RECON - ENTERPRISE CYBER AUDIT SERVER")
    print(f" Server active at: http://localhost:{PORT}")
    print(f" Auth Portal ready: http://localhost:{PORT}/login.html")
    print("==================================================")
    with ThreadingVanguardServer(("", PORT), VanguardRequestHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server...")

if __name__ == "__main__":
    run_server()
