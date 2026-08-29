from http.server import BaseHTTPRequestHandler
import sys
import os
import urllib.parse

# Ensure project root is in sys.path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from backend.api_handler import handle_api_request

class handler(BaseHTTPRequestHandler):
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
        parsed = urllib.parse.urlparse(self.path)
        status, headers, body = handle_api_request("GET", parsed.path, parsed.query, b"", dict(self.headers))
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self._handle_with_body("POST")

    def do_PUT(self):
        self._handle_with_body("PUT")

    def do_DELETE(self):
        self._handle_with_body("DELETE")

    def _handle_with_body(self, method):
        try:
            parsed = urllib.parse.urlparse(self.path)
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length) if content_length > 0 else b""
            status, headers, body = handle_api_request(method, parsed.path, parsed.query, post_data, dict(self.headers))
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(f'{{"success": false, "error": "{str(e)}"}}'.encode("utf-8"))
