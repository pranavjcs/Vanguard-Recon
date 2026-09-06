from http.server import BaseHTTPRequestHandler
import sys
import os
import urllib.parse

# Ensure project root is in sys.path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from backend.api_handler import handle_api_request

def resolve_request_path(raw_path, headers):
    """Extract actual intended path from Vercel rewrites and headers."""
    parsed = urllib.parse.urlparse(raw_path)
    path = parsed.path
    query = parsed.query

    # 1. Check explicit __route query param passed by Vercel rewrite
    query_dict = urllib.parse.parse_qs(query)
    if "__route" in query_dict and query_dict["__route"]:
        route = query_dict["__route"][0].lstrip("/")
        return f"/api/{route}", query

    # 2. Check Vercel standard routing headers
    matched_path = headers.get("x-matched-path") or headers.get("X-Matched-Path")
    if matched_path and matched_path != "/api/index.py":
        return matched_path.split("?")[0], query

    forwarded_uri = headers.get("x-forwarded-uri") or headers.get("X-Forwarded-Uri")
    if forwarded_uri and forwarded_uri != "/api/index.py":
        return forwarded_uri.split("?")[0], query

    route_matches = headers.get("x-now-route-matches") or headers.get("X-Now-Route-Matches")
    if route_matches:
        for item in route_matches.split("&"):
            if "=" in item:
                k, v = item.split("=", 1)
                clean_v = urllib.parse.unquote(v).lstrip("/")
                if clean_v and not clean_v.endswith(".py"):
                    return f"/api/{clean_v}", query

    return path, query

class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        req_path, req_query = resolve_request_path(self.path, dict(self.headers))
        status, headers, body = handle_api_request("OPTIONS", req_path, req_query, b"", dict(self.headers))
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        req_path, req_query = resolve_request_path(self.path, dict(self.headers))
        status, headers, body = handle_api_request("GET", req_path, req_query, b"", dict(self.headers))
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
            req_path, req_query = resolve_request_path(self.path, dict(self.headers))
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length) if content_length > 0 else b""
            status, headers, body = handle_api_request(method, req_path, req_query, post_data, dict(self.headers))
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
