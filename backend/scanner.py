import socket
import ssl
import json
import concurrent.futures
from urllib.parse import urlparse

COMMON_PORTS = {
    21: "FTP (File Transfer)",
    22: "SSH (Secure Shell)",
    23: "TELNET (Unencrypted Terminal)",
    25: "SMTP (Mail Server)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Web Server)",
    110: "POP3 (Mail Protocol)",
    143: "IMAP (Mail Access)",
    443: "HTTPS (Encrypted Web)",
    465: "SMTPS (Secure Mail)",
    587: "SMTP (Submission)",
    993: "IMAPS (Secure IMAP)",
    995: "POP3S (Secure POP3)",
    1433: "MSSQL (Database)",
    1521: "Oracle DB",
    3306: "MySQL (Database)",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL (Database)",
    5900: "VNC (Remote Access)",
    6379: "Redis (In-Memory DB)",
    8000: "HTTP-Alt / Dev Server",
    8080: "HTTP-Proxy / Tomcat",
    8443: "HTTPS-Alt / Admin",
    9200: "Elasticsearch API",
    27017: "MongoDB (NoSQL DB)"
}

SUBDOMAIN_PREFIXES = [
    "mail", "docs", "drive", "maps", "play", "news", "cloud", "support",
    "accounts", "calendar", "meet", "sites", "api", "dev", "staging",
    "admin", "app", "vpn", "test", "blog", "shop", "portal", "status",
    "dashboard", "cdn", "auth", "login", "db", "ws"
]

def resolve_target(target):
    """Clean URL or domain and resolve to IP address."""
    target = target.strip()
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        hostname = parsed.hostname or parsed.path.split('/')[0]
    else:
        hostname = target.split('/')[0].split(':')[0]

    try:
        ip = socket.gethostbyname(hostname)
        return {
            "success": True,
            "hostname": hostname,
            "ip": ip,
            "error": None
        }
    except Exception as e:
        return {
            "success": False,
            "hostname": hostname,
            "ip": None,
            "error": f"Failed to resolve hostname '{hostname}': {str(e)}"
        }

def scan_single_port(ip, port, timeout=2.0, hostname=""):
    """Scan a single TCP port and grab banner using SSL if encrypted."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown TCP Service")
                banner = ""
                try:
                    if port in [443, 8443, 465, 993, 995]:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        target_host = hostname or ip
                        with ctx.wrap_socket(s, server_hostname=target_host) as ssock:
                            ssock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + target_host.encode() + b"\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
                            banner_bytes = ssock.recv(256)
                            banner = banner_bytes.decode('utf-8', errors='ignore').split('\r\n')[0].strip()
                    elif port in [80, 8080, 8000]:
                        target_host = hostname or ip
                        s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + target_host.encode() + b"\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
                        banner_bytes = s.recv(256)
                        banner = banner_bytes.decode('utf-8', errors='ignore').split('\r\n')[0].strip()
                    else:
                        s.sendall(b"\r\n")
                        banner_bytes = s.recv(256)
                        banner = banner_bytes.decode('utf-8', errors='ignore').split('\r\n')[0].strip()
                except Exception:
                    banner = f"Active service listening on port {port}"

                if not banner:
                    banner = f"Active service on port {port}"

                return {
                    "port": port,
                    "state": "OPEN",
                    "service": service,
                    "banner": banner[:90]
                }
    except Exception:
        pass
    return None

def run_port_scan(ip, ports=None, hostname=""):
    """Multi-threaded port scanner with SSL banner grab support."""
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(scan_single_port, ip, port, 2.0, hostname): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)

    open_ports.sort(key=lambda x: x["port"])
    return open_ports

def check_subdomain(sub, domain):
    full_sub = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(full_sub)
        return {"subdomain": full_sub, "ip": ip, "status": "ACTIVE"}
    except Exception:
        return None

def enumerate_subdomains(hostname):
    """Multi-threaded DNS subdomain discovery."""
    parts = hostname.split('.')
    if len(parts) < 2:
        return []

    base_domain = '.'.join(parts[-2:])
    active_subdomains = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
        futures = [executor.submit(check_subdomain, sub, base_domain) for sub in SUBDOMAIN_PREFIXES]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                active_subdomains.append(res)

    active_subdomains.sort(key=lambda x: x["subdomain"])
    return active_subdomains

def lookup_dns_records(hostname):
    """Fetch DNS A record IPs."""
    records = []
    try:
        ips = socket.gethostbyname_ex(hostname)
        if ips and len(ips) >= 3:
            for ip in ips[2]:
                records.append({"type": "A (IPv4)", "val": ip})
    except Exception:
        pass
    if not records:
        try:
            records.append({"type": "A (IPv4)", "val": socket.gethostbyname(hostname)})
        except Exception:
            pass
    return records

def audit_ssl_tls(hostname, port=443):
    """Inspect SSL/TLS certificate details."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=3.5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))

                return {
                    "status": "VALID",
                    "version": version,
                    "cipher": cipher[0] if cipher else "Unknown",
                    "subject_cn": subject.get('commonName', hostname),
                    "issuer_o": issuer.get('organizationName', issuer.get('commonName', 'Google Trust Services / Trusted CA')),
                    "notBefore": cert.get('notBefore', 'N/A'),
                    "notAfter": cert.get('notAfter', 'N/A'),
                    "issue_detected": False,
                    "details": "SSL/TLS Certificate is active, valid, and secured."
                }
    except ssl.SSLError as e:
        return {
            "status": "WARNING",
            "version": "TLS Encryption Warning",
            "cipher": "None",
            "subject_cn": hostname,
            "issuer_o": "Untrusted / Self-Signed",
            "issue_detected": True,
            "details": f"SSL Certificate Warning: {str(e)}"
        }
    except Exception as e:
        return {
            "status": "INACTIVE",
            "version": "N/A",
            "cipher": "N/A",
            "subject_cn": hostname,
            "issuer_o": "N/A",
            "issue_detected": True,
            "details": f"Could not establish SSL connection: {str(e)}"
        }
