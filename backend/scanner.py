import socket
import ssl
import json
import concurrent.futures
from urllib.parse import urlparse

QUICK_PORTS = {
    80: "HTTP (Web Server)",
    443: "HTTPS (Encrypted Web)",
    22: "SSH (Secure Shell)",
    21: "FTP (File Transfer)",
    25: "SMTP (Mail Server)",
    3306: "MySQL (Database)",
    5432: "PostgreSQL (Database)",
    8080: "HTTP-Proxy / Tomcat",
    8443: "HTTPS-Alt / Admin",
    3389: "RDP (Remote Desktop)"
}

FULL_PORTS = {
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
    2082: "cPanel HTTP",
    2083: "cPanel HTTPS",
    2086: "WHM HTTP",
    2087: "WHM HTTPS",
    2375: "Docker Daemon REST API",
    3306: "MySQL (Database)",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL (Database)",
    5672: "RabbitMQ Message Broker",
    5900: "VNC (Remote Access)",
    6379: "Redis (In-Memory DB)",
    8000: "HTTP-Alt / Dev Server",
    8080: "HTTP-Proxy / Tomcat",
    8443: "HTTPS-Alt / Admin",
    8888: "Jupyter / Web Admin",
    9000: "SonarQube / PHP-FPM",
    9200: "Elasticsearch API",
    11211: "Memcached Memory Cache",
    27017: "MongoDB (NoSQL DB)"
}

COMMON_PORTS = FULL_PORTS

QUICK_SUBDOMAINS = [
    "mail", "docs", "api", "dev", "staging", "admin",
    "app", "vpn", "test", "cdn", "auth", "portal"
]

FULL_SUBDOMAINS = [
    "mail", "docs", "drive", "maps", "play", "news", "cloud", "support",
    "accounts", "calendar", "meet", "sites", "api", "dev", "staging",
    "admin", "app", "vpn", "test", "blog", "shop", "portal", "status",
    "dashboard", "cdn", "auth", "login", "db", "ws", "git", "jenkins",
    "corp", "sso", "monitor", "grafana", "beta", "demo", "stage"
]

SUBDOMAIN_PREFIXES = FULL_SUBDOMAINS

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

def scan_single_port(ip, port, timeout=1.8, hostname=""):
    """Scan a single TCP port and grab banner using SSL if encrypted."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                service = FULL_PORTS.get(port, QUICK_PORTS.get(port, "Active TCP Service"))
                banner = ""
                try:
                    if port in [443, 8443, 465, 993, 995, 2083, 2087]:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        target_host = hostname or ip
                        with ctx.wrap_socket(s, server_hostname=target_host) as ssock:
                            ssock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + target_host.encode() + b"\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
                            banner_bytes = ssock.recv(256)
                            banner = banner_bytes.decode('utf-8', errors='ignore').split('\r\n')[0].strip()
                    elif port in [80, 8080, 8000, 8888, 9000, 2082, 2086]:
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

def run_port_scan(ip, ports=None, hostname="", scan_mode="quick"):
    """Multi-threaded port scanner with distinct Quick vs Full depth."""
    if ports is None:
        if scan_mode == "full":
            ports = list(FULL_PORTS.keys())
        else:
            ports = list(QUICK_PORTS.keys())

    open_ports = []
    max_workers = 35 if scan_mode == "full" else 20
    timeout = 2.5 if scan_mode == "full" else 2.0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_single_port, ip, port, timeout, hostname): port for port in ports}
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

def enumerate_subdomains(hostname, scan_mode="quick"):
    """Multi-threaded DNS subdomain discovery tailored to Quick vs Full mode."""
    parts = hostname.split('.')
    if len(parts) < 2 or all(p.isdigit() for p in parts) or hostname in ["localhost", "127.0.0.1"]:
        return []

    base_domain = '.'.join(parts[-2:])
    active_subdomains = []

    sub_list = FULL_SUBDOMAINS if scan_mode == "full" else QUICK_SUBDOMAINS
    max_workers = 30 if scan_mode == "full" else 15

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(check_subdomain, sub, base_domain) for sub in sub_list]
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
    """Inspect SSL/TLS certificate details with protocol and cipher depth."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=3.5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))
                san_list = [v for k, v in cert.get('subjectAltName', []) if k == 'DNS']

                # Grade cipher strength
                cipher_name = cipher[0] if cipher else "Unknown"
                cipher_bits = cipher[2] if cipher and len(cipher) > 2 else 128
                cipher_strength = "HIGH (256-bit)" if cipher_bits >= 256 else "STANDARD (128-bit)"

                return {
                    "status": "VALID",
                    "version": version,
                    "cipher": cipher_name,
                    "cipher_strength": cipher_strength,
                    "subject_cn": subject.get('commonName', hostname),
                    "issuer_o": issuer.get('organizationName', issuer.get('commonName', 'Trusted Certificate Authority')),
                    "san_count": len(san_list),
                    "notBefore": cert.get('notBefore', 'N/A'),
                    "notAfter": cert.get('notAfter', 'N/A'),
                    "issue_detected": False,
                    "details": f"SSL/TLS Certificate is valid ({version}, {cipher_name})."
                }
    except ssl.SSLError as e:
        return {
            "status": "WARNING",
            "version": "TLS Warning",
            "cipher": "None",
            "cipher_strength": "WEAK",
            "subject_cn": hostname,
            "issuer_o": "Untrusted / Self-Signed",
            "san_count": 0,
            "issue_detected": True,
            "details": f"SSL Certificate Warning: {str(e)}"
        }
    except Exception as e:
        return {
            "status": "INACTIVE",
            "version": "N/A",
            "cipher": "N/A",
            "cipher_strength": "NONE",
            "subject_cn": hostname,
            "issuer_o": "N/A",
            "san_count": 0,
            "issue_detected": True,
            "details": f"Could not establish SSL connection on port 443: {str(e)}"
        }

