# Vanguard Recon — Automated Attack Surface & Web Security Audit Suite

[![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(StdLib)-brightgreen.svg)]()
[![Domain](https://img.shields.io/badge/Domain-Cybersecurity%20%7C%20DevSecOps-red.svg)]()

> **Vanguard Recon** is an enterprise-grade, lightweight, multi-threaded attack surface scanner and web vulnerability assessment suite. Designed for SOC Analysts, Security Engineers, and DevSecOps pipelines, it conducts concurrent port scanning, subdomain enumeration, SSL/TLS auditing, OWASP HTTP header checks, sensitive file disclosure detection, AI-powered security analysis, and executive HTML report generation.

---

## Key Features

* **Multi-Threaded Port Scanner & Service Banner Grabbing**: Concurrently audits critical TCP ports (HTTP, HTTPS, SSH, FTP, MySQL, RDP, etc.) with banner inspection.
* **Subdomain Enumeration**: Performs passive and DNS-based target subdomain discovery.
* **OWASP Security Header Auditor**: Audits `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and identifies information leakage headers.
* **SSL / TLS Certificate Inspector**: Validates certificate validity, expiration, issuer, protocol version support (TLS 1.2/1.3), and cipher strength.
* **Sensitive File Disclosure Detector**: Checks for publicly exposed `.env`, `.git/HEAD`, `wp-config.php`, `robots.txt`, and backup files.
* **AI Security Assistant**: Powered by Google Gemini AI to provide actionable remediation advice and vulnerability analysis in real-time.
* **Attack Surface Risk Scoring (0–100 & Letter Grade)**: Computes a normalized risk score (`A+` to `F`) backed by severity-ranked findings.
* **Executive Audit Report Exporter**: Generates a professional, printable dark-mode HTML / PDF Executive Security Audit Report.

---

## Quick Start (Zero External Dependencies)

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR-USERNAME/vanguard-recon.git
cd vanguard-recon
```

### 2. Launch the Server
Vanguard Recon is built using Python's standard library — **no `pip install` required!**

```bash
python server.py
```

### 3. Open the Dashboard
Navigate to `http://localhost:8000` in your web browser.

---

## Project Architecture

```
vanguard-recon/
├── backend/
│   ├── scanner.py          # Port scanner, banner grabber & SSL inspector
│   ├── owasp_checker.py    # OWASP header auditor & risk scoring engine
│   ├── gemini_assistant.py # AI security assistant & vulnerability analyst
│   └── report_gen.py       # HTML/PDF executive audit report generator
├── static/
│   ├── index.html          # Cyber security dashboard UI
│   ├── styles.css          # Glassmorphic dark-mode tactical theme
│   └── app.js              # Dashboard UI logic & REST API handler
├── config.json             # Optional API keys (AI Assistant integration)
├── server.py               # REST API server (Python http.server)
├── .gitignore              # Git ignore rules for virtualenvs & keys
├── LICENSE                 # MIT License
└── README.md               # Project documentation
```

---

## Resume Bullet Points (Copy & Paste)

> **Cyber Security Project — Vanguard Recon (Attack Surface Assessment Suite)**
> * Engineered an automated web security & attack surface scanner in **Python** featuring multi-threaded TCP port scanning, SSL/TLS inspection, and subdomain discovery.
> * Implemented **OWASP Top 10** heuristic security checks to identify missing security headers, server info leakage, and exposed sensitive files (`.env`, `.git`).
> * Integrated Google **Gemini AI** for automated threat intelligence synthesis and prioritized remediation advice.
> * Designed a normalized 0–100 risk scoring engine and built a zero-dependency dark-mode dashboard with printable executive HTML security audit reports.

---

## Ethical & Security Notice
*This tool is intended strictly for authorized security auditing, educational research, and defensive assessment. Always obtain explicit authorization before scanning target networks or systems.*

---

## License
Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more details.
