# Vanguard Recon — Automated Attack Surface & Web Security Audit Suite

[![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(StdLib)-brightgreen.svg)]()
[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new)
[![Domain](https://img.shields.io/badge/Domain-Cybersecurity%20%7C%20DevSecOps-red.svg)]()

> **Vanguard Recon** is an enterprise-grade, lightweight, multi-threaded attack surface scanner and web vulnerability assessment suite. Designed for SOC Analysts, Security Engineers, and DevSecOps pipelines, it conducts concurrent port scanning, subdomain enumeration, SSL/TLS auditing, OWASP HTTP header checks, sensitive file disclosure detection, AI-powered security analysis, JWT-authenticated role management, and executive HTML report generation.

---

## Key Features

* **Analyst Authentication & Role-Based Access (RBAC)**: Secure authentication portal using PBKDF2-HMAC-SHA256 salted password hashing, 256-bit JWT session tokens, user registration, and dynamic clearance levels (`Level 5 Pro`, `Level 4 Advanced`).
* **Multi-Threaded Port Scanner & Service Banner Grabbing**: Concurrently audits critical TCP ports (HTTP, HTTPS, SSH, FTP, MySQL, RDP, etc.) with banner inspection.
* **Subdomain Enumeration**: Performs passive and DNS-based target subdomain discovery.
* **OWASP Security Header Auditor**: Audits `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and identifies information leakage headers.
* **SSL / TLS Certificate Inspector**: Validates certificate validity, expiration, issuer, protocol version support (TLS 1.2/1.3), and cipher strength.
* **Sensitive File Disclosure Detector**: Checks for publicly exposed `.env`, `.git/HEAD`, `wp-config.php`, `robots.txt`, and backup files.
* **AI Security Assistant**: Powered by Google Gemini AI to provide actionable remediation advice and vulnerability analysis in real-time.
* **Attack Surface Risk Scoring (0–100 & Letter Grade)**: Computes a normalized risk score (`A+` to `F`) backed by severity-ranked findings.
* **Executive Audit Report Exporter**: Generates a professional, printable dark-mode HTML / PDF Executive Security Audit Report.
* **Ready for Vercel Serverless Deployment**: Pre-configured `vercel.json` and `api/index.py` serverless functions for 1-click cloud deployment.

---

## Pre-Configured Demo Credentials

| Role | Username / Email | Password | Clearance Level |
| :--- | :--- | :--- | :--- |
| **Lead Security Analyst (Admin)** | `admin` or `admin@vanguard.io` | `admin123` | `LEVEL 5 (PRO)` |
| **SOC Threat Specialist** | `analyst` or `analyst@vanguard.io` | `Analyst2026!` | `LEVEL 4 (ADVANCED)` |

*(You can also create a new analyst account anytime via the "Create Account" tab on the Login portal).*

---

## Quick Start (Local Server)

### 1. Clone the Repository
```bash
git clone https://github.com/pranavjcs/Vanguard-Recon.git
cd Vanguard-Recon
```

### 2. Launch the Server
Vanguard Recon is built using Python's standard library — **zero mandatory `pip install` required!**

```bash
python server.py
```

### 3. Open the Portal
Navigate to `http://localhost:8000` in your web browser. You will be greeted with the tactical authentication portal (`http://localhost:8000/login.html`).

---

## Deploying to Vercel

Vanguard Recon includes full Vercel serverless configuration (`vercel.json` + `api/index.py`).

### Method A: Deploy via Vercel CLI
1. Install the Vercel CLI (if not already installed):
   ```bash
   npm i -g vercel
   ```
2. Run the deployment command inside the project directory:
   ```bash
   vercel
   ```
3. Deploy to production:
   ```bash
   vercel --prod
   ```

### Method B: Deploy via GitHub & Vercel Dashboard
1. Push your repository to GitHub / GitLab / Bitbucket.
2. Go to [vercel.com/new](https://vercel.com/new) and import the repository.
3. Keep default settings (Framework Preset: `Other`, Root Directory: `./`).
4. (Optional) Set Environment Variables:
   - `JWT_SECRET`: A custom secret string for signing JWT tokens.
   - `GEMINI_API_KEY`: (Optional) Your Google Gemini API key for AI Copilot features.
5. Click **Deploy**!

---

## Project Architecture

```
vanguard-recon/
├── api/
│   └── index.py            # Vercel Serverless Function entrypoint (BaseHTTPRequestHandler)
├── backend/
│   ├── auth.py             # PBKDF2 hashing, JWT creation/verification & user store
│   ├── api_handler.py      # Unified API dispatcher for local & serverless environments
│   ├── scanner.py          # Port scanner, banner grabber & SSL inspector
│   ├── owasp_checker.py    # OWASP header auditor & risk scoring engine
│   ├── gemini_assistant.py # AI security assistant & vulnerability analyst
│   └── report_gen.py       # HTML/PDF executive audit report generator
├── static/
│   ├── login.html          # Tactical analyst authentication & registration portal
│   ├── auth.js             # Client session manager & route protection guard
│   ├── index.html          # Cyber security dashboard UI
│   ├── attack.html         # Attack console & scanner view
│   ├── profile.html        # Analyst profile & credentials manager
│   ├── history.html        # Scan history log repository
│   ├── threats.html        # Threat intel & OWASP findings
│   ├── topology.html       # Attack surface topology map
│   ├── hardening.html      # Server hardening config generator
│   ├── styles.css          # Glassmorphic tactical theme
│   └── app.js              # Dashboard UI logic & REST API handler
├── vercel.json             # Vercel serverless routing configuration
├── requirements.txt        # Python serverless dependencies
├── server.py               # Local multi-threaded HTTP development server
├── LICENSE                 # MIT License
└── README.md               # Project documentation
```

---

## Ethical & Security Notice
*This tool is intended strictly for authorized security auditing, educational research, and defensive assessment. Always obtain explicit authorization before scanning target networks or systems.*

---

## License
Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more details.
