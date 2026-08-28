# Changelog

All notable changes to **INSPIRE Security Suite** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-08-28

### Added
- **Asynchronous Multi-Vector Vulnerability Detection Engines**:
  - `SQL Injection (SQLi)`: Multi-DBMS error heuristics and boolean-based verification (MySQL, PostgreSQL, MSSQL, Oracle, SQLite).
  - `Cross-Site Scripting (XSS)`: Safe canary payload reflections across forms and query parameters.
  - `Security Headers & HTTP Configuration`: Audits HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and CORS misconfigurations.
  - `Sensitive Files & Information Disclosure`: Probes `.env`, `.git`, AWS credentials, backups, `phpinfo.php`, and administrative portals.
  - `Open Redirect`: Validates parameter sanitization against unvalidated external redirects.
  - `SSL/TLS Certificate Audit`: Expiry tracking, issuer validation, HTTPS enforcement, and secure protocol checks.
  - `Technology Stack Fingerprinting`: Web servers, backends, frameworks, CMS, and frontend library discovery.
- **Dedicated Web Malware & Client-Side Threat Detector**:
  - `Cryptojacking Hunter`: In-browser Monero/WASM cryptocurrency miners (Coinhive, CryptoLoot, WebMinePool, deepMiner).
  - `Card Skimmer (Magecart) Interceptor`: Intercepts form listeners and exfiltration hooks targeting card numbers, CVVs, and passwords.
  - `Obfuscated JavaScript Analyzer`: Flags `eval(unescape(...))`, `atob()` decoders, packed JS, and high-entropy payloads.
  - `Stealth Iframes & Droppers`: Flags hidden 0-pixel iframes executing drive-by download vectors.
  - `Web Shell & Backdoor Prober`: High-concurrency probing of 12+ common backdoor paths (`wso.php`, `c99.php`, `r57.php`, `b374k.php`, `shell.php`).
  - `Isolated Safe Demo Sandbox`: Local `/demo/malware-sample` endpoint for safe offline malware scanning verification.
- **Modern Cyber Glassmorphism Web Dashboard**:
  - Multi-view Single Page Application (SPA) architecture (Dashboard, Scan Launcher, Malware Scanner, Reports, Settings).
  - Interactive profile selector cards (`Quick`, `Standard`, `Deep`).
  - Live scanning radar animation with real-time multi-step progress indicators.
  - Interactive charts powered by Chart.js.
  - Live terminal telemetry over WebSockets.
  - Multi-accent color themes (Amber, Cyan, Emerald, Purple, Rose) and bilingual support (English / Bahasa Indonesia).
- **Multi-Format Enterprise Audit Reporting Engine**:
  - Executive PDF Reports (generated via ReportLab with tables and vulnerability breakdowns).
  - Standalone HTML Reports (single-file portable reports).
  - Full Structured JSON Reports (automation and CI/CD integration).
  - OASIS SARIF v2.1.0 Reports (compatible with GitHub Security and VS Code SARIF viewer).
  - Spreadsheet CSV Reports (tabular format for spreadsheet analysis).
- **Standalone Terminal CLI (`cli.py`)**:
  - Rich-formatted terminal tables and status panels.
  - Support for `--mode vuln` and `--mode malware`.
  - Batch report generation with `--all-reports`.
