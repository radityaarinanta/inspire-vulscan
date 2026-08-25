# INSPIRE — Modern Web Vulnerability Scanner & Security Audit Suite

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python Version" />
  <img src="https://img.shields.io/badge/FastAPI-0.110+-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/OWASP-Top%2010%20Aligned-00F0FF?style=for-the-badge&logo=owasp&logoColor=white" alt="OWASP Top 10" />
  <img src="https://img.shields.io/badge/AsyncIO-High%20Performance-10B981?style=for-the-badge&logo=speedtest&logoColor=white" alt="AsyncIO" />
  <img src="https://img.shields.io/badge/UI-Cyber%20Glassmorphism-f59e0b?style=for-the-badge" alt="UI Theme" />
  <img src="https://img.shields.io/badge/License-MIT-purple?style=for-the-badge" alt="License" />
</p>

```
  ___ _  _ ___ ___ ___ ___ 
 |_ _| \| / __| _ \ |_ _| _ \
  | || .` \__ \  _/ | || |/ /
 |___|_|\_|___/_| |___|_|_\_\
  Enterprise Web Security & Vulnerability Assessment Platform
```

**INSPIRE Security Suite** adalah platform audit keamanan web dan pemindai kerentanan (*web vulnerability scanner*) berbasis Python dengan arsitektur **asynchronous high-performance**. Dirancang untuk mendeteksi kerentanan keamanan web sesuai standar **OWASP Top 10**, dilengkapi antarmuka **Cyber Glassmorphism Dark Dashboard**, telemetri log real-time melalui **WebSocket**, visualisasi data interaktif **Chart.js**, **Security Letter Grade (*A+ hingga F*)**, serta ekspor laporan audit eksekutif **PDF & HTML** dalam 1 klik.

---

## Fitur Unggulan (Key Features)

### 1. Multi-Vector Vulnerability Detection Engines
Aplikasi dilengkapi dengan 7 modul deteksi keamanan otomatis:

* **SQL Injection (SQLi) Detection Engine**:
  * Menguji parameter URL dan formulir HTML (`GET` & `POST`).
  * Mendukung deteksi heuristik dan pencocokan pesan error database untuk **MySQL/MariaDB**, **PostgreSQL**, **Microsoft SQL Server**, **Oracle**, dan **SQLite**.
  * Dilengkapi payload non-destruktif (*syntax break, boolean-based, order by discovery*).
* **Cross-Site Scripting (XSS) Scanner**:
  * Menginjeksi *safe canary payloads* (`<script>`, `<img>`, `<svg>`, custom tags) ke seluruh parameter input.
  * Menganalisis respon HTTP untuk mendeteksi *reflected unescaped HTML context* yang berpotensi dieksploitasi.
* **Security Headers & Cookie Security Auditor**:
  * Memeriksa keberadaan dan konfigurasi header penting: `Content-Security-Policy` (CSP), `Strict-Transport-Security` (HSTS), `X-Frame-Options` (Clickjacking), `X-Content-Type-Options` (MIME sniffing), `Referrer-Policy`, dan `Permissions-Policy`.
  * Mendeteksi kebocoran informasi server (`Server`, `X-Powered-By`, `X-AspNet-Version`).
  * Menganalisis *Permissive CORS* (`Access-Control-Allow-Origin: *`).
  * Memeriksa kelengkapan atribut keamanan cookie (`HttpOnly`, `Secure`, `SameSite`).
* **Sensitive Files & Directory Exposure Prober**:
  * Memindai file konfigurasi dan dotfile kritis yang tidak sengaja terekspos ke publik: `.env`, `.git/HEAD`, `.aws/credentials`, `phpinfo.php`, `server-status`, `robots.txt`, `.gitignore`, dan dokumentasi API `swagger.json` / OpenAPI.
* **Open URL Redirection Scanner**:
  * Menguji parameter pengalihan URL yang rentan (`url`, `redirect`, `next`, `return_to`, `dest`, dll.) terhadap manipulasi domain eksternal berbahaya.
* **SSL/TLS & Cryptographic Inspector**:
  * Mengaudit komunikasi unencrypted HTTP vs HTTPS.
  * Memvalidasi tanggal kedaluwarsa sertifikat SSL, sisa hari aktif (*expiry warning*), penerbit sertifikat (*Issuer/CA*), subjek domain, protokol, cipher suite, dan mendeteksi sertifikat *self-signed* atau tidak valid.
* **Technology Stack Fingerprinting**:
  * Mengidentifikasi server web (Nginx, Apache, IIS, Caddy, LiteSpeed), CDN/Cloud (Cloudflare, Vercel, Netlify), backend framework (FastAPI, Flask, Django, Laravel, Express, ASP.NET), CMS (WordPress), dan pustaka frontend (React, Vue.js, Angular, jQuery, Bootstrap, Tailwind CSS).

---

### 2. Asynchronous Web Crawler & Form Extractor
* Mesin *crawler* asinkron cerdas yang memetakan struktur internal situs web, tautan navigasi, dan seluruh formulir HTML beserta atribut inputnya untuk pengujian keamanan otomatis yang mendalam.

---

### 3. Modern Cyber Dashboard & Real-Time Telemetry
* **Cyber Glassmorphism Dark UI**: Desain antarmuka futuristik bertema gelap dengan aksen terarah, navigasi sidebar responsif, dan tipografi modern (*Inter* & *JetBrains Mono*).
* **Real-Time WebSocket Stream**: Menampilkan log eksekusi langsung (*live terminal*) dengan kode warna dan progress bar persentase pemindaian.
* **Visualisasi Data Interaktif**: Grafik distribusi kategori kerentanan (*horizontal bar chart*) dan sebaran tingkat keparahan (*severity donut chart*) berbasis Chart.js.
* **Sistem Penilaian Risiko Cerdas**: Menghitung skor risiko (*Risk Score 0-100*) serta memberikan peringkat keamanan (*Security Grade A+, A, B, C, D, F*).
* **Interactive Vulnerability Table & Right Detail Drawer**: Tabel temuan yang dapat difilter berdasarkan keparahan (*Critical, High, Medium, Low, Info*), dilengkapi drawer samping (*Inspector*) untuk melihat detail CWE, kategori OWASP, dampak risiko, solusi remediasi, referensi eksternal, dan bukti temuan (*Proof of Concept / evidence snippet*).

---

### 4. Sistem Pengaturan & Kustomisasi Lengkap (Settings)
* **Dukungan Multi-Bahasa (i18n)**: Beralih instan antara **Bahasa Indonesia (ID)** dan **English (EN)**.
* **Pilihan Tema Warna Aksen (Accent Color)**: 5 palet warna dinamis (**Amber**, **Cyan**, **Emerald**, **Purple**, **Rose**) yang mengubah warna grafik, tombol, dan sorotan UI secara real-time.
* **Toggle Modul Pemindai Dinamis**: Aktifkan atau nonaktifkan modul pemindai secara granular (SQLi, XSS, Headers, Sensitive Files, SSL, Redirect, Tech Stack).
* **Mode Ringkas (Compact Mode)**: Mengoptimalkan tata letak dasbor agar lebih padat pada layar kecil.
* **Pengaturan Ekspor Laporan**: Tentukan awalan nama file laporan kustom (*prefix*), sertakan/kecualikan temuan kategori *INFO*, dan aktifkan fitur *auto-export*.
* **Penyimpanan Lokal (LocalStorage)**: Seluruh preferensi pengaturan tersimpan otomatis di browser dan dapat di-*reset* kapan saja.

---

### 5. Laporan Audit Eksekutif (PDF & Standalone HTML)
* **Executive PDF Report**: Dihasilkan menggunakan library ReportLab dengan layout profesional, ringkasan eksekutif, tabel metrik risiko, dan panduan mitigasi per kerentanan.
* **Standalone HTML Report**: Laporan mandiri dengan visual gelap modern yang dapat dibuka di browser mana pun tanpa ketergantungan server lokal.

---

### 6. Rich Terminal CLI
* Mendukung eksekusi mandiri langsung dari terminal menggunakan library `rich` dengan ASCII banner, progress spinner, tabel ringkasan terstruktur, dan opsi ekspor instan.

---

## Arsitektur Sistem

```mermaid
flowchart TD
    User([User / Security Auditor]) -->|Browser / HTTP| UI[Cyber Glassmorphism Dashboard]
    User -->|Terminal / Console| CLI[Rich CLI Engine]
    
    UI -->|REST API / WebSockets| Server[FastAPI Backend Server]
    CLI -->|Direct Async Calls| Core[Scan Orchestrator Core]
    Server --> Core
    
    subgraph Core Engine Modules
        Crawler[Async Web Crawler & Form Extractor]
        SQLi[SQL Injection Module]
        XSS[Cross-Site Scripting Module]
        Headers[Security Headers & Cookie Auditor]
        SensFiles[Sensitive File Exposure Prober]
        SSLMod[SSL/TLS & HTTPS Inspector]
        TechStack[Technology Fingerprinting]
    end
    
    Core --> Crawler
    Core --> SQLi
    Core --> XSS
    Core --> Headers
    Core --> SensFiles
    Core --> SSLMod
    Core --> TechStack
    
    Core --> Reporter[Executive Reporter Engine]
    Reporter --> PDF[(Executive PDF Report)]
    Reporter --> HTML[(Standalone HTML Report)]
```

---

## Pemetaan Standar OWASP Top 10 (2021) & CWE

| Kategori OWASP | Nama Kategori OWASP | Modul INSPIRE | Contoh CWE Terkait |
| :--- | :--- | :--- | :--- |
| **A01:2021** | Broken Access Control | Open Redirect Scanner, Permissive CORS Auditor | CWE-601, CWE-346 |
| **A02:2021** | Cryptographic Failures | SSL/TLS Inspector, Missing HSTS, Cleartext HTTP Transmission | CWE-319, CWE-295 |
| **A03:2021** | Injection | Heuristic SQL Injection Scanner, Reflected XSS Detector | CWE-89, CWE-79 |
| **A05:2021** | Security Misconfiguration | Security Headers, Cookie Flags, Sensitive Files (`.env`, `.git`, AWS keys) | CWE-1021, CWE-200, CWE-538 |

---

## Panduan Instalasi & Penggunaan

### Prasyarat
* **Python 3.10** atau versi yang lebih baru terpasang di sistem operasi Anda (Windows / Linux / macOS).

---

### 1. Clone Repository & Masuk ke Folder Proyek
```bash
git clone https://github.com/radityaarinanta/inspire-vulscan.git
cd inspire-vulscan
```

---

### 2. Buat Virtual Environment (Direkomendasikan) & Install Dependensi
```bash
# Membuat virtual environment
python -m venv venv

# Mengaktifkan virtual environment
# Pada Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Pada Windows (CMD):
.\venv\Scripts\activate.bat
# Pada Linux / macOS:
source venv/bin/activate

# Install dependensi
pip install -r requirements.txt
```

---

### 3. Menjalankan Web Dashboard (1-Click Launcher)
Jalankan perintah berikut:
```bash
python run.py
```
> **Catatan:** Script `run.py` akan secara otomatis memulai backend server FastAPI pada `http://127.0.0.1:8000` dan membuka dashboard di browser default Anda.
> 
> Anda juga dapat menjalankannya langsung melalui:
> ```bash
> uvicorn app:app --reload --host 127.0.0.1 --port 8000
> ```

---

### 4. Menjalankan via Command Line Interface (CLI)
Anda dapat melakukan pemindaian cepat langsung dari terminal:

```bash
# 1. Pemindaian standar dengan target URL
python cli.py http://testphp.vulnweb.com

# 2. Pemindaian cepat (Quick profile) + Ekspor PDF otomatis
python cli.py https://httpbin.org -p quick --pdf

# 3. Pemindaian mendalam (Deep profile) + Ekspor PDF & HTML sekaligus
python cli.py http://testphp.vulnweb.com -p deep --pdf --html
```

#### Argumen CLI:
* `url`: URL target yang akan dipindai (contoh: `http://testphp.vulnweb.com`).
* `-p, --profile`: Pilihan profil pemindaian (`quick`, `standard`, `deep`).
* `--pdf`: Otomatis membuat laporan eksekutif berformat PDF di folder `reports/`.
* `--html`: Otomatis membuat laporan audit berformat HTML mandiri di folder `reports/`.

---

## Pilihan Profil Pemindaian (Scan Profiles)

| Profil | Deskripsi & Cakupan Modul | Rekomendasi Penggunaan |
| :--- | :--- | :--- |
| **Quick** | Memindai Security Headers, SSL/TLS, Technology Stack, dan File Sensitif Dasar tanpa menjalankan web crawler. | *Reconnaissance* cepat & audit konfigurasi server awal. |
| **Standard** *(Default)* | Mencakup semua fitur *Quick* + Web Crawler (kedalaman 2 level, maks 15 halaman), pengujian injeksi SQLi, XSS, dan Open Redirect pada seluruh form & parameter. | Evaluasi keamanan menyeluruh standar aplikasi web. |
| **Deep** | Mencakup seluruh modul dengan analisis mendalam, pemetaan crawling penuh, dan verifikasi payload yang komprehensif. | *Penetration testing* mendalam pada aplikasi kompleks. |

---

## Struktur Direktori Proyek

```
Web Vulnerability Scanner/
├── app.py                      # FastAPI Backend Server & WebSocket endpoint
├── run.py                      # 1-Click Launcher (Auto-start server + buka browser)
├── cli.py                      # Standalone CLI tool dengan Rich formatting
├── requirements.txt            # Dependensi Python
├── LICENSE                     # Lisensi open-source MIT
├── README.md                   # Dokumentasi proyek lengkap
├── core/
│   ├── __init__.py
│   ├── engine.py               # Asynchronous Multi-threaded Scan Orchestrator
│   ├── models.py               # Pydantic Schemas (Vulnerability, Severity, Results, Config)
│   ├── reporter.py             # PDF (ReportLab) & HTML report generation engine
│   └── modules/                # Modul Deteksi Kerentanan Spesifik
│       ├── __init__.py
│       ├── crawler.py          # Asynchronous Web Crawler & Form Extractor
│       ├── headers.py          # Security Headers, HSTS, CSP, CORS, & Cookie Flags
│       ├── sqli.py             # SQL Injection heuristics & multi-DBMS error matching
│       ├── xss.py              # Reflected XSS detection dengan safe canary payloads
│       ├── sensitive_files.py  # .env, .git, AWS keys, phpinfo, & admin endpoint prober
│       ├── open_redirect.py    # Unvalidated external URL redirection scanner
│       ├── ssl_tls.py          # SSL certificate verification, expiry, & HTTPS checks
│       └── tech_stack.py       # Web Server, Framework, CMS & Frontend Fingerprinting
├── templates/
│   ├── index.html              # Cyber Glassmorphism Web Dashboard (SPA Multi-view)
│   └── report_template.html    # Template laporan HTML audit mandiri
├── static/
│   ├── css/
│   │   └── style.css           # Desain CSS Cyber Dark Theme & Multi-Accent System
│   └── js/
│       └── app.js              # Controller Frontend, WebSocket stream, Chart.js, & i18n
└── reports/                    # Direktori output laporan hasil pemindaian (PDF/HTML)
```

---

## Ringkasan Fitur Pengaturan (Settings Page)

Pada menu **Settings** di Web Dashboard, Anda dapat mengatur:
1. **Bahasa Tampilan**: Bahasa Indonesia atau English.
2. **Warna Aksen UI**: Pilihan warna tema (*Amber, Cyan, Emerald, Purple, Rose*).
3. **Batas Baris Log Terminal**: Menentukan jumlah riwayat baris log eksekusi (default: 100 baris).
4. **Mode Tampilan Ringkas (Compact Mode)**: Mengurangi padding antarmuka untuk layout lebih padat.
5. **Konfigurasi Modul Pemindai**: Mengaktifkan/menonaktifkan modul deteksi tertentu sebelum pemindaian.
6. **Preferensi Laporan**: Menentukan format ekspor default, awalan nama file kustom, opsi menampilkan temuan berlevel *INFO*, dan *Auto-Export*.

---

## Pernyataan Etika & Legal Disclaimer

> [!CAUTION]
> **Hanya untuk Tujuan Edukasi dan Audit yang Sah (Authorized Security Evaluation):**
> INSPIRE Security Suite dirancang khusus untuk keperluan edukasi, riset keamanan informasi, dan pengujian penetrasi pada sistem yang dimiliki secara pribadi atau telah memiliki izin tertulis (*mutual written consent*). Memindai atau mengeksploitasi target tanpa izin eksplisit dari pemilik sistem adalah tindakan ilegal dan melanggar hukum. Pembuat tidak bertanggung jawab atas segala bentuk penyalahgunaan atau kerusakan yang diakibatkan oleh penggunaan perangkat lunak ini.

---

## Lisensi

Proyek ini dilisensikan di bawah **[MIT License](LICENSE)**. Anda bebas menggunakan, memodifikasi, dan mendistribusikan program ini sesuai ketentuan lisensi.
