/**
 * Inspire Security Suite — Frontend Controller
 * Enterprise Dashboard with WebSocket telemetry, Chart.js, Vulnerability Table & Right Drawer
 */

// ─── State ─────────────────────────────────────────────────────
let currentScanId  = null;
let currentResult  = null;
let currentFilter  = 'ALL';
let categoryChart  = null;
let severityChart  = null;
let activeSocket   = null;
let activeRowEl    = null;

// ─── Init ───────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    lucide.createIcons();
    initCharts();
    setupScanForm();
    setupExportButtons();
    setupFilterChips();
    initSettings();
});

// ─── View Switcher ──────────────────────────────────────────────
function switchView(name) {
    document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
    document.getElementById(`view-${name}`).classList.remove('hidden');

    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const navEl = document.getElementById(`nav-${name}`);
    if (navEl) navEl.classList.add('active');

    // Breadcrumb
    const labels = { dashboard: 'Dashboard', scan: 'New Scan', reports: 'Reports', history: 'History' };
    document.querySelector('.bc-current').textContent = labels[name] || name;
}

// ─── Target Helper ──────────────────────────────────────────────
function setTarget(url) {
    document.getElementById('target-url-input').value = url;
}

// ─── Chart Initialization ───────────────────────────────────────
function initCharts() {
    // Category Bar Chart (horizontal)
    const catCtx = document.getElementById('categoryChart').getContext('2d');
    categoryChart = new Chart(catCtx, {
        type: 'bar',
        data: {
            labels: ['Security Headers', 'SQLi', 'XSS', 'Sensitive Files', 'Open Redirect', 'SSL/TLS'],
            datasets: [{
                label: 'Findings',
                data: [0, 0, 0, 0, 0, 0],
                backgroundColor: 'rgba(245, 158, 11, 0.7)',
                borderColor: '#f59e0b',
                borderWidth: 1,
                borderRadius: 3,
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: buildTooltipConfig()
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255,255,255,0.04)' },
                    ticks: { color: '#6b7280', font: { family: 'JetBrains Mono', size: 11 }, stepSize: 1 },
                    border: { color: '#2c2c2c' }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: '#9ca3af', font: { family: 'Inter', size: 11 } },
                    border: { color: '#2c2c2c' }
                }
            }
        }
    });

    // Severity Donut
    const sevCtx = document.getElementById('severityChart').getContext('2d');
    severityChart = new Chart(sevCtx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#3b82f6', '#6b7280'],
                borderColor: '#181818',
                borderWidth: 2,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '70%',
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#9ca3af',
                        font: { family: 'Inter', size: 11 },
                        padding: 10,
                        usePointStyle: true,
                        pointStyle: 'circle'
                    }
                },
                tooltip: buildTooltipConfig()
            }
        }
    });
}

function buildTooltipConfig() {
    return {
        backgroundColor: '#111',
        titleColor: '#f59e0b',
        bodyColor: '#e8e8e8',
        borderColor: '#2c2c2c',
        borderWidth: 1,
        padding: 10,
        cornerRadius: 6
    };
}

// ─── Scan Form ──────────────────────────────────────────────────
function setupScanForm() {
    document.getElementById('scan-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const targetUrl = document.getElementById('target-url-input').value.trim();
        const profile   = document.getElementById('scan-profile').value;
        if (!targetUrl) return;

        // Switch to dashboard to show progress
        switchView('dashboard');
        startScan(targetUrl, profile);
    });
}

async function startScan(targetUrl, profile) {
    // UI: scanning state
    setScanningState(true);
    clearDashboard();
    addLog(`[${ts()}] Initiating scan for ${targetUrl} (Profile: ${profile.toUpperCase()})...`, 'log-primary');

    try {
        const res = await fetch('/api/scan/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_url: targetUrl, profile })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Failed to start scan');

        currentScanId = data.scan_id;
        connectWS(currentScanId);
    } catch (err) {
        addLog(`[${ts()}] Error: ${err.message}`, 'log-crit');
        setScanningState(false);
    }
}

// ─── WebSocket ──────────────────────────────────────────────────
function connectWS(scanId) {
    if (activeSocket) activeSocket.close();
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    activeSocket = new WebSocket(`${proto}//${location.host}/ws/scan/${scanId}`);

    activeSocket.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        if (msg.event === 'progress')  handleProgress(msg.data);
        if (msg.event === 'completed') handleCompleted(msg.data);
    };
    activeSocket.onerror = () => {
        addLog(`[${ts()}] WebSocket error. Results will load when scan completes.`, 'log-warn');
    };
}

function handleProgress(data) {
    setProgress(data.progress_percentage, data.current_action);
    if (data.logs?.length > 0) {
        const last = data.logs[data.logs.length - 1];
        const type = last.includes('[!]') ? 'log-warn'
                   : last.includes('[✓]') ? 'log-success'
                   : 'log-primary';
        addLog(last, type);
    }
}

function handleCompleted(result) {
    currentResult = result;
    renderDashboard(result);
    setScanningState(false);
    addLog(`[${ts()}] ✓ Scan complete. Grade: ${result.summary.security_grade} | Risk: ${result.summary.risk_score}/100 | Findings: ${result.summary.total_findings}`, 'log-success');
}

// ─── Dashboard Render ───────────────────────────────────────────
function clearDashboard() {
    // Reset stat cards
    document.getElementById('stat-total').textContent = '—';
    document.getElementById('stat-since').textContent = 'Scanning...';
    document.getElementById('stat-grade').textContent = '—';
    document.getElementById('stat-risk').innerHTML = '—<small>/100</small>';
    document.getElementById('stat-duration').textContent = '—';
    document.getElementById('stat-crawled').textContent = 'Pages crawled: —';
    document.getElementById('grade-ring-fill').setAttribute('stroke-dasharray', '0 201');
    document.getElementById('findings-count-badge').textContent = '0';
    ['pdf', 'html', 'json', 'sarif', 'csv'].forEach(fmt => {
        const btn = document.getElementById(`btn-export-${fmt}`);
        if (btn) btn.disabled = true;
    });
    renderTableEmpty();
}

function renderDashboard(result) {
    const s = result.summary;

    // Stat cards
    document.getElementById('stat-total').textContent = s.total_findings;
    document.getElementById('stat-since').textContent = `Target: ${result.target_url.replace(/^https?:\/\//, '').slice(0, 40)}`;
    document.getElementById('stat-grade').textContent = s.security_grade;
    document.getElementById('stat-risk').innerHTML = `${s.risk_score}<small>/100</small>`;
    document.getElementById('stat-duration').textContent = `${s.duration_seconds}s`;
    document.getElementById('stat-crawled').textContent = `Pages crawled: ${s.urls_crawled_count}`;
    document.getElementById('findings-count-badge').textContent = s.total_findings;

    // Grade ring animation (circumference = 2π*32 ≈ 201)
    const gradeMap = { 'A+': 1, 'A': 0.92, 'B': 0.78, 'C': 0.62, 'D': 0.45, 'F': 0.28 };
    const pct = (gradeMap[s.security_grade] ?? 0.1);
    const circ = 201;
    document.getElementById('grade-ring-fill').setAttribute(
        'stroke-dasharray', `${Math.round(pct * circ)} ${circ}`
    );

    // Update charts
    updateCategoryChart(result.vulnerabilities);
    updateSeverityChart(s);

    // SSL info
    if (result.ssl_info?.is_https) {
        const si = result.ssl_info;
        const box = document.getElementById('ssl-info-box');
        box.style.display = 'block';
        document.getElementById('ssl-info-content').innerHTML = `
            <div class="ssl-info-content-row"><span>Issuer</span><span>${si.issuer || 'Unknown'}</span></div>
            <div class="ssl-info-content-row"><span>Expires</span><span>${si.expires_at?.slice(0,10) || '—'}</span></div>
            <div class="ssl-info-content-row"><span>Days Left</span><span style="color:${(si.days_left||0) < 30 ? 'var(--critical)' : 'var(--emerald)'}">${si.days_left ?? '—'}</span></div>
        `;
    }

    // Tech pills
    if (result.technologies?.length > 0) {
        const pillsEl = document.getElementById('tech-pills');
        pillsEl.innerHTML = '';
        result.technologies.forEach(t => {
            const p = document.createElement('span');
            p.className = 'tech-pill';
            p.title = t.category;
            p.textContent = t.name + (t.version ? ` ${t.version}` : '');
            pillsEl.appendChild(p);
        });
    }

    // Enable export buttons
    ['pdf', 'html', 'json', 'sarif', 'csv'].forEach(fmt => {
        const btn = document.getElementById(`btn-export-${fmt}`);
        if (btn) btn.disabled = false;
    });

    // Render table
    renderTable(result.vulnerabilities);
}

function updateCategoryChart(vulns) {
    const cats = ['Security Headers', 'Injection', 'Cross-Site Scripting (XSS)',
                  'Sensitive Data Exposure', 'Redirection & Phishing', 'Cryptographic Failures',
                  'Information Disclosure', 'Source Code Disclosure', 'API Information Disclosure',
                  'Transport Security', 'Session Management', 'Access Control'];

    // Map categories to short labels
    const shortLabels = {
        'Security Headers': 'Sec. Headers',
        'Injection': 'SQLi',
        'Cross-Site Scripting (XSS)': 'XSS',
        'Sensitive Data Exposure': 'Sensitive Files',
        'Redirection & Phishing': 'Open Redirect',
        'Cryptographic Failures': 'SSL/TLS',
        'Transport Security': 'SSL/TLS',
        'Information Disclosure': 'Info Disclosure',
        'Source Code Disclosure': 'Info Disclosure',
        'API Information Disclosure': 'Info Disclosure',
        'Session Management': 'Session Mgmt',
        'Access Control': 'Access Control'
    };

    const counts = {};
    vulns.forEach(v => {
        const short = shortLabels[v.category] || v.category;
        counts[short] = (counts[short] || 0) + 1;
    });

    const labels = Object.keys(counts);
    const data   = Object.values(counts);

    categoryChart.data.labels = labels.length ? labels : ['No findings'];
    categoryChart.data.datasets[0].data = data.length ? data : [0];
    categoryChart.update();
}

function updateSeverityChart(s) {
    severityChart.data.datasets[0].data = [
        s.critical_count, s.high_count, s.medium_count, s.low_count, s.info_count
    ];
    severityChart.update();
}

// ─── Vulnerability Table ────────────────────────────────────────
function setupFilterChips() {
    document.querySelectorAll('.filter-chip').forEach(chip => {
        chip.addEventListener('click', () => {
            document.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
            chip.classList.add('active');
            currentFilter = chip.dataset.filter;
            if (currentResult) renderTable(currentResult.vulnerabilities);
        });
    });
}

function renderTableEmpty() {
    document.getElementById('vuln-table-body').innerHTML = `
        <tr class="table-empty-row">
            <td colspan="7">
                <div class="table-empty-state">
                    <i data-lucide="shield" class="empty-icon"></i>
                    <p>No findings yet. Launch a scan to discover vulnerabilities.</p>
                </div>
            </td>
        </tr>`;
    lucide.createIcons();
}

function renderTable(vulns) {
    const tbody = document.getElementById('vuln-table-body');
    const filtered = currentFilter === 'ALL' ? vulns : vulns.filter(v => v.severity === currentFilter);

    if (!filtered.length) {
        tbody.innerHTML = `
            <tr class="table-empty-row">
                <td colspan="7">
                    <div class="table-empty-state">
                        <i data-lucide="check-circle-2" class="empty-icon"></i>
                        <p>No findings with severity "${currentFilter}" found.</p>
                    </div>
                </td>
            </tr>`;
        lucide.createIcons();
        return;
    }

    tbody.innerHTML = '';
    filtered.forEach((v, idx) => {
        const tr = document.createElement('tr');
        tr.dataset.idx = idx;
        tr.innerHTML = `
            <td style="color:var(--text-muted);font-family:var(--font-mono)">${idx + 1}</td>
            <td><span class="badge badge-${v.severity.toLowerCase()}">${v.severity}</span></td>
            <td class="vuln-name-cell">${esc(v.name)}</td>
            <td class="vuln-cvss">${v.cvss_score}</td>
            <td style="color:var(--text-muted)">${esc(v.category)}</td>
            <td style="color:var(--text-muted);font-size:11px">${esc(v.owasp_category || '—')}</td>
            <td><button class="btn-inspect" onclick="openDrawer(event, ${idx})">Inspect →</button></td>
        `;
        tr.addEventListener('click', (e) => {
            if (e.target.closest('.btn-inspect')) return;
            openDrawer(e, idx, filtered);
        });
        tbody.appendChild(tr);
    });
    lucide.createIcons();

    // Store filtered for drawer navigation
    tbody._filteredVulns = filtered;
}

// ─── Right Drawer ───────────────────────────────────────────────
function openDrawer(event, idx, filteredVulns) {
    const source = filteredVulns || getFilteredVulns();
    const vuln   = source[idx];
    if (!vuln) return;

    // Highlight row
    document.querySelectorAll('#vuln-table-body tr').forEach(r => r.classList.remove('row-active'));
    const rows = document.querySelectorAll('#vuln-table-body tr');
    if (rows[idx]) rows[idx].classList.add('row-active');

    // Badge & CVSS in header
    const badge = document.getElementById('drawer-badge');
    badge.className = `badge badge-${vuln.severity.toLowerCase()} drawer-badge`;
    badge.textContent = vuln.severity;
    document.getElementById('drawer-cvss').textContent = `CVSS ${vuln.cvss_score}`;

    // Build drawer body
    let evidenceHtml = '';
    if (vuln.evidence?.length > 0) {
        vuln.evidence.forEach(ev => {
            evidenceHtml += `
                <div class="evidence-block">
                    <div><strong>URL:</strong> ${esc(ev.url)}</div>
                    ${ev.parameter ? `<div><strong>Param:</strong> ${esc(ev.parameter)}</div>` : ''}
                    ${ev.payload   ? `<div><strong>Payload:</strong> ${esc(ev.payload)}</div>` : ''}
                    ${ev.response_status ? `<div><strong>Status:</strong> HTTP ${ev.response_status}</div>` : ''}
                    ${ev.response_snippet ? `<div style="margin-top:6px;border-top:1px solid #1e293b;padding-top:6px;color:#38bdf8"><strong>Match:</strong><br>${esc(ev.response_snippet)}</div>` : ''}
                    <div style="margin-top:5px;color:#4b5563">${esc(ev.description)}</div>
                </div>`;
        });
    }

    document.getElementById('drawer-body').innerHTML = `
        <div class="drawer-title-main">${esc(vuln.name)}</div>

        <div class="drawer-meta-row">
            ${vuln.cwe_id ? `<span class="meta-chip"><strong>CWE:</strong> ${esc(vuln.cwe_id)}</span>` : ''}
            ${vuln.owasp_category ? `<span class="meta-chip"><strong>OWASP:</strong> ${esc(vuln.owasp_category)}</span>` : ''}
            <span class="meta-chip"><strong>Category:</strong> ${esc(vuln.category)}</span>
        </div>

        <div class="drawer-divider"></div>

        <div class="drawer-section">
            <div class="drawer-section-label">Description</div>
            <div class="drawer-section-body">${esc(vuln.description)}</div>
        </div>

        <div class="drawer-section">
            <div class="drawer-section-label">Impact</div>
            <div class="drawer-section-body">${esc(vuln.impact)}</div>
        </div>

        <div class="remediation-block">
            <div class="remediation-block-label">🛡️ Remediation</div>
            ${esc(vuln.remediation)}
        </div>

        ${vuln.references?.length ? `
        <div class="drawer-section">
            <div class="drawer-section-label">References</div>
            <div style="display:flex;flex-direction:column;gap:4px;">
                ${vuln.references.map(r => `<a href="${esc(r)}" target="_blank" style="font-size:12px;color:var(--amber);font-family:var(--font-mono);word-break:break-all;">${esc(r)}</a>`).join('')}
            </div>
        </div>` : ''}

        ${evidenceHtml ? `
        <div class="drawer-section">
            <div class="drawer-section-label">Proof of Concept</div>
            ${evidenceHtml}
        </div>` : ''}
    `;

    lucide.createIcons();

    // Open drawer
    document.getElementById('detail-drawer').classList.add('open');
    document.getElementById('drawer-overlay').classList.add('open');
}

function closeDrawer() {
    document.getElementById('detail-drawer').classList.remove('open');
    document.getElementById('drawer-overlay').classList.remove('open');
    document.querySelectorAll('#vuln-table-body tr').forEach(r => r.classList.remove('row-active'));
}

function getFilteredVulns() {
    if (!currentResult) return [];
    return currentFilter === 'ALL'
        ? currentResult.vulnerabilities
        : currentResult.vulnerabilities.filter(v => v.severity === currentFilter);
}

// ─── Progress & Status UI ───────────────────────────────────────
function setProgress(pct, action) {
    document.getElementById('scan-progress-bar').style.width = `${pct}%`;
    document.getElementById('progress-pct').textContent = `${pct}%`;
    document.getElementById('progress-action-text').textContent = action || '';
}

function setScanningState(scanning) {
    const dot      = document.getElementById('hdr-status-dot');
    const txt      = document.getElementById('hdr-status-text');
    const scanBtn  = document.getElementById('btn-start-scan');
    const btnTxt   = document.getElementById('scan-btn-text');

    if (scanning) {
        dot.className = 'status-dot scanning';
        txt.textContent = 'Scanning...';
        if (scanBtn) { scanBtn.disabled = true; btnTxt.textContent = 'Scanning...'; }
    } else {
        dot.className = 'status-dot idle';
        txt.textContent = 'Engine Ready';
        if (scanBtn) { scanBtn.disabled = false; btnTxt.textContent = 'Launch Scan'; }
        setProgress(currentResult ? 100 : 0, currentResult ? 'Scan completed.' : 'Waiting for scan target...');
    }
}

// ─── Terminal Log ───────────────────────────────────────────────
function addLog(text, cls = 'log-primary') {
    const terminal = document.getElementById('terminal-logs');
    const div = document.createElement('div');
    div.className = `log-entry ${cls}`;
    div.textContent = text;
    terminal.appendChild(div);
    terminal.scrollTop = terminal.scrollHeight;
}

function ts() {
    return new Date().toLocaleTimeString('en-GB');
}

// ─── Export Buttons ─────────────────────────────────────────────
function setupExportButtons() {
    ['pdf', 'html', 'json', 'sarif', 'csv'].forEach(fmt => {
        const btn = document.getElementById(`btn-export-${fmt}`);
        if (btn) {
            btn.addEventListener('click', () => {
                if (currentScanId) window.open(`/api/scan/report/${fmt}/${currentScanId}`, '_blank');
            });
        }
    });
}

// ─── Utilities ──────────────────────────────────────────────────
function esc(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g,  '&amp;')
        .replace(/</g,  '&lt;')
        .replace(/>/g,  '&gt;')
        .replace(/"/g,  '&quot;')
        .replace(/'/g,  '&#039;');
}

// =============================================================================
// SETTINGS SYSTEM
// =============================================================================

// ─── Default Settings ────────────────────────────────────────────
const DEFAULT_SETTINGS = {
    language:      'en',
    accent:        'amber',
    terminalLines: 100,
    compactMode:   false,
    reportFormat:  'both',
    reportPrefix:  '',
    includeInfo:   true,
    autoExport:    false,
    modules: {
        sqli:     true,
        xss:      true,
        headers:  true,
        sensitive:true,
        ssl:      true,
        redirect: true,
        tech:     true
    }
};

// ─── i18n Translations ───────────────────────────────────────────
const TRANSLATIONS = {
    en: {
        'nav.dashboard':    'Dashboard',
        'nav.newScan':      'New Scan',
        'nav.reports':      'Reports',
        'nav.history':      'History',
        'nav.settings':     'Settings',
        'header.newScan':   'New Scan',
        'header.ready':     'Engine Ready',
        'header.scanning':  'Scanning...',
        'settings.title':   'Settings',
        'settings.subtitle':'Customize language, appearance, scanner defaults, and reporting preferences.',
        'settings.resetDefaults': 'Reset to Defaults',
        'settings.saved':   'Settings saved',
        'settings.lang.title':  'Language & Region',
        'settings.lang.desc':   'Choose the interface display language.',
        'settings.lang.interfaceLang':     'Interface Language',
        'settings.lang.interfaceLangHint': 'All UI labels, buttons, and messages will be displayed in this language.',
        'settings.appearance.title':    'Appearance',
        'settings.appearance.desc':     'Customize the dashboard look and feel.',
        'settings.appearance.accentColor':     'Accent Color',
        'settings.appearance.accentColorHint': 'Changes sidebar highlights, buttons, charts, and interactive elements.',
        'settings.appearance.terminalLines':     'Terminal Log Max Lines',
        'settings.appearance.terminalLinesHint': 'Maximum number of log lines shown before auto-clearing older entries.',
        'settings.appearance.compactMode':     'Compact Mode',
        'settings.appearance.compactModeHint': 'Reduce spacing and padding for a denser dashboard layout.',
        'settings.modules.title': 'Scanner Modules',
        'settings.modules.desc':  'Enable or disable individual detection modules. Disabled modules will be skipped during all scans.',
        'settings.modules.sqliHint':        'Test input fields and URL parameters for database injection vulnerabilities.',
        'settings.modules.xssHint':         'Probe parameters and forms for reflected XSS vulnerabilities.',
        'settings.modules.headers':         'Security Headers Audit',
        'settings.modules.headersHint':     'Check for missing or misconfigured HTTP security headers.',
        'settings.modules.sensitiveFiles':  'Sensitive File Discovery',
        'settings.modules.sensitiveFilesHint': 'Probe for exposed .env, .git, backups, phpinfo, and admin paths.',
        'settings.modules.sslHint':         'Verify SSL certificate validity, expiration, and HTTPS enforcement.',
        'settings.modules.redirectHint':    'Test redirect parameters for unvalidated external URL redirection.',
        'settings.modules.techStack':       'Technology Fingerprinting',
        'settings.modules.techStackHint':   'Identify web server, CMS, framework, and frontend library stack.',
        'settings.report.title':  'Report Settings',
        'settings.report.desc':   'Configure default report generation behavior.',
        'settings.report.defaultFormat':     'Default Export Format',
        'settings.report.defaultFormatHint': 'Determines which report format button is highlighted after a scan.',
        'settings.report.filenamePrefix':     'Report Filename Prefix',
        'settings.report.filenamePrefixHint': 'Custom prefix for generated report files (e.g. "MyCompany_Audit").',
        'settings.report.includeInfo':     'Include INFO Severity in Reports',
        'settings.report.includeInfoHint': 'When disabled, informational findings are excluded from exported reports.',
        'settings.report.autoExport':     'Auto-Export After Scan',
        'settings.report.autoExportHint': 'Automatically trigger report download when a scan finishes.',
    },
    id: {
        'nav.dashboard':    'Dasbor',
        'nav.newScan':      'Scan Baru',
        'nav.reports':      'Laporan',
        'nav.history':      'Riwayat',
        'nav.settings':     'Pengaturan',
        'header.newScan':   'Scan Baru',
        'header.ready':     'Mesin Siap',
        'header.scanning':  'Memindai...',
        'settings.title':   'Pengaturan',
        'settings.subtitle':'Sesuaikan bahasa, tampilan, konfigurasi scanner, dan preferensi pelaporan.',
        'settings.resetDefaults': 'Kembalikan ke Default',
        'settings.saved':   'Pengaturan disimpan',
        'settings.lang.title':  'Bahasa & Wilayah',
        'settings.lang.desc':   'Pilih bahasa tampilan antarmuka.',
        'settings.lang.interfaceLang':     'Bahasa Antarmuka',
        'settings.lang.interfaceLangHint': 'Semua label, tombol, dan pesan akan ditampilkan dalam bahasa yang dipilih.',
        'settings.appearance.title':    'Tampilan',
        'settings.appearance.desc':     'Sesuaikan tampilan dan nuansa dasbor.',
        'settings.appearance.accentColor':     'Warna Aksen',
        'settings.appearance.accentColorHint': 'Mengubah sorotan sidebar, tombol, grafik, dan elemen interaktif.',
        'settings.appearance.terminalLines':     'Batas Baris Log Terminal',
        'settings.appearance.terminalLinesHint': 'Jumlah maksimum baris log yang ditampilkan sebelum entri lama dihapus otomatis.',
        'settings.appearance.compactMode':     'Mode Ringkas',
        'settings.appearance.compactModeHint': 'Kurangi spasi dan padding untuk tata letak dasbor yang lebih padat.',
        'settings.modules.title': 'Modul Scanner',
        'settings.modules.desc':  'Aktifkan atau nonaktifkan modul deteksi individual. Modul yang dinonaktifkan akan dilewati saat scan.',
        'settings.modules.sqliHint':        'Uji kolom input dan parameter URL untuk kerentanan injeksi database.',
        'settings.modules.xssHint':         'Probe parameter dan form untuk kerentanan XSS yang direfleksikan.',
        'settings.modules.headers':         'Audit Header Keamanan',
        'settings.modules.headersHint':     'Periksa header keamanan HTTP yang hilang atau salah konfigurasi.',
        'settings.modules.sensitiveFiles':  'Penemuan File Sensitif',
        'settings.modules.sensitiveFilesHint': 'Probe untuk file .env, .git, backup, phpinfo, dan path admin yang terekspos.',
        'settings.modules.sslHint':         'Verifikasi validitas, kedaluwarsa sertifikat SSL, dan penegakan HTTPS.',
        'settings.modules.redirectHint':    'Uji parameter redirect untuk pengalihan URL eksternal yang tidak tervalidasi.',
        'settings.modules.techStack':       'Sidik Jari Teknologi',
        'settings.modules.techStackHint':   'Identifikasi web server, CMS, framework, dan stack library frontend.',
        'settings.report.title':  'Pengaturan Laporan',
        'settings.report.desc':   'Konfigurasi perilaku pembuatan laporan secara default.',
        'settings.report.defaultFormat':     'Format Ekspor Default',
        'settings.report.defaultFormatHint': 'Menentukan tombol format laporan mana yang disorot setelah scan selesai.',
        'settings.report.filenamePrefix':     'Awalan Nama File Laporan',
        'settings.report.filenamePrefixHint': 'Awalan kustom untuk file laporan yang dihasilkan (mis. "PerusahaanSaya_Audit").',
        'settings.report.includeInfo':     'Sertakan Temuan INFO dalam Laporan',
        'settings.report.includeInfoHint': 'Jika dinonaktifkan, temuan informatif akan dikecualikan dari laporan yang diekspor.',
        'settings.report.autoExport':     'Auto-Ekspor Setelah Scan',
        'settings.report.autoExportHint': 'Otomatis mengunduh laporan ketika scan selesai.',
    }
};

let currentLang = 'en';

// ─── Apply Language ───────────────────────────────────────────────
function applyLanguage(lang) {
    currentLang = lang;
    const t = TRANSLATIONS[lang] || TRANSLATIONS['en'];
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (t[key]) el.textContent = t[key];
    });
    // Update header dynamic text
    const hdrTxt = document.getElementById('hdr-status-text');
    if (hdrTxt) hdrTxt.textContent = t['header.ready'];
    // Update lang buttons
    document.querySelectorAll('.lang-btn').forEach(b => b.classList.remove('active'));
    const activeLangBtn = document.getElementById(`lang-${lang}`);
    if (activeLangBtn) activeLangBtn.classList.add('active');
    // Store on html lang attr
    document.documentElement.lang = lang === 'id' ? 'id' : 'en';
}

function setLanguage(lang) {
    applyLanguage(lang);
    saveSetting('language', lang);
}

// ─── Accent Color ─────────────────────────────────────────────────
function setAccent(accent) {
    document.body.dataset.accent = accent === 'amber' ? '' : accent;
    // Update swatch active state
    document.querySelectorAll('.accent-swatch').forEach(s => {
        s.classList.toggle('active', s.dataset.accent === accent);
    });
    // Update chart colors
    const accentColors = {
        amber:   '#f59e0b', cyan:    '#06b6d4',
        emerald: '#10b981', purple:  '#a855f7', rose: '#f43f5e'
    };
    const color = accentColors[accent] || '#f59e0b';
    if (categoryChart) {
        categoryChart.data.datasets[0].backgroundColor = color + 'b3';
        categoryChart.data.datasets[0].borderColor = color;
        categoryChart.update();
    }
    saveSetting('accent', accent);
}

// ─── Compact Mode ─────────────────────────────────────────────────
function applyCompactMode(on) {
    document.body.classList.toggle('compact-mode', on);
}

// ─── Save / Load Settings ─────────────────────────────────────────
function getSettings() {
    try {
        return JSON.parse(localStorage.getItem('inspire_settings')) || { ...DEFAULT_SETTINGS };
    } catch { return { ...DEFAULT_SETTINGS }; }
}

function saveSetting(key, value) {
    const s = getSettings();
    s[key] = value;
    localStorage.setItem('inspire_settings', JSON.stringify(s));
    showSavedIndicator();
}

function saveModule(mod, value) {
    const s = getSettings();
    if (!s.modules) s.modules = { ...DEFAULT_SETTINGS.modules };
    s.modules[mod] = value;
    localStorage.setItem('inspire_settings', JSON.stringify(s));
    showSavedIndicator();
}

function showSavedIndicator() {
    const el = document.getElementById('settings-saved-indicator');
    if (!el) return;
    el.classList.add('show');
    setTimeout(() => el.classList.remove('show'), 2200);
}

function resetSettings() {
    localStorage.removeItem('inspire_settings');
    initSettings();
    showSavedIndicator();
    addLog(`[${ts()}] Settings reset to defaults.`, 'log-info');
}

// ─── Init Settings ────────────────────────────────────────────────
function initSettings() {
    const s = getSettings();

    // Language
    applyLanguage(s.language || 'en');

    // Accent color
    const accent = s.accent || 'amber';
    document.body.dataset.accent = accent === 'amber' ? '' : accent;
    document.querySelectorAll('.accent-swatch').forEach(sw => {
        sw.classList.toggle('active', sw.dataset.accent === accent);
    });

    // Terminal lines
    const tlEl = document.getElementById('setting-terminal-lines');
    if (tlEl) tlEl.value = s.terminalLines || 100;

    // Compact mode
    const cmEl = document.getElementById('setting-compact');
    if (cmEl) { cmEl.checked = !!s.compactMode; applyCompactMode(!!s.compactMode); }

    // Report settings
    const rfEl = document.getElementById('setting-report-format');
    if (rfEl) rfEl.value = s.reportFormat || 'both';

    const rpEl = document.getElementById('setting-report-prefix');
    if (rpEl) rpEl.value = s.reportPrefix || '';

    const iiEl = document.getElementById('setting-include-info');
    if (iiEl) iiEl.checked = s.includeInfo !== false;

    const aeEl = document.getElementById('setting-auto-export');
    if (aeEl) aeEl.checked = !!s.autoExport;

    // Module toggles
    const mods = s.modules || DEFAULT_SETTINGS.modules;
    Object.entries(mods).forEach(([mod, val]) => {
        const el = document.getElementById(`mod-${mod}`);
        if (el) el.checked = val;
    });
}
