document.addEventListener('DOMContentLoaded', () => {
    // 1. Initialize Animated Particle Engine
    initBlackSandGrainsBackground();

    // Check localStorage for saved scan results & scan history list
    const savedScan = localStorage.getItem('vanguardScanData');
    if (savedScan) {
        try {
            currentScanData = JSON.parse(savedScan);
            renderDashboard(currentScanData);
            startTopologyAnimation(currentScanData);
            renderOWASPRadarChart(currentScanData);
            if (exportBtnGroup) exportBtnGroup.style.display = 'flex';
        } catch(e) {
            initOWASPRadarChart();
        }
    } else {
        initOWASPRadarChart();
    }

    renderScanHistoryTable();
    initProfilePage();

    function playSound(type) {
        // Audio effects disabled
    }

    // DOM Elements
    const scanBtn = document.getElementById('scanBtn');
    const targetInput = document.getElementById('targetInput');
    const progressContainer = document.getElementById('progressContainer');
    const progressBarFill = document.getElementById('progressBarFill');
    const progressText = document.getElementById('progressText');
    const exportBtnGroup = document.getElementById('exportBtnGroup');
    const reportBtn = document.getElementById('reportBtn');
    const exportJsonBtn = document.getElementById('exportJsonBtn');
    const exportCsvBtn = document.getElementById('exportCsvBtn');
    const cyberTerminal = document.getElementById('cyberTerminal');
    const clearTerminalBtn = document.getElementById('clearTerminalBtn');
    const cveQueryInput = document.getElementById('cveQueryInput');
    const cveSearchResults = document.getElementById('cveSearchResults');

    const nodeModal = document.getElementById('nodeModal');
    const nodeModalTitle = document.getElementById('nodeModalTitle');
    const nodeModalBody = document.getElementById('nodeModalBody');
    const closeNodeModal = document.getElementById('closeNodeModal');

    if (closeNodeModal) {
        closeNodeModal.addEventListener('click', () => {
            if (nodeModal) nodeModal.classList.remove('show');
        });
    }

    let currentScanData = null;
    let topologyAnimId = null;
    let selectedScanMode = 'quick';
    let currentFilterSeverity = 'all';

    // Toast Notification helper
    function showToast(msg, isSuccess = true) {
        const toast = document.getElementById('toastNotification');
        const icon = document.getElementById('toastIcon');
        const text = document.getElementById('toastMsg');
        if (!toast) return;
        icon.innerText = isSuccess ? '✓' : '!';
        text.innerText = msg;
        toast.classList.add('show');
        setTimeout(() => toast.classList.remove('show'), 3000);
    }

    // Live Clock HUD
    function initClockHUD() {
        const clockEl = document.getElementById('hudClock');
        if (!clockEl) return;
        function updateClock() {
            const now = new Date();
            clockEl.innerText = now.toUTCString().split(' ')[4] + ' UTC';
        }
        updateClock();
        setInterval(updateClock, 1000);
    }

    // Scan Profile Toggle
    document.querySelectorAll('.profile-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            playSound('click');
            document.querySelectorAll('.profile-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            selectedScanMode = btn.getAttribute('data-mode');
            logTerminal(`Scan profile switched to: ${selectedScanMode.toUpperCase()}`, 'CONFIG');
        });
    });

    // Preset target chip listener
    document.querySelectorAll('.target-chip').forEach(chip => {
        chip.addEventListener('click', () => {
            playSound('click');
            const targetInp = document.getElementById('targetInput');
            if (targetInp) {
                targetInp.value = chip.getAttribute('data-target');
                targetInp.focus();
            }
        });
    });

    // Vulnerability Filter Pills
    document.querySelectorAll('.filter-pill').forEach(pill => {
        pill.addEventListener('click', () => {
            playSound('click');
            document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
            pill.classList.add('active');
            currentFilterSeverity = pill.getAttribute('data-filter');
            if (currentScanData) renderVulnerabilities(currentScanData);
        });
    });

    if (clearTerminalBtn) {
        clearTerminalBtn.addEventListener('click', () => {
            playSound('click');
            if (cyberTerminal) cyberTerminal.innerHTML = '';
        });
    }

    // CVE Live Search
    if (cveQueryInput) {
        cveQueryInput.addEventListener('input', async (e) => {
            const query = e.target.value.trim();
            try {
                const res = await fetch(`/api/cve/search`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ query: query })
                });
                const data = await res.json();
                if (data.success) {
                    renderCveSearchResults(data.cve_list);
                }
            } catch (err) {}
        });
    }

    function renderCveSearchResults(cveList) {
        if (!cveSearchResults) return;
        cveSearchResults.innerHTML = '';
        if (!cveList || cveList.length === 0) {
            cveSearchResults.innerHTML = '<div style="font-size:12.5px; color:var(--text-muted); padding:6px;">No CVE entries found matching query.</div>';
            return;
        }
        cveList.forEach(item => {
            cveSearchResults.innerHTML += `
                <div style="background:rgba(255,255,255,0.8); border:1px solid var(--border-subtle); padding:10px; border-radius:6px; margin-bottom:8px;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span class="mono" style="font-weight:700; color:var(--sev-critical); font-size:12px;">${item.cve}</span>
                        <span style="font-size:11px; font-weight:700; color:var(--sev-high);">CVSS ${item.cvss}</span>
                    </div>
                    <div style="font-size:12.5px; font-weight:600; color:#09090b; margin:4px 0;">${item.title}</div>
                    <div style="font-size:11.5px; color:var(--text-secondary); line-height:1.4;">${item.summary}</div>
                </div>
            `;
        });
    }

    document.addEventListener('click', (e) => {
        const btn = e.target.closest('#scanBtn');
        if (btn) {
            e.preventDefault();
            startScan();
        }
    });

    const activeTargetInput = document.getElementById('targetInput');
    if (activeTargetInput) {
        activeTargetInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') startScan();
        });
    }

    if (reportBtn) reportBtn.addEventListener('click', downloadReport);
    if (exportJsonBtn) exportJsonBtn.addEventListener('click', exportJsonData);
    if (exportCsvBtn) exportCsvBtn.addEventListener('click', exportCsvData);

    // Copy command buttons listener
    document.addEventListener('click', (e) => {
        if (e.target.classList.contains('copy-cmd-btn')) {
            playSound('click');
            const targetId = e.target.getAttribute('data-target');
            const codeEl = document.getElementById(targetId);
            if (codeEl) {
                navigator.clipboard.writeText(codeEl.innerText);
                showToast('CLI Command copied to clipboard!');
            }
        }
    });

    // Server Hardening Tab Navigation
    const tabNginx = document.getElementById('tabNginx');
    const tabApache = document.getElementById('tabApache');
    const tabFirewall = document.getElementById('tabFirewall');
    const codeDisplay = document.getElementById('codeDisplay');

    if (tabNginx && tabApache && tabFirewall) {
        tabNginx.addEventListener('click', () => switchTab(tabNginx, 'nginx'));
        tabApache.addEventListener('click', () => switchTab(tabApache, 'apache'));
        tabFirewall.addEventListener('click', () => switchTab(tabFirewall, 'firewall'));
    }

    function switchTab(activeBtn, key) {
        playSound('click');
        [tabNginx, tabApache, tabFirewall].forEach(b => b.classList.remove('active'));
        activeBtn.classList.add('active');
        if (currentScanData && currentScanData.remediation_scripts) {
            codeDisplay.innerText = currentScanData.remediation_scripts[key] || '# No remediation rules generated.';
        }
    }

    // Terminal Logging Ticker
    function logTerminal(msg, type = 'INFO') {
        const terminal = document.getElementById('cyberTerminal');
        if (!terminal) return;
        const time = new Date().toLocaleTimeString();
        const line = document.createElement('div');
        line.className = 'terminal-line';
        line.innerHTML = `<span class="terminal-time">[${time}]</span> <span class="terminal-prefix">${type}:</span> ${msg}`;
        terminal.appendChild(line);
        terminal.scrollTop = terminal.scrollHeight;
    }

    // Animated Counter Function
    function animateCounter(elementId, targetValue, duration = 1200, suffix = '') {
        const el = document.getElementById(elementId);
        if (!el) return;
        
        let start = 0;
        const isNumeric = !isNaN(parseFloat(targetValue));
        if (!isNumeric) {
            el.innerText = targetValue;
            return;
        }

        const end = parseFloat(targetValue);
        const startTime = performance.now();

        function update(currentTime) {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            const current = Math.floor(start + (end - start) * (1 - Math.pow(1 - progress, 3)));
            
            if (elementId === 'statScore') {
                el.innerText = `${current} / 100`;
            } else {
                el.innerText = `${current}${suffix}`;
            }

            if (progress < 1) {
                requestAnimationFrame(update);
            } else {
                if (elementId === 'statScore') {
                    el.innerText = `${end} / 100`;
                } else {
                    el.innerText = `${end}${suffix}`;
                }
            }
        }
        requestAnimationFrame(update);
    }

    // Main Scan Controller
    window.startScan = async function() {
        const input = document.getElementById('targetInput');
        const btn = document.getElementById('scanBtn');
        const progCard = document.getElementById('progressContainer');

        if (!input) return;
        const target = input.value.trim();
        if (!target) {
            alert('Please enter a valid target host or domain.');
            return;
        }

        playSound('scan');
        if (btn) {
            btn.disabled = true;
            const span = btn.querySelector('span');
            if (span) span.innerText = 'Scanning Target...';
        }
        if (progCard) progCard.style.display = 'block';

        logTerminal(`Initiating ${selectedScanMode === 'full' ? 'ENTERPRISE FULL AUDIT' : 'SURFACE QUICK SCAN'} for target: ${target}`, 'TARGET');
        updateProgress(15, 'Resolving target DNS records & host IP...');

        const isFull = selectedScanMode === 'full';
        try {
            setTimeout(() => {
                logTerminal(isFull ? `Auditing 35+ enterprise ports (DBs, SSH, RDP, Redis, Mongo)...` : `Scanning Top 10 perimeter ports...`, 'SOCKET');
                updateProgress(40, isFull ? 'Scanning 35+ enterprise TCP ports & banners...' : 'Scanning Top 10 TCP ports & banner grabbing...');
            }, 500);

            setTimeout(() => {
                logTerminal(isFull ? `Deep DNS discovery: Scanning 38 subdomain prefixes & certificates...` : `Enumerating top 12 subdomains and tech stack...`, 'RECON');
                updateProgress(65, isFull ? 'Enumerating 38 subdomain prefixes...' : 'Enumerating public subdomains...');
            }, 1200);

            setTimeout(() => {
                logTerminal(isFull ? `Auditing 16 sensitive files, Cookie Security flags (HttpOnly/Secure) & CORS policies...` : `Auditing OWASP security headers & common configs...`, 'OWASP');
                updateProgress(85, isFull ? 'Deep checking 16 sensitive paths & session cookies...' : 'Auditing HTTP security headers...');
            }, 2000);

            const authFetch = typeof VanguardAuth !== 'undefined' ? VanguardAuth.fetchWithAuth : fetch;
            const response = await authFetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: target, scan_mode: selectedScanMode })
            });

            const data = await response.json();

            if (!data.success) {
                alert(`Scan Error: ${data.error}`);
                logTerminal(`Assessment failed: ${data.error}`, 'ERROR');
                resetScanBtn();
                return;
            }

            updateProgress(100, 'Security assessment completed!');
            logTerminal(`Audit completed. Posture Score: ${data.score}/100 Grade: ${data.grade}`, 'SUCCESS');
            currentScanData = data;
            try {
                localStorage.setItem('vanguardScanData', JSON.stringify(data));
                saveScanToHistory(data);
            } catch(e) {}
            playSound('complete');
            showToast(`Security assessment for ${data.hostname} completed!`);

            setTimeout(() => {
                if (progCard) progCard.style.display = 'none';
                renderDashboard(data);
                startTopologyAnimation(data);
                renderOWASPRadarChart(data);
                resetScanBtn();
                if (exportBtnGroup) exportBtnGroup.style.display = 'flex';
            }, 500);

        } catch (err) {
            alert(`Connection Error: ${err.message}`);
            logTerminal(`Network transport failure: ${err.message}`, 'FATAL');
            resetScanBtn();
        }
    }

    function updateProgress(percent, text) {
        const fill = document.getElementById('progressBarFill');
        const txt = document.getElementById('progressText');
        if (fill) fill.style.width = `${percent}%`;
        if (txt) txt.innerText = text;
    }

    function resetScanBtn() {
        const btn = document.getElementById('scanBtn');
        if (!btn) return;
        btn.disabled = false;
        const span = btn.querySelector('span');
        if (span) span.innerText = 'Launch Target Attack Assessment';
    }

    // Render OWASP Radar Canvas Chart
    function renderOWASPRadarChart(data) {
        const canvas = document.getElementById('owaspRadarCanvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const width = canvas.width;
        const height = canvas.height;
        const centerX = width / 2;
        const centerY = height / 2;
        const radius = 75;

        ctx.clearRect(0, 0, width, height);

        const categories = ["HSTS", "CSP", "X-Frame", "X-MIME", "Referrer", "Permissions"];
        const found = data ? (data.headers ? data.headers.headers_found || {} : {}) : {};
        const scores = [
            found["Strict-Transport-Security"] ? 1 : 0.2,
            found["Content-Security-Policy"] ? 1 : 0.2,
            found["X-Frame-Options"] ? 1 : 0.2,
            found["X-Content-Type-Options"] ? 1 : 0.2,
            found["Referrer-Policy"] ? 1 : 0.2,
            found["Permissions-Policy"] ? 1 : 0.2
        ];

        const numSides = categories.length;
        const angleStep = (Math.PI * 2) / numSides;

        // Draw Web Grids
        for (let level = 1; level <= 3; level++) {
            const r = (radius / 3) * level;
            ctx.beginPath();
            for (let i = 0; i < numSides; i++) {
                const angle = i * angleStep - Math.PI / 2;
                const x = centerX + r * Math.cos(angle);
                const y = centerY + r * Math.sin(angle);
                if (i === 0) ctx.moveTo(x, y);
                else ctx.lineTo(x, y);
            }
            ctx.closePath();
            ctx.strokeStyle = 'rgba(0, 0, 0, 0.12)';
            ctx.lineWidth = 1;
            ctx.stroke();
        }

        // Draw Axis Lines & Labels
        ctx.font = '600 10px "JetBrains Mono", monospace';
        ctx.fillStyle = '#52525b';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';

        for (let i = 0; i < numSides; i++) {
            const angle = i * angleStep - Math.PI / 2;
            const x = centerX + radius * Math.cos(angle);
            const y = centerY + radius * Math.sin(angle);

            ctx.beginPath();
            ctx.moveTo(centerX, centerY);
            ctx.lineTo(x, y);
            ctx.strokeStyle = 'rgba(0, 0, 0, 0.08)';
            ctx.stroke();

            const lx = centerX + (radius + 18) * Math.cos(angle);
            const ly = centerY + (radius + 14) * Math.sin(angle);
            ctx.fillText(categories[i], lx, ly);
        }

        // Draw Score Polygon
        ctx.beginPath();
        for (let i = 0; i < numSides; i++) {
            const angle = i * angleStep - Math.PI / 2;
            const r = radius * scores[i];
            const x = centerX + r * Math.cos(angle);
            const y = centerY + r * Math.sin(angle);
            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        }
        ctx.closePath();
        ctx.fillStyle = 'rgba(24, 24, 27, 0.18)';
        ctx.fill();
        ctx.strokeStyle = '#18181b';
        ctx.lineWidth = 2;
        ctx.stroke();
    }

    function initOWASPRadarChart() {
        renderOWASPRadarChart({
            headers: {
                headers_found: {
                    "Strict-Transport-Security": "max-age=31536000",
                    "X-Frame-Options": "SAMEORIGIN",
                    "Content-Security-Policy": "default-src 'self'"
                }
            }
        });
    }

    // Render Dashboard Results safely across any sub-page
    function renderDashboard(data) {
        if (!data) return;
        
        const gradeCircle = document.getElementById('gradeCircle');
        const scoreNum = document.getElementById('scoreNum');
        const gaugeFill = document.getElementById('gaugeFill');

        if (gradeCircle) gradeCircle.innerText = data.grade;
        if (scoreNum) scoreNum.innerText = `${data.score}/100`;

        const offset = 440 - (440 * data.score / 100);
        if (gaugeFill) gaugeFill.style.strokeDashoffset = offset;

        animateCounter('statScore', data.score);
        animateCounter('statPorts', data.open_ports ? data.open_ports.length : 0);
        animateCounter('statVulns', data.vulnerabilities ? data.vulnerabilities.length : 0);
        const sslStat = document.getElementById('statSsl');
        if (sslStat) sslStat.innerText = (data.ssl && data.ssl.version) ? data.ssl.version : 'TLSv1.3';

        const metaHost = document.getElementById('metaHost');
        const metaIp = document.getElementById('metaIp');
        const metaMode = document.getElementById('metaMode');
        const metaTime = document.getElementById('metaTime');
        if (metaHost) metaHost.innerText = data.hostname;
        if (metaIp) metaIp.innerText = data.ip;
        if (metaMode) {
            metaMode.innerText = data.scan_profile_label || (data.scan_mode === 'full' ? 'Full Audit' : 'Quick Scan');
            metaMode.style.color = data.scan_mode === 'full' ? 'var(--sev-high)' : 'var(--accent-blue)';
        }
        if (metaTime) metaTime.innerText = data.timestamp;

        // CLI Commands
        if (data.cli_commands) {
            const cmdNmap = document.getElementById('cmdNmap');
            const cmdCurl = document.getElementById('cmdCurl');
            if (cmdNmap) cmdNmap.innerText = data.cli_commands.nmap || `nmap -sV -sC ${data.hostname}`;
            if (cmdCurl) cmdCurl.innerText = data.cli_commands.curl || `curl -I https://${data.hostname}`;
        }

        // Tech Stack
        const techContainer = document.getElementById('techStackBadges');
        if (techContainer) {
            techContainer.innerHTML = '';
            (data.tech_stack || ['Standard Web Server']).forEach(tech => {
                techContainer.innerHTML += `<span class="subdomain-tag">${tech}</span>`;
            });
        }

        // Subdomains
        const subContainer = document.getElementById('subdomainsContainer');
        if (subContainer) {
            subContainer.innerHTML = '';
            if (!data.subdomains || data.subdomains.length === 0) {
                subContainer.innerHTML = '<div style="color:var(--text-muted); font-size:13.5px;">No public subdomains enumerated during DNS sweep.</div>';
            } else {
                data.subdomains.forEach(sub => {
                    subContainer.innerHTML += `<div class="subdomain-tag">${sub.subdomain} (${sub.ip})</div>`;
                });
            }
        }

        // Open Ports Grid
        const portsGrid = document.getElementById('portsGrid');
        if (portsGrid) {
            portsGrid.innerHTML = '';
            if (!data.open_ports || data.open_ports.length === 0) {
                portsGrid.innerHTML = '<div style="color:var(--text-muted); font-size:14px;">No open ports identified on standard scanned ports.</div>';
            } else {
                data.open_ports.forEach(p => {
                    portsGrid.innerHTML += `
                        <div class="port-card">
                            <div class="port-header">
                                <span class="port-num">:${p.port}</span>
                                <span class="port-status-badge">${p.state}</span>
                            </div>
                            <div class="port-service">${p.service}</div>
                            <div class="mono" style="font-size:11px; color:var(--text-muted);">${p.banner}</div>
                        </div>
                    `;
                });
            }
        }

        renderVulnerabilities(data);

        // SSL Specs
        const sslVersion = document.getElementById('sslVersion');
        const sslCipher = document.getElementById('sslCipher');
        const sslIssuer = document.getElementById('sslIssuer');
        if (sslVersion) sslVersion.innerText = (data.ssl && data.ssl.version) ? data.ssl.version : 'N/A';
        if (sslCipher) sslCipher.innerText = (data.ssl && data.ssl.cipher) ? data.ssl.cipher : 'N/A';
        if (sslIssuer) sslIssuer.innerText = (data.ssl && data.ssl.issuer_o) ? data.ssl.issuer_o : 'N/A';

        // Code Hardening Display
        const codeDisplay = document.getElementById('codeDisplay');
        if (codeDisplay && data.remediation_scripts) {
            codeDisplay.innerText = data.remediation_scripts.nginx || '# Nginx configuration rules generated.';
        }
    }

    function renderVulnerabilities(data) {
        const vulnContainer = document.getElementById('vulnContainer');
        if (!vulnContainer || !data) return;
        vulnContainer.innerHTML = '';
        
        let vulns = data.vulnerabilities || [];
        if (currentFilterSeverity !== 'all') {
            vulns = vulns.filter(v => v.severity.toLowerCase() === currentFilterSeverity);
        }

        if (vulns.length === 0) {
            vulnContainer.innerHTML = `
                <div style="color:var(--sev-safe); padding:16px; background:var(--sev-safe-bg); border:1px solid rgba(22,163,74,0.3); border-radius:var(--radius-md); font-size:14px; font-weight:600;">
                    No security vulnerabilities matching the selected filter severity level.
                </div>
            `;
        } else {
            vulns.forEach((v, idx) => {
                const verifyHtml = v.verification_steps ? `
                    <div style="font-size:12.5px; color:var(--text-secondary); background:rgba(0,0,0,0.03); border:1px solid var(--border-subtle); padding:12px 14px; border-radius:var(--radius-sm); margin-top:12px;">
                        <strong>Defensive Verification Method:</strong>
                        <div class="mono" style="font-size:11.5px; margin-top:6px; color:var(--text-primary); background:rgba(0,0,0,0.04); padding:8px 12px; border-radius:6px;">${v.verification_steps}</div>
                    </div>
                ` : '';

                const cardId = `vulnDetails_${idx}`;

                vulnContainer.innerHTML += `
                    <div class="vuln-card ${v.severity.toLowerCase()}" style="cursor:pointer;" onclick="toggleVulnDetails('${cardId}')">
                        <div class="vuln-header">
                            <span class="vuln-title">${v.title}</span>
                            <div style="display:flex; align-items:center; gap:10px;">
                                <span class="badge-sev badge-${v.severity}">${v.severity}</span>
                                <span style="font-size:12px; color:var(--text-muted); font-weight:700;" id="toggleIcon_${cardId}">Expand</span>
                            </div>
                        </div>
                        <div class="vuln-desc">${v.impact}</div>

                        <!-- Expanded Detailed Info Drawer -->
                        <div id="${cardId}" style="display:none; margin-top:14px; padding-top:14px; border-top:1px solid var(--border-subtle);">
                            <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:12px; font-size:12.5px;">
                                <div style="background:rgba(0,0,0,0.03); padding:10px; border-radius:6px; border:1px solid var(--border-subtle);">
                                    <strong style="color:var(--text-primary);">Vulnerability Category:</strong>
                                    <div style="color:var(--text-secondary); font-weight:600; margin-top:2px;">${v.category || 'OWASP Security Finding'}</div>
                                </div>
                                <div style="background:rgba(0,0,0,0.03); padding:10px; border-radius:6px; border:1px solid var(--border-subtle);">
                                    <strong style="color:var(--text-primary);">Audit Severity Rating:</strong>
                                    <div style="color:var(--text-secondary); font-weight:600; margin-top:2px;">${v.severity} Severity</div>
                                </div>
                            </div>

                            ${verifyHtml}

                            <div class="vuln-remediation" style="margin-top:12px;">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0; margin-top:2px;">
                                    <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>
                                </svg>
                                <div><strong>Remediation Action:</strong> ${v.remediation}</div>
                            </div>
                        </div>
                    </div>
                `;
            });
        }
    }

    // Toggle Vulnerability Card Detailed Drawer
    window.toggleVulnDetails = function(cardId) {
        playSound('click');
        const el = document.getElementById(cardId);
        const icon = document.getElementById(`toggleIcon_${cardId}`);
        if (!el) return;
        if (el.style.display === 'none' || !el.style.display) {
            el.style.display = 'block';
            if (icon) icon.innerText = 'Collapse';
        } else {
            el.style.display = 'none';
            if (icon) icon.innerText = 'Expand';
        }
    };

    // 2. Interactive Topology Graph Canvas Animation
    let currentTopologyNodes = [];

    function startTopologyAnimation(data) {
        const canvas = document.getElementById('topologyCanvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');

        if (topologyAnimId) cancelAnimationFrame(topologyAnimId);

        const width = canvas.width;
        const height = canvas.height;

        const rootNode = { x: width / 2, y: height / 2, label: data.hostname || 'Target Host', type: 'ROOT', data: data };
        const nodes = [rootNode];
        const links = [];

        const ipNode = { x: width / 2 - 220, y: height / 2, label: data.ip || '0.0.0.0', type: 'IP', data: { ip: data.ip } };
        nodes.push(ipNode);
        links.push({ from: rootNode, to: ipNode });

        if (data.open_ports && data.open_ports.length > 0) {
            let angle = -Math.PI / 3;
            const angleStep = (2 * Math.PI / 3) / Math.max(1, data.open_ports.length - 1);
            data.open_ports.forEach((p, idx) => {
                const radius = 210;
                const pAngle = data.open_ports.length === 1 ? 0 : angle + idx * angleStep;
                const x = width / 2 + radius * Math.cos(pAngle);
                const y = height / 2 + 80 * Math.sin(pAngle);
                const pNode = { x: x, y: y, label: `:${p.port} (${p.service})`, type: 'PORT', data: p };
                nodes.push(pNode);
                links.push({ from: rootNode, to: pNode });
            });
        }

        if (data.subdomains && data.subdomains.length > 0) {
            const subNode = { x: width / 2, y: height / 2 + 90, label: `${data.subdomains.length} Subdomains`, type: 'SUB', data: { count: data.subdomains.length } };
            nodes.push(subNode);
            links.push({ from: rootNode, to: subNode });
        }

        currentTopologyNodes = nodes;

        const packets = links.map(link => ({
            link: link,
            progress: Math.random(),
            speed: 0.006 + Math.random() * 0.004
        }));

        function drawFrame() {
            ctx.clearRect(0, 0, width, height);

            links.forEach(link => {
                ctx.beginPath();
                ctx.strokeStyle = 'rgba(0, 0, 0, 0.15)';
                ctx.lineWidth = 1.5;
                ctx.setLineDash([4, 4]);
                ctx.moveTo(link.from.x, link.from.y);
                ctx.lineTo(link.to.x, link.to.y);
                ctx.stroke();
                ctx.setLineDash([]);
            });

            packets.forEach(pkt => {
                pkt.progress += pkt.speed;
                if (pkt.progress > 1) pkt.progress = 0;

                const px = pkt.link.from.x + (pkt.link.to.x - pkt.link.from.x) * pkt.progress;
                const py = pkt.link.from.y + (pkt.link.to.y - pkt.link.from.y) * pkt.progress;

                ctx.beginPath();
                ctx.arc(px, py, 4, 0, Math.PI * 2);
                ctx.fillStyle = '#18181b';
                ctx.shadowColor = '#000000';
                ctx.shadowBlur = 6;
                ctx.fill();
                ctx.shadowBlur = 0;
            });

            const time = Date.now() * 0.003;
            nodes.forEach(node => {
                const isRoot = node.type === 'ROOT';
                const baseRadius = isRoot ? 18 : 12;
                const pulseRadius = baseRadius + Math.sin(time + node.x) * 3;

                ctx.beginPath();
                ctx.arc(node.x, node.y, pulseRadius + 6, 0, Math.PI * 2);
                ctx.fillStyle = isRoot ? 'rgba(24, 24, 27, 0.1)' : 'rgba(80, 80, 90, 0.08)';
                ctx.fill();

                ctx.beginPath();
                ctx.arc(node.x, node.y, baseRadius, 0, Math.PI * 2);
                ctx.fillStyle = isRoot ? '#18181b' : (node.type === 'PORT' ? '#3f3f46' : '#16a34a');
                ctx.shadowColor = ctx.fillStyle;
                ctx.shadowBlur = isRoot ? 12 : 6;
                ctx.fill();
                ctx.shadowBlur = 0;

                ctx.font = isRoot ? '700 12px "Plus Jakarta Sans", sans-serif' : '500 11px "JetBrains Mono", monospace';
                ctx.fillStyle = '#09090b';
                ctx.textAlign = 'center';
                ctx.fillText(node.label, node.x, node.y + (isRoot ? 34 : 26));
            });

            topologyAnimId = requestAnimationFrame(drawFrame);
        }

        drawFrame();
    }

    // Topology Canvas Click Listener for Node Popover
    const topoCanvas = document.getElementById('topologyCanvas');
    if (topoCanvas) {
        topoCanvas.addEventListener('click', (e) => {
            const rect = topoCanvas.getBoundingClientRect();
            const mouseX = (e.clientX - rect.left) * (topoCanvas.width / rect.width);
            const mouseY = (e.clientY - rect.top) * (topoCanvas.height / rect.height);

            currentTopologyNodes.forEach(node => {
                const dist = Math.hypot(node.x - mouseX, node.y - mouseY);
                if (dist < 22) {
                    playSound('click');
                    if (nodeModal && nodeModalTitle && nodeModalBody) {
                        nodeModalTitle.innerText = `Node: ${node.label}`;
                        if (node.type === 'PORT') {
                            nodeModalBody.innerHTML = `
                                <div><strong>Port Number:</strong> :${node.data.port}</div>
                                <div><strong>Service:</strong> ${node.data.service}</div>
                                <div><strong>State:</strong> <span style="color:#16a34a;">${node.data.state}</span></div>
                                <div style="margin-top:6px; font-family:monospace; font-size:11px; color:#52525b;">${node.data.banner}</div>
                            `;
                        } else if (node.type === 'IP') {
                            nodeModalBody.innerHTML = `
                                <div><strong>IP Address:</strong> ${node.data.ip}</div>
                                <div><strong>Host Status:</strong> Active & Resolved</div>
                            `;
                        } else {
                            nodeModalBody.innerHTML = `
                                <div><strong>Target Domain:</strong> ${currentScanData ? currentScanData.hostname : 'Host'}</div>
                                <div><strong>Security Posture Score:</strong> ${currentScanData ? currentScanData.score : 100}/100</div>
                                <div><strong>Grade:</strong> ${currentScanData ? currentScanData.grade : 'A+'}</div>
                            `;
                        }
                        nodeModal.classList.add('show');
                    }
                }
            });
        });
    }

    // Exporters
    async function downloadReport() {
        if (!currentScanData) {
            alert('Please run a security scan first before exporting report.');
            return;
        }
        playSound('click');
        try {
            const response = await fetch('/api/report', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(currentScanData)
            });
            const htmlContent = await response.text();

            const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `Vanguard_Executive_Report_${currentScanData.hostname}.html`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);

            showToast(`Executive HTML Report downloaded for ${currentScanData.hostname}!`);

            try {
                const reportWindow = window.open('', '_blank');
                if (reportWindow) {
                    reportWindow.document.write(htmlContent);
                    reportWindow.document.close();
                }
            } catch (err) {}
        } catch (e) {
            alert('Failed to generate executive audit report.');
        }
    }

    function exportJsonData() {
        if (!currentScanData) return;
        playSound('click');
        const str = JSON.stringify(currentScanData, null, 2);
        const blob = new Blob([str], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `Vanguard_Scan_${currentScanData.hostname}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        showToast('JSON audit data downloaded!');
    }

    function exportCsvData() {
        if (!currentScanData) return;
        playSound('click');
        let csv = 'Category,Title,Severity,Impact,Remediation\n';
        (currentScanData.vulnerabilities || []).forEach(v => {
            csv += `"${v.category}","${v.title}","${v.severity}","${v.impact.replace(/"/g, '""')}","${v.remediation.replace(/"/g, '""')}"\n`;
        });
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `Vanguard_Audit_${currentScanData.hostname}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        showToast('CSV vulnerability table downloaded!');
    }

    // 4. SCAN HISTORY & REPORT INSPECTION ENGINE
    function saveScanToHistory(scanData) {
        let history = [];
        try {
            const raw = localStorage.getItem('vanguardScanHistory');
            if (raw) history = JSON.parse(raw);
        } catch(e) {}

        // Remove duplicate entry for same target if present to keep history clean
        history = history.filter(item => item.hostname !== scanData.hostname);
        history.unshift(scanData);
        // Keep top 20 recent scans
        if (history.length > 20) history = history.slice(0, 20);

        try {
            localStorage.setItem('vanguardScanHistory', JSON.stringify(history));
        } catch(e) {}

        renderScanHistoryTable();
    }

    function renderScanHistoryTable() {
        const historyBody = document.getElementById('historyTableBody');
        const historyCount = document.getElementById('historyCountTotal');
        if (!historyBody) return;

        let history = [];
        try {
            const raw = localStorage.getItem('vanguardScanHistory');
            if (raw) history = JSON.parse(raw);
        } catch(e) {}

        if (historyCount) historyCount.innerText = history.length;
        historyBody.innerHTML = '';

        if (history.length === 0) {
            historyBody.innerHTML = `
                <tr>
                    <td colspan="6" style="text-align:center; padding:32px; color:var(--text-muted);">
                        No target scans performed yet. Go to <a href="attack.html" style="color:var(--text-primary); font-weight:bold;">Attack Console</a> to launch your first assessment.
                    </td>
                </tr>
            `;
            return;
        }

        history.forEach((scan, index) => {
            const tr = document.createElement('tr');
            tr.className = 'history-row';
            const gradeColor = scan.grade.startsWith('A') ? '#16a34a' : (scan.grade.startsWith('B') ? '#ca8a04' : '#dc2626');
            
            tr.innerHTML = `
                <td class="mono" style="font-weight:700; color:var(--text-primary);">${scan.hostname}</td>
                <td class="mono" style="color:var(--text-secondary);">${scan.ip}</td>
                <td><span style="background:${gradeColor}18; color:${gradeColor}; border:1px solid ${gradeColor}40; padding:3px 10px; border-radius:12px; font-weight:800; font-size:12px;">${scan.grade} (${scan.score}/100)</span></td>
                <td><span style="font-weight:600; color:var(--text-secondary);">${scan.vulnerabilities ? scan.vulnerabilities.length : 0} Findings</span></td>
                <td style="font-size:12.5px; color:var(--text-muted);">${scan.timestamp}</td>
                <td>
                    <button class="btn-secondary view-report-btn" data-index="${index}" style="font-size:11.5px; padding:4px 10px;">
                        View Report
                    </button>
                </td>
            `;
            historyBody.appendChild(tr);
        });

        document.querySelectorAll('.view-report-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const idx = parseInt(btn.getAttribute('data-index'));
                if (history[idx]) viewReportFromHistory(history[idx]);
            });
        });
    }

    async function viewReportFromHistory(scanData) {
        playSound('click');
        try {
            showToast(`Generating report for ${scanData.hostname}...`);
            const authFetch = typeof VanguardAuth !== 'undefined' ? VanguardAuth.fetchWithAuth : fetch;
            const response = await authFetch('/api/report', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(scanData)
            });
            const htmlReport = await response.text();

            let reportModal = document.getElementById('reportModalOverlay');
            if (!reportModal) {
                reportModal = document.createElement('div');
                reportModal.id = 'reportModalOverlay';
                reportModal.className = 'report-modal-content';
                document.body.appendChild(reportModal);
            }

            reportModal.innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; padding-bottom:12px; border-bottom:2px solid var(--border-subtle);">
                    <h3 style="font-family:'Outfit', sans-serif; font-size:20px; font-weight:800;">Executive Security Audit — ${scanData.hostname}</h3>
                    <button id="closeReportModalBtn" class="btn-secondary" style="padding:6px 14px;">Close</button>
                </div>
                <iframe id="reportFrame" style="width:100%; height:70vh; border:1px solid var(--border-subtle); border-radius:8px;"></iframe>
            `;

            reportModal.classList.add('show');
            const frame = document.getElementById('reportFrame');
            frame.contentWindow.document.open();
            frame.contentWindow.document.write(htmlReport);
            frame.contentWindow.document.close();

            document.getElementById('closeReportModalBtn').addEventListener('click', () => {
                reportModal.classList.remove('show');
            });
        } catch(err) {
            alert('Unable to load report for selected target history.');
        }
    }

    function initProfilePage() {
        const form = document.getElementById('profileForm');
        const pwdForm = document.getElementById('passwordForm');
        if (!form) return;

        // Load profile data from VanguardAuth or local storage
        function populateProfileUI(user) {
            if (!user) return;
            const name = user.full_name || user.username || 'User Profile';
            const role = user.role || 'Security Auditor';
            const email = user.email || 'user@example.com';
            const org = user.college || user.organization || '';

            const initials = name.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase() || 'AU';

            const profNameInput = document.getElementById('profName');
            const profRoleInput = document.getElementById('profRole');
            const profEmailInput = document.getElementById('profEmail');
            const profOrgInput = document.getElementById('profOrg');

            if (profNameInput) profNameInput.value = name;
            if (profRoleInput) profRoleInput.value = role;
            if (profEmailInput) profEmailInput.value = email;
            if (profOrgInput) profOrgInput.value = org;

            const nameEl = document.getElementById('profDisplayName');
            const roleEl = document.getElementById('profDisplayRole');
            const initialsEl = document.getElementById('profAvatarInitials');
            const collegeBadgeEl = document.getElementById('profDisplayCollegeBadge');
            const summaryRoleEl = document.getElementById('profSummaryRole');

            if (nameEl) nameEl.innerText = name;
            if (roleEl) roleEl.innerText = role;
            if (initialsEl) initialsEl.innerText = initials;
            if (summaryRoleEl) summaryRoleEl.innerText = role;
            if (collegeBadgeEl) {
                if (org && org.trim()) {
                    collegeBadgeEl.style.display = 'inline-block';
                    collegeBadgeEl.innerText = org.trim();
                } else {
                    collegeBadgeEl.style.display = 'none';
                }
            }
        }

        const currentUser = typeof VanguardAuth !== 'undefined' ? VanguardAuth.getCurrentUser() : null;
        if (currentUser) {
            populateProfileUI(currentUser);
        }

        // Fetch fresh profile from server if authenticated
        if (typeof VanguardAuth !== 'undefined' && VanguardAuth.isAuthenticated()) {
            VanguardAuth.fetchWithAuth('/api/auth/me')
                .then(r => r.json())
                .then(data => {
                    if (data.success && data.user) {
                        populateProfileUI(data.user);
                    }
                })
                .catch(() => {});
        }

        // Save Profile Form
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            playSound('click');
            const saveBtn = document.getElementById('saveProfBtn');
            if (saveBtn) {
                saveBtn.disabled = true;
                saveBtn.innerText = 'Saving...';
            }

            const updates = {
                full_name: document.getElementById('profName').value.trim(),
                role: document.getElementById('profRole').value.trim(),
                email: document.getElementById('profEmail').value.trim(),
                organization: document.getElementById('profOrg').value.trim()
            };

            try {
                if (typeof VanguardAuth !== 'undefined' && VanguardAuth.isAuthenticated()) {
                    const res = await VanguardAuth.fetchWithAuth('/api/auth/profile', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(updates)
                    });
                    const data = await res.json();
                    if (data.success && data.user) {
                        const token = VanguardAuth.getAuthToken();
                        VanguardAuth.setAuthSession(token, data.user);
                        populateProfileUI(data.user);
                        showToast('Personal Profile updated on server!');
                    } else {
                        showToast(data.error || 'Failed to update profile', false);
                    }
                } else {
                    localStorage.setItem('vanguardProfileData', JSON.stringify(updates));
                    populateProfileUI(updates);
                    showToast('Personal Profile updated locally!');
                }
            } catch(e) {
                showToast('Error updating profile: ' + e.message, false);
            } finally {
                if (saveBtn) {
                    saveBtn.disabled = false;
                    saveBtn.innerText = 'Save Changes';
                }
            }
        });

        // Change Password Form
        if (pwdForm) {
            pwdForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                playSound('click');
                const oldPwd = document.getElementById('oldPassword').value;
                const newPwd = document.getElementById('newPassword').value;
                const confirmPwd = document.getElementById('confirmNewPassword').value;

                if (newPwd !== confirmPwd) {
                    showToast('New passwords do not match!', false);
                    return;
                }
                if (newPwd.length < 6) {
                    showToast('New password must be at least 6 characters!', false);
                    return;
                }

                const changeBtn = document.getElementById('changePwdBtn');
                if (changeBtn) {
                    changeBtn.disabled = true;
                    changeBtn.innerText = 'Updating...';
                }

                try {
                    const res = await VanguardAuth.fetchWithAuth('/api/auth/change-password', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ old_password: oldPwd, new_password: newPwd })
                    });
                    const data = await res.json();
                    if (data.success) {
                        showToast('Security password updated successfully!');
                        pwdForm.reset();
                    } else {
                        showToast(data.error || 'Failed to update password', false);
                    }
                } catch(err) {
                    showToast('Network error updating password', false);
                } finally {
                    if (changeBtn) {
                        changeBtn.disabled = false;
                        changeBtn.innerText = 'Update Password';
                    }
                }
            });
        }
    }

    // 3. ANIMATED BLACK SAND GRAIN PARTICLE SYSTEM ON PALE OFF-WHITE CANVAS
    function initBlackSandGrainsBackground() {
        const bgCanvas = document.getElementById('bgCanvas');
        if (!bgCanvas) return;
        const ctx = bgCanvas.getContext('2d');

        let width = bgCanvas.width = window.innerWidth;
        let height = bgCanvas.height = window.innerHeight;
        let mouseX = width / 2;
        let mouseY = height / 2;

        window.addEventListener('resize', () => {
            width = bgCanvas.width = window.innerWidth;
            height = bgCanvas.height = window.innerHeight;
        });

        window.addEventListener('mousemove', (e) => {
            mouseX = e.clientX;
            mouseY = e.clientY;
        });

        const numSandGrains = Math.min(240, Math.floor(width / 5.5));
        const sandGrains = [];

        // Hues for black & dark onyx sand grains on pale off-white background
        const blackSandPalettes = [
            'rgba(15, 15, 20, ',
            'rgba(30, 30, 38, ',
            'rgba(45, 45, 55, ',
            'rgba(65, 65, 75, ',
            'rgba(90, 90, 100, '
        ];

        for (let i = 0; i < numSandGrains; i++) {
            sandGrains.push({
                x: Math.random() * width,
                y: Math.random() * height,
                vx: (Math.random() - 0.5) * 0.4,
                vy: Math.random() * 0.75 + 0.25, // Downward sand drift
                size: Math.random() * 1.7 + 0.5, // Tiny black sand grains
                baseAlpha: Math.random() * 0.65 + 0.25,
                twinklePhase: Math.random() * Math.PI * 2,
                twinkleSpeed: 0.02 + Math.random() * 0.035,
                colorPrefix: blackSandPalettes[Math.floor(Math.random() * blackSandPalettes.length)]
            });
        }

        function animateBlackSand() {
            ctx.clearRect(0, 0, width, height);

            sandGrains.forEach(p => {
                p.twinklePhase += p.twinkleSpeed;
                const alpha = Math.max(0.15, p.baseAlpha + Math.sin(p.twinklePhase) * 0.25);

                // Gentle horizontal breeze wafting
                p.x += p.vx + Math.sin(p.twinklePhase) * 0.15;
                p.y += p.vy;

                // Mouse Wind Impulse force field
                const dx = p.x - mouseX;
                const dy = p.y - mouseY;
                const dist = Math.hypot(dx, dy);
                if (dist < 130) {
                    const force = (130 - dist) / 130;
                    p.x += (dx / dist) * force * 1.8;
                    p.y += (dy / dist) * force * 1.8;
                }

                // Wrap around edges continuously
                if (p.y > height) {
                    p.y = -5;
                    p.x = Math.random() * width;
                }
                if (p.x < -10) p.x = width + 5;
                if (p.x > width + 10) p.x = -5;

                // Draw tiny black grain of sand
                ctx.beginPath();
                ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
                ctx.fillStyle = p.colorPrefix + alpha + ')';
                ctx.shadowColor = 'rgba(0, 0, 0, 0.4)';
                ctx.shadowBlur = p.size > 1.2 ? 3 : 0;
                ctx.fill();
                ctx.shadowBlur = 0;
            });

            requestAnimationFrame(animateBlackSand);
        }

        animateBlackSand();
    }

    // Initial Topology canvas state
    startTopologyAnimation({
        hostname: 'scanme.nmap.org',
        ip: '45.33.32.156',
        open_ports: [
            { port: 80, service: 'HTTP (Apache)', state: 'OPEN', banner: 'HTTP/1.1 200 OK' },
            { port: 443, service: 'HTTPS (TLS)', state: 'OPEN', banner: 'HTTP/1.1 200 OK' },
            { port: 22, service: 'SSH', state: 'OPEN', banner: 'SSH-2.0-OpenSSH' }
        ],
        subdomains: [{ subdomain: 'scanme.nmap.org', ip: '45.33.32.156' }]
    });

    // 5. GOOGLE GEMINI AI ASSISTANT CONTROLLER
    function initGeminiAssistant() {
        const copilotInput = document.getElementById('copilotInput');
        const sendCopilotBtn = document.getElementById('sendCopilotBtn');
        const copilotChatStream = document.getElementById('copilotChatStream');
        const chipBtns = document.querySelectorAll('.copilot-chip-btn');

        if (!copilotInput || !sendCopilotBtn || !copilotChatStream) return;

        function appendMessage(sender, htmlContent) {
            const msgDiv = document.createElement('div');
            msgDiv.className = `copilot-msg ${sender}`;
            if (sender === 'user') {
                msgDiv.innerHTML = `<strong>You:</strong><br>${escapeHtml(htmlContent)}`;
            } else {
                msgDiv.innerHTML = `<strong>Remediation Assistant:</strong><br>${formatMarkdown(htmlContent)}`;
            }
            copilotChatStream.appendChild(msgDiv);
            copilotChatStream.scrollTop = copilotChatStream.scrollHeight;
            return msgDiv;
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function formatMarkdown(text) {
            if (!text) return '';
            
            // 1. Preserve pre/code blocks
            const codeBlocks = [];
            let placeholderText = text.replace(/```(\w*)\n?([\s\S]*?)```/g, (match, lang, code) => {
                const id = `___CODEBLOCK_${codeBlocks.length}___`;
                const escapedCode = escapeHtml(code.trim());
                codeBlocks.push(`<pre><code class="language-${lang}">${escapedCode}</code></pre>`);
                return id;
            });

            // 2. Escape raw text
            placeholderText = escapeHtml(placeholderText);

            // 3. Process inline code
            const inlineCodes = [];
            placeholderText = placeholderText.replace(/`([^`]+)`/g, (match, code) => {
                const id = `___INLINECODE_${inlineCodes.length}___`;
                inlineCodes.push(`<code style="background:rgba(56,189,248,0.12); color:#0284c7; padding:2px 6px; border-radius:4px; font-family:monospace; font-size:12px;">${code}</code>`);
                return id;
            });

            // 4. Format markdown elements
            let html = placeholderText
                .replace(/^#### (.*$)/gim, '<h5 style="margin:10px 0 4px 0; color:var(--text-primary); font-weight:700;">$1</h5>')
                .replace(/^### (.*$)/gim, '<h4 style="margin:12px 0 6px 0; color:var(--accent-blue); font-weight:700;">$1</h4>')
                .replace(/^## (.*$)/gim, '<h3 style="margin:14px 0 6px 0; color:var(--accent-blue); font-weight:800;">$1</h3>')
                .replace(/^# (.*$)/gim, '<h2 style="margin:16px 0 8px 0; color:var(--accent-blue); font-weight:800;">$1</h2>')
                .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                .replace(/\*(.*?)\*/g, '<em>$1</em>')
                .replace(/^\s*[\-\*]\s+(.*$)/gim, '• $1')
                .replace(/\n/g, '<br>');

            // 5. Restore inline code and code blocks
            inlineCodes.forEach((codeHtml, idx) => {
                html = html.replace(`___INLINECODE_${idx}___`, codeHtml);
            });
            codeBlocks.forEach((codeHtml, idx) => {
                html = html.replace(`___CODEBLOCK_${idx}___`, codeHtml);
            });

            return html;
        }

        async function sendUserQuery(queryText) {
            const text = (queryText || copilotInput.value).trim();
            if (!text) return;

            appendMessage('user', text);
            copilotInput.value = '';

            const loadingMsg = appendMessage('bot', '<em>Generating remediation guidance...</em>');

            try {
                const authFetch = typeof VanguardAuth !== 'undefined' ? VanguardAuth.fetchWithAuth : fetch;
                const response = await authFetch('/api/copilot', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        query: text,
                        context: typeof currentScanData !== 'undefined' ? currentScanData : null
                    })
                });

                const data = await response.json();
                loadingMsg.remove();

                if (data && data.answer) {
                    appendMessage('bot', data.answer);
                } else {
                    appendMessage('bot', 'Error receiving response from Remediation Assistant. Please try again.');
                }
            } catch (err) {
                loadingMsg.remove();
                appendMessage('bot', 'Network error communicating with Remediation Assistant endpoint.');
            }
        }

        sendCopilotBtn.addEventListener('click', () => sendUserQuery());
        copilotInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') sendUserQuery();
        });

        chipBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const query = btn.getAttribute('data-query');
                if (query) sendUserQuery(query);
            });
        });
    }

    initGeminiAssistant();
});

