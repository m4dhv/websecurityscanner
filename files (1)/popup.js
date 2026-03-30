// Configuration
let config = {
    apiUrl: 'http://localhost:5000',
    maxDepth: 3,
    autoReport: true
};

// State
let scanState = {
    isScanning: false,
    sessionId: null,
    startTime: null,
    vulnerabilities: [],
    scannedUrls: new Set()
};

// DOM Elements
const elements = {
    currentUrl: document.getElementById('currentUrl'),
    startScanBtn: document.getElementById('startScanBtn'),
    stopScanBtn: document.getElementById('stopScanBtn'),
    scanProgress: document.getElementById('scanProgress'),
    progressText: document.getElementById('progressText'),
    statusText: document.getElementById('statusText'),
    resultsPanel: document.getElementById('resultsPanel'),
    vulnerabilityList: document.getElementById('vulnerabilityList'),
    vulnCount: document.getElementById('vulnCount'),
    settingsBtn: document.getElementById('settingsBtn'),
    settingsPanel: document.getElementById('settingsPanel'),
    saveSettingsBtn: document.getElementById('saveSettings'),
    viewDashboardBtn: document.getElementById('viewDashboard'),
    apiUrlInput: document.getElementById('apiUrl'),
    maxDepthInput: document.getElementById('maxDepth'),
    autoReportInput: document.getElementById('autoReport'),
    closeBtn: document.querySelector('.close')
};

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    loadSettings();
    getCurrentTab();
    setupEventListeners();
});

function setupEventListeners() {
    elements.startScanBtn.addEventListener('click', startScan);
    elements.stopScanBtn.addEventListener('click', stopScan);
    elements.settingsBtn.addEventListener('click', () => elements.settingsPanel.classList.remove('hidden'));
    elements.closeBtn.addEventListener('click', () => elements.settingsPanel.classList.add('hidden'));
    elements.saveSettingsBtn.addEventListener('click', saveSettings);
    elements.viewDashboardBtn.addEventListener('click', openDashboard);

    // Close modal when clicking outside
    window.addEventListener('click', (event) => {
        if (event.target === elements.settingsPanel) {
            elements.settingsPanel.classList.add('hidden');
        }
    });
}

function loadSettings() {
    chrome.storage.local.get(['apiUrl', 'maxDepth', 'autoReport'], (result) => {
        if (result.apiUrl) config.apiUrl = result.apiUrl;
        if (result.maxDepth) config.maxDepth = result.maxDepth;
        if (result.autoReport !== undefined) config.autoReport = result.autoReport;

        elements.apiUrlInput.value = config.apiUrl;
        elements.maxDepthInput.value = config.maxDepth;
        elements.autoReportInput.checked = config.autoReport;
    });
}

function saveSettings() {
    config.apiUrl = elements.apiUrlInput.value;
    config.maxDepth = parseInt(elements.maxDepthInput.value);
    config.autoReport = elements.autoReportInput.checked;

    chrome.storage.local.set({
        apiUrl: config.apiUrl,
        maxDepth: config.maxDepth,
        autoReport: config.autoReport
    }, () => {
        alert('Settings saved!');
        elements.settingsPanel.classList.add('hidden');
    });
}

function getCurrentTab() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const url = new URL(tabs[0].url);
        elements.currentUrl.textContent = url.hostname;
    });
}

async function startScan() {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
        const currentUrl = tabs[0].url;

        // Validate API connection
        try {
            const healthCheck = await fetch(`${config.apiUrl}/health`);
            if (!healthCheck.ok) {
                updateStatus('❌ Cannot connect to API server. Check settings.', 'error');
                return;
            }
        } catch (error) {
            updateStatus('❌ API server unreachable. Start the backend first.', 'error');
            return;
        }

        scanState.isScanning = true;
        scanState.startTime = Date.now();
        scanState.vulnerabilities = [];
        scanState.scannedUrls.clear();

        elements.startScanBtn.disabled = true;
        elements.stopScanBtn.classList.remove('hidden');
        elements.scanProgress.classList.remove('hidden');
        elements.resultsPanel.classList.add('hidden');

        updateStatus('🔄 Initializing scan...');

        // Start scan session
        try {
            const sessionResponse = await fetch(`${config.apiUrl}/api/scan/start`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    target_url: currentUrl,
                    browser: getBrowserName()
                })
            });

            const sessionData = await sessionResponse.json();
            scanState.sessionId = sessionData.session_id;

            // Perform scan
            await performScan(currentUrl);

            // Complete scan
            const duration = Math.floor((Date.now() - scanState.startTime) / 1000);
            await completeScan(duration);

            displayResults();
            updateStatus('✅ Scan completed successfully!', 'success');

        } catch (error) {
            console.error('Scan error:', error);
            updateStatus(`❌ Error: ${error.message}`, 'error');
        } finally {
            scanState.isScanning = false;
            elements.startScanBtn.disabled = false;
            elements.stopScanBtn.classList.add('hidden');
            elements.scanProgress.classList.add('hidden');
        }
    });
}

async function performScan(baseUrl) {
    updateStatus('🕷️ Crawling website...');
    
    // Extract base domain
    const baseUrlObj = new URL(baseUrl);
    const domain = baseUrlObj.origin;

    // For simplicity, we'll scan the current page and some common endpoints
    const urlsToScan = await discoverUrls(baseUrl);

    updateStatus(`🔍 Found ${urlsToScan.length} pages to scan`);

    // Scan URLs with different payloads
    const totalScans = urlsToScan.length * 3; // SQL injection, XSS, sensitive info
    let scansCompleted = 0;

    for (const url of urlsToScan) {
        if (!scanState.isScanning) break;

        await scanUrlForVulnerabilities(url);

        scansCompleted += 3;
        updateProgress((scansCompleted / totalScans) * 100);
    }

    scanState.scannedUrls = new Set(urlsToScan);
}

async function discoverUrls(baseUrl) {
    // Inject content script to discover links
    return new Promise((resolve) => {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            chrome.tabs.sendMessage(tabs[0].id, { action: 'getLinks' }, (response) => {
                resolve(response?.urls || [baseUrl]);
            });
        });
    });
}

async function scanUrlForVulnerabilities(url) {
    // Check for SQL injection
    await checkSQLInjection(url);
    
    // Check for XSS
    await checkXSS(url);
    
    // Check for sensitive info
    await checkSensitiveInfo(url);
}

async function checkSQLInjection(url) {
    const payloads = ["'", "1' OR '1'='1", "' OR 1=1--"];
    
    for (const payload of payloads) {
        try {
            const testUrl = addParameterToUrl(url, 'test', payload);
            const response = await fetch(testUrl);
            const text = await response.text();

            if (containsSQLErrors(text)) {
                reportVulnerability({
                    type: 'SQL Injection',
                    url: url,
                    parameter: 'test',
                    payload: payload,
                    severity: 'critical'
                });
            }
        } catch (error) {
            // Network errors are expected for non-existent parameters
        }
    }
}

async function checkXSS(url) {
    const payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>"
    ];

    for (const payload of payloads) {
        try {
            const testUrl = addParameterToUrl(url, 'test', encodeURIComponent(payload));
            const response = await fetch(testUrl);
            const text = await response.text();

            if (text.includes(payload)) {
                reportVulnerability({
                    type: 'Cross-Site Scripting (XSS)',
                    url: url,
                    parameter: 'test',
                    payload: payload,
                    severity: 'high'
                });
            }
        } catch (error) {
            // Network errors expected
        }
    }
}

async function checkSensitiveInfo(url) {
    try {
        const response = await fetch(url);
        const text = await response.text();

        const patterns = {
            'email': /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
            'api_key': /api[_-]?key[_-]?(['\"|`])([a-zA-Z0-9]{32,45})\1/g,
            'phone': /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g
        };

        for (const [infoType, pattern] of Object.entries(patterns)) {
            const matches = text.match(pattern);
            if (matches) {
                reportVulnerability({
                    type: 'Sensitive Information Exposure',
                    url: url,
                    info_type: infoType,
                    severity: 'medium'
                });
            }
        }
    } catch (error) {
        // Network errors expected
    }
}

function containsSQLErrors(text) {
    const errors = ['SQL', 'mysql', 'sqlite', 'postgresql', 'oracle', 'syntax error'];
    return errors.some(err => text.toLowerCase().includes(err.toLowerCase()));
}

function addParameterToUrl(url, param, value) {
    const urlObj = new URL(url);
    urlObj.searchParams.append(param, value);
    return urlObj.toString();
}

async function reportVulnerability(vulnerability) {
    scanState.vulnerabilities.push(vulnerability);

    if (config.autoReport && scanState.sessionId) {
        try {
            await fetch(`${config.apiUrl}/api/scan/${scanState.sessionId}/report`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(vulnerability)
            });
        } catch (error) {
            console.error('Failed to report vulnerability:', error);
        }
    }
}

async function completeScan(duration) {
    if (!scanState.sessionId) return;

    try {
        await fetch(`${config.apiUrl}/api/scan/${scanState.sessionId}/complete`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                total_urls_scanned: scanState.scannedUrls.size,
                duration_seconds: duration
            })
        });
    } catch (error) {
        console.error('Failed to complete scan:', error);
    }
}

function displayResults() {
    elements.resultsPanel.classList.remove('hidden');
    elements.vulnCount.textContent = scanState.vulnerabilities.length;

    elements.vulnerabilityList.innerHTML = '';
    scanState.vulnerabilities.forEach(vuln => {
        const vulnElement = document.createElement('div');
        vulnElement.className = `vuln-item ${vuln.severity || 'medium'}`;
        
        let html = `<div class="vuln-type">${vuln.type}</div>`;
        html += `<div class="vuln-url">${vuln.url}</div>`;
        
        if (vuln.parameter) {
            html += `<div class="vuln-param">Parameter: ${vuln.parameter}</div>`;
        }
        if (vuln.info_type) {
            html += `<div class="vuln-param">Type: ${vuln.info_type}</div>`;
        }

        vulnElement.innerHTML = html;
        elements.vulnerabilityList.appendChild(vulnElement);
    });
}

function updateStatus(message, type = 'info') {
    elements.statusText.textContent = message;
    const status = document.getElementById('scanStatus');
    status.className = `status ${type}`;
}

function updateProgress(percent) {
    elements.progressText.textContent = Math.round(percent) + '%';
    const progressBar = document.querySelector('.progress-bar');
    progressBar.style.width = percent + '%';
}

function stopScan() {
    scanState.isScanning = false;
    updateStatus('⏹️ Scan stopped by user');
}

function openDashboard() {
    const dashboardUrl = `${config.apiUrl}/dashboard?session_id=${scanState.sessionId}`;
    chrome.tabs.create({ url: dashboardUrl });
}

function getBrowserName() {
    if (navigator.userAgent.indexOf('Firefox') > -1) return 'Firefox';
    if (navigator.userAgent.indexOf('Chrome') > -1) return 'Chrome';
    return 'Unknown';
}
