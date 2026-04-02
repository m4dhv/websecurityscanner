/* popup.js — WebSec Scanner Extension
   Talks to the same FastAPI backend on http://localhost:8000
   Mirrors all logic from app2.py (Flet desktop app)
*/

// ── Config ──────────────────────────────────────────────────────────────────
const API_BASE      = 'http://localhost:8000';
const DEFAULT_KEY   = 'wsk_NAWtMhmt61PtpCz3K-TGadgYg-DSxXcZlLAQWqZCa8A';
const STORAGE_KEY   = 'websec_state';

const SCAN_MESSAGES = [
  '🔍  Analyzing target architecture…',
  '🕸   Crawling endpoints…',
  '💉  Testing for SQL injection…',
  '⚡  Probing XSS vectors…',
  '🔐  Checking for sensitive data exposure…',
  '📡  Aggregating findings…',
];

const URL_RE = /^(https?:\/\/)?(localhost|([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,})(:\d{1,5})?(\/[^\s]*)?$/i;

// ── State ────────────────────────────────────────────────────────────────────
let state = {
  dark:      true,
  apiKey:    DEFAULT_KEY,
  scanId:    null,
  status:    'IDLE',     // IDLE | SCANNING | DONE | ERROR
  vulns:     [],
  endpoints: 0,
  scanDone:  false,
};

let scanPollTimer   = null;
let msgCycleTimer   = null;
let dotAnimTimer    = null;
let msgIdx          = 0;
let dotStep         = 0;

// ── DOM refs ──────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

const apiKeyInput = $('apiKeyInput');
const urlInput    = $('urlInput');
const revealBtn   = $('revealBtn');
const useTabBtn   = $('useTabBtn');
const quickBtn    = $('quickBtn');
const deepBtn     = $('deepBtn');
const themeBtn    = $('themeBtn');

const statusDot   = $('statusDot');
const statusText  = $('statusText');
const scanDots    = $('scanDots');
const dots        = [$('d0'), $('d1'), $('d2')];

const progressBox = $('progressBox');
const progressMsg = $('progressMsg');
const progressBar = $('progressBar');
const banner      = $('banner');
const findingsList= $('findingsList');
const emptyState  = $('emptyState');
const toast       = $('toast');

const mEndpoints  = $('mEndpoints');
const mSqli       = $('mSqli');
const mXss        = $('mXss');
const mInfo       = $('mInfo');

// ── Init ─────────────────────────────────────────────────────────────────────
(async () => {
  // Restore saved state
  const saved = await loadState();
  if (saved) Object.assign(state, saved);

  apiKeyInput.value = state.apiKey || DEFAULT_KEY;
  applyTheme();
  refreshMetrics();
  refreshFindings();

  // If we were mid-scan, resume polling
  if (state.status === 'SCANNING' && state.scanId) {
    setStatus('SCANNING');
    startMsgCycle();
    startDotAnim();
    resumePoll(state.scanId);
  } else {
    setStatus(state.status || 'IDLE');
  }
})();

// ── Persistence ───────────────────────────────────────────────────────────────
function saveState() {
  try {
    chrome.storage.local.set({ [STORAGE_KEY]: JSON.parse(JSON.stringify(state)) });
  } catch (_) {}
}

async function loadState() {
  return new Promise(resolve => {
    try {
      chrome.storage.local.get([STORAGE_KEY], r => resolve(r[STORAGE_KEY] || null));
    } catch (_) { resolve(null); }
  });
}

// ── Theme ─────────────────────────────────────────────────────────────────────
function applyTheme() {
  document.body.classList.toggle('light', !state.dark);
  themeBtn.textContent = state.dark ? '🌙' : '☀️';
}

themeBtn.addEventListener('click', () => {
  state.dark = !state.dark;
  applyTheme();
  saveState();
});

// ── Status ────────────────────────────────────────────────────────────────────
function setStatus(s) {
  state.status = s;
  statusText.textContent = s;
  statusDot.className = 'status-dot';
  if (s === 'SCANNING') statusDot.classList.add('scanning');
  if (s === 'DONE')     statusDot.classList.add('done');
  if (s === 'ERROR')    statusDot.classList.add('error');

  const scanning = s === 'SCANNING';
  scanDots.classList.toggle('active', scanning);
  progressBox.classList.toggle('active', scanning);
  quickBtn.disabled = scanning;
  deepBtn.disabled  = scanning;

  if (!scanning) { stopMsgCycle(); stopDotAnim(); }
  saveState();
}

// ── Dot animation (mimics ScanAnimation from app) ────────────────────────────
function startDotAnim() {
  stopDotAnim();
  dotStep = 0;
  dotAnimTimer = setInterval(() => {
    dots.forEach((d, i) => d.style.opacity = i === (dotStep % 3) ? '1' : '0.2');
    dotStep++;
  }, 320);
}

function stopDotAnim() {
  if (dotAnimTimer) { clearInterval(dotAnimTimer); dotAnimTimer = null; }
  dots.forEach(d => d.style.opacity = '0.2');
}

// ── Msg cycle ────────────────────────────────────────────────────────────────
function startMsgCycle() {
  stopMsgCycle();
  msgIdx = 0;
  progressMsg.textContent = SCAN_MESSAGES[0];
  msgCycleTimer = setInterval(() => {
    msgIdx = (msgIdx + 1) % SCAN_MESSAGES.length;
    progressMsg.textContent = SCAN_MESSAGES[msgIdx];
  }, 2400);
}

function stopMsgCycle() {
  if (msgCycleTimer) { clearInterval(msgCycleTimer); msgCycleTimer = null; }
}

// ── Banner ───────────────────────────────────────────────────────────────────
function showBanner(msg, ok = false) {
  const col = ok ? 'var(--accent)' : 'var(--red)';
  banner.textContent = msg;
  banner.style.color      = col;
  banner.style.background = ok ? 'rgba(34,197,94,0.09)' : 'rgba(255,77,109,0.09)';
  banner.style.border     = `1px solid ${ok ? 'rgba(34,197,94,0.3)' : 'rgba(255,77,109,0.3)'}`;
  banner.classList.add('active');
}

function hideBanner() {
  banner.classList.remove('active');
}

// ── Toast ────────────────────────────────────────────────────────────────────
let toastTimer = null;
function showToast(msg, ok = true) {
  toast.textContent = (ok ? '✓  ' : '✕  ') + msg;
  toast.className   = 'toast show' + (ok ? '' : ' err');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('show'), 3200);
}

// ── Metrics ──────────────────────────────────────────────────────────────────
function refreshMetrics() {
  const vulns = state.vulns || [];
  const sq  = vulns.filter(v => (v.type||'').includes('SQL')).length;
  const xs  = vulns.filter(v => (v.type||'').includes('XSS')).length;
  const inf = vulns.filter(v => (v.type||'').includes('Sensitive')).length;
  mEndpoints.textContent = state.endpoints || 0;
  mSqli.textContent      = sq;
  mXss.textContent       = xs;
  mInfo.textContent      = inf;
}

// ── Severity helper ──────────────────────────────────────────────────────────
function getSeverity(vulnType) {
  if (vulnType.includes('SQL')) return { label: 'CRITICAL', color: 'var(--red)' };
  if (vulnType.includes('XSS')) return { label: 'HIGH',     color: 'var(--orange)' };
  return                               { label: 'MEDIUM',   color: 'var(--yellow)' };
}

// ── Findings ─────────────────────────────────────────────────────────────────
function refreshFindings() {
  findingsList.innerHTML = '';

  if (!state.scanDone) {
    findingsList.innerHTML = `
      <div class="empty-state">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        No active scan results. Enter a target URL and choose a scan mode to begin.
      </div>`;
    return;
  }

  const vulns = state.vulns || [];
  if (vulns.length === 0) {
    findingsList.innerHTML = `
      <div class="empty-state clean">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
        Target surface appears clean. No vulnerabilities detected.
      </div>`;
    return;
  }

  vulns.forEach((vuln, idx) => {
    const vType = vuln.type || 'Unknown';
    const vUrl  = vuln.url  || '';
    const sev   = getSeverity(vType);
    const shortUrl = vUrl.length > 42 ? vUrl.slice(0, 42) + '…' : vUrl;

    // Build detail rows (exclude "type")
    const detailRows = Object.entries(vuln)
      .filter(([k]) => k !== 'type')
      .map(([k, v]) => {
        const isPayload = ['payload','pattern','parameter'].includes(k);
        return `<div class="detail-row">
          <div class="detail-key">${k.toUpperCase()}</div>
          <div class="detail-val${isPayload ? ' payload' : ''}">${escHtml(String(v))}</div>
        </div>`;
      }).join('');

    const tile = document.createElement('div');
    tile.className = 'vuln-tile';
    tile.innerHTML = `
      <div class="vuln-header">
        <span class="sev-badge" style="color:${sev.color};background:${sev.color}22">${sev.label}</span>
        <span class="vuln-type">${escHtml(vType)}</span>
        <span class="vuln-url" title="${escHtml(vUrl)}">${escHtml(shortUrl)}</span>
        <span class="chevron">›</span>
      </div>
      <div class="vuln-body">${detailRows}</div>`;

    tile.querySelector('.vuln-header').addEventListener('click', () => {
      tile.classList.toggle('open');
    });

    findingsList.appendChild(tile);
  });
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── API calls (mirror ApiClient from app2.py) ────────────────────────────────
async function apiStartScan(targetUrl, scanType, apiKey) {
  const res = await fetch(`${API_BASE}/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey },
    body: JSON.stringify({ target_url: targetUrl, scan_type: scanType }),
  });
  if (!res.ok) {
    let detail = 'Unknown error';
    try { detail = (await res.json()).detail || detail; } catch(_) {}
    throw new Error(`API error: ${detail}`);
  }
  return res.json();
}

async function apiPollScan(scanId, apiKey) {
  const res = await fetch(`${API_BASE}/scans/${scanId}`, {
    headers: { 'X-API-Key': apiKey },
  });
  if (!res.ok) throw new Error(`Poll failed: ${res.status}`);
  return res.json();
}

// ── Polling loop ─────────────────────────────────────────────────────────────
function stopPoll() {
  if (scanPollTimer) { clearTimeout(scanPollTimer); scanPollTimer = null; }
}

function resumePoll(scanId) {
  const deadline = Date.now() + 180_000;
  schedulePoll(scanId, deadline);
}

function schedulePoll(scanId, deadline) {
  stopPoll();
  scanPollTimer = setTimeout(() => poll(scanId, deadline), 2000);
}

async function poll(scanId, deadline) {
  if (state.status !== 'SCANNING') return;
  if (Date.now() > deadline) {
    setStatus('ERROR');
    showBanner('Scan timed out waiting for backend.');
    return;
  }

  try {
    const result = await apiPollScan(scanId, state.apiKey);
    if (result.status === 'done' || result.status === 'error') {
      state.vulns     = result.vulnerabilities || [];
      state.endpoints = result.endpoints_count || 0;
      state.scanDone  = true;

      if (result.status === 'error') {
        setStatus('ERROR');
        showBanner('Scan completed with backend errors.');
        showToast('Scan finished with errors.', false);
      } else {
        setStatus('DONE');
        hideBanner();
        const n = state.vulns.length;
        const msg = n
          ? `Scan complete — ${n} issue${n !== 1 ? 's' : ''} found.`
          : 'Scan complete — target looks clean.';
        showToast(msg, true);
      }
      refreshMetrics();
      refreshFindings();
      saveState();
      return;
    }
  } catch (_) {
    // continue polling on transient errors
  }

  schedulePoll(scanId, deadline);
}

// ── Validation & scan trigger ─────────────────────────────────────────────────
async function validateAndScan(scanType) {
  hideBanner();
  $('urlRow').classList.remove('error');

  const apiKey = apiKeyInput.value.trim();
  if (!apiKey) { showBanner('⚠  API key is required.'); return; }
  state.apiKey = apiKey;

  let target = urlInput.value.trim();
  if (!target) { showBanner('⚠  Target URL cannot be empty.'); return; }

  const check = target.startsWith('http://') || target.startsWith('https://')
    ? target : 'https://' + target;

  if (!URL_RE.test(check)) {
    showBanner(`⚠  '${target}' is not a valid URL.`);
    $('urlRow').classList.add('error');
    return;
  }

  if (!target.startsWith('http://') && !target.startsWith('https://')) {
    target = 'https://' + target;
    urlInput.value = target;
  }

  // Reset
  state.vulns     = [];
  state.endpoints = 0;
  state.scanDone  = false;
  state.scanId    = null;
  refreshMetrics();
  refreshFindings();
  setStatus('SCANNING');
  startMsgCycle();
  startDotAnim();

  try {
    const resp = await apiStartScan(target, scanType, apiKey);
    state.scanId = resp.scan_id;
    saveState();
    resumePoll(resp.scan_id);
  } catch (err) {
    setStatus('ERROR');
    showBanner(err.message.includes('fetch') ? `Cannot reach backend: ${err.message}` : err.message);
    stopMsgCycle();
    stopDotAnim();
  }
}

// ── Buttons ───────────────────────────────────────────────────────────────────
quickBtn.addEventListener('click', () => validateAndScan('quickscan'));
deepBtn.addEventListener('click',  () => validateAndScan('deepscan'));

revealBtn.addEventListener('click', () => {
  const isPass = apiKeyInput.type === 'password';
  apiKeyInput.type  = isPass ? 'text' : 'password';
  revealBtn.textContent = isPass ? '🙈' : '👁';
});

// ── Use current tab ────────────────────────────────────────────────────────────
useTabBtn.addEventListener('click', () => {
  try {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (tabs && tabs[0] && tabs[0].url) {
        const url = tabs[0].url;
        if (url.startsWith('http://') || url.startsWith('https://')) {
          urlInput.value = url;
          $('urlRow').classList.remove('error');
        } else {
          showBanner('⚠  Current tab URL is not an HTTP/HTTPS URL.');
        }
      }
    });
  } catch (_) {
    showBanner('⚠  Could not read current tab URL.');
  }
});

// Persist API key on change
apiKeyInput.addEventListener('change', () => {
  state.apiKey = apiKeyInput.value.trim();
  saveState();
});
