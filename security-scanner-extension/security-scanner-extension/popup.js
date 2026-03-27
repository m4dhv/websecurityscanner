// popup.js

let allFindings = [];
let activeFilter = "all";

const scanBtn   = document.getElementById("scanBtn");
const btnLabel  = document.getElementById("btnLabel");
const urlBar    = document.getElementById("urlBar");
const results   = document.getElementById("results");
const statsBar  = document.getElementById("statsBar");
const filterBar = document.getElementById("filterBar");
const clearBtn  = document.getElementById("clearBtn");

// ── Load current tab URL into header ──
chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
  if (tab?.url) urlBar.textContent = tab.url;
});

// ── Scan button ──
scanBtn.addEventListener("click", () => {
  if (scanBtn.classList.contains("scanning")) return;

  scanBtn.classList.add("scanning");
  btnLabel.textContent = "SCANNING...";
  results.innerHTML = `<div class="placeholder"><p>RUNNING CHECKS...</p></div>`;
  statsBar.classList.remove("visible");
  filterBar.classList.remove("visible");
  clearBtn.style.display = "none";
  allFindings = [];

  chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
    if (!tab?.id) {
      showError("Cannot access current tab.");
      resetBtn();
      return;
    }

    // Inject content script first (handles cases where it wasn't injected)
    chrome.scripting.executeScript(
      { target: { tabId: tab.id }, files: ["content.js"] },
      () => {
        if (chrome.runtime.lastError) {
          // Script might already be there — send message anyway
        }
        chrome.tabs.sendMessage(tab.id, { action: "RUN_SCAN" }, (response) => {
          resetBtn();
          if (chrome.runtime.lastError || !response) {
            showError(
              chrome.runtime.lastError?.message ||
              "No response from page. Try reloading the tab."
            );
            return;
          }
          if (!response.success) {
            showError(response.error || "Scan failed.");
            return;
          }
          renderResults(response);
        });
      }
    );
  });
});

// ── Filter chips ──
filterBar.querySelectorAll(".chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    activeFilter = chip.dataset.filter;
    filterBar.querySelectorAll(".chip").forEach((c) => {
      c.className = "chip";
    });
    chip.classList.add(`active-${activeFilter}`);
    renderFindings();
  });
});

// ── Clear button ──
clearBtn.addEventListener("click", () => {
  allFindings = [];
  statsBar.classList.remove("visible");
  filterBar.classList.remove("visible");
  clearBtn.style.display = "none";
  results.innerHTML = `<div class="placeholder">
    <p>RESULTS CLEARED</p>
  </div>`;
  activeFilter = "all";
  filterBar.querySelectorAll(".chip").forEach((c) => c.className = "chip");
  filterBar.querySelector('[data-filter="all"]').classList.add("active-all");
});

// ─────────────────────────────────────────────
function renderResults(data) {
  allFindings = data.results || [];

  // Stats
  document.getElementById("cCritical").textContent = data.stats.critical;
  document.getElementById("cHigh").textContent     = data.stats.high;
  document.getElementById("cMedium").textContent   = data.stats.medium;
  document.getElementById("cLow").textContent      = data.stats.low;

  statsBar.classList.add("visible");
  if (allFindings.length > 0) {
    filterBar.classList.add("visible");
    clearBtn.style.display = "block";
  }

  renderFindings();
}

function renderFindings() {
  const filtered =
    activeFilter === "all"
      ? allFindings
      : allFindings.filter((f) => f.severity === activeFilter);

  if (filtered.length === 0 && activeFilter === "all") {
    results.innerHTML = `
      <div class="all-clear">
        <div class="check">✅</div>
        <p>NO ISSUES DETECTED</p>
        <small>No common vulnerabilities found on this page.<br>This is a heuristic scan — not a full audit.</small>
      </div>`;
    return;
  }

  if (filtered.length === 0) {
    results.innerHTML = `<div class="placeholder"><p>NO ${activeFilter.toUpperCase()} FINDINGS</p></div>`;
    return;
  }

  // Sort: critical → high → medium → low
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  const sorted = [...filtered].sort((a, b) => order[a.severity] - order[b.severity]);

  results.innerHTML = sorted
    .map((f) => `
      <div class="finding ${f.severity}">
        <div class="finding-header">
          <span class="sev-badge">${f.severity}</span>
          <span class="finding-type">${escapeHTML(f.type)}</span>
        </div>
        <div class="finding-detail">${escapeHTML(f.detail)}</div>
      </div>
    `)
    .join("");
}

function showError(msg) {
  results.innerHTML = `
    <div class="placeholder">
      <p style="color:#ff3b6b">ERROR</p>
      <p style="font-size:10px;text-align:center;max-width:280px;line-height:1.5">${escapeHTML(msg)}</p>
    </div>`;
}

function resetBtn() {
  scanBtn.classList.remove("scanning");
  btnLabel.textContent = "RUN SECURITY SCAN";
}

function escapeHTML(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
