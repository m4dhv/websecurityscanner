// content.js — Security Scanner content script
// Based on: https://www.freecodecamp.org/news/build-a-web-application-security-scanner-with-python/

(function () {
  "use strict";

  // ─────────────────────────────────────────────
  // SQL Injection Detection
  // Mirrors check_sql_injection: looks for SQL error keywords in URL params
  // ─────────────────────────────────────────────
  function checkSQLInjection() {
    const results = [];
    const sqlPayloads = ["'", "1' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"];
    const sqlErrors = ["sql", "mysql", "sqlite", "postgresql", "oracle", "syntax error", "unclosed quotation"];
    const url = window.location.href;
    const parsed = new URL(url);

    // Check URL params
    parsed.searchParams.forEach((value, param) => {
      sqlPayloads.forEach((payload) => {
        results.push({
          type: "SQL Injection Vector",
          severity: "high",
          detail: `Parameter "${param}" accepts user input — test with payload: ${payload}`,
          location: url,
        });
      });
    });

    // Scan visible page text for SQL error signatures (server-side leakage)
    const pageText = document.body ? document.body.innerText.toLowerCase() : "";
    sqlErrors.forEach((err) => {
      if (pageText.includes(err)) {
        results.push({
          type: "SQL Error Exposure",
          severity: "critical",
          detail: `Page text contains SQL error keyword: "${err}" — possible server-side SQL error leak`,
          location: url,
        });
      }
    });

    return results;
  }

  // ─────────────────────────────────────────────
  // XSS Detection
  // Mirrors check_xss: looks for unencoded script-like content in DOM
  // ─────────────────────────────────────────────
  function checkXSS() {
    const results = [];
    const url = window.location.href;
    const xssPatterns = [
      { pattern: /<script[^>]*>/i, label: "Inline <script> tag" },
      { pattern: /onerror\s*=/i, label: "onerror event handler" },
      { pattern: /onload\s*=/i, label: "onload event handler" },
      { pattern: /javascript:/i, label: "javascript: URI" },
      { pattern: /eval\s*\(/i, label: "eval() call" },
      { pattern: /document\.write\s*\(/i, label: "document.write() call" },
      { pattern: /innerHTML\s*=/i, label: "innerHTML assignment" },
    ];

    // Check all inline scripts
    document.querySelectorAll("script:not([src])").forEach((el) => {
      const code = el.textContent || "";
      xssPatterns.forEach(({ pattern, label }) => {
        if (pattern.test(code)) {
          results.push({
            type: "XSS Risk",
            severity: "high",
            detail: `Inline script contains ${label}`,
            location: url,
          });
        }
      });
    });

    // Check all element attributes for event handlers
    document.querySelectorAll("*").forEach((el) => {
      Array.from(el.attributes).forEach((attr) => {
        if (/^on\w+/i.test(attr.name)) {
          results.push({
            type: "XSS Risk",
            severity: "medium",
            detail: `Element <${el.tagName.toLowerCase()}> has inline event handler: ${attr.name}`,
            location: url,
          });
        }
        if (/javascript:/i.test(attr.value)) {
          results.push({
            type: "XSS Risk",
            severity: "high",
            detail: `Element <${el.tagName.toLowerCase()}> attribute "${attr.name}" contains javascript: URI`,
            location: url,
          });
        }
      });
    });

    // Check URL params reflected in page source
    const parsed = new URL(url);
    const rawHTML = document.documentElement.innerHTML;
    parsed.searchParams.forEach((value, param) => {
      if (value.length > 2 && rawHTML.includes(value)) {
        results.push({
          type: "Reflected Input",
          severity: "medium",
          detail: `URL param "${param}" value appears reflected in the page DOM — potential reflected XSS`,
          location: url,
        });
      }
    });

    return results;
  }

  // ─────────────────────────────────────────────
  // Sensitive Information Exposure
  // Mirrors check_sensitive_info: regex scan over visible page text
  // ─────────────────────────────────────────────
  function checkSensitiveInfo() {
    const results = [];
    const url = window.location.href;
    const pageText = document.documentElement.innerHTML;

    const patterns = [
      {
        label: "Email Address",
        severity: "low",
        regex: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
      },
      {
        label: "Phone Number",
        severity: "low",
        regex: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g,
      },
      {
        label: "SSN",
        severity: "critical",
        regex: /\b\d{3}-\d{2}-\d{4}\b/g,
      },
      {
        label: "API Key",
        severity: "critical",
        regex: /api[_\-]?key[_\-]?['"`]?\s*[:=]\s*['"`]?([a-zA-Z0-9]{32,45})/gi,
      },
      {
        label: "Bearer Token",
        severity: "critical",
        regex: /bearer\s+[a-zA-Z0-9\-._~+/]+=*/gi,
      },
      {
        label: "AWS Key",
        severity: "critical",
        regex: /AKIA[0-9A-Z]{16}/g,
      },
      {
        label: "Private Key Header",
        severity: "critical",
        regex: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
      },
    ];

    patterns.forEach(({ label, severity, regex }) => {
      const matches = [...pageText.matchAll(regex)];
      if (matches.length > 0) {
        results.push({
          type: "Sensitive Info Exposure",
          severity,
          detail: `${matches.length} instance(s) of ${label} detected in page source`,
          location: url,
        });
      }
    });

    return results;
  }

  // ─────────────────────────────────────────────
  // Security Headers Check (bonus — extension context)
  // ─────────────────────────────────────────────
  function checkSecurityMeta() {
    const results = [];
    const url = window.location.href;

    // CSP via meta tag
    const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    if (!cspMeta) {
      results.push({
        type: "Missing CSP",
        severity: "medium",
        detail: "No Content-Security-Policy meta tag found — XSS protections may be absent",
        location: url,
      });
    }

    // Check if running over HTTP (not HTTPS)
    if (window.location.protocol === "http:") {
      results.push({
        type: "Insecure Protocol",
        severity: "high",
        detail: "Page served over HTTP — data is transmitted unencrypted",
        location: url,
      });
    }

    // Mixed content
    const httpResources = [
      ...document.querySelectorAll("script[src], link[href], img[src], iframe[src]"),
    ].filter((el) => {
      const attr = el.src || el.href;
      return typeof attr === "string" && attr.startsWith("http://");
    });
    if (httpResources.length > 0) {
      results.push({
        type: "Mixed Content",
        severity: "medium",
        detail: `${httpResources.length} resource(s) loaded over HTTP on an HTTPS page`,
        location: url,
      });
    }

    // Forms without CSRF tokens (heuristic)
    const forms = document.querySelectorAll("form");
    forms.forEach((form, i) => {
      const hasCSRF = form.querySelector(
        'input[name*="csrf"], input[name*="token"], input[name*="_token"]'
      );
      if (!hasCSRF) {
        results.push({
          type: "Possible CSRF Risk",
          severity: "medium",
          detail: `Form #${i + 1} (action: ${form.action || "self"}) has no visible CSRF token field`,
          location: url,
        });
      }
    });

    return results;
  }

  // ─────────────────────────────────────────────
  // Main scan entry point — called from popup via chrome.tabs.sendMessage
  // ─────────────────────────────────────────────
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.action === "RUN_SCAN") {
      try {
        const sqlResults = checkSQLInjection();
        const xssResults = checkXSS();
        const sensitiveResults = checkSensitiveInfo();
        const metaResults = checkSecurityMeta();

        const all = [...sqlResults, ...xssResults, ...sensitiveResults, ...metaResults];

        sendResponse({
          success: true,
          url: window.location.href,
          title: document.title,
          results: all,
          stats: {
            critical: all.filter((r) => r.severity === "critical").length,
            high: all.filter((r) => r.severity === "high").length,
            medium: all.filter((r) => r.severity === "medium").length,
            low: all.filter((r) => r.severity === "low").length,
          },
        });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
      return true; // keep channel open for async
    }
  });
})();
