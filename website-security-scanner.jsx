import { useState, useEffect, useRef } from "react";

const COLORS = {
  bg: "#0a0f1e",
  bgCard: "#0d1525",
  bgCardHover: "#111c33",
  border: "#1a2540",
  borderAccent: "#1e3a6e",
  primary: "#00c8ff",
  primaryDim: "#0099cc",
  danger: "#ff3b3b",
  dangerDim: "#cc2222",
  warn: "#ffaa00",
  warnDim: "#cc8800",
  safe: "#00e67a",
  safeDim: "#00b35e",
  text: "#e8eeff",
  textMuted: "#6b7fa3",
  textDim: "#3d5080",
};

const SCAN_PHASES = [
  "Resolving DNS...",
  "Checking SSL certificate...",
  "Scanning HTTP headers...",
  "Detecting vulnerabilities...",
  "Running OWASP checks...",
  "Analyzing page speed...",
  "Checking AdBlock compatibility...",
  "Generating report...",
];

function generateScanResult(url) {
  const domain = url.replace(/https?:\/\//, "").split("/")[0];
  const isHttps = url.startsWith("https");
  const seed = domain.split("").reduce((a, c) => a + c.charCodeAt(0), 0);
  const rand = (min, max, s = seed) => min + ((s * 9301 + 49297) % 233280) / 233280 * (max - min) | 0;

  const sslScore = isHttps ? rand(60, 100) : rand(0, 30);
  const headersScore = rand(30, 90, seed + 1);
  const speedScore = rand(25, 95, seed + 2);
  const vulnCount = rand(0, 8, seed + 3);
  const overallScore = Math.round((sslScore * 0.4 + headersScore * 0.3 + speedScore * 0.2 + (100 - vulnCount * 10) * 0.1));

  const missingHeaders = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
  ].filter((_, i) => rand(0, 10, seed + i * 7) < 5);

  const vulns = [
    { id: 1, name: "Missing HSTS Header", severity: "high", desc: "Your site doesn't enforce HTTPS, leaving users vulnerable to downgrade attacks." },
    { id: 2, name: "Clickjacking Vulnerability", severity: "high", desc: "No X-Frame-Options header detected. Attackers can embed your site in an iframe." },
    { id: 3, name: "Mixed Content", severity: "medium", desc: "HTTP resources loaded on HTTPS page weaken your security posture." },
    { id: 4, name: "Missing CSP Header", severity: "high", desc: "Content Security Policy not set. XSS attacks are significantly easier." },
    { id: 5, name: "Insecure Cookie Flags", severity: "medium", desc: "Session cookies lack Secure and HttpOnly flags." },
    { id: 6, name: "Server Version Exposed", severity: "low", desc: "Server response reveals version info that aids targeted attacks." },
    { id: 7, name: "Directory Listing Enabled", severity: "medium", desc: "Server may expose sensitive file listings to unauthorized users." },
    { id: 8, name: "Outdated TLS Version", severity: "high", desc: "TLS 1.0 or 1.1 detected — vulnerable to POODLE and BEAST attacks." },
  ].slice(0, vulnCount);

  return {
    url, domain,
    ssl: {
      valid: isHttps,
      score: sslScore,
      expiry: isHttps ? `${rand(30, 365, seed + 10)} days remaining` : "No SSL certificate",
      grade: sslScore > 80 ? "A+" : sslScore > 60 ? "B" : sslScore > 40 ? "C" : "F",
    },
    headers: { score: headersScore, missing: missingHeaders },
    speed: {
      score: speedScore,
      loadTime: `${(rand(8, 50, seed + 4) / 10).toFixed(1)}s`,
      pageSize: `${rand(200, 4000, seed + 5)} KB`,
      requests: rand(10, 120, seed + 6),
    },
    vulnerabilities: vulns,
    adBlock: rand(0, 2, seed + 8) === 0,
    overallScore,
    scannedAt: new Date().toLocaleString(),
  };
}

function ScoreRing({ score, size = 120, label }) {
  const r = size / 2 - 10;
  const circ = 2 * Math.PI * r;
  const pct = score / 100;
  const color = score >= 70 ? COLORS.safe : score >= 40 ? COLORS.warn : COLORS.danger;
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}>
      <svg width={size} height={size} style={{ transform: "rotate(-90deg)" }}>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={COLORS.border} strokeWidth={8} />
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth={8}
          strokeDasharray={circ} strokeDashoffset={circ * (1 - pct)} strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 1.2s ease" }} />
        <text x={size/2} y={size/2 + 6} textAnchor="middle" fill={color}
          style={{ fontSize: 22, fontWeight: 700, transform: "rotate(90deg)", transformOrigin: `${size/2}px ${size/2}px`, fontFamily: "monospace" }}>
          {score}
        </text>
      </svg>
      <span style={{ fontSize: 11, color: COLORS.textMuted, letterSpacing: 1, textTransform: "uppercase" }}>{label}</span>
    </div>
  );
}

function SeverityBadge({ severity }) {
  const map = { high: [COLORS.danger, "#3a0a0a"], medium: [COLORS.warn, "#2d1f00"], low: [COLORS.primary, "#001f2d"] };
  const [color, bg] = map[severity] || [COLORS.textMuted, COLORS.bgCard];
  return (
    <span style={{ background: bg, color, border: `1px solid ${color}40`, borderRadius: 4, padding: "2px 8px", fontSize: 10, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase" }}>
      {severity}
    </span>
  );
}

function ProgressBar({ value, color, label }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
        <span style={{ fontSize: 12, color: COLORS.textMuted }}>{label}</span>
        <span style={{ fontSize: 12, color, fontWeight: 700 }}>{value}%</span>
      </div>
      <div style={{ height: 6, background: COLORS.border, borderRadius: 3, overflow: "hidden" }}>
        <div style={{ width: `${value}%`, height: "100%", background: color, borderRadius: 3, transition: "width 1s ease" }} />
      </div>
    </div>
  );
}

function ScannerPage({ onScanComplete }) {
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [phase, setPhase] = useState(0);
  const [phaseText, setPhaseText] = useState("");

  const handleScan = async () => {
    let target = url.trim();
    if (!target) return;
    if (!target.startsWith("http")) target = "https://" + target;
    setScanning(true);
    for (let i = 0; i < SCAN_PHASES.length; i++) {
      setPhase(Math.round((i / SCAN_PHASES.length) * 100));
      setPhaseText(SCAN_PHASES[i]);
      await new Promise(r => setTimeout(r, 350 + Math.random() * 200));
    }
    setPhase(100);
    await new Promise(r => setTimeout(r, 300));
    onScanComplete(generateScanResult(target));
  };

  return (
    <div style={{ minHeight: "100vh", background: COLORS.bg, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: 24 }}>
      <div style={{ textAlign: "center", marginBottom: 48 }}>
        <div style={{ fontSize: 11, letterSpacing: 3, color: COLORS.primary, marginBottom: 16, textTransform: "uppercase" }}>
          ◈ Security Intelligence Platform
        </div>
        <h1 style={{ fontSize: 48, fontWeight: 800, color: COLORS.text, margin: 0, lineHeight: 1.1, fontFamily: "monospace" }}>
          WEBSITE<br /><span style={{ color: COLORS.primary }}>SCANNER</span>
        </h1>
        <p style={{ color: COLORS.textMuted, marginTop: 16, fontSize: 15 }}>
          Detect SSL issues · Security vulnerabilities · Performance threats
        </p>
      </div>

      {!scanning ? (
        <div style={{ width: "100%", maxWidth: 600 }}>
          <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
            <input
              value={url}
              onChange={e => setUrl(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleScan()}
              placeholder="Enter website URL (e.g. example.com)"
              style={{
                flex: 1, padding: "14px 20px", background: COLORS.bgCard, border: `1px solid ${COLORS.borderAccent}`,
                borderRadius: 8, color: COLORS.text, fontSize: 15, outline: "none", fontFamily: "monospace",
              }}
            />
            <button onClick={handleScan} style={{
              padding: "14px 28px", background: COLORS.primary, border: "none", borderRadius: 8,
              color: "#000", fontSize: 14, fontWeight: 700, cursor: "pointer", letterSpacing: 1,
              textTransform: "uppercase", fontFamily: "monospace",
            }}>
              SCAN →
            </button>
          </div>
          <div style={{ display: "flex", gap: 8, justifyContent: "center", flexWrap: "wrap" }}>
            {["google.com", "github.com", "http://example.com"].map(s => (
              <button key={s} onClick={() => setUrl(s)} style={{
                padding: "6px 14px", background: "transparent", border: `1px solid ${COLORS.border}`,
                borderRadius: 20, color: COLORS.textMuted, fontSize: 12, cursor: "pointer",
              }}>
                {s}
              </button>
            ))}
          </div>
        </div>
      ) : (
        <div style={{ width: "100%", maxWidth: 500, textAlign: "center" }}>
          <div style={{ marginBottom: 24 }}>
            <div style={{ fontSize: 48, fontWeight: 800, color: COLORS.primary, fontFamily: "monospace" }}>
              {phase}%
            </div>
            <div style={{ color: COLORS.textMuted, fontSize: 14, marginTop: 8, fontFamily: "monospace" }}>{phaseText}</div>
          </div>
          <div style={{ height: 4, background: COLORS.border, borderRadius: 2, overflow: "hidden" }}>
            <div style={{ width: `${phase}%`, height: "100%", background: `linear-gradient(90deg, ${COLORS.primaryDim}, ${COLORS.primary})`, transition: "width 0.3s ease", borderRadius: 2 }} />
          </div>
          <div style={{ marginTop: 24, display: "flex", gap: 8, justifyContent: "center", flexWrap: "wrap" }}>
            {SCAN_PHASES.map((p, i) => (
              <span key={i} style={{
                width: 8, height: 8, borderRadius: "50%",
                background: i < Math.floor(phase / (100 / SCAN_PHASES.length)) ? COLORS.primary : COLORS.border,
                transition: "background 0.3s",
              }} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function ReportPage({ result, onRescan }) {
  const [activeTab, setActiveTab] = useState("overview");
  const score = result.overallScore;
  const scoreColor = score >= 70 ? COLORS.safe : score >= 40 ? COLORS.warn : COLORS.danger;

  const tabs = ["overview", "ssl", "vulnerabilities", "performance", "headers"];

  return (
    <div style={{ minHeight: "100vh", background: COLORS.bg, color: COLORS.text, fontFamily: "'Courier New', monospace" }}>
      {/* Header */}
      <div style={{ background: COLORS.bgCard, borderBottom: `1px solid ${COLORS.border}`, padding: "16px 24px", display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 12 }}>
        <div>
          <div style={{ fontSize: 10, color: COLORS.textMuted, letterSpacing: 2, textTransform: "uppercase", marginBottom: 4 }}>Security Report</div>
          <div style={{ fontSize: 16, color: COLORS.primary, fontWeight: 700 }}>{result.domain}</div>
          <div style={{ fontSize: 11, color: COLORS.textDim }}>Scanned: {result.scannedAt}</div>
        </div>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          {result.adBlock && (
            <div style={{ background: "#2d1f00", border: `1px solid ${COLORS.warn}40`, color: COLORS.warn, borderRadius: 6, padding: "6px 12px", fontSize: 11 }}>
              ⚠ AdBlock Detected
            </div>
          )}
          <div style={{ textAlign: "center", background: `${scoreColor}15`, border: `2px solid ${scoreColor}`, borderRadius: 10, padding: "8px 20px" }}>
            <div style={{ fontSize: 28, fontWeight: 800, color: scoreColor }}>{score}</div>
            <div style={{ fontSize: 9, color: scoreColor, letterSpacing: 2, textTransform: "uppercase" }}>Security Score</div>
          </div>
          <button onClick={onRescan} style={{ padding: "8px 16px", background: "transparent", border: `1px solid ${COLORS.border}`, borderRadius: 6, color: COLORS.textMuted, cursor: "pointer", fontSize: 12 }}>
            ↩ Rescan
          </button>
        </div>
      </div>

      {/* Urgency banner */}
      {score < 50 && (
        <div style={{ background: "#3a0a0a", borderBottom: `2px solid ${COLORS.danger}`, padding: "10px 24px", display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ color: COLORS.danger, fontSize: 16 }}>⚡</span>
          <span style={{ color: COLORS.danger, fontWeight: 700, fontSize: 13 }}>CRITICAL RISK DETECTED</span>
          <span style={{ color: "#ff8080", fontSize: 12 }}>— Your website has serious vulnerabilities that could compromise user data. Immediate action required.</span>
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: "flex", borderBottom: `1px solid ${COLORS.border}`, padding: "0 24px", overflowX: "auto" }}>
        {tabs.map(t => (
          <button key={t} onClick={() => setActiveTab(t)} style={{
            padding: "14px 20px", background: "transparent", border: "none",
            borderBottom: activeTab === t ? `2px solid ${COLORS.primary}` : "2px solid transparent",
            color: activeTab === t ? COLORS.primary : COLORS.textMuted,
            cursor: "pointer", fontSize: 12, letterSpacing: 1, textTransform: "uppercase", whiteSpace: "nowrap",
          }}>
            {t}
          </button>
        ))}
      </div>

      <div style={{ padding: 24, maxWidth: 1100, margin: "0 auto" }}>
        {activeTab === "overview" && (
          <div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 16, marginBottom: 24 }}>
              {[
                { label: "SSL Security", score: result.ssl.score, icon: "🔒" },
                { label: "Headers", score: result.headers.score, icon: "🛡" },
                { label: "Performance", score: result.speed.score, icon: "⚡" },
                { label: "Vulnerability Risk", score: Math.max(0, 100 - result.vulnerabilities.length * 12), icon: "🔍" },
              ].map(card => {
                const c = card.score >= 70 ? COLORS.safe : card.score >= 40 ? COLORS.warn : COLORS.danger;
                return (
                  <div key={card.label} style={{ background: COLORS.bgCard, border: `1px solid ${COLORS.border}`, borderRadius: 10, padding: 20, position: "relative", overflow: "hidden" }}>
                    <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 3, background: c }} />
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                      <div>
                        <div style={{ fontSize: 11, color: COLORS.textMuted, letterSpacing: 1, textTransform: "uppercase", marginBottom: 8 }}>{card.label}</div>
                        <div style={{ fontSize: 36, fontWeight: 800, color: c }}>{card.score}</div>
                        <div style={{ fontSize: 10, color: COLORS.textMuted }}>out of 100</div>
                      </div>
                      <div style={{ fontSize: 28 }}>{card.icon}</div>
                    </div>
                  </div>
                );
              })}
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 16 }}>
              <div style={{ background: COLORS.bgCard, border: `1px solid ${COLORS.border}`, borderRadius: 10, padding: 20 }}>
                <div style={{ fontSize: 11, color: COLORS.textMuted, letterSpacing: 1, textTransform: "uppercase", marginBottom: 16 }}>Score Breakdown</div>
                <ProgressBar value={result.ssl.score} color={result.ssl.score >= 70 ? COLORS.safe : result.ssl.score >= 40 ? COLORS.warn : COLORS.danger} label="SSL / HTTPS" />
                <ProgressBar value={result.headers.score} color={result.headers.score >= 70 ? COLORS.safe : result.headers.score >= 40 ? COLORS.warn : COLORS.danger} label="Security Headers" />
                <ProgressBar value={result.speed.score} color={result.speed.score >= 70 ? COLORS.safe : result.speed.score >= 40 ? COLORS.warn : COLORS.danger} label="Page Speed" />
                <ProgressBar value={Math.max(0, 100 - result.vulnerabilities.length * 12)} color={result.vulnerabilities.length === 0 ? COLORS.safe : result.vulnerabilities.length < 3 ? COLORS.warn : COLORS.danger} label="No Vulnerabilities" />
              </div>

              <div style={{ background: COLORS.bgCard, border: `1px solid ${COLORS.border}`, borderRadius: 10, padding: 20 }}>
                <div style={{ fontSize: 11, color: COLORS.textMuted, letterSpacing: 1, textTransform: "uppercase", marginBottom: 16 }}>Quick Stats</div>
                {[
                  { label: "SSL Status", value: result.ssl.valid ? "✓ Secure" : "✗ Insecure", color: result.ssl.valid ? COLORS.safe : COLORS.danger },
                  { label: "SSL Grade", value: result.ssl.grade, color: result.ssl.grade === "A+" ? COLORS.safe : COLORS.warn },
                  { label: "Cert Expiry", value: result.ssl.expiry, color: COLORS.text },
                  { label: "Vulnerabilities", value: `${result.vulnerabilities.length} found`, color: result.vulnerabilities.length === 0 ? COLORS.safe : result.vulnerabilities.length < 3 ? COLORS.warn : COLORS.danger },
                  { label: "Missing Headers", value: `${result.headers.missing.length} missing`, color: result.headers.missing.length === 0 ? COLORS.safe : COLORS.warn },
                  { label: "Load Time", value: result.speed.loadTime, color: COLORS.text },
                ].map(item => (
                  <div key={item.label} style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: `1px solid ${COLORS.border}` }}>
                    <span style={{ fontSize: 13, color: COLORS.textMuted }}>{item.label}</span>
                    <span style={{ fontSize: 13, color: item.color, fontWeight: 700 }}>{item.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === "ssl" && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 16 }}>
            <div style={{ background: COLORS.bgCard, border: `1px solid ${result.ssl.valid ? COLORS.safe : COLORS.danger}40`, borderRadius: 10, padding: 24 }}>
              <div style={{ fontSize: 11, color: COLORS.textMuted, letterSpacing: 1, textTransform: "uppercase", marginBottom: 20 }}>SSL Certificate</div>
              <div style={{ display: "flex", justifyContent: "space-around", marginBottom: 24 }}>
                <ScoreRing score={result.ssl.score} label="SSL Score" size={100} />
              </div>
              {[
                { label: "HTTPS", value: result.ssl.valid ? "Enabled" : "Not Enabled", ok: result.ssl.valid },
                { label: "Certificate", value: result.ssl.valid ? "Valid" : "Missing", ok: result.ssl.valid },
                { label: "Grade", value: result.ssl.grade, ok: ["A+", "A", "B"].includes(result.ssl.grade) },
                { label: "Expiry", value: result.ssl.expiry, ok: result.ssl.valid },
              ].map(row => (
                <div key={row.label} style={{ display: "flex", justifyContent: "space-between", padding: "10px 0", borderBottom: `1px solid ${COLORS.border}` }}>
                  <span style={{ fontSize: 13, color: COLORS.textMuted }}>{row.label}</span>
                  <span style={{ fontSize: 13, color: row.ok ? COLORS.safe : COLORS.danger, fontWeight: 700 }}>
                    {row.ok ? "✓ " : "✗ "}{row.value}
                  </span>
                </div>
              ))}
            </div>
            <div style={{ background: COLORS.bgCard, border: `1px solid ${COLORS.border}`, borderRadius: 10, padding: 24 }}>
              <div style={{ fontSize: 11, color: COLORS.textMuted, letterSpacing: 1, textTransform: "uppercase", marginBottom: 16 }}>What This Means</div>
              {result.ssl.valid ? (
                <div>
                  <p style={{ color: COLORS.safe, fontSize: 14, marginTop: 0 }}>✓ SSL is properly configured</p>
                  <p style={{ color: COLORS.textMuted, fontSize: 13, lineHeight: 1.6 }}>Your website uses HTTPS encryption. Data transmitted between users and your server is encrypted and protected from eavesdropping.</p>
                </div>
              ) : (
                <div>
                  <div style={{ background: "#3a0a0a", border: `1px solid ${COLORS.danger}40`, borderRadius: 8, padding: 16, marginBottom: 16 }}>
                    <div style={{ color: COLORS.danger, fontWeight: 700, marginBottom: 8 }}>⚡ Fix Immediately</div>
                    <p style={{ color: "#ff8080", fontSize: 13, margin: 0, lineHeight: 1.6 }}>No SSL certificate detected. All data is transmitted in plain text. Users are at HIGH risk of data theft.</p>
                  </div>
                  <p style={{ color: COLORS.textMuted, fontSize: 13, lineHeight: 1.6 }}>Install an SSL certificate immediately. Free options include Let's Encrypt. Your hosting provider may offer automated SSL installation.</p>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === "vulnerabilities" && (
          <div>
            <div style={{ display: "flex", gap: 12, marginBottom: 20, flexWrap: "wrap" }}>
              {["high", "medium", "low"].map(sev => {
                const count = result.vulnerabilities.filter(v => v.severity === sev).length;
                const color = sev === "high" ? COLORS.danger : sev === "medium" ? COLORS.warn : COLORS.primary;
                return (
                  <div key={sev} style={{ background: COLORS.bgCard, border: `1px solid ${color}40`, borderRadius: 8, padding: "12px 20px", display: "flex", alignItems: "center", gap: 12 }}>
                    <div style={{ fontSize: 24, fontWeight: 800, color }}>{count}</div>
                    <div style={{ fontSize: 11, color: COLORS.textMuted, textTransform: "uppercase", letterSpacing: 1 }}>{sev}<br />Severity</div>
                  </div>
                );
              })}
            </div>
            {result.vulnerabilities.length === 0 ? (
              <div style={{ background: COLORS.bgCard, border: `1px solid ${COLORS.safe}40`, borderRadius: 10, padding: 32, textAlign: "center" }}>
                <div style={{ fontSize: 36, marginBottom: 12 }}>✓</div>
                <div style={{ color: COLORS.safe, fontSize: 18, fontWeight: 700 }}>No Vulnerabilities Detected</div>
                <div style={{ color: COLORS.textMuted, fontSize: 13, marginTop: 8 }}>Great job! Your website passed all vulnerability checks.</div>
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                {result.vulnerabilities.map(v => {
                  const color = v.severity === "high" ? COLORS.danger : v.severity === "medium" ? COLORS.warn : COLORS.primary;
                  return (
                    <div key={v.id} style={{ background: COLORS.bgCard, border: `1px solid ${color}30`, borderLeft: `3px solid ${color}`, borderRadius: 10, padding: 20 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8, flexWrap: "wrap", gap: 8 }}>
                        <div style={{ fontSize: 14, fontWeight: 700, color: COLORS.text }}>{v.name}</div>
                        <SeverityBadge severity={v.severity} />
                      </div>
                      <div style={{ fontSize: 13, color: COLORS.textMuted, lineHeight: 1.6 }}>{v.desc}</div>
                      {v.severity === "high" && (
                        <div style={{ marginTop: 12, padding: "6px 12px", background: "#3a0a0a", borderRadius: 6, display: "inline-block" }}>
                          <span style={{ color: COLORS.danger, fontSize: 11, fontWeight: 700 }}>⚡ FIX IMMEDIATELY</span>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {activeTab === "performance" && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 16 }}>
            <div style={{ background: COLORS.bgCard, border: `1px solid ${COLORS.border}`, borderRadius: 10, padding: 24 }}>
              <div style={{ fontSize: 11, color: COLORS.textMuted, letterSpacing: 1, textTransform: "uppercase", marginBottom: 20 }}>Performance Metrics</div>
              <div style={{ display: "flex", justifyContent: "center", marginBottom: 24 }}>
                <ScoreRing score={result.speed.score} label="Performance" size={110} />
              </div>
              {[
                { label: "Load Time", value: result.speed.loadTime, good: parseFloat(result.speed.loadTime) < 3 },
                { label: "Page Size", value: result.speed.pageSize, good: parseInt(result.speed.pageSize) < 1000 },
                { label: "HTTP Requests", value: `${result.speed.requests}`, good: result.speed.requests < 50 },
              ].map(row => (
                <div key={row.label} style={{ display: "flex", justifyContent: "space-between", padding: "10px 0", borderBottom: `1px solid ${COLORS.border}` }}>
                  <span style={{ fontSize: 13, color: COLORS.textMuted }}>{row.label}</span>
                  <span style={{ fontSize: 13, color: row.good ? COLORS.safe : COLORS.warn, fontWeight: 700 }}>{row.value}</span>
                </div>
              ))}
            </div>
            <div style={{ background: COLORS.bgCard, border: `1px solid ${COLORS.border}`, borderRadius: 10, padding: 24 }}>
              <div style={{ fontSize: 11, color: COLORS.textMuted, letterSpacing: 1, textTransform: "uppercase", marginBottom: 16 }}>Optimization Tips</div>
              {[
                "Compress and optimize images using WebP format",
                "Enable browser caching with proper cache-control headers",
                "Minify CSS, JS and HTML files",
                "Use a Content Delivery Network (CDN)",
                "Reduce number of HTTP requests by bundling assets",
                "Enable Gzip or Brotli compression on server",
              ].map((tip, i) => (
                <div key={i} style={{ display: "flex", gap: 10, padding: "8px 0", borderBottom: `1px solid ${COLORS.border}` }}>
                  <span style={{ color: COLORS.primary, fontSize: 12 }}>→</span>
                  <span style={{ fontSize: 12, color: COLORS.textMuted, lineHeight: 1.5 }}>{tip}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === "headers" && (
          <div>
            <div style={{ background: COLORS.bgCard, border: `1px solid ${COLORS.border}`, borderRadius: 10, padding: 24, marginBottom: 16 }}>
              <div style={{ fontSize: 11, color: COLORS.textMuted, letterSpacing: 1, textTransform: "uppercase", marginBottom: 16 }}>Security Headers Status</div>
              {["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"].map(h => {
                const missing = result.headers.missing.includes(h);
                return (
                  <div key={h} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 0", borderBottom: `1px solid ${COLORS.border}`, flexWrap: "wrap", gap: 8 }}>
                    <div>
                      <div style={{ fontSize: 13, color: missing ? COLORS.danger : COLORS.text, fontWeight: 600 }}>{h}</div>
                      <div style={{ fontSize: 11, color: COLORS.textMuted, marginTop: 2 }}>
                        {missing ? "Not configured — vulnerability risk" : "Properly configured"}
                      </div>
                    </div>
                    <span style={{ fontSize: 11, fontWeight: 700, padding: "4px 12px", borderRadius: 4, background: missing ? "#3a0a0a" : "#0a2d1a", color: missing ? COLORS.danger : COLORS.safe, border: `1px solid ${missing ? COLORS.danger : COLORS.safe}40` }}>
                      {missing ? "✗ MISSING" : "✓ PRESENT"}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

const MOCK_ADMIN = {
  totalUsers: 2847,
  totalScans: 15392,
  todayScans: 183,
  contact: { phone: "+91 98765 43210", email: "support@scannerapp.com", address: "Mumbai, India" },
  recentScans: [
    { url: "google.com", score: 94, time: "2 min ago", status: "safe" },
    { url: "example.com", score: 42, time: "5 min ago", status: "warning" },
    { url: "test-site.net", score: 18, time: "12 min ago", status: "danger" },
    { url: "github.com", score: 88, time: "18 min ago", status: "safe" },
    { url: "oldsite.org", score: 33, time: "25 min ago", status: "danger" },
  ],
};

function AdminPage({ onBack }) {
  const [contact, setContact] = useState(MOCK_ADMIN.contact);
  const [editMode, setEditMode] = useState(false);
  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    setSaved(true);
    setEditMode(false);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div style={{ minHeight: "100vh", background: COLORS.bg, color: COLORS.text, fontFamily: "'Courier New', monospace" }}>
      <div style={{ background: COLORS.bgCard, borderBottom: `1px solid ${COLORS.border}`, padding: "16px 24px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <div style={{ fontSize: 10, color: COLORS.textMuted, letterSpacing: 2, textTransform: "uppercase" }}>Admin Panel</div>
          <div style={{ fontSize: 18, fontWeight: 700, color: COLORS.primary }}>System Dashboard</div>
        </div>
        <button onClick={onBack} style={{ padding: "8px 16px", background: "transparent", border: `1px solid ${COLORS.border}`, borderRadius: 6, color: COLORS.textMuted, cursor: "pointer", fontSize: 12 }}>
          ← Back to Scanner
        </button>
      </div>

      <div style={{ padding: 24, maxWidth: 1100, margin: "0 auto" }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 16, marginBottom: 24 }}>
          {[
            { label: "Total Users", value: MOCK_ADMIN.totalUsers.toLocaleString(), color: COLORS.primary },
            { label: "Total Scans", value: MOCK_ADMIN.totalScans.toLocaleString(), color: COLORS.safe },
            { label: "Today's Scans", value: MOCK_ADMIN.todayScans, color: COLORS.warn },
            { label: "Avg Score", value: "67", color: COLORS.text },
          ].map(stat => (
            <div key={stat.label} style={{ background: COLORS.bgCard, border: `1px solid ${COLORS.border}`, borderRadius: 10, padding: 20 }}>
              <div style={{ fontSize: 11, color: COLORS.textMuted, letterSpacing: 1, textTransform: "uppercase", marginBottom: 8 }}>{stat.label}</div>
              <div style={{ fontSize: 32, fontWeight: 800, color: stat.color }}>{stat.value}</div>
            </div>
          ))}
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 16 }}>
          <div style={{ background: COLORS.bgCard, border: `1px solid ${COLORS.border}`, borderRadius: 10, padding: 24 }}>
            <div style={{ fontSize: 11, color: COLORS.textMuted, letterSpacing: 1, textTransform: "uppercase", marginBottom: 16 }}>Recent Scans</div>
            {MOCK_ADMIN.recentScans.map((scan, i) => {
              const color = scan.status === "safe" ? COLORS.safe : scan.status === "warning" ? COLORS.warn : COLORS.danger;
              return (
                <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 0", borderBottom: `1px solid ${COLORS.border}` }}>
                  <div>
                    <div style={{ fontSize: 13, color: COLORS.text }}>{scan.url}</div>
                    <div style={{ fontSize: 11, color: COLORS.textDim }}>{scan.time}</div>
                  </div>
                  <div style={{ fontSize: 16, fontWeight: 800, color }}>{scan.score}</div>
                </div>
              );
            })}
          </div>

          <div style={{ background: COLORS.bgCard, border: `1px solid ${COLORS.border}`, borderRadius: 10, padding: 24 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
              <div style={{ fontSize: 11, color: COLORS.textMuted, letterSpacing: 1, textTransform: "uppercase" }}>Contact Settings</div>
              {saved && <span style={{ color: COLORS.safe, fontSize: 11 }}>✓ Saved!</span>}
            </div>
            {["phone", "email", "address"].map(field => (
              <div key={field} style={{ marginBottom: 16 }}>
                <div style={{ fontSize: 11, color: COLORS.textMuted, letterSpacing: 1, textTransform: "uppercase", marginBottom: 6 }}>{field}</div>
                {editMode ? (
                  <input value={contact[field]} onChange={e => setContact({ ...contact, [field]: e.target.value })}
                    style={{ width: "100%", padding: "8px 12px", background: COLORS.bg, border: `1px solid ${COLORS.borderAccent}`, borderRadius: 6, color: COLORS.text, fontSize: 13, outline: "none", boxSizing: "border-box" }} />
                ) : (
                  <div style={{ fontSize: 13, color: COLORS.text, padding: "8px 0" }}>{contact[field]}</div>
                )}
              </div>
            ))}
            <div style={{ display: "flex", gap: 10 }}>
              {editMode ? (
                <>
                  <button onClick={handleSave} style={{ flex: 1, padding: "8px", background: COLORS.primary, border: "none", borderRadius: 6, color: "#000", cursor: "pointer", fontSize: 12, fontWeight: 700 }}>Save</button>
                  <button onClick={() => setEditMode(false)} style={{ flex: 1, padding: "8px", background: "transparent", border: `1px solid ${COLORS.border}`, borderRadius: 6, color: COLORS.textMuted, cursor: "pointer", fontSize: 12 }}>Cancel</button>
                </>
              ) : (
                <button onClick={() => setEditMode(true)} style={{ flex: 1, padding: "8px", background: "transparent", border: `1px solid ${COLORS.borderAccent}`, borderRadius: 6, color: COLORS.primary, cursor: "pointer", fontSize: 12 }}>
                  Edit Contact Info
                </button>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [view, setView] = useState("scanner");
  const [result, setResult] = useState(null);

  return (
    <div style={{ position: "relative" }}>
      {view !== "admin" && (
        <button onClick={() => setView("admin")} style={{
          position: "absolute", top: 12, right: 12, zIndex: 100,
          padding: "6px 14px", background: "transparent", border: `1px solid ${COLORS.border}`,
          borderRadius: 6, color: COLORS.textMuted, cursor: "pointer", fontSize: 11, fontFamily: "monospace", letterSpacing: 1,
        }}>
          ADMIN
        </button>
      )}

      {view === "scanner" && <ScannerPage onScanComplete={r => { setResult(r); setView("report"); }} />}
      {view === "report" && result && <ReportPage result={result} onRescan={() => setView("scanner")} />}
      {view === "admin" && <AdminPage onBack={() => setView(result ? "report" : "scanner")} />}
    </div>
  );
}
