import customtkinter as ctk
import threading
import time
import sys
import os
from collections import defaultdict

sys.path.insert(0, os.path.dirname(__file__))
try:
    from scanner import WebSecurityScanner
    SCANNER_AVAILABLE = True
except ImportError:
    SCANNER_AVAILABLE = False

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ── Palette ────────────────────────────────────────────────────────────────────
BG      = "#0d1117"
PANEL   = "#161b22"
PANEL2  = "#1c2330"
DARK    = "#21262d"
BORDER  = "#30363d"
CYAN    = "#58a6ff"
GREEN   = "#3fb950"
YELLOW  = "#d29922"
ORANGE  = "#f0883e"
RED     = "#f85149"
PURPLE  = "#bc8cff"
WHITE   = "#e6edf3"
MUTED   = "#8b949e"

MONO_XS = ("Courier New", 10)
MONO_SM = ("Courier New", 11)

# Severity config — highest first
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_MAP = {
    "sql injection":                  ("CRITICAL", RED),
    "cross-site scripting":           ("HIGH",     ORANGE),
    "xss":                            ("HIGH",     ORANGE),
    "sensitive information exposure": ("MEDIUM",   YELLOW),
}

def get_severity(vuln_type):
    low = vuln_type.lower()
    for k, v in SEVERITY_MAP.items():
        if k in low:
            return v
    return ("LOW", MUTED)


class ScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("WebSec Scanner")
        self.geometry("940x800")
        self.minsize(780, 640)
        self.configure(fg_color=BG)

        self._scanning = False
        self._vulns    = []
        self._url_count = 0

        self._build_ui()

    # ── Build ──────────────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Header bar ──
        hdr = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=0,
                           border_width=0, height=52)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        ctk.CTkLabel(hdr, text="⬡  WebSec Scanner",
                     font=("Segoe UI", 16, "bold"), text_color=WHITE
                     ).pack(side="left", padx=20)

        self._status = ctk.CTkLabel(hdr, text="● IDLE",
                                    font=("Segoe UI", 10, "bold"), text_color=MUTED)
        self._status.pack(side="right", padx=20)

        if not SCANNER_AVAILABLE:
            ctk.CTkLabel(hdr, text="demo mode",
                         font=("Segoe UI", 10), text_color=YELLOW
                         ).pack(side="right", padx=4)

        # ── URL + buttons ──
        top = ctk.CTkFrame(self, fg_color=PANEL2, corner_radius=0,
                           border_width=0)
        top.pack(fill="x", padx=0, pady=(1, 0))

        inner = ctk.CTkFrame(top, fg_color="transparent")
        inner.pack(fill="x", padx=20, pady=14)
        inner.columnconfigure(0, weight=1)

        # URL entry
        ctk.CTkLabel(inner, text="TARGET URL",
                     font=("Segoe UI", 9, "bold"), text_color=MUTED
                     ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 4))

        self.url_entry = ctk.CTkEntry(
            inner,
            placeholder_text="https://target.com/page?param=value",
            font=MONO_SM, fg_color=DARK, border_color=BORDER,
            text_color=CYAN, placeholder_text_color=MUTED,
            height=40, corner_radius=6
        )
        self.url_entry.grid(row=1, column=0, sticky="ew", padx=(0, 10))
        self.url_entry.bind("<Return>", lambda _: self._start_scan("quick"))

        self.btn_quick = ctk.CTkButton(
            inner, text="⚡  Quick Scan",
            font=("Segoe UI", 12, "bold"),
            width=150, height=40, corner_radius=6,
            fg_color=CYAN, text_color=BG, hover_color="#3d8fd4",
            command=lambda: self._start_scan("quick")
        )
        self.btn_quick.grid(row=1, column=1, padx=(0, 6))

        self.btn_deep = ctk.CTkButton(
            inner, text="🕷  Deep Scan",
            font=("Segoe UI", 12, "bold"),
            width=150, height=40, corner_radius=6,
            fg_color=PURPLE, text_color=BG, hover_color="#9a6fd8",
            command=lambda: self._start_scan("deep")
        )
        self.btn_deep.grid(row=1, column=2)

        ctk.CTkLabel(inner, text="Single URL, no crawling",
                     font=("Segoe UI", 9), text_color=MUTED
                     ).grid(row=2, column=1, pady=(3, 0))
        ctk.CTkLabel(inner, text="Crawls entire site",
                     font=("Segoe UI", 9), text_color=MUTED
                     ).grid(row=2, column=2, pady=(3, 0))

        # ── Progress bar ──
        self.progress = ctk.CTkProgressBar(
            self, height=3, fg_color=DARK,
            progress_color=CYAN, corner_radius=0
        )
        self.progress.pack(fill="x")
        self.progress.set(0)

        # ── Stats row ──
        stats_wrap = ctk.CTkFrame(self, fg_color="transparent")
        stats_wrap.pack(fill="x", padx=20, pady=(10, 0))
        stats_wrap.columnconfigure((0, 1, 2, 3), weight=1)

        self._s_urls = self._stat_box(stats_wrap, "0",  "URLs Scanned", CYAN,   0)
        self._s_crit = self._stat_box(stats_wrap, "0",  "Critical",     RED,    1)
        self._s_high = self._stat_box(stats_wrap, "0",  "High",         ORANGE, 2)
        self._s_med  = self._stat_box(stats_wrap, "0",  "Medium",       YELLOW, 3)

        # ── Main pane ──
        pane = ctk.CTkFrame(self, fg_color="transparent")
        pane.pack(fill="both", expand=True, padx=20, pady=(10, 0))
        pane.columnconfigure(0, weight=5)
        pane.columnconfigure(1, weight=3)
        pane.rowconfigure(0, weight=1)

        # Left — live log
        log_outer = ctk.CTkFrame(pane, fg_color=PANEL, corner_radius=8,
                                 border_width=1, border_color=BORDER)
        log_outer.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        log_outer.rowconfigure(1, weight=1)
        log_outer.columnconfigure(0, weight=1)

        ctk.CTkLabel(log_outer, text="LIVE OUTPUT",
                     font=("Segoe UI", 9, "bold"), text_color=MUTED
                     ).grid(row=0, column=0, sticky="w", padx=12, pady=(8, 2))

        self.terminal = ctk.CTkTextbox(
            log_outer, font=MONO_XS, fg_color=BG,
            text_color=WHITE, wrap="word",
            scrollbar_button_color=DARK, border_width=0, corner_radius=0
        )
        self.terminal.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))
        self.terminal.configure(state="disabled")

        tw = self.terminal._textbox
        tw.tag_config("info",   foreground=CYAN)
        tw.tag_config("ok",     foreground=GREEN)
        tw.tag_config("warn",   foreground=YELLOW)
        tw.tag_config("err",    foreground=RED)
        tw.tag_config("dim",    foreground=MUTED)
        tw.tag_config("purple", foreground=PURPLE)
        tw.tag_config("orange", foreground=ORANGE)

        # Right — findings
        find_outer = ctk.CTkFrame(pane, fg_color=PANEL, corner_radius=8,
                                  border_width=1, border_color=BORDER)
        find_outer.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        find_outer.rowconfigure(1, weight=1)
        find_outer.columnconfigure(0, weight=1)

        ctk.CTkLabel(find_outer, text="FINDINGS",
                     font=("Segoe UI", 9, "bold"), text_color=MUTED
                     ).grid(row=0, column=0, sticky="w", padx=12, pady=(8, 2))

        self.findings_scroll = ctk.CTkScrollableFrame(
            find_outer, fg_color=BG, corner_radius=0,
            scrollbar_button_color=DARK
        )
        self.findings_scroll.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))
        self.findings_scroll.columnconfigure(0, weight=1)

        self._draw_findings()

        # Footer
        ctk.CTkLabel(
            self,
            text="⚠  Only scan systems you own or have explicit permission to test.",
            font=("Segoe UI", 9), text_color=MUTED
        ).pack(pady=(6, 8))

        self._log("Ready. Enter a URL and press Quick Scan or Deep Scan.", "dim")

    def _stat_box(self, parent, val, label, color, col):
        box = ctk.CTkFrame(parent, fg_color=PANEL, corner_radius=6,
                           border_width=1, border_color=BORDER)
        box.grid(row=0, column=col, padx=4, sticky="ew")
        num = ctk.CTkLabel(box, text=val,
                           font=("Segoe UI", 24, "bold"), text_color=color)
        num.pack(pady=(10, 0))
        ctk.CTkLabel(box, text=label,
                     font=("Segoe UI", 9), text_color=MUTED).pack(pady=(0, 10))
        return num

    # ── Logging ────────────────────────────────────────────────────────────────

    def _log(self, text, tag="plain"):
        self.terminal.configure(state="normal")
        self.terminal._textbox.insert("end", text + "\n", tag)
        self.terminal.configure(state="disabled")
        self.terminal._textbox.see("end")

    def _clear_log(self):
        self.terminal.configure(state="normal")
        self.terminal.delete("0.0", "end")
        self.terminal.configure(state="disabled")

    # ── Findings ───────────────────────────────────────────────────────────────

    def _draw_findings(self):
        for w in self.findings_scroll.winfo_children():
            w.destroy()

        if not self._vulns:
            ctk.CTkLabel(self.findings_scroll,
                         text="No findings yet.", font=("Segoe UI", 10),
                         text_color=MUTED).grid(row=0, column=0, pady=24)
            return

        # Sort by severity then group by type
        sorted_vulns = sorted(
            self._vulns,
            key=lambda v: SEVERITY_ORDER.get(get_severity(v["type"])[0], 9)
        )
        grouped = defaultdict(list)
        for v in sorted_vulns:
            grouped[v["type"]].append(v)

        # Preserve severity order across groups
        seen = []
        for v in sorted_vulns:
            if v["type"] not in seen:
                seen.append(v["type"])

        row = 0
        for vtype in seen:
            items = grouped[vtype]
            sev, color = get_severity(vtype)

            # ── Group header ──
            hdr = ctk.CTkFrame(self.findings_scroll, fg_color=PANEL2,
                               corner_radius=6, border_width=1, border_color=color)
            hdr.grid(row=row, column=0, sticky="ew", pady=(6, 2), padx=2)
            hdr.columnconfigure(1, weight=1)
            row += 1

            ctk.CTkLabel(hdr, text="●", font=("Segoe UI", 11),
                         text_color=color, width=18
                         ).grid(row=0, column=0, padx=(8, 4), pady=8)

            ctk.CTkLabel(hdr, text=vtype,
                         font=("Segoe UI", 10, "bold"),
                         text_color=WHITE, anchor="w"
                         ).grid(row=0, column=1, sticky="w")

            badge_frame = ctk.CTkFrame(hdr, fg_color=color, corner_radius=4)
            badge_frame.grid(row=0, column=2, padx=(4, 8))
            ctk.CTkLabel(badge_frame,
                         text=f"  {sev} · {len(items)}  ",
                         font=("Segoe UI", 8, "bold"),
                         text_color=BG).pack()

            # ── Individual cards ──
            for v in items:
                card = ctk.CTkFrame(self.findings_scroll, fg_color=DARK,
                                    corner_radius=4, border_width=1,
                                    border_color=BORDER)
                card.grid(row=row, column=0, sticky="ew",
                          pady=(1, 0), padx=10)
                card.columnconfigure(0, weight=1)
                row += 1

                details = {k: val for k, val in v.items() if k != "type"}
                for k, val in details.items():
                    line = ctk.CTkFrame(card, fg_color="transparent")
                    line.pack(fill="x", padx=10, pady=(4 if k == list(details)[0] else 1,
                                                        4 if k == list(details)[-1] else 1))
                    ctk.CTkLabel(line, text=f"{k}:",
                                 font=("Segoe UI", 9, "bold"),
                                 text_color=MUTED, width=70, anchor="w"
                                 ).pack(side="left")
                    ctk.CTkLabel(line, text=str(val),
                                 font=MONO_XS, text_color=WHITE,
                                 anchor="w", wraplength=180, justify="left"
                                 ).pack(side="left", fill="x", expand=True)

    def _refresh_stats(self):
        counts = defaultdict(int)
        for v in self._vulns:
            sev, _ = get_severity(v["type"])
            counts[sev] += 1
        self._s_urls.configure(text=str(self._url_count))
        self._s_crit.configure(text=str(counts["CRITICAL"]))
        self._s_high.configure(text=str(counts["HIGH"]))
        self._s_med.configure(text=str(counts["MEDIUM"]))

    # ── Scan ───────────────────────────────────────────────────────────────────

    def _start_scan(self, mode):
        if self._scanning:
            return
        url = self.url_entry.get().strip()
        if not url:
            self._log("✗  No URL provided.", "warn"); return
        if not url.startswith(("http://", "https://")):
            self._log("✗  URL must start with http:// or https://", "warn"); return

        self._scanning = True
        self._vulns = []
        self._url_count = 0
        self._clear_log()
        self._draw_findings()
        self._refresh_stats()

        self.btn_quick.configure(state="disabled", fg_color=DARK, text_color=MUTED)
        self.btn_deep.configure(state="disabled",  fg_color=DARK, text_color=MUTED)

        color = CYAN if mode == "quick" else PURPLE
        label = "QUICK SCAN" if mode == "quick" else "DEEP SCAN"
        self._status.configure(text=f"● {label}...", text_color=color)
        self.progress.configure(progress_color=color)

        threading.Thread(target=self._run, args=(url, mode), daemon=True).start()
        self._pulse()

    def _pulse(self):
        if not self._scanning:
            self.progress.set(0); return
        self.progress.set((self.progress.get() + 0.015) % 1.0)
        self.after(40, self._pulse)

    def _run(self, url, mode):
        t0 = time.time()
        tag = "info" if mode == "quick" else "purple"
        label = "Quick Scan" if mode == "quick" else "Deep Scan"

        self.after(0, self._log, f"[{label}]  {url}", tag)
        self.after(0, self._log, "─" * 56, "dim")

        if SCANNER_AVAILABLE:
            self._real_scan(url, mode)
        else:
            self._demo_scan(url, mode)

        elapsed = f"{time.time() - t0:.1f}s"
        total = len(self._vulns)
        self.after(0, self._log, "─" * 56, "dim")
        self.after(0, self._log,
                   f"Done  ·  {self._url_count} URL(s)  ·  {total} finding(s)  ·  {elapsed}",
                   "ok" if total == 0 else "warn")
        self.after(0, self._finish)

    def _real_scan(self, url, mode):
        scanner = WebSecurityScanner(url)
        orig = scanner.report_vulnerability

        def hook(v):
            orig(v)
            sev, _ = get_severity(v["type"])
            tag = {"CRITICAL": "err", "HIGH": "orange",
                   "MEDIUM": "warn", "LOW": "dim"}.get(sev, "dim")
            self.after(0, self._log,
                       f"  ⚠  [{sev}] {v['type']}  —  "
                       f"{v.get('parameter', v.get('info_type', ''))}", tag)
            self._vulns.append(dict(v))
            self.after(0, self._draw_findings)
            self.after(0, self._refresh_stats)

        scanner.report_vulnerability = hook

        if mode == "quick":
            for step in ("SQL injection", "XSS", "Sensitive data"):
                self.after(0, self._log, f"  → Checking {step}...", "dim")
            scanner.quickscan()
            self._url_count = 1
        else:
            self.after(0, self._log, "  → Crawling site (depth 3)...", "dim")
            scanner.deepscan()
            self._url_count = len(scanner.visited_urls)
            self.after(0, self._log, f"  → Crawled {self._url_count} URL(s)", "dim")

        self.after(0, self._refresh_stats)

    def _demo_scan(self, url, mode):
        import random
        self.after(0, self._log, "  (demo — place scanner.py in same folder)", "warn")

        steps = (["SQL injection", "XSS payloads", "Sensitive data"]
                 if mode == "quick" else
                 ["Crawling site...", "Building URL queue",
                  "SQL injection (threaded)", "XSS (threaded)", "Sensitive data"])
        for s in steps:
            self.after(0, self._log, f"  → {s}", "dim")
            time.sleep(random.uniform(0.3, 0.7))

        self._url_count = 1 if mode == "quick" else random.randint(4, 14)
        self.after(0, self._log, f"  → Scanned {self._url_count} URL(s)", "dim")

        if "?" in url and "=" in url:
            param = url.split("?")[1].split("=")[0]
            demos = [
                {"type": "SQL Injection",                  "url": url, "parameter": param, "payload": "' OR 1=1--"},
                {"type": "Cross-Site Scripting (XSS)",     "url": url, "parameter": param, "payload": "<script>alert(1)</script>"},
                {"type": "Sensitive Information Exposure", "url": url, "info_type": "email", "pattern": "[email regex]"},
            ]
            for v in demos:
                sev, _ = get_severity(v["type"])
                tag = {"CRITICAL": "err", "HIGH": "orange", "MEDIUM": "warn"}.get(sev, "dim")
                self.after(0, self._log,
                           f"  ⚠  [{sev}] {v['type']}", tag)
                self._vulns.append(v)
                self.after(0, self._draw_findings)
                self.after(0, self._refresh_stats)
                time.sleep(0.2)
        else:
            self.after(0, self._log, "  ✓  No vulnerabilities detected.", "ok")

    def _finish(self):
        self._scanning = False
        self.btn_quick.configure(state="normal", fg_color=CYAN,   text_color=BG)
        self.btn_deep.configure(state="normal",  fg_color=PURPLE, text_color=BG)
        has = bool(self._vulns)
        self._status.configure(
            text="● FINDINGS FOUND" if has else "● CLEAN",
            text_color=RED if has else GREEN
        )
        self.progress.set(1)
        self.after(900, self.progress.set, 0)


if __name__ == "__main__":
    app = ScannerApp()
    app.mainloop()
