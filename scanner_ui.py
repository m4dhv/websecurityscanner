import customtkinter as ctk
import threading
import time
import sys
import os

# Allow running standalone or alongside scanner.py
sys.path.insert(0, os.path.dirname(__file__))
try:
    from scanner import WebSecurityScanner
    SCANNER_AVAILABLE = True
except ImportError:
    SCANNER_AVAILABLE = False

# ── Theme ──────────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

BG        = "#050a0e"
PANEL     = "#0a1520"
ACCENT    = "#00e5ff"
RED       = "#ff3c5a"
GREEN     = "#39ff14"
YELLOW    = "#ffb700"
DIM       = "#3a5566"
TEXT      = "#c8d8e4"
MONO      = ("Courier New", 12)
MONO_SM   = ("Courier New", 10)
TITLE_F   = ("Courier New", 22, "bold")
LABEL_F   = ("Courier New", 10)


class ScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("WebSec Scanner")
        self.geometry("860x720")
        self.minsize(720, 580)
        self.configure(fg_color=BG)

        self._scan_thread = None
        self._scanning = False
        self._vuln_count = 0
        self._url_count = 0

        self._build_ui()

    # ── UI Construction ────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Header ──
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=28, pady=(24, 0))

        ctk.CTkLabel(hdr, text="WEBSEC SCANNER", font=TITLE_F,
                     text_color=ACCENT).pack(side="left")

        if not SCANNER_AVAILABLE:
            ctk.CTkLabel(hdr, text="⚠  scanner.py not found — demo mode",
                         font=LABEL_F, text_color=YELLOW).pack(side="right", padx=4)

        # ── Config panel ──
        cfg = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=6,
                           border_width=1, border_color=DIM)
        cfg.pack(fill="x", padx=24, pady=(16, 0))

        ctk.CTkLabel(cfg, text="TARGET URL", font=LABEL_F,
                     text_color=DIM).pack(anchor="w", padx=16, pady=(12, 0))

        url_row = ctk.CTkFrame(cfg, fg_color="transparent")
        url_row.pack(fill="x", padx=16, pady=(4, 12))

        self.url_entry = ctk.CTkEntry(
            url_row, placeholder_text="https://target.com/page?param=value",
            font=MONO_SM, fg_color=BG, border_color=DIM,
            text_color=ACCENT, placeholder_text_color=DIM, height=38
        )
        self.url_entry.pack(fill="x")
        self.url_entry.bind("<Return>", lambda _: self._toggle_scan())

        # ── Mode selector ──
        mode_row = ctk.CTkFrame(cfg, fg_color="transparent")
        mode_row.pack(fill="x", padx=16, pady=(0, 14))
        mode_row.columnconfigure((0, 1), weight=1)

        self._mode = ctk.StringVar(value="quick")

        self.btn_quick = ctk.CTkButton(
            mode_row, text="⚡  Quick Scan\nSingle URL · no crawling",
            font=LABEL_F, height=52,
            fg_color=ACCENT, text_color=BG, hover_color="#00b8cc",
            command=lambda: self._set_mode("quick")
        )
        self.btn_quick.grid(row=0, column=0, padx=(0, 6), sticky="ew")

        self.btn_deep = ctk.CTkButton(
            mode_row, text="🕷  Deep Scan\nCrawls entire site",
            font=LABEL_F, height=52,
            fg_color=PANEL, text_color=DIM,
            border_width=1, border_color=DIM, hover_color="#0d2233",
            command=lambda: self._set_mode("deep")
        )
        self.btn_deep.grid(row=0, column=1, padx=(6, 0), sticky="ew")

        # ── Scan button ──
        self.scan_btn = ctk.CTkButton(
            cfg, text="▶  INITIATE SCAN",
            font=("Courier New", 13, "bold"), height=42,
            fg_color="transparent", border_width=1, border_color=ACCENT,
            text_color=ACCENT, hover_color="#0d2233",
            command=self._toggle_scan
        )
        self.scan_btn.pack(fill="x", padx=16, pady=(0, 16))

        # ── Progress bar ──
        self.progress = ctk.CTkProgressBar(self, height=3,
                                           fg_color=PANEL, progress_color=ACCENT)
        self.progress.pack(fill="x", padx=24, pady=(8, 0))
        self.progress.set(0)

        # ── Stats row ──
        stats_row = ctk.CTkFrame(self, fg_color="transparent")
        stats_row.pack(fill="x", padx=24, pady=(10, 0))
        stats_row.columnconfigure((0, 1, 2), weight=1)

        self._lbl_urls  = self._stat_box(stats_row, "0", "URLs SCANNED",  0)
        self._lbl_vulns = self._stat_box(stats_row, "0", "VULNERABILITIES", 1)
        self._lbl_time  = self._stat_box(stats_row, "—", "SECONDS",        2)

        # ── Terminal output ──
        term_frame = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=6,
                                  border_width=1, border_color=DIM)
        term_frame.pack(fill="both", expand=True, padx=24, pady=(10, 8))

        ctk.CTkLabel(term_frame, text="SCAN OUTPUT", font=LABEL_F,
                     text_color=DIM).pack(anchor="w", padx=14, pady=(8, 0))

        self.terminal = ctk.CTkTextbox(
            term_frame, font=MONO_SM, fg_color=BG,
            text_color=TEXT, wrap="word",
            scrollbar_button_color=DIM, border_width=0
        )
        self.terminal.pack(fill="both", expand=True, padx=10, pady=(4, 10))
        self.terminal.configure(state="disabled")

        # Colour tags via underlying tk Text widget
        tw = self.terminal._textbox
        tw.tag_config("info",  foreground=ACCENT)
        tw.tag_config("vuln",  foreground=RED)
        tw.tag_config("ok",    foreground=GREEN)
        tw.tag_config("warn",  foreground=YELLOW)
        tw.tag_config("dim",   foreground=DIM)
        tw.tag_config("plain", foreground=TEXT)

        # ── Footer ──
        ctk.CTkLabel(
            self,
            text="Only scan systems you own or have explicit written permission to test.",
            font=LABEL_F, text_color=DIM
        ).pack(pady=(0, 10))

        self._log("WebSec Scanner ready.", "dim")
        self._log("Enter a URL, choose a mode, then hit INITIATE SCAN.", "dim")

    def _stat_box(self, parent, num, label, col):
        box = ctk.CTkFrame(parent, fg_color=PANEL, corner_radius=4,
                           border_width=1, border_color=DIM)
        box.grid(row=0, column=col, padx=4, sticky="ew")
        num_lbl = ctk.CTkLabel(box, text=num,
                               font=("Courier New", 26, "bold"), text_color=ACCENT)
        num_lbl.pack(pady=(10, 0))
        ctk.CTkLabel(box, text=label, font=LABEL_F, text_color=DIM).pack(pady=(0, 10))
        return num_lbl

    # ── Mode toggle ───────────────────────────────────────────────────────────

    def _set_mode(self, mode):
        self._mode.set(mode)
        if mode == "quick":
            self.btn_quick.configure(fg_color=ACCENT, text_color=BG)
            self.btn_deep.configure(fg_color=PANEL, text_color=DIM, border_color=DIM)
        else:
            self.btn_deep.configure(fg_color=ACCENT, text_color=BG)
            self.btn_quick.configure(fg_color=PANEL, text_color=DIM, border_color=DIM)

    # ── Terminal helpers ───────────────────────────────────────────────────────

    def _log(self, text, tag="plain"):
        self.terminal.configure(state="normal")
        self.terminal._textbox.insert("end", text + "\n", tag)
        self.terminal.configure(state="disabled")
        self.terminal._textbox.see("end")

    def _clear_terminal(self):
        self.terminal.configure(state="normal")
        self.terminal.delete("0.0", "end")
        self.terminal.configure(state="disabled")

    def _update_stats(self, urls, vulns):
        self._lbl_urls.configure(text=str(urls))
        color = RED if vulns > 0 else ACCENT
        self._lbl_vulns.configure(text=str(vulns), text_color=color)

    # ── Scan control ──────────────────────────────────────────────────────────

    def _toggle_scan(self):
        if self._scanning:
            return
        url = self.url_entry.get().strip()
        if not url:
            self._log("ERROR: No target URL specified.", "warn")
            return
        if not url.startswith(("http://", "https://")):
            self._log("ERROR: URL must start with http:// or https://", "warn")
            return

        self._scanning = True
        self.scan_btn.configure(text="⟳  SCANNING...", state="disabled")
        self._vuln_count = 0
        self._url_count = 0
        self._lbl_time.configure(text="—")
        self._update_stats(0, 0)
        self._clear_terminal()

        mode = self._mode.get()
        self._scan_thread = threading.Thread(
            target=self._run_scan, args=(url, mode), daemon=True
        )
        self._scan_thread.start()
        self._animate_progress()

    def _animate_progress(self):
        """Pulse the progress bar while scanning."""
        if not self._scanning:
            self.progress.set(0)
            return
        v = self.progress.get()
        self.progress.set((v + 0.012) % 1.0)
        self.after(40, self._animate_progress)

    def _run_scan(self, url, mode):
        start = time.time()
        self.after(0, self._log, f"$ python scanner.py --{mode}scan {url}", "dim")
        self.after(0, self._log, "")

        if SCANNER_AVAILABLE:
            self._real_scan(url, mode)
        else:
            self._demo_scan(url, mode)

        elapsed = f"{time.time() - start:.1f}"
        self.after(0, self._log, "")
        self.after(0, self._log, "Scan complete!", "ok")
        self.after(0, self._log, f"Total URLs scanned : {self._url_count}", "dim")
        self.after(0, self._log, f"Vulnerabilities    : {self._vuln_count}",
                   "vuln" if self._vuln_count else "ok")
        self.after(0, self._log, f"Time elapsed       : {elapsed}s", "dim")
        self.after(0, self._lbl_time.configure, {"text": elapsed})
        self.after(0, self._finish_scan)

    def _real_scan(self, url, mode):
        """Run the actual WebSecurityScanner and stream results."""
        scanner = WebSecurityScanner(url)

        # Monkey-patch report_vulnerability to stream into UI
        original_report = scanner.report_vulnerability
        def ui_report(vuln):
            original_report(vuln)
            self._vuln_count += 1
            self.after(0, self._log, "[VULNERABILITY FOUND]", "vuln")
            for k, v in vuln.items():
                self.after(0, self._log, f"  {k}: {v}", "plain")
            self.after(0, self._log, "")
            self.after(0, self._update_stats, self._url_count, self._vuln_count)

        scanner.report_vulnerability = ui_report

        self.after(0, self._log,
                   f"[{'Quick' if mode == 'quick' else 'Deep'} Scan] {url}", "info")
        self.after(0, self._log, "")

        if mode == "quick":
            scanner.quickscan()
            self._url_count = 1
        else:
            self.after(0, self._log, "  → Crawling site...", "dim")
            scanner.deepscan()
            self._url_count = len(scanner.visited_urls)

        self.after(0, self._update_stats, self._url_count, self._vuln_count)

    def _demo_scan(self, url, mode):
        """Demo mode when scanner.py is not present."""
        import random
        self.after(0, self._log, f"[{'Quick' if mode == 'quick' else 'Deep'} Scan] {url}", "info")
        self.after(0, self._log, "  (demo mode — place scanner.py in the same folder)", "warn")
        self.after(0, self._log, "")

        steps = (
            ["Checking SQL Injection vectors...",
             "Testing XSS payloads...",
             "Scanning for sensitive data..."]
            if mode == "quick" else
            ["Crawling site (depth 3)...",
             "Building URL queue...",
             "SQL Injection checks (threaded)...",
             "XSS checks (threaded)...",
             "Sensitive data scan..."]
        )

        for step in steps:
            self.after(0, self._log, f"  → {step}", "dim")
            time.sleep(random.uniform(0.4, 0.8))

        self._url_count = 1 if mode == "quick" else random.randint(3, 12)

        has_params = "?" in url and "=" in url
        if has_params:
            param = url.split("?")[1].split("=")[0]
            for vuln in [
                {"type": "SQL Injection",    "url": url, "parameter": param, "payload": "' OR 1=1--"},
                {"type": "XSS",              "url": url, "parameter": param, "payload": "<script>alert('XSS')</script>"},
            ]:
                self._vuln_count += 1
                self.after(0, self._log, "[VULNERABILITY FOUND]", "vuln")
                for k, v in vuln.items():
                    self.after(0, self._log, f"  {k}: {v}", "plain")
                self.after(0, self._log, "")
                self.after(0, self._update_stats, self._url_count, self._vuln_count)
                time.sleep(0.2)

        if self._vuln_count == 0:
            self.after(0, self._log, "No vulnerabilities detected.", "ok")

    def _finish_scan(self):
        self._scanning = False
        self.scan_btn.configure(text="▶  INITIATE SCAN", state="normal")
        self.progress.set(1)
        self.after(800, self.progress.set, 0)


if __name__ == "__main__":
    app = ScannerApp()
    app.mainloop()
