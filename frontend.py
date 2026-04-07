"""
app.py — WebSec Scanner · Customer Desktop App (Flet 0.83.x)
Run: python app.py

Requires the FastAPI backend (scanner.py) on http://localhost:8000.
    WEBSEC_API_BASE=http://localhost:8000
    WEBSEC_API_KEY=wsk_...
"""

from __future__ import annotations

import os
import re
import threading
import time
from typing import Any, Dict, List, Optional

import flet as ft
import httpx

# ── Config ─────────────────────────────────────────────────────────────────────
API_BASE        = os.getenv("WEBSEC_API_BASE", "http://localhost:8000")
DEFAULT_API_KEY = os.getenv("WEBSEC_API_KEY", "wsk_NAWtMhmt61PtpCz3K-TGadgYg-DSxXcZlLAQWqZCa8A")

MONO = "monospace"

# ── Theme palettes ────────────────────────────────────────────────────────────
DARK = {
    "bg":      "#07090f",
    "surface": "#0d111c",
    "surf2":   "#151926",
    "border":  "#1e2540",
    "text":    "#e8ecf4",
    "text2":   "#9ba3be",
    "muted":   "#5a6480",
    "accent":  "#22C55E",
    "red":     "#ff4d6d",
    "orange":  "#ffa94d",
    "yellow":  "#ffd54d",
    "green":   "#22c55e",
    "white":   "#ffffff",
}

LIGHT = {
    "bg":      "#f8faff",
    "surface": "#ffffff",
    "surf2":   "#f1f4ff",
    "border":  "#e2e8f5",
    "text":    "#0f172a",
    "text2":   "#475569",
    "muted":   "#71717a",
    "accent":  "#0d7e0f",
    "red":     "#ff4d6d",
    "orange":  "#ffa94d",
    "yellow":  "#b38600",
    "green":   "#0d7e0f",
    "white":   "#ffffff",
}


# ══════════════════════════════════════════════════════════════════════════════
# API client
# ══════════════════════════════════════════════════════════════════════════════

class ApiClient:
    def __init__(self, api_key: str) -> None:
        self._h = {"X-API-Key": api_key, "Content-Type": "application/json"}

    def start_scan(self, target_url: str, scan_type: str) -> Dict[str, Any]:
        with httpx.Client(base_url=API_BASE, timeout=15) as c:
            r = c.post("/scans",
                       json={"target_url": target_url, "scan_type": scan_type},
                       headers=self._h)
            r.raise_for_status()
            return r.json()

    def poll_scan(self, scan_id: int) -> Dict[str, Any]:
        with httpx.Client(base_url=API_BASE, timeout=10) as c:
            r = c.get(f"/scans/{scan_id}", headers=self._h)
            r.raise_for_status()
            return r.json()


# ══════════════════════════════════════════════════════════════════════════════
# Scan animation
# ══════════════════════════════════════════════════════════════════════════════

class ScanAnimation(ft.Row):
    def __init__(self, accent: str) -> None:
        self._dots = [
            ft.Container(width=7, height=7, border_radius=4, bgcolor=accent)
            for _ in range(3)
        ]
        super().__init__(
            controls=self._dots, spacing=5,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        )
        self._running = False
        self._lock    = threading.Lock()

    def start(self) -> None:
        with self._lock:
            if self._running:
                return          # already running — don't spawn a second thread
            self._running = True
        threading.Thread(target=self._pulse, daemon=True).start()

    def stop(self) -> None:
        with self._lock:
            self._running = False

    def _pulse(self) -> None:
        step = 0
        while True:
            with self._lock:
                if not self._running:
                    break
            for i, d in enumerate(self._dots):
                d.opacity = 1.0 if i == (step % 3) else 0.2
            try:
                self.update()
            except Exception:
                break           # page gone / control detached — exit cleanly
            time.sleep(0.32)
            step += 1


def _severity(vuln_type: str, C: dict):
    if "SQL" in vuln_type:
        return "CRITICAL", C["red"]
    if "XSS" in vuln_type:
        return "HIGH", C["orange"]
    return "MEDIUM", C["yellow"]


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main(page: ft.Page) -> None:
    page.title             = "WebSec Scanner"
    page.window.width      = 1060
    page.window.height     = 800
    page.window.min_width  = 820
    page.window.min_height = 600
    page.padding           = 0
    page.theme_mode        = ft.ThemeMode.DARK

    state: Dict[str, Any] = {
        "dark":      True,
        "api_key":   DEFAULT_API_KEY,
        "scan_id":   None,
        "status":    "IDLE",
        "vulns":     [],
        "endpoints": 0,
        "scan_done": False,
    }

    def C() -> dict:
        return DARK if state["dark"] else LIGHT

    def _t(text: str, color: Optional[str] = None, size: int = 12,
           weight=ft.FontWeight.NORMAL, mono: bool = False,
           selectable: bool = False) -> ft.Text:
        col   = color or C()["text2"]
        style = ft.TextStyle(font_family=MONO) if mono else None
        return ft.Text(text, color=col, size=size, weight=weight,
                       style=style, selectable=selectable)

    def _label(txt: str) -> ft.Text:
        return _t(txt.upper(), color=C()["muted"], size=10,
                  weight=ft.FontWeight.W_600, mono=True)

    def _metric_card(label: str, val_ref: ft.Text) -> ft.Container:
        return ft.Container(
            content=ft.Column(
                controls=[_label(label), val_ref],
                spacing=6, tight=True,
            ),
            bgcolor=C()["surface"],
            border=ft.Border.all(1, C()["border"]),
            border_radius=16,
            padding=ft.Padding(left=22, right=22, top=20, bottom=20),
            expand=True,
        )

    def _vuln_tile(vuln: Dict[str, Any]) -> ft.Container:
        v_type = vuln.get("type", "Unknown")
        v_url  = vuln.get("url", "")
        sev_label, sev_color = _severity(v_type, C())

        detail_rows: List[ft.Control] = []
        for k, v in vuln.items():
            if k == "type":
                continue
            is_payload = k in ("payload", "pattern", "parameter")
            val_color  = C()["orange"] if is_payload else C()["text2"]
            detail_rows.append(
                ft.Row(
                    controls=[
                        ft.Container(
                            content=_t(k.upper(), color=C()["muted"],
                                       size=10, mono=True),
                            width=100,
                        ),
                        ft.Text(str(v), color=val_color, size=11,
                                selectable=True, expand=True,
                                style=ft.TextStyle(font_family=MONO)),
                    ],
                    spacing=10,
                    vertical_alignment=ft.CrossAxisAlignment.START,
                )
            )

        title_row = ft.Row(
            controls=[
                ft.Container(
                    content=ft.Text(
                        sev_label, size=9, weight=ft.FontWeight.W_700,
                        color=sev_color,
                        style=ft.TextStyle(font_family=MONO),
                    ),
                    bgcolor=ft.Colors.with_opacity(0.15, sev_color),
                    border_radius=4,
                    padding=ft.Padding(left=7, right=7, top=2, bottom=2),
                ),
                ft.Text(v_type, color=C()["text"], size=12,
                        weight=ft.FontWeight.W_600, expand=True),
                ft.Text(
                    (v_url[:58] + "…") if len(v_url) > 58 else v_url,
                    color=C()["muted"], size=10,
                    style=ft.TextStyle(font_family=MONO),
                ),
            ],
            spacing=10,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        )

        return ft.Container(
            content=ft.ExpansionTile(
                title=title_row,
                controls=[
                    ft.Container(
                        content=ft.Column(controls=detail_rows, spacing=8),
                        padding=ft.Padding(left=16, right=16, top=10, bottom=14),
                    )
                ],
                tile_padding=ft.Padding(left=14, right=14, top=2, bottom=2),
                collapsed_bgcolor=C()["surf2"],
                bgcolor=C()["surface"],
                icon_color=C()["muted"],
                collapsed_icon_color=C()["muted"],
                text_color=C()["text"],
                collapsed_text_color=C()["text"],
            ),
            border=ft.Border.all(1, C()["border"]),
            border_radius=12,
            clip_behavior=ft.ClipBehavior.HARD_EDGE,
            margin=ft.margin.only(bottom=8),
        )

    val_endpoints = ft.Text("0", size=34, weight=ft.FontWeight.W_800)
    val_sqli      = ft.Text("0", size=34, weight=ft.FontWeight.W_800)
    val_xss       = ft.Text("0", size=34, weight=ft.FontWeight.W_800)
    val_info      = ft.Text("0", size=34, weight=ft.FontWeight.W_800)

    status_dot  = ft.Container(width=8, height=8, border_radius=4)
    status_text = ft.Text("IDLE", size=11, style=ft.TextStyle(font_family=MONO))
    scan_anim   = ScanAnimation(DARK["accent"])
    scan_anim.visible = False

    url_field = ft.TextField(
        hint_text="enter URL of target website here",
        hint_style=ft.TextStyle(color=DARK["muted"]),
        text_style=ft.TextStyle(font_family=MONO),
        border_color=DARK["border"],
        focused_border_color=DARK["accent"],
        bgcolor=DARK["surface"],
        color=DARK["text"],
        text_size=13,
        height=54,
        content_padding=ft.Padding(left=18, right=18, top=0, bottom=0),
        expand=True,
    )

    banner_text = ft.Text("", size=12, style=ft.TextStyle(font_family=MONO))
    banner = ft.Container(
        content=banner_text,
        border_radius=10,
        padding=ft.Padding(left=16, right=16, top=10, bottom=10),
        visible=False,
    )

    findings_col = ft.Column(spacing=0)

    toggle_btn = ft.IconButton(
        icon=ft.Icons.LIGHT_MODE,
        icon_color=ft.Colors.WHITE,
        icon_size=18,
        tooltip="Toggle theme",
        style=ft.ButtonStyle(
            bgcolor={"": "#000000"},
            shape=ft.CircleBorder(),
            padding=ft.Padding(left=10, right=10, top=10, bottom=10),
            side=ft.BorderSide(1, "#333333"),
        ),
    )

    _SCAN_MESSAGES = [
        "🔍  Analyzing target architecture…",
        "🕸   Crawling endpoints…",
        "💉  Testing for SQL injection…",
        "⚡  Probing XSS vectors…",
        "🔐  Checking for sensitive data exposure…",
        "📡  Aggregating findings…",
    ]
    scan_msg_text = ft.Text(
        _SCAN_MESSAGES[0], size=12,
        style=ft.TextStyle(font_family=MONO),
        color=DARK["accent"],
    )
    scan_bar = ft.ProgressBar(
        value=None,
        color=DARK["accent"],
        bgcolor=ft.Colors.with_opacity(0.15, DARK["accent"]),
        height=3,
        border_radius=2,
    )
    scan_progress = ft.Container(
        content=ft.Column(
            controls=[
                ft.Row(
                    controls=[
                        ft.ProgressRing(width=13, height=13, stroke_width=2,
                                        color=DARK["accent"]),
                        scan_msg_text,
                    ],
                    spacing=10,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                ft.Container(height=8),
                scan_bar,
            ],
            spacing=0,
            tight=True,
        ),
        bgcolor=ft.Colors.with_opacity(0.06, DARK["accent"]),
        border=ft.Border.all(1, ft.Colors.with_opacity(0.18, DARK["accent"])),
        border_radius=10,
        padding=ft.Padding(left=16, right=16, top=12, bottom=12),
        visible=False,
    )

    # ── Scan message cycling ───────────────────────────────────────────────────
    # Use an Event so the cycle thread stops reliably even across thread boundaries
    _scan_stop_event = threading.Event()

    def _cycle_scan_messages() -> None:
        idx = 0
        while not _scan_stop_event.wait(timeout=2.4):
            idx = (idx + 1) % len(_SCAN_MESSAGES)
            scan_msg_text.value = _SCAN_MESSAGES[idx]
            try:
                scan_msg_text.update()
            except Exception:
                break

    def apply_theme() -> None:
        T = C()
        page.bgcolor = T["bg"]

        # metric value colours — endpoints uses text colour, NOT white
        val_endpoints.color = T["white"]
        val_sqli.color      = T["red"]
        val_xss.color       = T["orange"]
        val_info.color      = T["yellow"]

        status_text.color = T["text2"]
        _repaint_status_dot()

        url_field.hint_style           = ft.TextStyle(color=T["muted"])
        url_field.bgcolor              = T["surface"]
        url_field.border_color         = T["border"]
        url_field.focused_border_color = T["accent"]
        url_field.color                = T["text"]

        icon = ft.Icons.LIGHT_MODE if state["dark"] else ft.Icons.DARK_MODE
        bg   = "#000000" if state["dark"] else "#f0f0f0"
        bd   = "#333333" if state["dark"] else "#cbd5e1"
        ic   = ft.Colors.WHITE if state["dark"] else "#0f172a"
        toggle_btn.icon       = icon
        toggle_btn.icon_color = ic
        toggle_btn.style      = ft.ButtonStyle(
            bgcolor={"": bg},
            shape=ft.CircleBorder(),
            padding=ft.Padding(left=10, right=10, top=10, bottom=10),
            side=ft.BorderSide(1, bd),
        )

        logo_web_span.style  = ft.TextStyle(color=T["text"],   size=17, weight=ft.FontWeight.W_800)
        logo_sec_span.style  = ft.TextStyle(color=T["accent"], size=17, weight=ft.FontWeight.W_800)
        header_sub.color     = T["accent"]
        header_main.color    = T["text"]
        findings_title.color = T["text"]

        for ft_text in footer_texts:
            ft_text.color = T["border"] if ft_text.value == "•" else T["muted"]

        btn_quick_text.color = ft.Colors.WHITE
        btn_deep_text.color  = ft.Colors.WHITE

        scan_msg_text.color   = T["accent"]
        scan_bar.color        = T["accent"]
        scan_bar.bgcolor      = ft.Colors.with_opacity(0.15, T["accent"])
        scan_progress.bgcolor = ft.Colors.with_opacity(0.06, T["accent"])
        scan_progress.border  = ft.Border.all(1, ft.Colors.with_opacity(0.18, T["accent"]))

        # containers that need repainting
        status_pill.bgcolor           = T["surf2"]
        status_pill.border            = ft.Border.all(1, T["border"])
        divider_ctrl.color            = T["border"]

        try:
            page.update()
        except Exception:
            pass

    def _repaint_status_dot() -> None:
        T = C()
        s = state["status"]
        if s == "SCANNING":
            status_dot.bgcolor = T["orange"]
        elif s == "DONE":
            status_dot.bgcolor = T["accent"]
        elif s == "ERROR":
            status_dot.bgcolor = T["red"]
        else:
            status_dot.bgcolor = T["green"]

    def set_status(s: str) -> None:
        state["status"]    = s
        status_text.value  = s
        _repaint_status_dot()
        if s == "SCANNING":
            scan_anim.visible     = True
            scan_anim.start()
            scan_progress.visible = True
            scan_msg_text.value   = _SCAN_MESSAGES[0]
            _scan_stop_event.clear()
            threading.Thread(target=_cycle_scan_messages, daemon=True).start()
        else:
            _scan_stop_event.set()   # unblocks the wait() in _cycle_scan_messages
            scan_anim.stop()
            scan_anim.visible     = False
            scan_progress.visible = False
        try:
            status_dot.update()
            status_text.update()
            scan_anim.update()
            scan_progress.update()
        except Exception:
            pass

    def show_banner(msg: str, ok: bool = False) -> None:
        T = C()
        col = T["accent"] if ok else T["red"]
        banner_text.value = msg
        banner_text.color = col
        banner.bgcolor    = ft.Colors.with_opacity(0.09, col)
        banner.border     = ft.Border.all(1, ft.Colors.with_opacity(0.3, col))
        banner.visible    = True
        try:
            banner.update()
        except Exception:
            pass

    def hide_banner() -> None:
        banner.visible = False
        try:
            banner.update()
        except Exception:
            pass

    def refresh_metrics() -> None:
        vulns = state["vulns"]
        sq  = sum(1 for v in vulns if "SQL"       in v.get("type", ""))
        xs  = sum(1 for v in vulns if "XSS"       in v.get("type", ""))
        inf = sum(1 for v in vulns if "Sensitive"  in v.get("type", ""))
        val_endpoints.value = str(state["endpoints"])
        val_sqli.value      = str(sq)
        val_xss.value       = str(xs)
        val_info.value      = str(inf)
        try:
            for v in (val_endpoints, val_sqli, val_xss, val_info):
                v.update()
        except Exception:
            pass

    def refresh_findings() -> None:
        T = C()
        findings_col.controls.clear()
        vulns = state["vulns"]
        if not state["scan_done"]:
            findings_col.controls.append(
                ft.Container(
                    content=ft.Row(
                        controls=[
                            ft.Icon(ft.Icons.INFO_OUTLINE, color=T["text2"], size=16),
                            ft.Text(
                                "No active scan results. Enter a target URL and choose a scan mode to begin.",
                                color=T["text2"], size=12,
                            ),
                        ],
                        spacing=8,
                    ),
                    bgcolor=ft.Colors.with_opacity(0.05, T["text2"]),
                    border=ft.Border.all(1, T["border"]),
                    border_radius=10,
                    padding=ft.Padding(left=16, right=16, top=14, bottom=14),
                )
            )
        elif not vulns:
            findings_col.controls.append(
                ft.Container(
                    content=ft.Row(
                        controls=[
                            ft.Icon(ft.Icons.CHECK_CIRCLE_OUTLINE,
                                    color=T["green"], size=16),
                            ft.Text(
                                "Target surface appears clean. No vulnerabilities detected.",
                                color=T["green"], size=12,
                            ),
                        ],
                        spacing=8,
                    ),
                    bgcolor=ft.Colors.with_opacity(0.06, T["green"]),
                    border=ft.Border.all(1, ft.Colors.with_opacity(0.3, T["green"])),
                    border_radius=10,
                    padding=ft.Padding(left=16, right=16, top=14, bottom=14),
                )
            )
        else:
            for v in vulns:
                findings_col.controls.append(_vuln_tile(v))
        try:
            findings_col.update()
        except Exception:
            pass

    def run_scan(target_url: str, scan_type: str) -> None:
        client = ApiClient(state["api_key"])
        try:
            resp = client.start_scan(target_url, scan_type)
        except httpx.HTTPStatusError as e:
            try:
                detail = e.response.json().get("detail", str(e))
            except Exception:
                detail = str(e)
            page.run_thread(lambda: (set_status("ERROR"), show_banner(f"API error: {detail}")))
            return
        except Exception as e:
            err = str(e)
            page.run_thread(lambda: (set_status("ERROR"), show_banner(f"Cannot reach backend: {err}")))
            return

        scan_id = resp["scan_id"]
        state["scan_id"] = scan_id
        deadline = time.time() + 180

        while time.time() < deadline:
            time.sleep(2)
            # Check if user cancelled / page closed
            if state.get("status") != "SCANNING":
                return
            try:
                result = client.poll_scan(scan_id)
            except Exception:
                continue
            if result["status"] in ("done", "error"):
                # Capture result values before crossing thread boundary
                vulns     = result.get("vulnerabilities", [])
                endpoints = result.get("endpoints_count", 0)
                is_error  = result["status"] == "error"

                def _finish(vulns=vulns, endpoints=endpoints, is_error=is_error):
                    state["vulns"]     = vulns
                    state["endpoints"] = endpoints
                    state["scan_done"] = True
                    if is_error:
                        set_status("ERROR")
                        show_banner("Scan completed with backend errors.")
                        _show_snackbar("Scan finished with errors.", ok=False)
                    else:
                        set_status("DONE")
                        hide_banner()
                        n   = len(state["vulns"])
                        msg = (f"Scan complete — {n} issue{'s' if n != 1 else ''} found."
                               if n else "Scan complete — target looks clean.")
                        _show_snackbar(msg, ok=True)
                    refresh_metrics()
                    refresh_findings()

                page.run_thread(_finish)
                return

        page.run_thread(lambda: (set_status("ERROR"), show_banner("Scan timed out waiting for backend.")))

    _URL_RE = re.compile(
        r"^(https?://)?(localhost|([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,})"
        r"(:\d{1,5})?(/[^\s]*)?$",
        re.IGNORECASE,
    )

    def _show_snackbar(msg: str, ok: bool = True) -> None:
        T = C()
        col = T["accent"] if ok else T["red"]
        page.open(
            ft.SnackBar(
                content=ft.Row(
                    controls=[
                        ft.Icon(
                            ft.Icons.CHECK_CIRCLE_OUTLINE if ok else ft.Icons.ERROR_OUTLINE,
                            color=ft.Colors.WHITE, size=16,
                        ),
                        ft.Text(msg, color=ft.Colors.WHITE, size=12,
                                style=ft.TextStyle(font_family=MONO)),
                    ],
                    spacing=10,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                bgcolor=col,
                duration=3000,
                show_close_icon=True,
                close_icon_color=ft.Colors.WHITE,
            )
        )

    def validate_and_scan(scan_type: str) -> None:
        hide_banner()
        state["api_key"] = DEFAULT_API_KEY

        target = url_field.value.strip()
        if not target:
            show_banner("⚠  Target URL cannot be empty.")
            return

        target_check = target if target.startswith(("http://", "https://")) else "https://" + target
        if not _URL_RE.match(target_check):
            show_banner(f"⚠  '{target}' is not a valid URL. Enter a proper domain or localhost.")
            url_field.border_color = C()["red"]
            url_field.focused_border_color = C()["red"]
            url_field.update()
            return

        url_field.border_color         = C()["border"]
        url_field.focused_border_color = C()["accent"]
        url_field.update()

        if not target.startswith(("http://", "https://")):
            target = "https://" + target
            url_field.value = target
            url_field.update()

        state["vulns"]     = []
        state["endpoints"] = 0
        state["scan_done"] = False
        refresh_metrics()
        refresh_findings()
        set_status("SCANNING")
        threading.Thread(target=run_scan, args=(target, scan_type), daemon=True).start()

    def on_quick(e: ft.ControlEvent) -> None:
        validate_and_scan("quickscan")

    def on_deep(e: ft.ControlEvent) -> None:
        validate_and_scan("deepscan")

    logo_web_span  = ft.TextSpan("Web", style=ft.TextStyle(
        color=DARK["text"], size=17, weight=ft.FontWeight.W_800))
    logo_sec_span  = ft.TextSpan("Sec", style=ft.TextStyle(
        color=DARK["accent"], size=17, weight=ft.FontWeight.W_800))
    logo_text_ctrl = ft.Text(spans=[logo_web_span, logo_sec_span])

    header_sub  = ft.Text("AUTOMATED SECURITY AUDIT",
                           color=DARK["accent"], size=10,
                           weight=ft.FontWeight.W_600,
                           style=ft.TextStyle(font_family=MONO, letter_spacing=1.5))
    header_main = ft.Text("Website Security Scanner",
                           color=DARK["text"], size=28,
                           weight=ft.FontWeight.W_800)

    findings_title = ft.Text("Security Findings",
                              color=DARK["text"], size=17,
                              weight=ft.FontWeight.W_700)

    footer_texts = [
        ft.Text("⚠️ AUTHORIZED USE ONLY", color=DARK["muted"],
                size=10, style=ft.TextStyle(font_family=MONO)),
        ft.Text("•", color=DARK["border"], size=10),
        ft.Text("COMPLIANCE REQUIRED", color=DARK["muted"],
                size=10, style=ft.TextStyle(font_family=MONO)),
        ft.Text("•", color=DARK["border"], size=10),
        ft.Text("WEBSEC ENGINE V2.5", color=DARK["muted"],
                size=10, style=ft.TextStyle(font_family=MONO)),
    ]

    btn_quick_text = ft.Text("Quick Scan", weight=ft.FontWeight.W_700,
                              color=ft.Colors.WHITE, size=13)
    btn_deep_text  = ft.Text("Deep Scan", weight=ft.FontWeight.W_700,
                              color=ft.Colors.WHITE, size=13)

    # ── Updated Button factory matching frontend.py ────────────────
    def _scan_btn(icon_data: str, label_ref: ft.Text, on_click) -> ft.ElevatedButton:
        return ft.ElevatedButton(
            content=ft.Row(
                controls=[
                    ft.Icon(icon_data, size=16, color=ft.Colors.WHITE),
                    label_ref
                ],
                spacing=6, tight=True,
                alignment=ft.MainAxisAlignment.CENTER,
            ),
            bgcolor=DARK["accent"],
            on_click=on_click,
            expand=True,
            height=44,
            style=ft.ButtonStyle(
                shape=ft.RoundedRectangleBorder(radius=22),
            ),
        )

    status_pill = ft.Container(
        content=ft.Row(
            controls=[status_dot, status_text, scan_anim],
            spacing=8,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        bgcolor=DARK["surf2"],
        border=ft.Border.all(1, DARK["border"]),
        border_radius=100,
        padding=ft.Padding(left=12, right=16, top=6, bottom=6),
    )

    divider_ctrl = ft.Divider(height=1, color=DARK["border"])

    def on_toggle_theme(e: ft.ControlEvent) -> None:
        state["dark"] = not state["dark"]
        page.theme_mode = ft.ThemeMode.DARK if state["dark"] else ft.ThemeMode.LIGHT
        apply_theme()
        refresh_findings()

    toggle_btn.on_click = on_toggle_theme

    top_nav = ft.Container(
        content=ft.Row(
            controls=[
                ft.Row(
                    controls=[
                        ft.Container(
                            content=ft.Text("🛡️", size=18),
                            bgcolor=DARK["accent"],
                            border_radius=8,
                            width=36, height=36,
                            alignment=ft.Alignment(0, 0),
                        ),
                        logo_text_ctrl,
                    ],
                    spacing=10,
                ),
                ft.Row(expand=True),
                status_pill,
                ft.Container(width=12),
                toggle_btn,
            ],
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        padding=ft.Padding(left=60, right=60, top=24, bottom=0),
    )

    page_header = ft.Container(
        content=ft.Column(
            controls=[
                ft.Container(height=28),
                header_sub,
                header_main,
                ft.Container(height=6),
            ],
            spacing=3, tight=True,
        ),
        padding=ft.Padding(left=60, right=60, top=0, bottom=0),
    )

    url_row = ft.Container(
        content=url_field,
        margin=ft.margin.only(left=60, right=60, bottom=14),
    )

    btn_row = ft.Container(
        content=ft.Row(
            controls=[
                ft.Container(expand=True),
                ft.Container(
                    content=ft.Row(
                        controls=[
                            _scan_btn(ft.Icons.BOLT, btn_quick_text, on_quick),
                            _scan_btn(ft.Icons.RADAR, btn_deep_text, on_deep),
                        ],
                        spacing=14,
                    ),
                    width=460,
                ),
                ft.Container(expand=True),
            ],
        ),
        margin=ft.margin.only(left=60, right=60, bottom=8),
    )

    progress_row = ft.Container(
        content=scan_progress,
        margin=ft.margin.only(left=60, right=60, bottom=4),
    )

    banner_row = ft.Container(
        content=banner,
        margin=ft.margin.only(left=60, right=60, bottom=4),
    )

    metrics_row = ft.Container(
        content=ft.Row(
            controls=[
                _metric_card("Endpoints",          val_endpoints),
                _metric_card("Critical (SQLi)",    val_sqli),
                _metric_card("High (XSS)",         val_xss),
                _metric_card("Medium (Info Leak)", val_info),
            ],
            spacing=14,
        ),
        margin=ft.margin.only(left=60, right=60, top=28, bottom=28),
    )

    findings_section = ft.Container(
        content=ft.Column(
            controls=[
                findings_title,
                ft.Container(height=10),
                findings_col,
            ],
            spacing=0,
        ),
        margin=ft.margin.only(left=60, right=60, bottom=50),
    )

    footer = ft.Container(
        content=ft.Row(
            controls=footer_texts,
            spacing=14,
            alignment=ft.MainAxisAlignment.CENTER,
        ),
        border=ft.Border.only(top=ft.BorderSide(1, DARK["border"])),
        padding=ft.Padding(left=60, right=60, top=18, bottom=22),
    )

    page.add(
        ft.Column(
            controls=[
                top_nav,
                page_header,
                url_row,
                btn_row,
                progress_row,
                banner_row,
                divider_ctrl,
                metrics_row,
                findings_section,
                footer,
            ],
            spacing=0,
            scroll=ft.ScrollMode.AUTO,
            expand=True,
        )
    )

    apply_theme()
    refresh_findings()


if __name__ == "__main__":
    ft.run(main)
