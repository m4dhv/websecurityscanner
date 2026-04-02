"""
frontend.py — WebSec Scanner · Customer Desktop App (Flet 0.83.x)
Run: python frontend.py

Requires the FastAPI backend (scanner.py) on http://localhost:8000.
    WEBSEC_API_BASE=http://localhost:8000
    WEBSEC_API_KEY=wsk_...
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any, Dict, List, Optional

import flet as ft
import httpx

# ── Config ─────────────────────────────────────────────────────────────────────
API_BASE        = os.getenv("WEBSEC_API_BASE", "http://localhost:8000")
DEFAULT_API_KEY = os.getenv("WEBSEC_API_KEY", "")

# ── Palette ────────────────────────────────────────────────────────────────────
C = {
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
}

MONO = "monospace"


# ══════════════════════════════════════════════════════════════════════════════
# UI helpers
# ══════════════════════════════════════════════════════════════════════════════

def _t(text: str, color: str = C["text2"], size: int = 11,
       weight=ft.FontWeight.NORMAL, mono: bool = False) -> ft.Text:
    style = ft.TextStyle(font_family=MONO) if mono else None
    return ft.Text(text, color=color, size=size, weight=weight, style=style)


def _label(txt: str) -> ft.Text:
    return _t(txt.upper(), color=C["muted"], size=10,
              weight=ft.FontWeight.W_600, mono=True)


def _divider() -> ft.Divider:
    return ft.Divider(height=1, color=C["border"])


def _logo_text() -> ft.Text:
    """'WebSec' two-colour — ft.Text(spans=[]) replaces removed ft.RichText."""
    return ft.Text(
        spans=[
            ft.TextSpan("Web", style=ft.TextStyle(
                color=C["text"], size=16, weight=ft.FontWeight.W_800)),
            ft.TextSpan("Sec", style=ft.TextStyle(
                color=C["accent"], size=16, weight=ft.FontWeight.W_800)),
        ]
    )


def _severity(vuln_type: str):
    if "SQL" in vuln_type:
        return "CRITICAL", C["red"]
    if "XSS" in vuln_type:
        return "HIGH", C["orange"]
    return "MEDIUM", C["yellow"]


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
# Metric card
# ══════════════════════════════════════════════════════════════════════════════

def metric_card(label: str, value: str, color: str) -> ft.Container:
    return ft.Container(
        content=ft.Column(
            controls=[
                _label(label),
                ft.Text(value, size=32, weight=ft.FontWeight.W_800, color=color),
            ],
            spacing=6,
            tight=True,
        ),
        bgcolor=C["surface"],
        border=ft.Border.all(1, C["border"]),   # ft.Border.all not ft.border.all
        border_radius=14,
        padding=20,
        expand=True,
    )


# ══════════════════════════════════════════════════════════════════════════════
# Vuln tile (expandable finding card)
# ══════════════════════════════════════════════════════════════════════════════

def vuln_tile(vuln: Dict[str, Any]) -> ft.Container:
    v_type = vuln.get("type", "Unknown")
    v_url  = vuln.get("url", "")
    sev_label, sev_color = _severity(v_type)

    detail_rows: List[ft.Control] = []
    for k, v in vuln.items():
        if k == "type":
            continue
        is_payload = k in ("payload", "pattern", "parameter")
        val_color  = C["orange"] if is_payload else C["text2"]
        detail_rows.append(
            ft.Row(
                controls=[
                    ft.Container(
                        content=_t(k.upper(), color=C["muted"], size=10, mono=True),
                        width=90,
                    ),
                    ft.Text(
                        str(v), color=val_color, size=11,
                        selectable=True, expand=True,
                        style=ft.TextStyle(font_family=MONO),
                    ),
                ],
                spacing=10,
                vertical_alignment=ft.CrossAxisAlignment.START,
            )
        )

    header = ft.Row(
        controls=[
            ft.Container(
                content=ft.Text(
                    sev_label, size=9, weight=ft.FontWeight.W_700,
                    color=sev_color,
                    style=ft.TextStyle(font_family=MONO),
                ),
                bgcolor=ft.Colors.with_opacity(0.12, sev_color),
                border_radius=4,
                padding=ft.Padding(left=6, right=6, top=2, bottom=2),
            ),
            ft.Text(v_type, color=C["text"], size=12,
                    weight=ft.FontWeight.W_600, expand=True),
            ft.Text(
                (v_url[:55] + "…") if len(v_url) > 55 else v_url,
                color=C["muted"], size=10,
                style=ft.TextStyle(font_family=MONO),
            ),
        ],
        spacing=10,
        vertical_alignment=ft.CrossAxisAlignment.CENTER,
    )

    return ft.Container(
        content=ft.ExpansionTile(
            title=header,
            controls=[
                ft.Container(
                    content=ft.Column(controls=detail_rows, spacing=6),
                    padding=ft.Padding(left=16, right=16, top=8, bottom=12),
                )
            ],
            tile_padding=ft.Padding(left=14, right=14, top=0, bottom=0),
            collapsed_bgcolor=C["surf2"],
            bgcolor=C["surface"],
            icon_color=C["muted"],
            collapsed_icon_color=C["muted"],
            text_color=C["text"],
            collapsed_text_color=C["text"],
        ),
        border=ft.Border.all(1, C["border"]),
        border_radius=10,
        clip_behavior=ft.ClipBehavior.HARD_EDGE,
        margin=ft.margin.only(bottom=6),        # ft.margin.only not ft.Margin(...)
    )


# ══════════════════════════════════════════════════════════════════════════════
# Scan animation (three pulsing dots)
# ══════════════════════════════════════════════════════════════════════════════

class ScanAnimation(ft.Row):
    def __init__(self) -> None:
        self._dots = [
            ft.Container(width=8, height=8, border_radius=4, bgcolor=C["accent"])
            for _ in range(3)
        ]
        super().__init__(
            controls=self._dots,
            spacing=6,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        )
        self._running = False

    def start(self) -> None:
        self._running = True
        threading.Thread(target=self._pulse, daemon=True).start()

    def stop(self) -> None:
        self._running = False

    def _pulse(self) -> None:
        step = 0
        while self._running:
            for i, dot in enumerate(self._dots):
                dot.opacity = 1.0 if i == (step % 3) else 0.25
            try:
                self.update()
            except Exception:
                pass
            time.sleep(0.35)
            step += 1


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main(page: ft.Page) -> None:
    page.title             = "WebSec Scanner"
    page.bgcolor           = C["bg"]
    page.window.width      = 1000
    page.window.height     = 760
    page.window.min_width  = 800
    page.window.min_height = 600
    page.padding           = 0
    page.theme_mode        = ft.ThemeMode.DARK
    page.theme             = ft.Theme(color_scheme_seed=C["accent"])

    # ── State ──────────────────────────────────────────────────────────────────
    state: Dict[str, Any] = {
        "api_key":   DEFAULT_API_KEY,
        "scan_id":   None,
        "status":    "IDLE",
        "vulns":     [],
        "endpoints": 0,
        "scan_done": False,
    }

    # ── Controls ───────────────────────────────────────────────────────────────

    api_key_field = ft.TextField(
        value=state["api_key"],
        hint_text="Paste your API key (wsk_…)",
        hint_style=ft.TextStyle(color=C["muted"]),
        text_style=ft.TextStyle(font_family=MONO),
        bgcolor=C["surf2"],
        border_color=C["border"],
        focused_border_color=C["accent"],
        color=C["text"],
        text_size=11,
        password=True,
        can_reveal_password=True,
        height=40,
        content_padding=ft.Padding(left=12, right=8, top=0, bottom=0),
        expand=True,
    )

    url_field = ft.TextField(
        hint_text="Enter target URL  (e.g. https://example.com)",
        hint_style=ft.TextStyle(color=C["muted"]),
        text_style=ft.TextStyle(font_family=MONO),
        bgcolor=C["surface"],
        border_color=C["border"],
        focused_border_color=C["accent"],
        color=C["text"],
        text_size=13,
        height=52,
        content_padding=ft.Padding(left=16, right=16, top=0, bottom=0),
        expand=True,
    )

    status_dot  = ft.Container(width=8, height=8, border_radius=4, bgcolor=C["green"])
    status_text = _t("IDLE", color=C["text2"], size=11, mono=True)
    scan_anim   = ScanAnimation()
    scan_anim.visible = False

    m_endpoints = metric_card("Endpoints",       "0", C["text"])
    m_sqli      = metric_card("Critical (SQLi)", "0", C["red"])
    m_xss       = metric_card("High (XSS)",      "0", C["orange"])
    m_info      = metric_card("Medium (Info)",   "0", C["yellow"])

    findings_col = ft.Column(
        controls=[
            ft.Container(
                content=_t(
                    "No active scan results. Enter a target URL and choose a scan mode.",
                    color=C["muted"], size=12,
                ),
                padding=ft.Padding(left=0, right=0, top=8, bottom=0),
            )
        ],
        spacing=0,
    )

    banner_text = ft.Text("", color=C["red"], size=12,
                          style=ft.TextStyle(font_family=MONO))
    banner = ft.Container(
        content=banner_text,
        bgcolor=ft.Colors.with_opacity(0.08, C["red"]),
        border=ft.Border.all(1, ft.Colors.with_opacity(0.3, C["red"])),
        border_radius=8,
        padding=ft.Padding(left=14, right=14, top=10, bottom=10),
        visible=False,
    )

    # ── Helpers ────────────────────────────────────────────────────────────────

    def show_banner(msg: str, ok: bool = False) -> None:
        col = C["accent"] if ok else C["red"]
        banner_text.value = msg
        banner_text.color = col
        banner.bgcolor    = ft.Colors.with_opacity(0.08, col)
        banner.border     = ft.Border.all(1, ft.Colors.with_opacity(0.3, col))
        banner.visible    = True
        banner.update()

    def hide_banner() -> None:
        banner.visible = False
        banner.update()

    def set_status(s: str) -> None:
        state["status"]    = s
        status_text.value  = s
        if s == "SCANNING":
            status_dot.bgcolor = C["orange"]
            scan_anim.visible  = True
            scan_anim.start()
        else:
            scan_anim.stop()
            scan_anim.visible  = False
            status_dot.bgcolor = (
                C["green"] if s == "IDLE" else
                C["accent"] if s == "DONE" else C["red"]
            )
        status_dot.update()
        status_text.update()
        scan_anim.update()

    def refresh_metrics() -> None:
        vulns = state["vulns"]
        sq  = sum(1 for v in vulns if "SQL"      in v.get("type", ""))
        xs  = sum(1 for v in vulns if "XSS"      in v.get("type", ""))
        inf = sum(1 for v in vulns if "Sensitive" in v.get("type", ""))
        m_endpoints.content.controls[1].value = str(state["endpoints"])
        m_sqli.content.controls[1].value      = str(sq)
        m_xss.content.controls[1].value       = str(xs)
        m_info.content.controls[1].value      = str(inf)
        for card in (m_endpoints, m_sqli, m_xss, m_info):
            card.update()

    def refresh_findings() -> None:
        findings_col.controls.clear()
        vulns = state["vulns"]
        if not state["scan_done"]:
            findings_col.controls.append(
                ft.Container(
                    content=_t(
                        "No active scan results. Enter a target URL and choose a scan mode.",
                        color=C["muted"], size=12,
                    ),
                    padding=ft.Padding(left=0, right=0, top=8, bottom=0),
                )
            )
        elif not vulns:
            findings_col.controls.append(
                ft.Row(
                    controls=[
                        ft.Icon(ft.Icons.CHECK_CIRCLE_OUTLINE, color=C["green"], size=18),
                        ft.Text("No vulnerabilities detected.", color=C["green"], size=13),
                    ],
                    spacing=8,
                )
            )
        else:
            for v in vulns:
                findings_col.controls.append(vuln_tile(v))
        findings_col.update()

    # ── Scan runner ────────────────────────────────────────────────────────────

    def run_scan(target_url: str, scan_type: str) -> None:
        client = ApiClient(state["api_key"])
        try:
            resp = client.start_scan(target_url, scan_type)
        except httpx.HTTPStatusError as e:
            try:
                detail = e.response.json().get("detail", str(e))
            except Exception:
                detail = str(e)
            set_status("ERROR")
            show_banner(f"API error: {detail}")
            return
        except Exception as e:
            set_status("ERROR")
            show_banner(f"Cannot reach backend: {e}")
            return

        scan_id = resp["scan_id"]
        state["scan_id"] = scan_id
        deadline = time.time() + 180

        while time.time() < deadline:
            time.sleep(2)
            try:
                result = client.poll_scan(scan_id)
            except Exception:
                continue
            if result["status"] in ("done", "error"):
                state["vulns"]     = result.get("vulnerabilities", [])
                state["endpoints"] = result.get("endpoints_count", 0)
                state["scan_done"] = True
                if result["status"] == "error":
                    set_status("ERROR")
                    show_banner("Scan completed with backend errors.")
                else:
                    set_status("DONE")
                    hide_banner()
                refresh_metrics()
                refresh_findings()
                return

        set_status("ERROR")
        show_banner("Scan timed out waiting for backend.")

    # ── Button handlers ────────────────────────────────────────────────────────

    def validate_and_scan(scan_type: str) -> None:
        hide_banner()
        api_key = api_key_field.value.strip()
        if not api_key:
            show_banner("API key is required.")
            return
        state["api_key"] = api_key

        target = url_field.value.strip()
        if not target:
            show_banner("Target URL cannot be empty.")
            return
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

    # ── Layout ─────────────────────────────────────────────────────────────────

    top_bar = ft.Container(
        content=ft.Row(
            controls=[
                ft.Row(
                    controls=[
                        ft.Container(
                            content=ft.Text("🛡️", size=18),
                            bgcolor=C["accent"],
                            border_radius=8,
                            width=34, height=34,
                            alignment=ft.Alignment(0, 0),
                        ),
                        _logo_text(),
                    ],
                    spacing=10,
                ),
                ft.Row(expand=True),
                ft.Container(
                    content=ft.Row(
                        controls=[status_dot, status_text, scan_anim],
                        spacing=8,
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    ),
                    bgcolor=C["surf2"],
                    border=ft.Border.all(1, C["border"]),
                    border_radius=100,
                    padding=ft.Padding(left=12, right=14, top=6, bottom=6),
                ),
            ],
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        padding=ft.Padding(left=40, right=40, top=20, bottom=16),
    )

    header_bar = ft.Container(
        content=ft.Column(
            controls=[
                ft.Text(
                    "AUTOMATED SECURITY AUDIT",
                    color=C["accent"], size=10, weight=ft.FontWeight.W_600,
                    style=ft.TextStyle(font_family=MONO),
                ),
                ft.Text("Website Security Scanner", color=C["text"],
                        size=26, weight=ft.FontWeight.W_800),
            ],
            spacing=2,
            tight=True,
        ),
        padding=ft.Padding(left=40, right=40, top=0, bottom=20),
    )

    api_key_row = ft.Container(
        content=ft.Row(
            controls=[
                ft.Icon(ft.Icons.KEY_OUTLINED, color=C["muted"], size=16),
                api_key_field,
            ],
            spacing=10,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        bgcolor=C["surf2"],
        border=ft.Border.all(1, C["border"]),
        border_radius=10,
        padding=ft.Padding(left=12, right=12, top=6, bottom=6),
        margin=ft.margin.only(left=40, right=40, bottom=16),
    )

    scan_controls = ft.Container(
        content=ft.Column(
            controls=[
                ft.Row(controls=[url_field]),
                ft.Row(
                    controls=[
                        ft.ElevatedButton(
                            content=ft.Row(
                                controls=[
                                    ft.Icon(ft.Icons.BOLT, size=16, color=ft.Colors.WHITE),
                                    ft.Text("Quick Scan", weight=ft.FontWeight.W_700,
                                            color=ft.Colors.WHITE, size=13),
                                ],
                                spacing=6, tight=True,
                            ),
                            bgcolor=C["accent"],
                            on_click=on_quick,
                            expand=True,
                            height=44,
                            style=ft.ButtonStyle(
                                shape=ft.RoundedRectangleBorder(radius=22)),
                        ),
                        ft.ElevatedButton(
                            content=ft.Row(
                                controls=[
                                    ft.Icon(ft.Icons.RADAR, size=16, color=ft.Colors.WHITE),
                                    ft.Text("Deep Scan", weight=ft.FontWeight.W_700,
                                            color=ft.Colors.WHITE, size=13),
                                ],
                                spacing=6, tight=True,
                            ),
                            bgcolor=C["surf2"],
                            on_click=on_deep,
                            expand=True,
                            height=44,
                            style=ft.ButtonStyle(
                                shape=ft.RoundedRectangleBorder(radius=22),
                                side=ft.BorderSide(1, C["border"]),
                            ),
                        ),
                    ],
                    spacing=12,
                ),
            ],
            spacing=12,
        ),
        padding=ft.Padding(left=40, right=40, top=0, bottom=20),
    )

    metrics_row = ft.Container(
        content=ft.Row(
            controls=[m_endpoints, m_sqli, m_xss, m_info],
            spacing=12,
        ),
        padding=ft.Padding(left=40, right=40, top=0, bottom=24),
    )

    findings_section = ft.Container(
        content=ft.Column(
            controls=[
                ft.Text("Security Findings", color=C["text"], size=16,
                        weight=ft.FontWeight.W_700),
                ft.Container(height=4),
                banner,
                findings_col,
            ],
            spacing=8,
        ),
        padding=ft.Padding(left=40, right=40, top=0, bottom=40),
    )

    footer = ft.Container(
        content=ft.Row(
            controls=[
                _t("⚠  AUTHORIZED USE ONLY", color=C["muted"], size=10),
                _t("•", color=C["border"], size=10),
                _t("COMPLIANCE REQUIRED", color=C["muted"], size=10),
                _t("•", color=C["border"], size=10),
                _t("WEBSEC ENGINE V2.5", color=C["muted"], size=10),
            ],
            spacing=12,
            alignment=ft.MainAxisAlignment.CENTER,
        ),
        border=ft.Border.only(top=ft.BorderSide(1, C["border"])),
        padding=ft.Padding(left=40, right=40, top=16, bottom=20),
    )

    page.add(
        ft.Column(
            controls=[
                top_bar, header_bar, api_key_row, scan_controls,
                _divider(),
                ft.Container(height=8),
                metrics_row, findings_section, footer,
            ],
            spacing=0,
            scroll=ft.ScrollMode.AUTO,
            expand=True,
        )
    )


if __name__ == "__main__":
    ft.run(main)
