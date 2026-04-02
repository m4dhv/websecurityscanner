"""
admin.py — WebSec Scanner · Admin Desktop App (Flet 0.83.x)
Run: python admin.py

Requires the FastAPI backend (scanner.py) on http://localhost:8000.
    WEBSEC_API_BASE=http://localhost:8000
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any, Dict, List, Optional

import flet as ft
import httpx

# ── Config ─────────────────────────────────────────────────────────────────────
API_BASE = os.getenv("WEBSEC_API_BASE", "http://localhost:8000")

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


def _label(txt: str, size: int = 10) -> ft.Text:
    return _t(txt.upper(), color=C["muted"], size=size,
              weight=ft.FontWeight.W_600, mono=True)


def _divider() -> ft.Divider:
    return ft.Divider(height=1, color=C["border"])


def _section_title(text: str) -> ft.Text:
    return ft.Text(text, color=C["text"], size=15, weight=ft.FontWeight.W_700)


def _logo_text() -> ft.Text:
    """'WebSec' two-colour spans — ft.Text(spans=[]) replaces removed ft.RichText."""
    return ft.Text(
        spans=[
            ft.TextSpan("Web", style=ft.TextStyle(
                color=C["text"], size=16, weight=ft.FontWeight.W_800)),
            ft.TextSpan("Sec", style=ft.TextStyle(
                color=C["accent"], size=16, weight=ft.FontWeight.W_800)),
        ]
    )


def _badge(text: str, color: str) -> ft.Container:
    return ft.Container(
        content=ft.Text(text, size=9, weight=ft.FontWeight.W_700,
                        color=color, style=ft.TextStyle(font_family=MONO)),
        bgcolor=ft.Colors.with_opacity(0.12, color),
        border_radius=4,
        padding=ft.Padding(left=6, right=6, top=2, bottom=2),
    )


def _icon_btn(icon: str, tooltip: str, color: str, on_click) -> ft.IconButton:
    return ft.IconButton(
        icon=icon, icon_color=color, tooltip=tooltip,
        on_click=on_click, icon_size=16,
        style=ft.ButtonStyle(
            padding=ft.Padding(left=4, right=4, top=4, bottom=4)),
    )


# ══════════════════════════════════════════════════════════════════════════════
# API client
# ══════════════════════════════════════════════════════════════════════════════

class AdminClient:
    def __init__(self, token: str) -> None:
        self._h = {"Authorization": f"Bearer {token}",
                   "Content-Type": "application/json"}

    def get_stats(self) -> Dict[str, Any]:
        with httpx.Client(base_url=API_BASE, timeout=10) as c:
            r = c.get("/admin/stats", headers=self._h)
            r.raise_for_status()
            return r.json()

    def list_keys(self) -> List[Dict[str, Any]]:
        with httpx.Client(base_url=API_BASE, timeout=10) as c:
            r = c.get("/admin/api-keys", headers=self._h)
            r.raise_for_status()
            return r.json()

    def create_key(self, label: str) -> Dict[str, Any]:
        with httpx.Client(base_url=API_BASE, timeout=10) as c:
            r = c.post("/admin/api-keys", params={"label": label}, headers=self._h)
            r.raise_for_status()
            return r.json()

    def revoke_key(self, key_id: int) -> None:
        with httpx.Client(base_url=API_BASE, timeout=10) as c:
            r = c.delete(f"/admin/api-keys/{key_id}", headers=self._h)
            r.raise_for_status()


def do_login(username: str, password: str) -> str:
    with httpx.Client(base_url=API_BASE, timeout=10) as c:
        r = c.post("/auth/login",
                   json={"username": username, "password": password})
        r.raise_for_status()
        return r.json()["access_token"]


# ══════════════════════════════════════════════════════════════════════════════
# Breakdown bar widget
# ══════════════════════════════════════════════════════════════════════════════

def breakdown_row(label: str,
                  a_label: str, a_val: int,
                  b_label: str, b_val: int,
                  a_color: str, b_color: str) -> ft.Container:
    total = max(a_val + b_val, 1)
    a_pct = int((a_val / total) * 100)
    b_pct = 100 - a_pct
    return ft.Container(
        content=ft.Column(
            controls=[
                ft.Row(controls=[
                    _label(label),
                    ft.Row(expand=True),
                    _t(f"{a_label} {a_val}   {b_label} {b_val}",
                       color=C["text2"], size=10),
                ]),
                ft.Row(
                    controls=[
                        ft.Container(height=6, expand=max(a_pct, 1),
                                     bgcolor=a_color, border_radius=3),
                        ft.Container(height=6, expand=max(b_pct, 1),
                                     bgcolor=b_color, border_radius=3),
                    ],
                    spacing=3,
                ),
            ],
            spacing=6,
        ),
        bgcolor=C["surface"],
        border=ft.Border.all(1, C["border"]),
        border_radius=12,
        padding=16,
        expand=True,
    )


# ══════════════════════════════════════════════════════════════════════════════
# IP table row
# ══════════════════════════════════════════════════════════════════════════════

def ip_row(ip: str, last_seen: str) -> ft.Container:
    ts = last_seen[:19].replace("T", "  ") if last_seen else "—"
    return ft.Container(
        content=ft.Row(
            controls=[
                ft.Icon(ft.Icons.COMPUTER_OUTLINED, color=C["muted"], size=14),
                _t(ip, color=C["text2"], size=12, mono=True),
                ft.Row(expand=True),
                _t(ts, color=C["muted"], size=10, mono=True),
            ],
            spacing=10,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        border=ft.Border.only(bottom=ft.BorderSide(1, C["border"])),
        padding=ft.Padding(left=0, right=0, top=10, bottom=10),
    )


# ══════════════════════════════════════════════════════════════════════════════
# API key row
# ══════════════════════════════════════════════════════════════════════════════

def key_row(key_data: Dict[str, Any], on_revoke, on_copy) -> ft.Container:
    key_id  = key_data.get("id", "—")
    label   = key_data.get("label") or "(no label)"
    active  = key_data.get("active", False)
    created = key_data.get("created_at", "")[:10]
    key_val = key_data.get("key", "")

    status_badge = _badge("ACTIVE", C["green"]) if active else _badge("REVOKED", C["muted"])

    return ft.Container(
        content=ft.Row(
            controls=[
                ft.Column(
                    controls=[
                        ft.Row(
                            controls=[
                                status_badge,
                                _t(f"#{key_id}", color=C["muted"], size=10),
                                ft.Text(label, color=C["text"], size=12,
                                        weight=ft.FontWeight.W_600),
                            ],
                            spacing=8,
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        ),
                        _t(f"Created {created}", color=C["muted"], size=10),
                    ],
                    spacing=3,
                    tight=True,
                    expand=True,
                ),
                ft.Row(
                    controls=[
                        _icon_btn(
                            ft.Icons.COPY_OUTLINED, "Copy key", C["text2"],
                            lambda e, k=key_val: on_copy(k),
                        ),
                        _icon_btn(
                            ft.Icons.BLOCK_OUTLINED, "Revoke key",
                            C["red"] if active else C["muted"],
                            lambda e, kid=key_id, a=active: on_revoke(kid, a),
                        ),
                    ],
                    spacing=0,
                ),
            ],
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        border=ft.Border.only(bottom=ft.BorderSide(1, C["border"])),
        padding=ft.Padding(left=0, right=0, top=12, bottom=12),
    )


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main(page: ft.Page) -> None:
    page.title             = "WebSec Admin"
    page.bgcolor           = C["bg"]
    page.window.width      = 1060
    page.window.height     = 800
    page.window.min_width  = 860
    page.window.min_height = 640
    page.padding           = 0
    page.theme_mode        = ft.ThemeMode.DARK
    page.theme             = ft.Theme(color_scheme_seed=C["accent"])

    # ── App state ──────────────────────────────────────────────────────────────
    state: Dict[str, Any] = {
        "token":    None,
        "username": None,
        "client":   None,
    }

    # ══════════════════════════════════════════════════════════════════════════
    # LOGIN CONTROLS
    # ══════════════════════════════════════════════════════════════════════════

    login_error   = ft.Text("", color=C["red"], size=12,
                             style=ft.TextStyle(font_family=MONO))
    login_spinner = ft.ProgressRing(width=18, height=18, stroke_width=2,
                                    color=C["accent"], visible=False)

    user_field = ft.TextField(
        hint_text="Username",
        hint_style=ft.TextStyle(color=C["muted"]),
        text_style=ft.TextStyle(font_family=MONO),
        bgcolor=C["surf2"],
        border_color=C["border"],
        focused_border_color=C["accent"],
        color=C["text"],
        text_size=13,
        height=48,
        content_padding=ft.Padding(left=16, right=16, top=0, bottom=0),
    )

    pass_field = ft.TextField(
        hint_text="Password",
        hint_style=ft.TextStyle(color=C["muted"]),
        text_style=ft.TextStyle(font_family=MONO),
        bgcolor=C["surf2"],
        border_color=C["border"],
        focused_border_color=C["accent"],
        color=C["text"],
        text_size=13,
        password=True,
        can_reveal_password=True,
        height=48,
        content_padding=ft.Padding(left=16, right=16, top=0, bottom=0),
    )

    def attempt_login(e: ft.ControlEvent) -> None:
        login_error.value     = ""
        login_spinner.visible = True
        login_error.update()
        login_spinner.update()

        username = user_field.value.strip()
        password = pass_field.value

        if not username or not password:
            login_error.value     = "Username and password are required."
            login_spinner.visible = False
            login_error.update()
            login_spinner.update()
            return

        def _do() -> None:
            try:
                token = do_login(username, password)
                state["token"]    = token
                state["username"] = username
                state["client"]   = AdminClient(token)
                page.run_thread(_load_and_show_dashboard)
            except httpx.HTTPStatusError as exc:
                try:
                    msg = exc.response.json().get("detail", "Invalid credentials.")
                except Exception:
                    msg = "Invalid credentials."
                login_error.value     = msg
                login_spinner.visible = False
                login_error.update()
                login_spinner.update()
            except Exception as exc:
                login_error.value     = f"Cannot reach backend: {exc}"
                login_spinner.visible = False
                login_error.update()
                login_spinner.update()

        threading.Thread(target=_do, daemon=True).start()

    pass_field.on_submit = attempt_login

    login_view = ft.Column(
        controls=[
            ft.Container(expand=True),
            ft.Container(
                content=ft.Column(
                    controls=[
                        ft.Row(
                            controls=[
                                ft.Container(
                                    content=ft.Text("🛡️", size=22),
                                    bgcolor=C["accent"],
                                    border_radius=10,
                                    width=42, height=42,
                                    alignment=ft.Alignment(0, 0),
                                ),
                                ft.Column(
                                    controls=[
                                        _logo_text(),
                                        _t("Admin Console", color=C["muted"], size=10),
                                    ],
                                    spacing=0,
                                    tight=True,
                                ),
                            ],
                            alignment=ft.MainAxisAlignment.CENTER,
                            spacing=12,
                        ),
                        ft.Container(height=8),
                        ft.Text("Sign in to continue", color=C["muted"],
                                size=13, text_align=ft.TextAlign.CENTER),
                        ft.Container(height=16),
                        user_field,
                        ft.Container(height=8),
                        pass_field,
                        ft.Container(height=4),
                        login_error,
                        ft.Container(height=12),
                        ft.ElevatedButton(
                            content=ft.Row(
                                controls=[
                                    login_spinner,
                                    ft.Text("Login", weight=ft.FontWeight.W_700,
                                            color=ft.Colors.WHITE, size=13),
                                ],
                                alignment=ft.MainAxisAlignment.CENTER,
                                spacing=8, tight=True,
                            ),
                            bgcolor=C["accent"],
                            on_click=attempt_login,
                            width=360,
                            height=46,
                            style=ft.ButtonStyle(
                                shape=ft.RoundedRectangleBorder(radius=22)),
                        ),
                    ],
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    spacing=0,
                    tight=True,
                ),
                width=380,
                bgcolor=C["surface"],
                border=ft.Border.all(1, C["border"]),
                border_radius=18,
                padding=36,
                alignment=ft.Alignment(0, 0),
            ),
            ft.Container(expand=True),
            ft.Container(
                content=_t("⚠  AUTHORIZED PERSONNEL ONLY  •  WEBSEC ENGINE V2.5",
                           color=C["muted"], size=10),
                alignment=ft.Alignment(0, 0),
                padding=ft.Padding(left=0, right=0, top=0, bottom=24),
            ),
        ],
        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        expand=True,
    )

    # ══════════════════════════════════════════════════════════════════════════
    # DASHBOARD — mutable refs
    # ══════════════════════════════════════════════════════════════════════════

    s_total  = ft.Text("—", size=30, weight=ft.FontWeight.W_800, color=C["text"])
    s_sqli   = ft.Text("—", size=30, weight=ft.FontWeight.W_800, color=C["red"])
    s_xss    = ft.Text("—", size=30, weight=ft.FontWeight.W_800, color=C["orange"])
    s_info   = ft.Text("—", size=30, weight=ft.FontWeight.W_800, color=C["yellow"])
    s_errors = ft.Text("—", size=30, weight=ft.FontWeight.W_800, color=C["muted"])

    breakdown_col   = ft.Column(spacing=12)
    ip_col          = ft.Column(spacing=0)
    key_col         = ft.Column(spacing=0)
    new_key_out     = ft.Container(visible=False)
    refresh_spinner = ft.ProgressRing(width=16, height=16, stroke_width=2,
                                      color=C["accent"], visible=False)
    auth_name       = _t("", color=C["text2"], size=11)

    dash_banner_text = ft.Text("", color=C["red"], size=12,
                                style=ft.TextStyle(font_family=MONO))
    dash_banner = ft.Container(
        content=dash_banner_text,
        bgcolor=ft.Colors.with_opacity(0.08, C["red"]),
        border=ft.Border.all(1, ft.Colors.with_opacity(0.3, C["red"])),
        border_radius=8,
        padding=ft.Padding(left=14, right=14, top=10, bottom=10),
        visible=False,
        margin=ft.margin.only(left=40, right=40),
    )

    new_label_field = ft.TextField(
        hint_text="Key label  (optional)",
        hint_style=ft.TextStyle(color=C["muted"]),
        text_style=ft.TextStyle(font_family=MONO),
        bgcolor=C["surf2"],
        border_color=C["border"],
        focused_border_color=C["accent"],
        color=C["text"],
        text_size=12,
        height=40,
        content_padding=ft.Padding(left=12, right=12, top=0, bottom=0),
        expand=True,
    )

    # ── Dashboard helpers ──────────────────────────────────────────────────────

    def _show_dash_err(msg: str) -> None:
        dash_banner_text.value = msg
        dash_banner_text.color = C["red"]
        dash_banner.bgcolor    = ft.Colors.with_opacity(0.08, C["red"])
        dash_banner.border     = ft.Border.all(1, ft.Colors.with_opacity(0.3, C["red"]))
        dash_banner.visible    = True
        dash_banner.update()

    def _show_dash_ok(msg: str) -> None:
        dash_banner_text.value = msg
        dash_banner_text.color = C["accent"]
        dash_banner.bgcolor    = ft.Colors.with_opacity(0.08, C["accent"])
        dash_banner.border     = ft.Border.all(1, ft.Colors.with_opacity(0.3, C["accent"]))
        dash_banner.visible    = True
        dash_banner.update()
        def _hide():
            time.sleep(3)
            dash_banner.visible = False
            try:
                dash_banner.update()
            except Exception:
                pass
        threading.Thread(target=_hide, daemon=True).start()

    def _populate_stats(stats: Dict[str, Any]) -> None:
        t = stats.get("totals", {})
        s_total.value  = str(t.get("total_scans", 0) or 0)
        s_sqli.value   = str(t.get("total_sqli",  0) or 0)
        s_xss.value    = str(t.get("total_xss",   0) or 0)
        s_info.value   = str(t.get("total_info",  0) or 0)
        s_errors.value = str(t.get("error_count", 0) or 0)
        for ctrl in (s_total, s_sqli, s_xss, s_info, s_errors):
            ctrl.update()

        quick  = t.get("quick_count", 0) or 0
        deep   = t.get("deep_count",  0) or 0
        vulns  = t.get("total_vulns", 0) or 0
        total  = t.get("total_scans", 0) or 0
        clean  = max(total - (t.get("total_sqli", 0) or 0)
                           - (t.get("total_xss",  0) or 0)
                           - (t.get("total_info", 0) or 0), 0)
        breakdown_col.controls = [
            breakdown_row("Scan Type Split",
                          "Quick", quick, "Deep", deep,
                          C["accent"], C["orange"]),
            breakdown_row("Findings vs Clean",
                          "Vulns", vulns, "Clean", clean,
                          C["red"], C["green"]),
        ]
        breakdown_col.update()

    def _populate_ips(ips: List[Dict[str, Any]]) -> None:
        ip_col.controls.clear()
        if not ips:
            ip_col.controls.append(
                _t("No scan activity recorded yet.", color=C["muted"], size=12))
        else:
            for entry in ips:
                ip_col.controls.append(
                    ip_row(entry.get("client_ip", ""), entry.get("last_seen", ""))
                )
        ip_col.update()

    def _populate_keys(keys: List[Dict[str, Any]]) -> None:
        key_col.controls.clear()
        if not keys:
            key_col.controls.append(
                _t("No API keys found.", color=C["muted"], size=12))
        else:
            for k in keys:
                key_col.controls.append(
                    key_row(k, on_revoke=_on_revoke, on_copy=_on_copy))
        key_col.update()

    # ── Dashboard actions ──────────────────────────────────────────────────────

    def _on_copy(key_val: str) -> None:
        page.set_clipboard(key_val)
        _show_dash_ok("API key copied to clipboard.")

    def _on_revoke(key_id: int, active: bool) -> None:
        if not active:
            return
        def _do() -> None:
            try:
                state["client"].revoke_key(key_id)
                _show_dash_ok(f"Key #{key_id} revoked.")
                _refresh_keys()
            except Exception as exc:
                _show_dash_err(f"Revoke failed: {exc}")
        threading.Thread(target=_do, daemon=True).start()

    def _on_create_key(e: ft.ControlEvent) -> None:
        label = new_label_field.value.strip()
        def _do() -> None:
            try:
                result = state["client"].create_key(label)
                new_key = result.get("key", "")
                new_key_out.content = ft.Container(
                    content=ft.Column(
                        controls=[
                            _label("New API Key — copy now, shown once"),
                            ft.Row(
                                controls=[
                                    ft.Text(new_key, color=C["accent"], size=11,
                                            selectable=True, expand=True,
                                            style=ft.TextStyle(font_family=MONO)),
                                    ft.IconButton(
                                        icon=ft.Icons.COPY_OUTLINED,
                                        icon_color=C["accent"],
                                        icon_size=15,
                                        tooltip="Copy key",
                                        on_click=lambda e, k=new_key: _on_copy(k),
                                    ),
                                ],
                                spacing=6,
                            ),
                        ],
                        spacing=6,
                        tight=True,
                    ),
                    bgcolor=ft.Colors.with_opacity(0.06, C["accent"]),
                    border=ft.Border.all(1, ft.Colors.with_opacity(0.25, C["accent"])),
                    border_radius=10,
                    padding=14,
                )
                new_key_out.visible    = True
                new_label_field.value  = ""
                new_key_out.update()
                new_label_field.update()
                _refresh_keys()
            except Exception as exc:
                _show_dash_err(f"Failed to create key: {exc}")
        threading.Thread(target=_do, daemon=True).start()

    def _refresh_stats() -> None:
        try:
            stats = state["client"].get_stats()
            _populate_stats(stats)
            _populate_ips(stats.get("recent_client_ips", []))
        except Exception as exc:
            _show_dash_err(f"Failed to refresh stats: {exc}")

    def _refresh_keys() -> None:
        try:
            keys = state["client"].list_keys()
            _populate_keys(keys)
        except Exception as exc:
            _show_dash_err(f"Failed to refresh keys: {exc}")

    def _on_refresh(e: ft.ControlEvent) -> None:
        refresh_spinner.visible = True
        refresh_spinner.update()
        def _do() -> None:
            _refresh_stats()
            _refresh_keys()
            refresh_spinner.visible = False
            try:
                refresh_spinner.update()
            except Exception:
                pass
        threading.Thread(target=_do, daemon=True).start()

    def _on_logout(e: ft.ControlEvent) -> None:
        state.update(token=None, username=None, client=None)
        user_field.value  = ""
        pass_field.value  = ""
        login_error.value = ""
        _switch_to_login()

    # ── Dashboard layout ───────────────────────────────────────────────────────

    def _stat_card(label_txt: str, value_ref: ft.Text) -> ft.Container:
        return ft.Container(
            content=ft.Column(
                controls=[_label(label_txt), value_ref],
                spacing=4, tight=True,
            ),
            bgcolor=C["surface"],
            border=ft.Border.all(1, C["border"]),
            border_radius=14, padding=20, expand=True,
        )

    dashboard_view = ft.Column(
        controls=[
            # ── Top bar ──
            ft.Container(
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
                                ft.Container(
                                    content=_t("Admin", color=C["accent"], size=9),
                                    bgcolor=ft.Colors.with_opacity(0.1, C["accent"]),
                                    border_radius=4,
                                    padding=ft.Padding(left=6, right=6, top=2, bottom=2),
                                ),
                            ],
                            spacing=10,
                        ),
                        ft.Row(expand=True),
                        refresh_spinner,
                        ft.IconButton(
                            icon=ft.Icons.REFRESH_OUTLINED,
                            icon_color=C["text2"],
                            tooltip="Refresh data",
                            on_click=_on_refresh,
                            icon_size=18,
                        ),
                        ft.Container(
                            content=ft.Row(
                                controls=[
                                    ft.Icon(ft.Icons.PERSON_OUTLINE,
                                            color=C["muted"], size=14),
                                    auth_name,
                                ],
                                spacing=6,
                            ),
                            bgcolor=C["surf2"],
                            border=ft.Border.all(1, C["border"]),
                            border_radius=100,
                            padding=ft.Padding(left=10, right=14, top=6, bottom=6),
                        ),
                        ft.TextButton(
                            content=ft.Text("Logout", color=C["muted"],
                                            size=11,
                                            style=ft.TextStyle(font_family=MONO)),
                            on_click=_on_logout,
                            style=ft.ButtonStyle(
                                padding=ft.Padding(left=10, right=10, top=4, bottom=4)),
                        ),
                    ],
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                padding=ft.Padding(left=40, right=40, top=20, bottom=16),
            ),

            # ── Sub-header ──
            ft.Container(
                content=ft.Column(
                    controls=[
                        ft.Text("SECURITY OPERATIONS CENTER",
                                color=C["accent"], size=10,
                                weight=ft.FontWeight.W_600,
                                style=ft.TextStyle(font_family=MONO)),
                        ft.Text("Admin Dashboard", color=C["text"],
                                size=24, weight=ft.FontWeight.W_800),
                    ],
                    spacing=2, tight=True,
                ),
                padding=ft.Padding(left=40, right=40, top=0, bottom=20),
            ),

            # ── Banner ──
            dash_banner,
            ft.Container(height=4),

            # ── Scrollable body ──
            ft.Column(
                controls=[

                    # Stat cards
                    ft.Container(
                        content=ft.Row(
                            controls=[
                                _stat_card("Total Scans",    s_total),
                                _stat_card("Critical (SQLi)", s_sqli),
                                _stat_card("High (XSS)",     s_xss),
                                _stat_card("Medium (Info)",  s_info),
                                _stat_card("Scan Errors",    s_errors),
                            ],
                            spacing=12,
                        ),
                        padding=ft.Padding(left=40, right=40, top=0, bottom=20),
                    ),

                    # Breakdown bars
                    ft.Container(
                        content=ft.Row(controls=[breakdown_col], spacing=0),
                        padding=ft.Padding(left=40, right=40, top=0, bottom=24),
                    ),

                    _divider(),
                    ft.Container(height=20),

                    # Client IPs
                    ft.Container(
                        content=ft.Column(
                            controls=[
                                ft.Row(controls=[
                                    _section_title("Recent Client IPs"),
                                    ft.Row(expand=True),
                                    _t("No PII stored beyond IP address",
                                       color=C["muted"], size=10),
                                ]),
                                ft.Container(height=6),
                                ft.Container(
                                    content=ip_col,
                                    bgcolor=C["surface"],
                                    border=ft.Border.all(1, C["border"]),
                                    border_radius=12,
                                    padding=ft.Padding(left=16, right=16,
                                                       top=4, bottom=4),
                                    clip_behavior=ft.ClipBehavior.HARD_EDGE,
                                ),
                            ],
                            spacing=0,
                        ),
                        padding=ft.Padding(left=40, right=40, top=0, bottom=24),
                    ),

                    _divider(),
                    ft.Container(height=20),

                    # API key management
                    ft.Container(
                        content=ft.Column(
                            controls=[
                                _section_title("API Key Management"),
                                ft.Container(height=12),
                                ft.Container(
                                    content=ft.Row(
                                        controls=[
                                            new_label_field,
                                            ft.ElevatedButton(
                                                content=ft.Row(
                                                    controls=[
                                                        ft.Icon(ft.Icons.ADD, size=15,
                                                                color=ft.Colors.WHITE),
                                                        ft.Text("Generate Key", size=12,
                                                                weight=ft.FontWeight.W_700,
                                                                color=ft.Colors.WHITE),
                                                    ],
                                                    spacing=6, tight=True,
                                                ),
                                                bgcolor=C["accent"],
                                                on_click=_on_create_key,
                                                height=42,
                                                style=ft.ButtonStyle(
                                                    shape=ft.RoundedRectangleBorder(
                                                        radius=10)),
                                            ),
                                        ],
                                        spacing=10,
                                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                                    ),
                                    bgcolor=C["surf2"],
                                    border=ft.Border.all(1, C["border"]),
                                    border_radius=10,
                                    padding=ft.Padding(left=12, right=12,
                                                       top=8, bottom=8),
                                ),
                                new_key_out,
                                ft.Container(height=8),
                                ft.Container(
                                    content=key_col,
                                    bgcolor=C["surface"],
                                    border=ft.Border.all(1, C["border"]),
                                    border_radius=12,
                                    padding=ft.Padding(left=16, right=16,
                                                       top=4, bottom=4),
                                    clip_behavior=ft.ClipBehavior.HARD_EDGE,
                                ),
                            ],
                            spacing=6,
                        ),
                        padding=ft.Padding(left=40, right=40, top=0, bottom=40),
                    ),

                    # Footer
                    ft.Container(
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
                    ),
                ],
                spacing=0,
                scroll=ft.ScrollMode.AUTO,
                expand=True,
            ),
        ],
        spacing=0,
        expand=True,
    )

    # ══════════════════════════════════════════════════════════════════════════
    # View switcher
    # ══════════════════════════════════════════════════════════════════════════

    def _switch_to_login() -> None:
        page.controls.clear()
        page.add(ft.Container(content=login_view, expand=True, bgcolor=C["bg"]))
        page.update()

    def _switch_to_dashboard() -> None:
        page.controls.clear()
        page.add(ft.Container(content=dashboard_view, expand=True, bgcolor=C["bg"]))
        page.update()

    def _load_and_show_dashboard() -> None:
        auth_name.value       = state.get("username", "")
        login_spinner.visible = False
        try:
            login_spinner.update()
        except Exception:
            pass
        try:
            stats = state["client"].get_stats()
            _populate_stats(stats)
            _populate_ips(stats.get("recent_client_ips", []))
        except Exception:
            pass
        try:
            keys = state["client"].list_keys()
            _populate_keys(keys)
        except Exception:
            pass
        _switch_to_dashboard()

    _switch_to_login()


if __name__ == "__main__":
    ft.run(main)
