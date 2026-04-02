import flet as ft
import requests
import threading

# Backend Configuration
API_URL = "http://localhost:8000/api/scan"
API_KEY = "default_api_key_12345"

def main(page: ft.Page):
    # ─── Bulletproof Page Configuration ──────────────────────────────
    page.title = "WebSec Scanner"
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = "#07090f"
    page.padding = 40 
    
    # Hardcoded Hex Colors (Bypassing ft.colors completely)
    SURFACE_COLOR = "#0d111c"
    BORDER_COLOR = "#1e2540"
    ACCENT_GREEN = "#22c55e"
    RED = "#ff4d6d"
    ORANGE = "#ffa94d"
    YELLOW = "#ffd54d"
    
    # Standard UI Colors 
    WHITE = "#ffffff"
    WHITE54 = "#8a8a8a"
    RED_900 = "#b71c1c"

    # ─── UI Components ───────────────────────────────────────────────
    
    header = ft.Row(
        controls=[
            ft.Column([
                ft.Text("AUTOMATED SECURITY AUDIT", color=ACCENT_GREEN, size=10, weight="bold", font_family="monospace"),
                ft.Text("🛡️ Website Security Scanner", size=32, weight="bold", color=WHITE),
            ]),
            ft.TextButton("☀️ / 🌙", on_click=lambda e: toggle_theme(e))
        ],
        alignment=ft.MainAxisAlignment.SPACE_BETWEEN
    )

    url_input = ft.TextField(
        hint_text="enter URL of target website here (e.g., http://localhost)",
        bgcolor=SURFACE_COLOR,
        border_color=BORDER_COLOR,
        border_radius=10,
        color=WHITE,
        text_style=ft.TextStyle(font_family="monospace"),
        expand=True
    )

    def create_metric(title, value, value_color):
        return ft.Container(
            content=ft.Column([
                ft.Text(title, size=11, color=WHITE54, weight="w600", font_family="monospace"),
                ft.Text(str(value), size=36, color=value_color, weight="bold")
            ]),
            bgcolor=SURFACE_COLOR, border=ft.border.all(1, BORDER_COLOR), border_radius=12, padding=20, expand=True
        )

    metrics_row = ft.Row([
        create_metric("ENDPOINTS", "0", WHITE),
        create_metric("CRITICAL (SQLi)", "0", RED),
        create_metric("HIGH (XSS)", "0", ORANGE),
        create_metric("MEDIUM (INFO LEAK)", "0", YELLOW),
    ], spacing=15)

    findings_area = ft.Column(scroll=ft.ScrollMode.AUTO, expand=True)

    def show_empty_state():
        findings_area.controls.clear()
        findings_area.controls.append(
            ft.Container(
                content=ft.Text("No active scan results. Enter a target URL and choose a scan mode to begin.", color=WHITE54),
                bgcolor=SURFACE_COLOR, border=ft.border.all(1, BORDER_COLOR), border_radius=8, padding=20, width=float("inf")
            )
        )

    show_empty_state()

    # ─── Event Handlers ──────────────────────────────────────────────

    def toggle_theme(e):
        page.theme_mode = ft.ThemeMode.LIGHT if page.theme_mode == ft.ThemeMode.DARK else ft.ThemeMode.DARK
        page.bgcolor = "#f8faff" if page.theme_mode == ft.ThemeMode.LIGHT else "#07090f"
        page.update()

    def update_metrics(m_dict):
        metrics_row.controls[0] = create_metric("ENDPOINTS", m_dict.get("endpoints", 0), WHITE)
        metrics_row.controls[1] = create_metric("CRITICAL (SQLi)", m_dict.get("critical_sqli", 0), RED)
        metrics_row.controls[2] = create_metric("HIGH (XSS)", m_dict.get("high_xss", 0), ORANGE)
        metrics_row.controls[3] = create_metric("MEDIUM (INFO LEAK)", m_dict.get("medium_info", 0), YELLOW)
        page.update()

    def run_scan(scan_type):
        target = url_input.value.strip()
        if not target:
            page.snack_bar = ft.SnackBar(ft.Text("Please enter a target URL"), bgcolor=RED_900)
            page.snack_bar.open = True
            page.update()
            return

        quick_btn.disabled = True
        deep_btn.disabled = True
        url_input.disabled = True
        
        findings_area.controls.clear()
        findings_area.controls.append(
            ft.Container(
                content=ft.Row([
                    ft.ProgressRing(color=ACCENT_GREEN, width=24, height=24),
                    ft.Text(f" {scan_type.capitalize()} Scan in progress... Analyzing target architecture", color=ACCENT_GREEN, weight="bold")
                ], alignment=ft.MainAxisAlignment.CENTER),
                padding=40
            )
        )
        page.update()

        def call_api():
            try:
                headers = {"X-API-Key": API_KEY}
                payload = {"target_url": target, "scan_type": scan_type}
                res = requests.post(API_URL, json=payload, headers=headers)
                
                if res.status_code != 200:
                    raise Exception(res.json().get("detail", "API Error"))
                
                data = res.json()
                page.run_task(process_results, data)
            except Exception as ex:
                page.run_task(show_error, str(ex))

        threading.Thread(target=call_api).start()

    def process_results(data):
        update_metrics(data["metrics"])
        findings_area.controls.clear()
        vulns = data.get("vulnerabilities", [])
        
        if not vulns:
            findings_area.controls.append(
                ft.Container(
                    content=ft.Text("✅ Target surface appears clean. No vulnerabilities detected.", color=ACCENT_GREEN, weight="bold"),
                    bgcolor=SURFACE_COLOR, border=ft.border.all(1, ACCENT_GREEN), border_radius=8, padding=20
                )
            )
        else:
            for v in vulns:
                v_type = v.get("type", "Unknown")
                v_url = v.get("url", "")
                
                if "SQL" in v_type:
                    badge_color, badge_text = RED, "CRITICAL"
                elif "XSS" in v_type:
                    badge_color, badge_text = ORANGE, "HIGH"
                else:
                    badge_color, badge_text = YELLOW, "MEDIUM"

                details_col = ft.Column()
                for k, val in v.items():
                    if k != "type":
                        details_col.controls.append(
                            ft.Row([
                                ft.Text(k.upper(), color=WHITE54, width=100, font_family="monospace"), 
                                ft.Text(str(val), color=WHITE, font_family="monospace", expand=True)
                            ])
                        )

                findings_area.controls.append(
                    ft.ExpansionTile(
                        title=ft.Row([
                            ft.Text(f"[{badge_text}]", size=12, weight="bold", color=badge_color),
                            ft.Text(f"{v_type} — {v_url[:60]}...", size=14, color=WHITE)
                        ]),
                        controls=[ft.Container(content=details_col, padding=20, bgcolor="#0a0d15")],
                        bgcolor=SURFACE_COLOR, collapsed_bgcolor=SURFACE_COLOR,
                    )
                )

        quick_btn.disabled = False
        deep_btn.disabled = False
        url_input.disabled = False
        page.update()

    def show_error(err_msg):
        findings_area.controls.clear()
        findings_area.controls.append(ft.Text(f"❌ Scan Error: {err_msg}", color=RED))
        quick_btn.disabled = False
        deep_btn.disabled = False
        url_input.disabled = False
        page.update()

    # ─── Action Buttons ──────────────────────────────────────────────
    quick_btn = ft.ElevatedButton(
        text="⚡ QUICK SCAN",
        bgcolor=ACCENT_GREEN, color=WHITE,
        style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=8), padding=20),
        expand=True, on_click=lambda _: run_scan("quick")
    )
    
    deep_btn = ft.ElevatedButton(
        text="🐛 DEEP SCAN",
        bgcolor=ACCENT_GREEN, color=WHITE,
        style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=8), padding=20),
        expand=True, on_click=lambda _: run_scan("deep")
    )

    # ─── Main Layout ─────────────────────────────────────────────────
    page.add(
        header,
        ft.Container(height=20),
        ft.Row([url_input], alignment=ft.MainAxisAlignment.CENTER),
        ft.Container(height=10),
        ft.Row([ft.Container(expand=1), quick_btn, deep_btn, ft.Container(expand=1)], spacing=20),
        ft.Container(height=20),
        metrics_row,
        ft.Container(height=20),
        ft.Text("Security Findings", size=24, weight="bold", color=WHITE),
        ft.Divider(color=BORDER_COLOR),
        findings_area
    )

if __name__ == "__main__":
    try:
        ft.app(target=main)
    except TypeError:
        ft.app(main)