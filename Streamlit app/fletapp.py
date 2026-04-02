import flet as ft
import sqlite3
import hashlib
import json
import re
import asyncio
from datetime import datetime
# Assuming scanner.py contains WebSecurityScanner class
from scanner import WebSecurityScanner

# ── Database Initialization (Shared logic) ──────────────────────────────────
def init_db():
    conn = sqlite3.connect("websec.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE, username TEXT UNIQUE,
                    password_hash TEXT, role TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
                    target_url TEXT, scan_type TEXT, timestamp DATETIME,
                    vulns_json TEXT, endpoints_count INTEGER, sqli_count INTEGER,
                    xss_count INTEGER, info_count INTEGER, total_vulns INTEGER,
                    FOREIGN KEY(user_id) REFERENCES users(id))""")
    c.execute("SELECT id FROM users WHERE username='admin'")
    if not c.fetchone():
        admin_hash = hashlib.sha256(b"admin").hexdigest()
        c.execute("INSERT INTO users (email, username, password_hash, role) VALUES (?, ?, ?, ?)",
                  ("admin@websec.local", "admin", admin_hash, "admin"))
    conn.commit()
    conn.close()

def hash_pass(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# ── Main Flet App ─────────────────────────────────────────────────────────────
async def main(page: ft.Page):
    page.title = "WebSec Scanner 🛡️"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 40
    page.fonts = {
        "Syne": "https://fonts.googleapis.com/css2?family=Syne:wght@400;700;800&display=swap",
        "DMMono": "https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&display=swap"
    }
    page.theme = ft.Theme(font_family="Syne")

    # State Management
    user_data = {"id": None, "role": "user", "logged_in": False}
    
    # ── UI Components ──────────────────────────────────────────────────────────
    
    # Header / Logo
    logo = ft.Row([
        ft.Container(content=ft.Text("🛡️", size=18), bgcolor=ft.colors.GREEN_500, padding=5, border_radius=8),
        ft.Text("WebSec", weight=ft.FontWeight.BOLD, size=20, spans=[ft.TextSpan(" Scanner", ft.TextStyle(color=ft.colors.GREEN_500))])
    ])

    status_dot = ft.Container(width=10, height=10, border_radius=5, bgcolor=ft.colors.GREEN_400)
    status_text = ft.Text("IDLE", font_family="DMMono", size=12)
    status_pill = ft.Container(
        content=ft.Row([status_dot, status_text], spacing=8),
        border=ft.border.all(1, ft.colors.OUTLINE_VARIANT),
        padding=ft.padding.symmetric(6, 14),
        border_radius=100
    )

    # Metric Cards
    def metric_card(label, value, color=ft.colors.WHITE):
        return ft.Container(
            expand=True,
            bgcolor=ft.colors.SURFACE_VARIANT,
            padding=20,
            border_radius=16,
            content=ft.Column([
                ft.Text(label.upper(), size=10, font_family="DMMono", color=ft.colors.ON_SURFACE_VARIANT),
                ft.Text(value, size=32, weight=ft.FontWeight.BOLD, color=color)
            ], spacing=5)
        )

    metrics_row = ft.Row([
        metric_card("Endpoints", "0"),
        metric_card("Critical", "0", ft.colors.RED_400),
        metric_card("High", "0", ft.colors.ORANGE_400),
        metric_card("Medium", "0", ft.colors.YELLOW_400)
    ], spacing=15)

    # Scan Inputs
    target_input = ft.TextField(
        label="Target URL",
        placeholder="https://example.com",
        border_radius=12,
        text_style=ft.TextStyle(font_family="DMMono")
    )

    results_list = ft.ListView(expand=True, spacing=10, padding=20)

    # ── Auth View ──────────────────────────────────────────────────────────────
    async def login_clicked(e):
        conn = sqlite3.connect("websec.db")
        c = conn.cursor()
        pwd_hash = hash_pass(pass_field.value)
        c.execute("SELECT id, role FROM users WHERE (email=? OR username=?) AND password_hash=?",
                  (user_field.value, user_field.value, pwd_hash))
        user = c.fetchone()
        conn.close()

        if user:
            user_data["id"], user_data["role"], user_data["logged_in"] = user[0], user[1], True
            await show_scanner()
        else:
            page.snack_bar = ft.SnackBar(ft.Text("Invalid credentials"))
            page.snack_bar.open = True
            await page.update_async()

    user_field = ft.TextField(label="Username/Email", border_radius=12)
    pass_field = ft.TextField(label="Password", password=True, can_reveal_password=True, border_radius=12)
    
    auth_view = ft.Container(
        alignment=ft.alignment.center,
        content=ft.Column([
            ft.Text("Log In", size=30, weight="bold"),
            user_field, pass_field,
            ft.ElevatedButton("Login", on_click=login_clicked, bgcolor=ft.colors.GREEN_500, color=ft.colors.WHITE, width=300)
        ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=20)
    )

    # ── Scan Logic ──────────────────────────────────────────────────────────────
    async def run_scan(scan_mode):
        url = target_input.value.strip()
        if not re.match(r"^(https?://)?(localhost|([a-z0-9-]+\.)+[a-z]{2,})", url):
            page.snack_bar = ft.SnackBar(ft.Text("Invalid URL"))
            page.snack_bar.open = True
            await page.update_async()
            return

        status_dot.bgcolor = ft.colors.ORANGE_400
        status_text.value = "SCANNING..."
        results_list.controls.clear()
        await page.update_async()

        # In Flet, we run heavy blocking code in a thread to keep UI responsive
        scanner = WebSecurityScanner(url if url.startswith("http") else f"http://{url}")
        
        loop = asyncio.get_event_loop()
        vulns = await loop.run_in_executor(None, scanner.quickscan if scan_mode == "quick" else scanner.deepscan)

        # Update Metrics
        sql_cnt = sum(1 for v in vulns if "SQL" in v.get("type", ""))
        xss_cnt = sum(1 for v in vulns if "XSS" in v.get("type", ""))
        info_cnt = sum(1 for v in vulns if "Sensitive" in v.get("type", ""))
        
        metrics_row.controls[0].content.controls[1].value = str(len(scanner.visited_urls))
        metrics_row.controls[1].content.controls[1].value = str(sql_cnt)
        metrics_row.controls[2].content.controls[1].value = str(xss_cnt)
        metrics_row.controls[3].content.controls[1].value = str(info_cnt)

        for v in vulns:
            color = ft.colors.RED_400 if "SQL" in v['type'] else ft.colors.ORANGE_400
            results_list.controls.append(
                ft.ExpansionTile(
                    title=ft.Text(f"{v['type']} - {v['url'][:40]}..."),
                    subtitle=ft.Text("Security Finding", color=color),
                    controls=[ft.ListTile(title=ft.Text(f"{k}: {val}")) for k, val in v.items()]
                )
            )

        status_dot.bgcolor = ft.colors.GREEN_400
        status_text.value = "IDLE"
        await page.update_async()

    # ── View Routing ────────────────────────────────────────────────────────────
    async def show_scanner():
        page.controls.clear()
        page.add(
            ft.Row([logo, ft.Row([status_pill, ft.IconButton(ft.icons.LOGOUT, on_click=lambda _: page.window_destroy())])], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.Divider(height=40, color=ft.colors.TRANSPARENT),
            ft.Text("AUTOMATED SECURITY AUDIT", size=10, color=ft.colors.GREEN_500, font_family="DMMono"),
            ft.Text("Website Security Scanner", size=36, weight=ft.FontWeight.BOLD),
            ft.Divider(height=20, color=ft.colors.TRANSPARENT),
            metrics_row,
            ft.Divider(height=20, color=ft.colors.TRANSPARENT),
            target_input,
            ft.Row([
                ft.ElevatedButton("⚡ Quick Scan", on_click=lambda _: run_scan("quick"), bgcolor=ft.colors.GREEN_600, color=ft.colors.WHITE, expand=True),
                ft.ElevatedButton("🕷 Deep Scan", on_click=lambda _: run_scan("deep"), bgcolor=ft.colors.BLUE_600, color=ft.colors.WHITE, expand=True),
            ], spacing=20),
            ft.Text("Security Findings", size=20, weight="bold"),
            results_list
        )
        await page.update_async()

    # Start with Auth
    init_db()
    page.add(auth_view)
    await page.update_async()

ft.app(target=main)