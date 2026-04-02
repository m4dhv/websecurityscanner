import flet as ft
import sqlite3
import hashlib
import json
import re
import time
import io
from datetime import datetime
from contextlib import redirect_stdout

# Note: Ensure scanner.py is in the same directory
try:
    from scanner import WebSecurityScanner
except ImportError:
    class WebSecurityScanner:
        def __init__(self, url, max_depth=3):
            self.url = url
            self.visited_urls = [url]
        def quickscan(self): return []
        def deepscan(self): return []

# ── Database Initialization ───────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect("websec.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE,
                    username TEXT UNIQUE,
                    password_hash TEXT,
                    role TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    target_url TEXT,
                    scan_type TEXT,
                    timestamp DATETIME,
                    vulns_json TEXT,
                    endpoints_count INTEGER,
                    sqli_count INTEGER,
                    xss_count INTEGER,
                    info_count INTEGER,
                    total_vulns INTEGER,
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

# ── Main Application ──────────────────────────────────────────────────────────
def main(page: ft.Page):
    page.title = "WebSec Scanner"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 50
    page.window_width = 1100
    page.window_height = 900
    
    # Global state for this session
    state = {
        "user_id": None,
        "role": "user",
        "logged_in": False,
        "status": "IDLE",
        "vulns": [],
        "urls_cnt": 0
    }

    # ── UI Helpers ───────────────────────────────────────────────────────────
    def get_status_pill():
        # Using string colors to avoid 'module has no attribute colors'
        dot_color = "green" if state["status"] == "IDLE" else "orange"
        if not state["logged_in"]: dot_color = "red"
        
        return ft.Container(
            content=ft.Row([
                ft.Container(width=8, height=8, bgcolor=dot_color, border_radius=4),
                ft.Text(state["status"] if state["logged_in"] else "LOCKED", 
                        size=12, color="bluegrey200")
            ], spacing=8),
            padding=10,
            border=ft.border.all(1, "white10"),
            border_radius=20
        )

    def header_section():
        return ft.Row([
            ft.Row([
                ft.Container(content=ft.Text("🛡️", size=20), bgcolor="green", 
                             padding=5, border_radius=8),
                ft.Text("WebSec", weight="bold", size=24)
            ], spacing=12),
            get_status_pill()
        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN)

    # ── Navigation & Views ────────────────────────────────────────────────────
    def show_login(e=None):
        page.clean()
        user_input = ft.TextField(label="Username or Email", border_radius=12)
        pass_input = ft.TextField(label="Password", password=True, can_reveal_password=True, border_radius=12)
        
        def login_click(e):
            conn = sqlite3.connect("websec.db")
            c = conn.cursor()
            c.execute("SELECT id, role FROM users WHERE (email=? OR username=?) AND password_hash=?",
                      (user_input.value, user_input.value, hash_pass(pass_input.value)))
            user = c.fetchone()
            conn.close()
            if user:
                state["logged_in"] = True
                state["user_id"] = user[0]
                state["role"] = user[1]
                show_scanner()
            else:
                page.snack_bar = ft.SnackBar(ft.Text("Invalid Credentials"))
                page.snack_bar.open = True
                page.update()

        page.add(
            ft.Column([
                header_section(),
                ft.Container(height=50),
                ft.Column([
                    ft.Text("Log In", size=30, weight="bold"),
                    ft.Text("Enter credentials to continue", color="bluegrey400"),
                    user_input,
                    pass_input,
                    ft.ElevatedButton("Login", bgcolor="green", color="white", 
                                      width=400, height=50, on_click=login_click),
                    ft.TextButton("Create Account", on_click=show_register)
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=20)
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER)
        )

    def show_register(e=None):
        page.clean()
        email_in = ft.TextField(label="Email", border_radius=12)
        user_in = ft.TextField(label="Username", border_radius=12)
        pass_in = ft.TextField(label="Password", password=True, border_radius=12)
        
        def reg_click(e):
            try:
                conn = sqlite3.connect("websec.db")
                c = conn.cursor()
                c.execute("INSERT INTO users (email, username, password_hash, role) VALUES (?, ?, ?, ?)",
                          (email_in.value, user_in.value, hash_pass(pass_in.value), "user"))
                conn.commit()
                conn.close()
                show_login()
            except:
                page.snack_bar = ft.SnackBar(ft.Text("User already exists or DB error"))
                page.snack_bar.open = True
                page.update()

        page.add(
            ft.Column([
                header_section(),
                ft.Column([
                    ft.Text("New Account", size=30, weight="bold"),
                    email_in, user_in, pass_in,
                    ft.ElevatedButton("Sign Up", bgcolor="green", color="white", width=400, on_click=reg_click),
                    ft.TextButton("Back to Login", on_click=show_login)
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=20)
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER)
        )

    def show_scanner(e=None):
        page.clean()
        url_input = ft.TextField(hint_text="https://example.com", expand=True, border_radius=12)
        results_col = ft.Column(spacing=10)
        
        metrics = ft.Row([
            ft.Container(ft.Column([ft.Text("ENDPOINTS", size=10), ft.Text("0", size=30, weight="bold")], spacing=2), expand=1, bgcolor="white10", padding=20, border_radius=15),
            ft.Container(ft.Column([ft.Text("SQLi", size=10), ft.Text("0", size=30, weight="bold", color="red")], spacing=2), expand=1, bgcolor="white10", padding=20, border_radius=15),
            ft.Container(ft.Column([ft.Text("XSS", size=10), ft.Text("0", size=30, weight="bold", color="orange")], spacing=2), expand=1, bgcolor="white10", padding=20, border_radius=15),
        ])

        def run_scan(stype):
            if not url_input.value: return
            state["status"] = "SCANNING"
            page.update()
            
            scanner = WebSecurityScanner(url_input.value)
            vulns = scanner.quickscan() if stype == "quick" else scanner.deepscan()
            
            # UI Updates
            metrics.controls[0].content.controls[1].value = str(len(scanner.visited_urls))
            metrics.controls[1].content.controls[1].value = str(sum(1 for v in vulns if "SQL" in v.get("type", "")))
            metrics.controls[2].content.controls[1].value = str(sum(1 for v in vulns if "XSS" in v.get("type", "")))
            
            results_col.controls.clear()
            for v in vulns:
                results_col.controls.append(
                    ft.ExpansionTile(
                        title=ft.Text(v.get("type", "Finding")),
                        subtitle=ft.Text(v.get("url", ""), color="bluegrey400"),
                        controls=[ft.ListTile(title=ft.Text(f"{k}: {val}")) for k, val in v.items()]
                    )
                )
            state["status"] = "IDLE"
            page.update()

        page.add(
            ft.Column([
                header_section(),
                ft.Text("Website Security Scanner", size=32, weight="bold"),
                ft.Row([
                    url_input,
                    ft.ElevatedButton("Quick Scan", on_click=lambda _: run_scan("quick"), bgcolor="green", color="white"),
                    ft.ElevatedButton("Deep Scan", on_click=lambda _: run_scan("deep"), bgcolor="blue700", color="white"),
                ]),
                metrics,
                results_col
            ], scroll=ft.ScrollMode.AUTO)
        )

    init_db()
    show_login()

if __name__ == "__main__":
    ft.app(target=main)