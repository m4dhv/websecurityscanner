import flet as ft
import requests

API_URL = "http://localhost:8000"

def main(page: ft.Page):
    page.title = "WebSec Admin Panel"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 40
    page.bgcolor = "#07090f"

    jwt_token = {"token": None}

    username_input = ft.TextField(label="Admin Username", width=300)
    password_input = ft.TextField(label="Password", password=True, width=300)
    
    dashboard_container = ft.Column(visible=False, expand=True)
    login_container = ft.Column([
        ft.Text("Admin Authentication", size=24, weight=ft.FontWeight.BOLD),
        ft.Text("Authorized personnel only.", color=ft.Colors.GREY_500),
        username_input,
        password_input,
        ft.ElevatedButton("Authenticate", on_click=lambda e: handle_login(), bgcolor=ft.Colors.BLUE_700, color=ft.Colors.WHITE)
    ], alignment=ft.MainAxisAlignment.CENTER)

    def handle_login():
        try:
            response = requests.post(f"{API_URL}/auth/login", json={"username": username_input.value, "password": password_input.value})
            if response.status_code == 200:
                jwt_token["token"] = response.json().get("access_token")
                login_container.visible = False
                dashboard_container.visible = True
                load_admin_data()
            else:
                page.snack_bar = ft.SnackBar(ft.Text("Authentication Failed", color=ft.Colors.WHITE), bgcolor=ft.Colors.RED_900)
                page.snack_bar.open = True
        except requests.exceptions.ConnectionError:
            page.snack_bar = ft.SnackBar(ft.Text("Connection Failed: Backend running?", color=ft.Colors.WHITE), bgcolor=ft.Colors.RED_900)
            page.snack_bar.open = True
        page.update()

    def load_admin_data():
        dashboard_container.controls.clear()
        dashboard_container.controls.append(
            ft.Row([
                ft.Text("Global Security Stats", size=28, weight=ft.FontWeight.BOLD),
                ft.ElevatedButton("Refresh", on_click=lambda e: load_admin_data())
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN)
        )
        
        try:
            headers = {"Authorization": f"Bearer {jwt_token['token']}"}
            response = requests.get(f"{API_URL}/admin/stats", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                totals = data.get("totals", {})
                
                # Render Totals Cards
                dashboard_container.controls.append(
                    ft.Row([
                        ft.Card(content=ft.Container(padding=15, content=ft.Column([ft.Text("TOTAL SCANS", size=10), ft.Text(str(totals.get('total_scans', 0)), size=24)]))),
                        ft.Card(content=ft.Container(padding=15, content=ft.Column([ft.Text("ERRORS", size=10), ft.Text(str(totals.get('error_count', 0)), size=24, color=ft.Colors.RED)]))),
                        ft.Card(content=ft.Container(padding=15, content=ft.Column([ft.Text("TOTAL SQLi", size=10), ft.Text(str(totals.get('total_sqli', 0)), size=24, color=ft.Colors.RED)]))),
                        ft.Card(content=ft.Container(padding=15, content=ft.Column([ft.Text("TOTAL XSS", size=10), ft.Text(str(totals.get('total_xss', 0)), size=24, color=ft.Colors.ORANGE)]))),
                    ])
                )
                
                # Render Recent IPs
                dashboard_container.controls.append(ft.Text("Recent Client IPs", size=20, weight=ft.FontWeight.BOLD))
                recent_ips = data.get("recent_client_ips", [])
                
                columns = [ft.DataColumn(ft.Text("IP Address")), ft.DataColumn(ft.Text("Last Seen (UTC)"))]
                rows = [ft.DataRow(cells=[ft.DataCell(ft.Text(ip.get("client_ip"))), ft.DataCell(ft.Text(ip.get("last_seen")))]) for ip in recent_ips]
                
                dashboard_container.controls.append(ft.ListView([ft.DataTable(columns=columns, rows=rows)], expand=True))
            else:
                dashboard_container.controls.append(ft.Text(f"Failed to retrieve data. Status: {response.status_code}", color=ft.Colors.RED))
        except Exception as e:
            dashboard_container.controls.append(ft.Text(f"Error loading dashboard: {str(e)}", color=ft.Colors.RED))
        
        page.update()

    page.add(login_container, dashboard_container)

if __name__ == "__main__":
    ft.app(main)