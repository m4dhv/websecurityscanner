import flet as ft
import requests
import threading
import time

API_URL = "http://localhost:8000"

def main(page: ft.Page):
    page.title = "WebSec Scanner"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 40
    page.bgcolor = "#07090f"

    api_key_input = ft.TextField(label="Enter API Key", password=True, width=400, border_color="#1e2540")
    target_url_input = ft.TextField(label="Target URL (e.g., https://example.com)", width=600, border_color="#1e2540")
    
    status_text = ft.Text("IDLE", color=ft.Colors.BLUE_GREY_500, weight=ft.FontWeight.BOLD)
    progress_ring = ft.ProgressRing(visible=False)
    results_container = ft.Column()

    def execute_scan(scan_type):
        if not target_url_input.value:
            page.snack_bar = ft.SnackBar(ft.Text("Target URL is required."))
            page.snack_bar.open = True
            page.update()
            return

        status_text.value = "STARTING SCAN..."
        status_text.color = ft.Colors.ORANGE
        progress_ring.visible = True
        results_container.controls.clear()
        page.update()

        # Hardcode the key so you never have to type it
        headers = {"X-API-Key": "wsk_default_desktop_client"} 
        payload = {"target_url": target_url_input.value, "scan_type": scan_type}

        status_text.value = "STARTING SCAN..."
        status_text.color = ft.Colors.ORANGE
        progress_ring.visible = True
        results_container.controls.clear()
        page.update()

        # Hardcode the key so you never have to type it
        headers = {"X-API-Key": "wsk_default_desktop_client"} 
        payload = {"target_url": target_url_input.value, "scan_type": scan_type}

        status_text.value = "STARTING SCAN..."
        status_text.color = ft.Colors.ORANGE
        progress_ring.visible = True
        results_container.controls.clear()
        page.update()

        headers = {"X-API-Key": api_key_input.value}
        payload = {"target_url": target_url_input.value, "scan_type": scan_type}
        
        try:
            # 1. Start the scan
            init_res = requests.post(f"{API_URL}/scans", headers=headers, json=payload)
            if init_res.status_code != 200:
                raise Exception(init_res.json().get("detail", "Failed to start scan"))
            
            scan_id = init_res.json()["scan_id"]
            status_text.value = f"SCANNING (ID: {scan_id})..."
            page.update()

            # 2. Poll for results
            while True:
                time.sleep(2)
                poll_res = requests.get(f"{API_URL}/scans/{scan_id}", headers=headers)
                if poll_res.status_code == 200:
                    data = poll_res.json()
                    if data["status"] in ["done", "error"]:
                        break

            # 3. Render Results
            if data["status"] == "error":
                status_text.value = "SCAN ERROR"
                status_text.color = ft.Colors.RED
                results_container.controls.append(ft.Text("The scan encountered an error and could not complete.", color=ft.Colors.RED))
            else:
                status_text.value = "COMPLETE"
                status_text.color = ft.Colors.GREEN
                
                metrics_row = ft.Row([
                    ft.Card(content=ft.Container(padding=20, content=ft.Column([ft.Text("ENDPOINTS", size=12), ft.Text(str(data.get('endpoints_count', 0)), size=28, weight=ft.FontWeight.BOLD)]))),
                    ft.Card(content=ft.Container(padding=20, content=ft.Column([ft.Text("CRITICAL (SQLi)", size=12), ft.Text(str(data.get('sqli_count', 0)), size=28, color=ft.Colors.RED, weight=ft.FontWeight.BOLD)]))),
                    ft.Card(content=ft.Container(padding=20, content=ft.Column([ft.Text("HIGH (XSS)", size=12), ft.Text(str(data.get('xss_count', 0)), size=28, color=ft.Colors.ORANGE, weight=ft.FontWeight.BOLD)]))),
                ])
                results_container.controls.append(metrics_row)
                
                vulns = data.get('vulnerabilities', [])
                if not vulns:
                    results_container.controls.append(ft.Text("Target surface appears clean. No vulnerabilities detected.", color=ft.Colors.GREEN))
                else:
                    for vuln in vulns:
                        results_container.controls.append(
                            ft.ExpansionTile(
                                title=ft.Text(f"{vuln.get('type')} — {vuln.get('url')}"),
                                controls=[ft.Container(padding=10, content=ft.Text(f"Parameter: {vuln.get('parameter', 'N/A')} | Payload/Info: {vuln.get('payload', vuln.get('info_type', 'N/A'))}", color=ft.Colors.ORANGE))]
                            )
                        )
        except Exception as e:
            status_text.value = "ERROR"
            status_text.color = ft.Colors.RED
            results_container.controls.append(ft.Text(f"System Error: {str(e)}", color=ft.Colors.RED))

        progress_ring.visible = False
        page.update()

    def start_quick_scan(e):
        threading.Thread(target=execute_scan, args=("quickscan",)).start()

    def start_deep_scan(e):
        threading.Thread(target=execute_scan, args=("deepscan",)).start()

    page.add(
        ft.Row([
            ft.Row([ft.Text("🛡️ WebSec", size=24, weight=ft.FontWeight.BOLD)]),
            ft.Row([progress_ring, status_text], alignment=ft.MainAxisAlignment.END)
        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
        ft.Divider(color="#1e2540", height=40),
        target_url_input,
        ft.Row([
            ft.ElevatedButton("⚡ Quick Scan", on_click=start_quick_scan, bgcolor="#0d7e0f", color=ft.Colors.WHITE),
            ft.ElevatedButton("🕷 Deep Scan", on_click=start_deep_scan, bgcolor="#0d7e0f", color=ft.Colors.WHITE)
        ]),
        ft.Divider(color="#1e2540", height=40),
        results_container
    )

if __name__ == "__main__":
    ft.app(main)