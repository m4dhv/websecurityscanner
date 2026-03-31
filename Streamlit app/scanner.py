import requests
from bs4 import BeautifulSoup
import urllib.parse
import re
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Set
import sys
import colorama
import sqlite3
import json
from datetime import datetime

class WebSecurityScanner:
    def __init__(self, target_url: str, max_depth: int = 3):
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.session = requests.Session()
        colorama.init()

    def normalize_url(self, url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def crawl(self, url: str, depth: int = 0) -> None:
        if depth > self.max_depth or url in self.visited_urls:
            return
        try:
            self.visited_urls.add(url)
            response = self.session.get(url, verify=False, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                next_url = urllib.parse.urljoin(url, link['href'])
                if next_url.startswith(self.target_url):
                    self.crawl(next_url, depth + 1)
        except Exception as e:
            # RESTORED: Explicit error reporting
            print(f"Error crawling {url}: {str(e)}")

    def check_sql_injection(self, url: str) -> None:
        sql_payloads = ["'", "1' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"]
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for payload in sql_payloads:
                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    response = self.session.get(test_url, timeout=5)
                    if any(err in response.text.lower() for err in ['sql', 'mysql', 'sqlite', 'postgresql', 'oracle']):
                        self.vulnerabilities.append({'type': 'SQL Injection', 'url': url, 'parameter': param, 'payload': payload})
                        print(f"{colorama.Fore.RED}[VULNERABILITY FOUND]{colorama.Style.RESET_ALL} SQL Injection at {url}")
        except Exception as e:
            # RESTORED: Explicit error reporting
            print(f"Error testing SQL injection on {url}: {str(e)}")

    def check_xss(self, url: str) -> None:
        xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "javascript:alert('XSS')"]
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for payload in xss_payloads:
                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={urllib.parse.quote(payload)}")
                    response = self.session.get(test_url, timeout=5)
                    if payload in response.text:
                        self.vulnerabilities.append({'type': 'Cross-Site Scripting (XSS)', 'url': url, 'parameter': param, 'payload': payload})
                        print(f"{colorama.Fore.RED}[VULNERABILITY FOUND]{colorama.Style.RESET_ALL} XSS at {url}")
        except Exception as e:
            # RESTORED: Explicit error reporting
            print(f"Error testing XSS on {url}: {str(e)}")

    def check_sensitive_info(self, url: str) -> None:
        patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'api_key': r'api[_-]?key[_-]?([\'"|`])([a-zA-Z0-9]{32,45})\1'
        }
        try:
            response = self.session.get(url, timeout=5)
            for info_type, pattern in patterns.items():
                for match in re.finditer(pattern, response.text):
                    self.vulnerabilities.append({'type': 'Sensitive Information Exposure', 'url': url, 'info_type': info_type, 'pattern': pattern})
                    print(f"{colorama.Fore.RED}[VULNERABILITY FOUND]{colorama.Style.RESET_ALL} Sensitive {info_type} at {url}")
        except Exception as e:
            # RESTORED: Explicit error reporting for "bullshit" URLs
            print(f"Error checking sensitive information on {url}: {str(e)}")

    def quickscan(self) -> List[Dict]:
        self.visited_urls.add(self.target_url)
        self.check_sql_injection(self.target_url)
        self.check_xss(self.target_url)
        self.check_sensitive_info(self.target_url)
        return self.vulnerabilities

    def deepscan(self) -> List[Dict]:
        self.crawl(self.target_url)
        with ThreadPoolExecutor(max_workers=5) as executor:
            for url in self.visited_urls:
                executor.submit(self.check_sql_injection, url)
                executor.submit(self.check_xss, url)
                executor.submit(self.check_sensitive_info, url)
        return self.vulnerabilities

if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] not in ("--quickscan", "--deepscan"):
        print("Usage: python scanner.py --quickscan|--deepscan <target_url> [username]")
        sys.exit(1)

    mode, target_url = sys.argv[1], sys.argv[2]
    username = sys.argv[3] if len(sys.argv) > 3 else "admin"

    url_pattern = re.compile(
        r"^(https?://)?(localhost|([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,})(:\d{1,5})?(/[^\s]*)?$",
        re.IGNORECASE
    )
    if not url_pattern.match(target_url):
        print(f"{colorama.Fore.RED}[!] Error: '{target_url}' is not a valid URL structure.{colorama.Style.RESET_ALL}")
        sys.exit(1)

    scanner = WebSecurityScanner(target_url)
    vulnerabilities = scanner.quickscan() if mode == "--quickscan" else scanner.deepscan()

    print(f"\n{colorama.Fore.GREEN}Scan Complete!{colorama.Style.RESET_ALL}")
    print(f"Total URLs scanned: {len(scanner.visited_urls)}")
    print(f"Vulnerabilities found: {len(vulnerabilities)}")

    # Database Logging
    try:
        conn = sqlite3.connect("websec.db")
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username=?", (username,))
        user_row = c.fetchone()
        if user_row:
            sql_cnt = sum(1 for v in vulnerabilities if "SQL" in v.get("type", ""))
            xss_cnt = sum(1 for v in vulnerabilities if "XSS" in v.get("type", ""))
            info_cnt = sum(1 for v in vulnerabilities if "Sensitive" in v.get("type", ""))
            c.execute("""INSERT INTO scans 
                         (user_id, target_url, scan_type, timestamp, vulns_json, endpoints_count, sqli_count, xss_count, info_count, total_vulns) 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                      (user_row[0], target_url, mode[2:], datetime.now(), json.dumps(vulnerabilities), len(scanner.visited_urls), sql_cnt, xss_cnt, info_cnt, len(vulnerabilities)))
            conn.commit()
        conn.close()
    except Exception:
         pass