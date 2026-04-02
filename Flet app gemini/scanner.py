import logging
import sqlite3
import json
import urllib.parse
import re
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Set
from datetime import datetime

from fastapi import FastAPI, HTTPException, Security, Request, Depends
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, HttpUrl

# Configure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# FastAPI Setup
app = FastAPI(title="WebSec Scanner API", version="3.0")
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

# ─── DATABASE DEPENDENCY ────────────────────────────────────────────────────────
def get_db_connection():
    conn = sqlite3.connect("websec.db", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def verify_api_key(api_key: str = Security(api_key_header)):
    conn = get_db_connection()
    c = conn.cursor()
    # Check against the api_keys table defined in database.py
    c.execute("SELECT active FROM api_keys WHERE key = ?", (api_key,))
    row = c.fetchone()
    conn.close()
    
    if not row or not row["active"]:
        logger.warning(f"Failed API access attempt with key: {api_key[:8]}...")
        raise HTTPException(status_code=403, detail="Invalid or inactive API Key")
    return api_key

# ─── MODELS ───────────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    target_url: str
    scan_type: str = "quick"  # "quick" or "deep"

# ─── SCANNER ENGINE ───────────────────────────────────────────────────────────
class WebSecurityScanner:
    def __init__(self, target_url: str, max_depth: int = 3):
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.session = requests.Session()
        # Suppress insecure request warnings if scanning internal dev environments
        requests.packages.urllib3.disable_warnings() 

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
            logger.error(f"Error crawling {url}: {str(e)}")

    def check_sql_injection(self, url: str) -> None:
        sql_payloads = ["'", "1' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"]
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for payload in sql_payloads:
                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    response = self.session.get(test_url, verify=False, timeout=5)
                    if any(err in response.text.lower() for err in ['sql', 'mysql', 'sqlite', 'postgresql', 'oracle']):
                        self.vulnerabilities.append({
                            'type': 'SQL Injection', 
                            'url': url, 
                            'parameter': param, 
                            'payload': payload
                        })
                        logger.warning(f"[SQLi] Vulnerability found at {url}")
        except Exception as e:
            logger.error(f"Error testing SQL injection on {url}: {str(e)}")

    def check_xss(self, url: str) -> None:
        xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "javascript:alert('XSS')"]
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for payload in xss_payloads:
                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={urllib.parse.quote(payload)}")
                    response = self.session.get(test_url, verify=False, timeout=5)
                    if payload in response.text:
                        self.vulnerabilities.append({
                            'type': 'Cross-Site Scripting (XSS)', 
                            'url': url, 
                            'parameter': param, 
                            'payload': payload
                        })
                        logger.warning(f"[XSS] Vulnerability found at {url}")
        except Exception as e:
            logger.error(f"Error testing XSS on {url}: {str(e)}")

    def check_sensitive_info(self, url: str) -> None:
        patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'api_key': r'api[_-]?key[_-]?([\'"|`])([a-zA-Z0-9]{32,45})\1'
        }
        try:
            response = self.session.get(url, verify=False, timeout=5)
            for info_type, pattern in patterns.items():
                for match in re.finditer(pattern, response.text):
                    self.vulnerabilities.append({
                        'type': 'Sensitive Information Exposure', 
                        'url': url, 
                        'info_type': info_type, 
                        'pattern': pattern
                    })
                    logger.warning(f"[INFO LEAK] Sensitive {info_type} found at {url}")
        except Exception as e:
            logger.error(f"Error checking sensitive info on {url}: {str(e)}")

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

# ─── API ENDPOINTS ────────────────────────────────────────────────────────────
@app.post("/api/scan")
def perform_scan(payload: ScanRequest, request: Request, api_key: str = Depends(verify_api_key)):
    """
    Executes a security scan against a target URL.
    Requires a valid API key in the X-API-Key header.
    """
    target_url = payload.target_url.strip()
    
    # URL Validation
    url_pattern = re.compile(
        r"^(https?://)?(localhost|([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,})(:\d{1,5})?(/[^\s]*)?$",
        re.IGNORECASE
    )
    if not url_pattern.match(target_url):
        raise HTTPException(status_code=400, detail="Invalid target URL format.")

    if not target_url.startswith("http"):
        target_url = "http://" + target_url

    logger.info(f"Initiating {payload.scan_type} scan on {target_url}")
    
    # Initialize and run scanner
    scanner = WebSecurityScanner(target_url, max_depth=3)
    try:
        if payload.scan_type == "quick":
            vulns = scanner.quickscan()
        elif payload.scan_type == "deep":
            vulns = scanner.deepscan()
        else:
            raise HTTPException(status_code=400, detail="Invalid scan_type. Must be 'quick' or 'deep'.")
    except Exception as e:
        logger.error(f"Scanner engine failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal scanning engine error.")

    # Calculate metrics
    endpoints_count = len(scanner.visited_urls)
    total_vulns = len(vulns)
    sql_cnt = sum(1 for v in vulns if "SQL" in v.get("type", ""))
    xss_cnt = sum(1 for v in vulns if "XSS" in v.get("type", ""))
    info_cnt = sum(1 for v in vulns if "Sensitive" in v.get("type", ""))

    metrics = {
        "endpoints": endpoints_count,
        "critical_sqli": sql_cnt,
        "high_xss": xss_cnt,
        "medium_info": info_cnt,
        "total": total_vulns
    }

    # Log to database
    client_ip = request.client.host if request.client else "unknown"
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
            INSERT INTO scans (client_ip, target, vulns, metrics, timestamp) 
            VALUES (?, ?, ?, ?, ?)
        """, (
            client_ip,
            target_url,
            json.dumps(vulns),
            json.dumps(metrics),
            datetime.now().isoformat()
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to log scan to database: {str(e)}")
        # We don't fail the request if logging fails, but it's noted in standard output

    return {
        "status": "success",
        "target": target_url,
        "scan_type": payload.scan_type,
        "metrics": metrics,
        "vulnerabilities": vulns
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("scanner:app", host="0.0.0.0", port=8000, reload=True)