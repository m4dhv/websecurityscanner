from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
import urllib.parse
import sqlite3
import bcrypt
import jwt
import requests
import re
import time
import json

# Import DB connection from the previously generated database.py
from database import get_db_connection

# --- Configuration ---
SECRET_KEY = "SUPER_SECRET_PRODUCTION_KEY_CHANGE_ME"  # In prod, use os.getenv()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120

app = FastAPI(title="WebSec Engine API", version="2.5")

# Enable CORS for the React SPA
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict this to your Vercel/Netlify domains in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Security & Auth Dependencies ---
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
jwt_bearer = HTTPBearer(auto_error=False)

def verify_api_key(api_key: str = Depends(api_key_header)):
    if not api_key:
        raise HTTPException(status_code=401, detail="API Key missing")
    
    conn = get_db_connection()
    key_record = conn.execute("SELECT id FROM api_keys WHERE key=? AND active=1", (api_key,)).fetchone()
    conn.close()
    
    if not key_record:
        raise HTTPException(status_code=401, detail="Invalid or inactive API Key")
    return api_key

def verify_jwt(credentials: HTTPAuthorizationCredentials = Depends(jwt_bearer)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Bearer token missing")
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# --- Rate Limiter ---
RATE_LIMIT = 10  # Max requests per minute per IP
ip_tracker: Dict[str, List[float]] = {}

def rate_limiter(request: Request):
    client_ip = request.client.host
    current_time = time.time()
    
    if client_ip not in ip_tracker:
        ip_tracker[client_ip] = []
    
    # Filter out timestamps older than 60 seconds
    ip_tracker[client_ip] = [t for t in ip_tracker[client_ip] if current_time - t < 60]
    
    if len(ip_tracker[client_ip]) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Please try again later.")
    
    ip_tracker[client_ip].append(current_time)
    return client_ip


# --- Core Scanner Logic ---
class WebSecurityScanner:
    def __init__(self, target_url: str, max_depth: int = 3):
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited_urls = set()
        self.vulnerabilities = []
        self.session = requests.Session()
        
        # Stricter SQLi detection to prevent false positives from generic words
        self.sqli_regex = re.compile(
            r"(you have an error in your sql syntax|warning: mysql|unclosed quotation mark after the character string|quoted string not properly terminated|ora-[0-9]{4,5})",
            re.IGNORECASE
        )

    def crawl(self, url: str, depth: int = 0) -> None:
        if depth > self.max_depth or url in self.visited_urls:
            return
        try:
            self.visited_urls.add(url)
            # FIX: verify=True enforces SSL verification, timeout prevents hanging
            response = self.session.get(url, verify=True, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                next_url = urllib.parse.urljoin(url, link['href'])
                if next_url.startswith(self.target_url):
                    self.crawl(next_url, depth + 1)
        except requests.RequestException:
            pass # Silent fail for crawler to continue

    def check_sql_injection(self, url: str) -> None:
        sql_payloads = ["'", "1' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"]
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for payload in sql_payloads:
                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={urllib.parse.quote(payload)}")
                    # FIX: Enforce verify=True and 5s timeout
                    response = self.session.get(test_url, verify=True, timeout=5)
                    if self.sqli_regex.search(response.text):
                        self.vulnerabilities.append({'type': 'SQL Injection', 'url': url, 'parameter': param, 'payload': payload})
        except requests.RequestException:
            pass

    def check_xss(self, url: str) -> None:
        xss_payloads = ["<script>alert('XSS')</script>", "\"><img src=x onerror=alert('XSS')>"]
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for payload in xss_payloads:
                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={urllib.parse.quote(payload)}")
                    response = self.session.get(test_url, verify=True, timeout=5)
                    if payload in response.text:
                        self.vulnerabilities.append({'type': 'Cross-Site Scripting (XSS)', 'url': url, 'parameter': param, 'payload': payload})
        except requests.RequestException:
            pass

    def check_sensitive_info(self, url: str) -> None:
        patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'api_key': r'(?i)api[_-]?key[_-]?([\'"|`])([a-zA-Z0-9]{32,45})\1'
        }
        try:
            response = self.session.get(url, verify=True, timeout=5)
            for info_type, pattern in patterns.items():
                for match in re.finditer(pattern, response.text):
                    self.vulnerabilities.append({'type': 'Sensitive Information Exposure', 'url': url, 'info_type': info_type})
        except requests.RequestException:
            pass

    def execute_scan(self, scan_type: str) -> List[Dict]:
        self.visited_urls.add(self.target_url)
        if scan_type == "deep":
            self.crawl(self.target_url)
            
        # Multithreaded execution for faster processing
        with ThreadPoolExecutor(max_workers=5) as executor:
            for url in self.visited_urls:
                executor.submit(self.check_sql_injection, url)
                executor.submit(self.check_xss, url)
                executor.submit(self.check_sensitive_info, url)
                
        return self.vulnerabilities


# --- Pydantic Models ---
class LoginRequest(BaseModel):
    username: str
    password: str

class ScanRequest(BaseModel):
    target_url: HttpUrl
    scan_type: str = "quick" # "quick" or "deep"


# --- API Routes ---

@app.post("/admin/login")
def admin_login(creds: LoginRequest):
    conn = get_db_connection()
    user = conn.execute("SELECT id, password_hash FROM admin_users WHERE username=?", (creds.username,)).fetchone()
    conn.close()

    if not user or not bcrypt.checkpw(creds.password.encode('utf-8'), user["password_hash"].encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = jwt.encode({"sub": creds.username, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)
    
    return {"access_token": token, "token_type": "bearer"}


@app.post("/scans")
def trigger_scan(
    payload: ScanRequest, 
    client_ip: str = Depends(rate_limiter), 
    api_key: str = Depends(verify_api_key)
):
    target = str(payload.target_url)
    
    # Initialize and run scanner
    scanner = WebSecurityScanner(target)
    vulns = scanner.execute_scan(payload.scan_type)
    
    # Calculate Metrics
    metrics = {
        "endpoints_scanned": len(scanner.visited_urls),
        "total_vulns": len(vulns),
        "sqli_count": sum(1 for v in vulns if "SQL" in v["type"]),
        "xss_count": sum(1 for v in vulns if "XSS" in v["type"]),
        "info_count": sum(1 for v in vulns if "Sensitive" in v["type"])
    }

    # Save to Database
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO scans (client_ip, target, vulns, metrics) VALUES (?, ?, ?, ?)",
        (client_ip, target, json.dumps(vulns), json.dumps(metrics))
    )
    conn.commit()
    conn.close()

    return {
        "target": target,
        "metrics": metrics,
        "vulnerabilities": vulns
    }


@app.get("/scans")
def get_scans(
    api_key: Optional[str] = Depends(api_key_header),
    jwt_token: Optional[str] = Depends(jwt_bearer)
):
    """Accessible by either a valid API Key (Customer View) or JWT (Admin View)"""
    if not api_key and not jwt_token:
         raise HTTPException(status_code=401, detail="Authentication required")
         
    if api_key:
        verify_api_key(api_key)
    elif jwt_token:
        verify_jwt(jwt_token)

    conn = get_db_connection()
    # Mask client_ip to ensure no PII is exposed to the frontend
    rows = conn.execute("SELECT id, substr(client_ip, 1, 6) || '***' as client_ip, target, metrics, timestamp FROM scans ORDER BY timestamp DESC LIMIT 50").fetchall()
    conn.close()

    result = []
    for r in rows:
        result.append({
            "id": r["id"],
            "client_ip": r["client_ip"],
            "target": r["target"],
            "metrics": json.loads(r["metrics"]),
            "timestamp": r["timestamp"]
        })
        
    return result