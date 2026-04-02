from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import List, Dict, Set, Optional
import requests
from bs4 import BeautifulSoup
import urllib.parse
import re
from concurrent.futures import ThreadPoolExecutor
import uvicorn
import database

app = FastAPI(title="Web Security Scanner API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# Request/Response Models
class ScanRequest(BaseModel):
    target_url: str
    max_depth: Optional[int] = 3

class ScanResponse(BaseModel):
    success: bool
    message: str
    scan_id: Optional[int] = None
    urls_scanned: int
    vulnerabilities: List[Dict]
    total_vulnerabilities: int

# API Key Authentication
def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    if not database.verify_api_key(token):
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")
    return token

# WebSecurityScanner Class (ported from original)
class WebSecurityScanner:
    def __init__(self, target_url: str, max_depth: int = 3):
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebSecurityScanner/1.0'
        })

    def normalize_url(self, url: str) -> str:
        """Normalize URL for comparison"""
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def crawl(self, url: str, depth: int = 0) -> None:
        """Crawl website recursively up to max_depth"""
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
            print(f"Error crawling {url}: {str(e)}")

    def check_sql_injection(self, url: str) -> None:
        """Test for SQL injection vulnerabilities"""
        sql_payloads = [
            "'", 
            "1' OR '1'='1", 
            "' OR 1=1--", 
            "' UNION SELECT NULL--",
            "' AND 1=2--",
            "admin'--"
        ]
        
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            if not params:
                return
            
            for payload in sql_payloads:
                for param in params:
                    original_value = params[param][0]
                    test_url = url.replace(
                        f"{param}={original_value}", 
                        f"{param}={urllib.parse.quote(payload)}"
                    )
                    
                    response = self.session.get(test_url, timeout=5)
                    
                    # Check for SQL error messages
                    sql_errors = [
                        'sql', 'mysql', 'sqlite', 'postgresql', 'oracle',
                        'syntax error', 'database error', 'warning: mysql'
                    ]
                    
                    if any(err in response.text.lower() for err in sql_errors):
                        self.vulnerabilities.append({
                            'type': 'SQL Injection',
                            'severity': 'HIGH',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'description': f'Possible SQL injection in parameter "{param}"'
                        })
                        break
        except Exception as e:
            print(f"Error testing SQL injection on {url}: {str(e)}")

    def check_xss(self, url: str) -> None:
        """Test for Cross-Site Scripting vulnerabilities"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'-alert(1)-'",
            "\"><script>alert(String.fromCharCode(88,83,83))</script>"
        ]
        
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            if not params:
                return
            
            for payload in xss_payloads:
                for param in params:
                    original_value = params[param][0]
                    test_url = url.replace(
                        f"{param}={original_value}",
                        f"{param}={urllib.parse.quote(payload)}"
                    )
                    
                    response = self.session.get(test_url, timeout=5)
                    
                    # Check if payload is reflected in response
                    if payload in response.text or urllib.parse.unquote(payload) in response.text:
                        self.vulnerabilities.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'MEDIUM',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'description': f'Possible XSS vulnerability in parameter "{param}"'
                        })
                        break
        except Exception as e:
            print(f"Error testing XSS on {url}: {str(e)}")

    def check_sensitive_info(self, url: str) -> None:
        """Check for sensitive information exposure"""
        patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'api_key': r'api[_-]?key[_-]?([\'"|`])([a-zA-Z0-9]{32,45})\1',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
        }
        
        try:
            response = self.session.get(url, timeout=5)
            
            for info_type, pattern in patterns.items():
                matches = list(re.finditer(pattern, response.text))
                if matches:
                    self.vulnerabilities.append({
                        'type': 'Sensitive Information Exposure',
                        'severity': 'MEDIUM',
                        'url': url,
                        'info_type': info_type,
                        'count': len(matches),
                        'description': f'Found {len(matches)} {info_type} pattern(s) in response'
                    })
        except Exception as e:
            print(f"Error checking sensitive information on {url}: {str(e)}")

    def quickscan(self) -> List[Dict]:
        """Quick scan - only tests the target URL"""
        self.visited_urls.add(self.target_url)
        self.check_sql_injection(self.target_url)
        self.check_xss(self.target_url)
        self.check_sensitive_info(self.target_url)
        return self.vulnerabilities

    def deepscan(self) -> List[Dict]:
        """Deep scan - crawls and tests all discovered URLs"""
        self.crawl(self.target_url)
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            for url in self.visited_urls:
                executor.submit(self.check_sql_injection, url)
                executor.submit(self.check_xss, url)
                executor.submit(self.check_sensitive_info, url)
        
        return self.vulnerabilities

# API Endpoints
@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    database.init_database()
    print("Database initialized")

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Web Security Scanner API",
        "version": "1.0.0",
        "endpoints": {
            "quickscan": "/api/quickscan",
            "deepscan": "/api/deepscan",
            "health": "/health"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}

@app.post("/api/quickscan", response_model=ScanResponse)
async def quickscan(
    scan_request: ScanRequest,
    request: Request,
    api_key: str = Depends(verify_api_key)
):
    """
    Perform a quick security scan on the target URL
    Tests only the provided URL for vulnerabilities
    """
    target_url = scan_request.target_url
    
    # Validate URL format
    url_pattern = re.compile(
        r"^(https?://)?(localhost|([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,})(:\d{1,5})?(/[^\s]*)?$",
        re.IGNORECASE
    )
    if not url_pattern.match(target_url):
        raise HTTPException(status_code=400, detail="Invalid URL format")
    
    # Ensure URL has scheme
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    # Get client IP
    client_ip = request.client.host
    
    try:
        # Perform scan
        scanner = WebSecurityScanner(target_url, max_depth=scan_request.max_depth)
        vulnerabilities = scanner.quickscan()
        
        # Save to database
        scan_id = database.save_scan(
            client_ip=client_ip,
            target_url=target_url,
            scan_type="quickscan",
            vulnerabilities=vulnerabilities,
            endpoints_count=len(scanner.visited_urls)
        )
        
        return ScanResponse(
            success=True,
            message="Quick scan completed successfully",
            scan_id=scan_id,
            urls_scanned=len(scanner.visited_urls),
            vulnerabilities=vulnerabilities,
            total_vulnerabilities=len(vulnerabilities)
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@app.post("/api/deepscan", response_model=ScanResponse)
async def deepscan(
    scan_request: ScanRequest,
    request: Request,
    api_key: str = Depends(verify_api_key)
):
    """
    Perform a deep security scan on the target URL
    Crawls the website and tests all discovered URLs
    """
    target_url = scan_request.target_url
    
    # Validate URL format
    url_pattern = re.compile(
        r"^(https?://)?(localhost|([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,})(:\d{1,5})?(/[^\s]*)?$",
        re.IGNORECASE
    )
    if not url_pattern.match(target_url):
        raise HTTPException(status_code=400, detail="Invalid URL format")
    
    # Ensure URL has scheme
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    # Get client IP
    client_ip = request.client.host
    
    try:
        # Perform scan
        scanner = WebSecurityScanner(target_url, max_depth=scan_request.max_depth)
        vulnerabilities = scanner.deepscan()
        
        # Save to database
        scan_id = database.save_scan(
            client_ip=client_ip,
            target_url=target_url,
            scan_type="deepscan",
            vulnerabilities=vulnerabilities,
            endpoints_count=len(scanner.visited_urls)
        )
        
        return ScanResponse(
            success=True,
            message="Deep scan completed successfully",
            scan_id=scan_id,
            urls_scanned=len(scanner.visited_urls),
            vulnerabilities=vulnerabilities,
            total_vulnerabilities=len(vulnerabilities)
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: int, api_key: str = Depends(verify_api_key)):
    """Retrieve a specific scan by ID"""
    scan = database.get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.get("/api/scans")
async def list_scans(limit: int = 100, api_key: str = Depends(verify_api_key)):
    """List recent scans"""
    scans = database.get_all_scans(limit=limit)
    return {"scans": scans, "count": len(scans)}

@app.get("/api/stats")
async def get_stats(api_key: str = Depends(verify_api_key)):
    """Get aggregated scan statistics"""
    stats = database.get_scan_stats()
    return stats

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
