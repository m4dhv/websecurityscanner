"""
scanner.py — WebSec Scanner · FastAPI backend
Run: uvicorn scanner:app --host 0.0.0.0 --port 8000

Auth layers
  Admin endpoints  →  JWT Bearer  (POST /auth/login → token)
  Scan  endpoints  →  X-API-Key header
"""

from __future__ import annotations
import json
import logging
import re
import threading
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set
from contextlib import asynccontextmanager
import requests
from bs4 import BeautifulSoup
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.hash import bcrypt as _bcrypt
from pydantic import BaseModel, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

import database as db

# ── Logging ────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s: %(message)s",
)
log = logging.getLogger("websec.scanner")

# ── JWT config (override via env in production) ────────────────────────────────

JWT_SECRET      = "CHANGE_ME_IN_PRODUCTION_USE_ENV_VAR"
JWT_ALGORITHM   = "HS256"
JWT_EXPIRE_MINS = 60

# ── Rate limiter (per remote IP) ───────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address)

# ── Lifespan (must be defined before FastAPI app) ─────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: runs before the app starts taking requests
    db.init_db()
    log.info("Database initialised.")

    yield

    # Shutdown: runs when the app is closing
    log.info("Shutting down scanner...")

# ── FastAPI app ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="WebSec Scanner API",
    version="2.5.0",
    docs_url="/docs",
    redoc_url=None,
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:*"],   # tighten for production
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ══════════════════════════════════════════════════════════════════════════════
# WebSecurityScanner class
# ══════════════════════════════════════════════════════════════════════════════

# Stricter SQLi detection: require DB error keywords inside a plausible
# error context rather than bare substring match on any page content.
_SQLI_ERROR_RE = re.compile(
    r"(sql\s*syntax|you have an error in your sql|"
    r"warning:\s*mysql|unclosed quotation mark|"
    r"pg_query\(\)|sqlite3?\s*exception|"
    r"ORA-\d{5}|microsoft\s+ole\s+db\s+provider|"
    r"odbc\s+sql\s+server\s+driver)",
    re.IGNORECASE,
)

# URL allow-list: only https:// or http://localhost
_SAFE_URL_RE = re.compile(
    r"^https://[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*"
    r"(\.[a-z]{2,})(:\d{1,5})?(/[^\s]*)?$"
    r"|^http://localhost(:\d{1,5})?(/[^\s]*)?$",
    re.IGNORECASE,
)

# Deepscan hard limits
_CRAWL_URL_CAP   = 50   # max URLs to crawl per scan
_THREAD_WORKERS  = 5
_REQUEST_TIMEOUT = 8    # seconds per HTTP request
_DEEPSCAN_BUDGET = 120  # total wall-clock seconds for deepscan thread pool


class WebSecurityScanner:
    """
    Passive web-security scanner.

    Changes from original
    ─────────────────────
    • verify=True on all requests (SSL certs validated)
    • Per-request timeout via _REQUEST_TIMEOUT
    • Deepscan thread pool bounded by _DEEPSCAN_BUDGET
    • Crawl capped at _CRAWL_URL_CAP to prevent runaway
    • SQLi detection uses _SQLI_ERROR_RE (no false positives on page text)
    • Thread-safe vulnerability list via threading.Lock
    • Removed colorama / print-based side effects; uses logging instead
    """

    def __init__(self, target_url: str, max_depth: int = 3) -> None:
        self.target_url  = target_url
        self.max_depth   = max_depth
        self.visited_urls: Set[str] = set()
        self._vuln_lock  = threading.Lock()
        self._vulns: List[Dict[str, Any]] = []

        self.session = requests.Session()
        self.session.headers["User-Agent"] = "WebSecScanner/2.5 (+internal)"
        # verify=True is the default but stated explicitly for clarity
        self.session.verify = True

    # ── internal helpers ───────────────────────────────────────────────────────

    def _record(self, vuln: Dict[str, Any]) -> None:
        with self._vuln_lock:
            self._vulns.append(vuln)
        log.info("[VULN] %s at %s", vuln.get("type"), vuln.get("url"))

    def _get(self, url: str) -> Optional[requests.Response]:
        try:
            return self.session.get(url, timeout=_REQUEST_TIMEOUT, allow_redirects=True)
        except requests.exceptions.SSLError as exc:
            log.warning("SSL error for %s: %s", url, exc)
        except requests.exceptions.ConnectionError as exc:
            log.warning("Connection error for %s: %s", url, exc)
        except requests.exceptions.Timeout:
            log.warning("Timeout for %s", url)
        except requests.exceptions.RequestException as exc:
            log.warning("Request error for %s: %s", url, exc)
        return None

    # ── crawl ──────────────────────────────────────────────────────────────────

    def crawl(self, url: str, depth: int = 0) -> None:
        if depth > self.max_depth:
            return
        if url in self.visited_urls:
            return
        if len(self.visited_urls) >= _CRAWL_URL_CAP:
            log.info("Crawl cap (%d) reached; stopping.", _CRAWL_URL_CAP)
            return

        self.visited_urls.add(url)
        resp = self._get(url)
        if resp is None:
            return

        soup = BeautifulSoup(resp.text, "html.parser")
        for tag in soup.find_all("a", href=True):
            next_url = urllib.parse.urljoin(url, tag["href"])
            # Stay within the target origin; strip fragments
            next_url = next_url.split("#")[0]
            if next_url.startswith(self.target_url) and next_url not in self.visited_urls:
                self.crawl(next_url, depth + 1)

    # ── SQL injection check ────────────────────────────────────────────────────

    _SQLI_PAYLOADS = [
        "'",
        "''",
        "1' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL,NULL--",
        "1; SELECT SLEEP(0)--",
    ]

    def check_sql_injection(self, url: str) -> None:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return

        for param, values in params.items():
            original_value = values[0]
            for payload in self._SQLI_PAYLOADS:
                new_qs = urllib.parse.urlencode(
                    {**{p: v[0] for p, v in params.items()}, param: payload}
                )
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                resp = self._get(test_url)
                if resp is None:
                    continue
                if _SQLI_ERROR_RE.search(resp.text):
                    self._record({
                        "type":      "SQL Injection",
                        "url":       url,
                        "parameter": param,
                        "payload":   payload,
                    })
                    # One finding per parameter is enough
                    break

    # ── XSS check ─────────────────────────────────────────────────────────────

    _XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        '"><svg onload=alert(1)>',
    ]

    def check_xss(self, url: str) -> None:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return

        for param, values in params.items():
            for payload in self._XSS_PAYLOADS:
                new_qs = urllib.parse.urlencode(
                    {**{p: v[0] for p, v in params.items()}, param: payload}
                )
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                resp = self._get(test_url)
                if resp is None:
                    continue
                # Check that the unencoded payload is reflected verbatim
                if payload in resp.text:
                    self._record({
                        "type":      "Cross-Site Scripting (XSS)",
                        "url":       url,
                        "parameter": param,
                        "payload":   payload,
                    })
                    break

    # ── Sensitive info check ───────────────────────────────────────────────────

    _SENSITIVE_PATTERNS: Dict[str, re.Pattern] = {
        "email":   re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
        "phone":   re.compile(r"\b\d{3}[.\-]?\d{3}[.\-]?\d{4}\b"),
        "ssn":     re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "api_key": re.compile(
            r'(?:api[_\-]?key|token|secret)[_\-]?\s*[=:]\s*[\'"`]?([A-Za-z0-9\-_]{32,64})[\'"`]?',
            re.IGNORECASE,
        ),
    }

    def check_sensitive_info(self, url: str) -> None:
        resp = self._get(url)
        if resp is None:
            return
        for info_type, pattern in self._SENSITIVE_PATTERNS.items():
            if pattern.search(resp.text):
                self._record({
                    "type":      "Sensitive Information Exposure",
                    "url":       url,
                    "info_type": info_type,
                })

    # ── scan modes ─────────────────────────────────────────────────────────────

    def quickscan(self) -> List[Dict]:
        self.visited_urls.add(self.target_url)
        self.check_sql_injection(self.target_url)
        self.check_xss(self.target_url)
        self.check_sensitive_info(self.target_url)
        return list(self._vulns)

    def deepscan(self) -> List[Dict]:
        self.crawl(self.target_url)
        urls_snapshot = list(self.visited_urls)

        futures = []
        with ThreadPoolExecutor(max_workers=_THREAD_WORKERS) as pool:
            for url in urls_snapshot:
                futures.append(pool.submit(self.check_sql_injection, url))
                futures.append(pool.submit(self.check_xss, url))
                futures.append(pool.submit(self.check_sensitive_info, url))

            start    = datetime.now(timezone.utc)
            for f in futures:
                elapsed   = (datetime.now(timezone.utc) - start).total_seconds()
                remaining = _DEEPSCAN_BUDGET - elapsed
                if remaining <= 0:
                    log.warning("Deepscan budget exhausted; cancelling remaining tasks.")
                    f.cancel()
                    continue
                try:
                    f.result(timeout=remaining)
                except FuturesTimeout:
                    log.warning("A scan task timed out within the budget window.")
                except Exception as exc:
                    log.error("Scan task raised: %s", exc)

        return list(self._vulns)


# ══════════════════════════════════════════════════════════════════════════════
# Auth helpers
# ══════════════════════════════════════════════════════════════════════════════

def _create_jwt(username: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINS)
    return jwt.encode(
        {"sub": username, "exp": expire},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


def _decode_jwt(token: str) -> str:
    """Return username or raise HTTP 401."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub", "")
        if not username:
            raise ValueError("empty sub")
        return username
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


# ── FastAPI dependency: validate Bearer JWT ────────────────────────────────────

async def require_admin(authorization: str = Header(...)) -> str:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Bearer token required.")
    return _decode_jwt(token)


# ── FastAPI dependency: validate API key ───────────────────────────────────────

async def require_api_key(x_api_key: str = Header(...)) -> db.sqlite3.Row:
    row = db.get_api_key(x_api_key)
    if row is None:
        raise HTTPException(status_code=403, detail="Invalid or revoked API key.")
    return row


# ══════════════════════════════════════════════════════════════════════════════
# Pydantic schemas
# ══════════════════════════════════════════════════════════════════════════════

class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    expires_in:   int = JWT_EXPIRE_MINS * 60


class ScanRequest(BaseModel):
    target_url: str
    scan_type:  str   # "quickscan" | "deepscan"

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        if not _SAFE_URL_RE.match(v):
            raise ValueError(
                "URL must be https:// (or http://localhost). "
                "IP addresses and plain http are not permitted."
            )
        return v

    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, v: str) -> str:
        if v not in ("quickscan", "deepscan"):
            raise ValueError("scan_type must be 'quickscan' or 'deepscan'.")
        return v


class ScanResponse(BaseModel):
    scan_id:    int
    status:     str
    message:    str


class ScanResult(BaseModel):
    scan_id:         int
    status:          str
    target_url:      str
    scan_type:       str
    started_at:      str
    finished_at:     Optional[str]
    endpoints_count: int
    sqli_count:      int
    xss_count:       int
    info_count:      int
    total_vulns:     int
    vulnerabilities: List[Dict[str, Any]]


# ══════════════════════════════════════════════════════════════════════════════
# Background scan runner
# ══════════════════════════════════════════════════════════════════════════════

def _run_scan(scan_id: int, target_url: str, scan_type: str) -> None:
    """Executed in a daemon thread; updates DB when done."""
    db.update_scan_running(scan_id)
    try:
        scanner = WebSecurityScanner(target_url, max_depth=3)
        vulns   = scanner.quickscan() if scan_type == "quickscan" else scanner.deepscan()

        sqli_cnt = sum(1 for v in vulns if "SQL"       in v.get("type", ""))
        xss_cnt  = sum(1 for v in vulns if "XSS"       in v.get("type", ""))
        info_cnt = sum(1 for v in vulns if "Sensitive"  in v.get("type", ""))

        db.finish_scan(
            scan_id,
            vulns=vulns,
            endpoints_count=len(scanner.visited_urls),
            sqli_count=sqli_cnt,
            xss_count=xss_cnt,
            info_count=info_cnt,
        )
        log.info("Scan %d done — %d vulns found.", scan_id, len(vulns))
    except Exception as exc:
        log.error("Scan %d failed: %s", scan_id, exc)
        db.finish_scan(
            scan_id,
            vulns=[],
            endpoints_count=0,
            sqli_count=0,
            xss_count=0,
            info_count=0,
            error=True,
        )


# ══════════════════════════════════════════════════════════════════════════════
# Routes
# ══════════════════════════════════════════════════════════════════════════════

# ── POST /auth/login ──────────────────────────────────────────────────────────

@app.post("/auth/login", response_model=LoginResponse, tags=["Admin"])
@limiter.limit("10/minute")
async def login(request: Request, body: LoginRequest) -> LoginResponse:
    """Admin login. Returns a short-lived JWT."""
    if not db.verify_admin_password(body.username, body.password):
        # Constant-time-ish: verify against a dummy hash on bad username
        raise HTTPException(status_code=401, detail="Invalid credentials.")
    token = _create_jwt(body.username)
    return LoginResponse(access_token=token)


# ── POST /scans ───────────────────────────────────────────────────────────────

@app.post("/scans", response_model=ScanResponse, tags=["Scans"])
@limiter.limit("5/minute")
async def start_scan(
    request: Request,
    body: ScanRequest,
    key_row=Depends(require_api_key),
) -> ScanResponse:
    """
    Enqueue a new scan.  Runs asynchronously in a background thread.
    Poll GET /scans/{scan_id} for results.
    """
    client_ip = request.client.host if request.client else "unknown"
    scan_id   = db.create_scan(
        client_ip  = client_ip,
        api_key_id = key_row["id"],
        target_url = body.target_url,
        scan_type  = body.scan_type,
    )
    # Fire-and-forget daemon thread (replace with Celery/ARQ for production)
    t = threading.Thread(
        target=_run_scan,
        args=(scan_id, body.target_url, body.scan_type),
        daemon=True,
        name=f"scan-{scan_id}",
    )
    t.start()
    log.info("Scan %d enqueued for %s (%s)", scan_id, body.target_url, body.scan_type)
    return ScanResponse(
        scan_id=scan_id,
        status="pending",
        message=f"Scan enqueued. Poll GET /scans/{scan_id} for results.",
    )


# ── GET /scans ────────────────────────────────────────────────────────────────

@app.get("/scans", tags=["Scans"])
@limiter.limit("30/minute")
async def list_scans(
    request: Request,
    key_row=Depends(require_api_key),
    limit: int = 20,
) -> List[Dict[str, Any]]:
    """Return the last *limit* scans for the authenticated API key."""
    rows = db.get_scans_for_key(key_row["id"], limit=min(limit, 100))
    return [dict(r) for r in rows]


# ── GET /scans/{scan_id} ──────────────────────────────────────────────────────

@app.get("/scans/{scan_id}", response_model=ScanResult, tags=["Scans"])
@limiter.limit("60/minute")
async def get_scan(
    request: Request,
    scan_id: int,
    key_row=Depends(require_api_key),
) -> ScanResult:
    """Return full results for a single scan (only if owned by caller's API key)."""
    row = db.get_scan(scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if row["api_key_id"] != key_row["id"]:
        raise HTTPException(status_code=403, detail="Access denied.")

    vulns = json.loads(row["vulns_json"]) if row["vulns_json"] else []
    return ScanResult(
        scan_id         = row["id"],
        status          = row["status"],
        target_url      = row["target_url"],
        scan_type       = row["scan_type"],
        started_at      = row["started_at"],
        finished_at     = row["finished_at"],
        endpoints_count = row["endpoints_count"],
        sqli_count      = row["sqli_count"],
        xss_count       = row["xss_count"],
        info_count      = row["info_count"],
        total_vulns     = row["total_vulns"],
        vulnerabilities = vulns,
    )


# ── Admin-only: GET /admin/stats ───────────────────────────────────────────────

@app.get("/admin/stats", tags=["Admin"])
@limiter.limit("30/minute")
async def admin_stats(
    request: Request,
    username: str = Depends(require_admin),
) -> Dict[str, Any]:
    """Aggregated scan stats for the admin dashboard. No PII."""
    return db.get_aggregate_stats()


# ── Admin-only: POST /admin/api-keys ──────────────────────────────────────────

@app.post("/admin/api-keys", tags=["Admin"])
@limiter.limit("10/minute")
async def create_key(
    request: Request,
    label: str = "",
    username: str = Depends(require_admin),
) -> Dict[str, Any]:
    """Generate a new API key."""
    return db.create_api_key(label=label)


# ── Admin-only: DELETE /admin/api-keys/{key_id} ───────────────────────────────

@app.delete("/admin/api-keys/{key_id}", tags=["Admin"])
@limiter.limit("10/minute")
async def revoke_key(
    request: Request,
    key_id: int,
    username: str = Depends(require_admin),
) -> Dict[str, str]:
    """Revoke an API key by id."""
    ok = db.revoke_api_key(key_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Key not found.")
    return {"detail": f"API key {key_id} revoked."}
