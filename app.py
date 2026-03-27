from datetime import datetime, timedelta
from typing import List
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl

app = FastAPI(title="SiteShield Scanner API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/assets", StaticFiles(directory="."), name="assets")

REQUIRED_SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
]


class ScanOptions(BaseModel):
    ssl: bool = True
    headers: bool = True
    perf: bool = True
    vulns: bool = True


class ScanRequest(BaseModel):
    url: HttpUrl
    options: ScanOptions = ScanOptions()


def normalize_url(raw_url: str) -> str:
    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        raw_url = "https://" + raw_url
    return raw_url


def evaluate_ssl(hostname: str, timeout: int = 10):
    import socket
    import ssl

    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                if not not_after:
                    raise ValueError("Missing certificate expiry info")
                expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = max((expiry_date - datetime.utcnow()).days, 0)
                grade = "A+" if days_left > 90 else "A" if days_left > 30 else "B" if days_left > 7 else "C"
                return {
                    "valid": True,
                    "daysLeft": days_left,
                    "grade": grade,
                    "protocol": "TLS",
                    "expires": expiry_date.isoformat() + "Z",
                }
    except Exception as e:
        return {
            "valid": False,
            "daysLeft": 0,
            "grade": "F",
            "protocol": "None",
            "error": str(e),
        }


def evaluate_security_headers(headers: httpx.Headers):
    present = []
    missing = []
    lower_headers = {k.lower(): v for k, v in headers.items()}
    for required in REQUIRED_SECURITY_HEADERS:
        if required in lower_headers:
            present.append(required)
        else:
            missing.append(required)
    score = int(len(present) / len(REQUIRED_SECURITY_HEADERS) * 100)
    return {
        "present": present,
        "missing": missing,
        "score": score,
    }


def detect_vulnerabilities(ssl_data: dict, headers_data: dict, response: httpx.Response):
    issues = []
    if not ssl_data.get("valid", False):
        issues.append({"sev": "fail", "msg": "HTTPS not configured or invalid certificate."})
    if "server" in response.headers:
        issues.append({"sev": "info", "msg": "Server header is exposed, consider hiding version metadata."})
    if "x-frame-options" not in map(str.lower, response.headers.keys()):
        issues.append({"sev": "warn", "msg": "Missing X-Frame-Options header (clickjacking risk)."})
    if "content-security-policy" not in map(str.lower, response.headers.keys()):
        issues.append({"sev": "warn", "msg": "Missing Content-Security-Policy header (XSS mitigation)."})
    if response.status_code >= 500:
        issues.append({"sev": "warn", "msg": f"Server returned status code {response.status_code}."})
    if len(issues) == 0:
        issues.append({"sev": "ok", "msg": "No obvious vulnerabilities detected from initial checks."})
    return issues


@app.get("/", response_class=FileResponse)
async def root():
    return FileResponse("index.html")


@app.post("/api/scan")
async def api_scan(payload: ScanRequest):
    url = normalize_url(str(payload.url))
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="URL scheme must be http or https")

    ssl_data = {
        "valid": False,
        "daysLeft": 0,
        "grade": "F",
        "protocol": "None",
    }
    if payload.options.ssl and parsed.scheme == "https":
        ssl_data = evaluate_ssl(parsed.hostname)

    try:
        start = datetime.utcnow()
        async with httpx.AsyncClient(timeout=20.0, verify=True, follow_redirects=True) as client:
            resp = await client.get(url)
        end = datetime.utcnow()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Unable to reach target: {exc}")

    header_data = evaluate_security_headers(resp.headers) if payload.options.headers else {"present": [], "missing": [], "score": 0}
    perf_score = 0
    perf = {
        "score": 0,
        "ttfb": resp.elapsed.total_seconds() * 1000,
        "fcp": None,
        "lcp": None,
        "cls": None,
        "totalTimeMs": (end - start).total_seconds() * 1000,
        "contentLength": len(resp.content),
    }
    if payload.options.perf:
        norm = min(100, max(0, int(100 - (perf["ttfb"] / 20))))
        perf_score = int((norm * 0.7) + (min(100, int(min(5000, perf["contentLength"]) / 50)) * 0.3))
        perf["score"] = perf_score
    else:
        perf_score = 50
        perf["score"] = 50

    vulnerabilities = detect_vulnerabilities(ssl_data, header_data, resp) if payload.options.vulns else [{"sev": "ok", "msg": "Vulnerability checks skipped."}]

    overall = int(
        (30 if ssl_data.get("valid") else 0) +
        (40 * (header_data["score"] / 100)) +
        (30 * (perf_score / 100))
    )
    overall = min(max(overall, 0), 100)

    response = {
        "score": overall,
        "ssl": ssl_data,
        "headers": header_data,
        "vulns": vulnerabilities,
        "perf": perf,
    }

    return response
